//! The **Shared Directory List** on the actor (ADR-0101, "Shared
//! Directories"): the download directory the Core Settings name, the
//! directories the operator added, and which of them are scanned. The download
//! directory is guarded whenever it is named, and every entry when it appears
//! after missing; an added entry is guarded again at attach too, since what
//! its path leads to can change between runs. One the guards refuse is listed,
//! never scanned, and covers nothing. An add is guarded, then scanned asking;
//! the operator's yes stores it. A remove unshares its files at once through
//! the path every leaving row takes, and sets their hashes aside. Every list
//! change reconciles the scans with the outermost entries and installs the
//! list on the diagnostics level.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::directory_scan::{
    HashTurn, InstalledDirectory, InstalledState, RefusedFolders, admit, canonical, covering,
    guard_in_place,
};
use crate::registry::SharedFileRegistry;
use crate::registry_check::{CheckInput, WithheldReason};
use crate::service::activity::ScanRole;
use crate::service::{ScanEvent, ServeEvent};
use crate::store::registry::SetAsideRuling;
use crate::{DirectoryRefusal, DirectoryRole, DirectoryState, ShareGuards};

use super::{CoreActor, send_event};

/// What the actor holds of the list besides its scans.
#[derive(Debug, Default)]
pub(super) struct DirectoryList {
    /// Entry 0, as the Core Settings name it.
    pub(super) download_dir: Option<PathBuf>,
    /// The guard entry 0 failed when last judged; `None` while it passes.
    pub(super) download_refused: Option<DirectoryRefusal>,
    /// The operator's entries, by canonical path, in the order added.
    pub(super) added: Vec<PathBuf>,
    /// The guard each refused entry of `added` failed where its path led, at
    /// attach or as it appeared after missing. It stays in the list until the
    /// operator removes it, and is judged again at the next start.
    pub(super) added_refused: BTreeMap<PathBuf, DirectoryRefusal>,
    /// Why an entry with no scan has none: declined or unlistable. Cleared
    /// when its scan starts again.
    pub(super) ended: BTreeMap<PathBuf, DirectoryState>,
    /// The one turn to read a file, shared by every scan.
    pub(super) turn: HashTurn,
    /// What the guards refuse beyond the filesystem's own facts.
    pub(super) guards: ShareGuards,
    /// The Temp Directory (ADR-0115): where the next download placed keeps
    /// its part file, and what no entry may be or hold. `None` on a core
    /// given neither the setting nor a data directory.
    pub(super) temp_dir: Option<PathBuf>,
}

/// One list entry: the directory its scan walks, its canonical form, what
/// kind it is.
struct Entry {
    dir: PathBuf,
    canonical: PathBuf,
    role: ScanRole,
}

impl DirectoryList {
    /// Judge `dir` by the guards on what a directory is, where its path
    /// leads now ([`guard_in_place`]), the Temp Directory among them.
    pub(super) fn guard_in_place(&self, dir: &Path) -> Result<(), DirectoryRefusal> {
        guard_in_place(dir, &self.guards, self.temp_dir.as_deref())
    }

    /// The download directory, unless the guards refuse it.
    fn shared_download_dir(&self) -> Option<&PathBuf> {
        self.download_dir
            .as_ref()
            .filter(|_| self.download_refused.is_none())
    }

    /// The entries that may be scanned, in list order: a refused entry is
    /// not one.
    fn entries(&self) -> Vec<Entry> {
        self.shared_download_dir()
            .into_iter()
            .map(|dir| Entry {
                dir: dir.clone(),
                canonical: canonical(dir),
                role: ScanRole::DownloadDirectory,
            })
            .chain(
                self.added
                    .iter()
                    .filter(|dir| !self.added_refused.contains_key(*dir))
                    .map(|dir| Entry {
                        dir: dir.clone(),
                        canonical: dir.clone(),
                        role: ScanRole::Added,
                    }),
            )
            .collect()
    }

    /// Every entry in list order — the download directory, then the
    /// operator's — with the guard it failed, if it was refused.
    fn listed(&self) -> impl Iterator<Item = (&PathBuf, ScanRole, Option<&DirectoryRefusal>)> {
        let download = self.download_dir.iter().map(|dir| {
            (
                dir,
                ScanRole::DownloadDirectory,
                self.download_refused.as_ref(),
            )
        });
        let added = self
            .added
            .iter()
            .map(|dir| (dir, ScanRole::Added, self.added_refused.get(dir)));
        download.chain(added)
    }

    /// Whether a file at `path` lies under a refused entry, by its spelling
    /// or where it leads ([`RefusedFolders::refuses`]).
    pub(super) fn refuses(&self, path: &Path) -> bool {
        self.refused_folders().refuses(path)
    }

    /// The list as the refused-folder rule reads it now, for a caller that
    /// rules on many rows at once.
    fn refused_folders(&self) -> RefusedFolders {
        RefusedFolders::read(
            self.listed()
                .map(|(dir, _, refused)| (dir.as_path(), refused.is_some())),
        )
    }

    /// Each entry with the entry it lies under, if it is covered.
    fn covered(&self) -> Vec<(Entry, Option<PathBuf>)> {
        let entries = self.entries();
        let canon: Vec<PathBuf> = entries.iter().map(|e| e.canonical.clone()).collect();
        let by: Vec<Option<PathBuf>> = covering(&canon).into_iter().map(|(_, by)| by).collect();
        entries
            .into_iter()
            .zip(by)
            .map(|(entry, by)| {
                let by = by.map(|parent| {
                    self.entries()
                        .into_iter()
                        .find(|other| other.canonical == parent)
                        .map_or(parent, |other| other.dir)
                });
                (entry, by)
            })
            .collect()
    }
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Read the operator's entries from the store and scan them, the
    /// download directory the Core Settings name among them: the prologue's
    /// last step, once the Registry Check runs. The download directory's scan
    /// asks its first-share question from the answer recorded for it, as it
    /// does when the operator sets it on a running core.
    pub(super) async fn start_shared_directories(&mut self) {
        if let Some(dir) = self.wiring.settings.download_dir.clone() {
            self.name_download_dir(dir).await;
        }
        match self.wiring.registry.shared_directories() {
            Ok(added) => self.directories.added = added,
            Err(error) => {
                tracing::warn!(%error, "shared directories unreadable; only the download directory is scanned");
            }
        }
        for dir in self.directories.added.clone() {
            if let Err(reason) = self.directories.guard_in_place(&dir) {
                self.directories
                    .added_refused
                    .insert(dir.clone(), reason.clone());
                self.refuse(dir, reason).await;
            }
        }
        self.match_refusals().await;
        self.reconcile().await;
        self.install_directories();
    }

    /// Make the refused marks match the list. Every registry row under a
    /// refused entry is withheld as refused: a refusal at attach finds rows
    /// an earlier run offered, and one at a return finds rows withheld as
    /// their folder missing. Every row withheld as refused that no refused
    /// entry holds now — the download directory moved, or a passing entry
    /// covers it — is looked at by the Registry Check at once, since no look
    /// touches it while it is refused. A Served Download whose destination
    /// lies under a refused entry is held back the same way (ADR-0113).
    async fn match_refusals(&mut self) {
        let rows = match self.wiring.registry.list() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "rows under a refused directory not withheld; none is offered again while it is refused");
                self.match_served_refusals().await;
                return;
            }
        };
        let refused = self.directories.refused_folders();
        for row in rows {
            if refused.refuses(&row.path) {
                self.withhold(row.file_hash, Some(&row.path), WithheldReason::Refused)
                    .await;
            } else if self
                .registry_check
                .withheld
                .get(row.file_hash)
                .is_some_and(|held| held.reason == WithheldReason::Refused)
            {
                self.registry_check
                    .tell(CheckInput::RefusalLifted(row.file_hash));
            }
        }
        self.match_served_refusals().await;
    }

    /// The root of `dir`'s scan appeared after missing: judge it by the
    /// guards where its path leads now, before its pass reads anything.
    /// `false` when they refuse it, its scan stopped and the refusal said.
    pub(super) async fn returned_root_admitted(&mut self, dir: &Path) -> bool {
        match self.activities.scan(dir).map(|scan| scan.role.clone()) {
            Some(ScanRole::DownloadDirectory) => {
                if self.name_download_dir(dir.to_path_buf()).await {
                    return true;
                }
                self.refused_download_dir(dir).await;
                false
            }
            Some(ScanRole::Added) => match self.directories.guard_in_place(dir) {
                Ok(()) => true,
                Err(reason) => {
                    self.refused_added(dir.to_path_buf(), reason).await;
                    false
                }
            },
            // Guarded by the add a moment ago.
            Some(ScanRole::Adding { .. }) | None => true,
        }
    }

    /// The guards refuse the added entry `dir` where its path leads now: its
    /// scan stops, the refusal is said, the entries it covered are scanned,
    /// and the list shows it refused.
    async fn refused_added(&mut self, dir: PathBuf, reason: DirectoryRefusal) {
        self.directories
            .added_refused
            .insert(dir.clone(), reason.clone());
        self.stop_scan(&dir).await;
        self.refuse(dir, reason).await;
        self.match_refusals().await;
        self.reconcile().await;
        self.install_directories();
    }

    /// Name `dir` entry 0 and judge it by the guards, saying so when they
    /// refuse it; `true` when it passes.
    async fn name_download_dir(&mut self, dir: PathBuf) -> bool {
        let refused = self.directories.guard_in_place(&dir).err();
        self.directories.download_dir = Some(dir.clone());
        self.directories.download_refused.clone_from(&refused);
        let Some(reason) = refused else {
            return true;
        };
        tracing::warn!(dir = %dir.display(), ?reason, "download directory refused; not shared");
        send_event(
            &self.evt_tx,
            ScanEvent::DownloadDirectoryRefused { dir, reason }.into(),
        )
        .await;
        false
    }

    /// The download directory moves (the operator's set on a running core):
    /// the old one's scan stops, and the new one is guarded, then scanned
    /// unless an added entry covers it. A move to the directory already
    /// scanned is a no-op, but one whose watch did not hold runs a fresh pass.
    pub(super) async fn download_directory(&mut self, dir: PathBuf) {
        if let Some(old) = self.directories.download_dir.clone()
            && old != dir
            && !self.directories.added.contains(&old)
        {
            self.stop_scan(&old).await;
            self.directories.ended.remove(&old);
        }
        self.directories.ended.remove(&dir);
        if !self.name_download_dir(dir.clone()).await {
            return self.refused_download_dir(&dir).await;
        }
        let covered = self
            .directories
            .covered()
            .into_iter()
            .any(|(entry, by)| entry.role == ScanRole::DownloadDirectory && by.is_some());
        if !covered {
            self.start_scan(dir, ScanRole::DownloadDirectory).await;
        }
        self.match_refusals().await;
        self.reconcile().await;
        self.install_directories();
    }

    /// The Temp Directory moved (the operator's set on a running core,
    /// ADR-0115): every entry is judged again against it, as at attach, so
    /// one refused for the old Temp Directory is scanned once it passes, and
    /// an add waiting on its confirm that now is, holds or lies inside the
    /// new one is refused, its scan stopped and nothing stored.
    pub(super) async fn temp_directory_moved(&mut self, dir: PathBuf) {
        self.directories.temp_dir = Some(dir);
        let adding: Vec<PathBuf> = self
            .activities
            .scans()
            .filter(|scan| matches!(scan.role, ScanRole::Adding { .. }))
            .map(|scan| scan.dir.clone())
            .collect();
        for dir in adding {
            if let Err(reason) = self.directories.guard_in_place(&dir) {
                self.stop_scan(&dir).await;
                self.refuse(dir, reason).await;
            }
        }
        for dir in self.directories.added.clone() {
            match self.directories.guard_in_place(&dir) {
                Ok(()) => {
                    self.directories.added_refused.remove(&dir);
                }
                Err(reason) => {
                    let was = self
                        .directories
                        .added_refused
                        .insert(dir.clone(), reason.clone());
                    if was.as_ref() != Some(&reason) {
                        self.stop_scan(&dir).await;
                        self.refuse(dir, reason).await;
                    }
                }
            }
        }
        if let Some(download) = self.directories.download_dir.clone() {
            let refused = self.directories.guard_in_place(&download).err();
            if refused != self.directories.download_refused {
                if refused.is_some() {
                    self.name_download_dir(download.clone()).await;
                    self.refused_download_dir(&download).await;
                } else {
                    self.directories.download_refused = None;
                }
            }
        }
        self.match_refusals().await;
        self.reconcile().await;
        self.install_directories();
    }

    /// The guards refuse the download directory `dir`: its scan stops, the
    /// entries it covered are scanned, and the list shows it refused.
    async fn refused_download_dir(&mut self, dir: &Path) {
        if self
            .activities
            .scan(dir)
            .is_some_and(|scan| scan.role == ScanRole::DownloadDirectory)
        {
            self.stop_scan(dir).await;
        }
        self.match_refusals().await;
        self.reconcile().await;
        self.install_directories();
    }

    /// Scan every outermost entry that has no scan and did not end, and
    /// stop the scan of every entry now covered.
    async fn reconcile(&mut self) {
        for (entry, by) in self.directories.covered() {
            let scanned = self.activities.scan(&entry.dir).is_some();
            match by {
                Some(_) if scanned => self.stop_scan(&entry.dir).await,
                None if !scanned && !self.directories.ended.contains_key(&entry.dir) => {
                    self.start_scan(entry.dir, entry.role).await;
                }
                _ => {}
            }
        }
    }

    /// Guard `path`, then scan it asking: the confirm names what it would
    /// offer and which entries it replaces.
    pub(super) async fn add_shared_directory(&mut self, path: PathBuf) {
        // A refused entry is still the operator's: the same path is not added
        // twice.
        let listed: Vec<PathBuf> = self
            .directories
            .entries()
            .into_iter()
            .map(|entry| entry.canonical)
            .chain(self.directories.added_refused.keys().cloned())
            .chain(
                self.activities
                    .scans()
                    .filter(|scan| matches!(scan.role, ScanRole::Adding { .. }))
                    .map(|scan| scan.dir.clone()),
            )
            .collect();
        let dir = match admit(
            &path,
            &listed,
            &self.directories.guards,
            self.directories.temp_dir.as_deref(),
        ) {
            Ok(dir) => dir,
            Err(reason) => return self.refuse(path, reason).await,
        };
        let replaces = self
            .directories
            .added
            .iter()
            .filter(|entry| entry.starts_with(&dir))
            .cloned()
            .collect();
        self.start_scan(dir, ScanRole::Adding { replaces }).await;
    }

    /// The operator's yes to the directory being added: store it, retire
    /// the entries it replaces, and let its pass go on.
    pub(super) async fn confirm_add(&mut self, dir: PathBuf, replaces: Vec<PathBuf>) {
        if let Err(error) = self.wiring.registry.add_shared_directory(&dir, &replaces) {
            tracing::warn!(dir = %dir.display(), %error, "shared directory not stored");
            self.release_consent(&dir, false);
            return self.refuse(dir, DirectoryRefusal::StoreFailed).await;
        }
        self.directories
            .added
            .retain(|entry| !replaces.contains(entry));
        self.directories.added.push(dir.clone());
        for child in &replaces {
            self.directories.ended.remove(child);
            self.directories.added_refused.remove(child);
            self.stop_scan(child).await;
        }
        if let Some(scan) = self.activities.scan_mut(&dir) {
            scan.role = ScanRole::Added;
        }
        self.release_consent(&dir, true);
        self.scans_changed();
        self.match_refusals().await;
        send_event(
            &self.evt_tx,
            ScanEvent::DirectoryAdded {
                dir,
                replaced: replaces,
            }
            .into(),
        )
        .await;
        self.reconcile().await;
        self.install_directories();
    }

    /// Take `path` out of the list: its scan stops, and every file under it
    /// leaves the registry at once, set aside, never Had.
    pub(super) async fn remove_shared_directory(&mut self, path: PathBuf) {
        let spelled = canonical(&path);
        if self
            .directories
            .download_dir
            .as_ref()
            .is_some_and(|dl| *dl == path || canonical(dl) == spelled)
        {
            return self.refuse(path, DirectoryRefusal::DownloadDirectory).await;
        }
        let Some(dir) = self
            .directories
            .added
            .iter()
            .find(|entry| **entry == path || **entry == spelled)
            .cloned()
        else {
            return self.refuse(path, DirectoryRefusal::NotShared).await;
        };
        self.stop_scan(&dir).await;
        let kept: Vec<PathBuf> = self
            .directories
            .shared_download_dir()
            .into_iter()
            .flat_map(|dl| [dl.clone(), canonical(dl)])
            .collect();
        let rulings = match self.wiring.registry.remove_shared_directory(&dir, &kept) {
            Ok(Some(rulings)) => rulings,
            Ok(None) => return self.refuse(dir, DirectoryRefusal::NotShared).await,
            Err(error) => {
                tracing::warn!(dir = %dir.display(), %error, "shared directory not removed");
                return self.refuse(dir, DirectoryRefusal::StoreFailed).await;
            }
        };
        self.directories.added.retain(|entry| *entry != dir);
        self.directories.ended.remove(&dir);
        self.directories.added_refused.remove(&dir);
        let files = rulings.len();
        for ruling in rulings {
            match ruling {
                SetAsideRuling::Left(file_hash) => self.row_left(file_hash, Ok(true)).await,
                SetAsideRuling::Moved(file_hash) => {
                    send_event(&self.evt_tx, ServeEvent::FileShared { file_hash }.into()).await;
                    self.row_shared(file_hash);
                }
            }
        }
        self.match_refusals().await;
        tracing::info!(dir = %dir.display(), files, "shared directory removed");
        send_event(
            &self.evt_tx,
            ScanEvent::DirectoryRemoved { dir, files }.into(),
        )
        .await;
        self.reconcile().await;
        self.install_directories();
    }

    async fn refuse(&mut self, dir: PathBuf, reason: DirectoryRefusal) {
        tracing::info!(dir = %dir.display(), ?reason, "shared directory refused");
        send_event(
            &self.evt_tx,
            ScanEvent::DirectoryRefused { dir, reason }.into(),
        )
        .await;
    }

    /// Show the list on the diagnostics level: each entry's state, read from
    /// its scan's progress cell while one runs, then the directories being
    /// added.
    pub(super) fn install_directories(&self) {
        let covered = self.directories.covered();
        let mut list: Vec<InstalledDirectory> = self
            .directories
            .listed()
            .map(|(dir, role, refused)| {
                let by = covered
                    .iter()
                    .find(|(entry, _)| entry.role == role && entry.dir == *dir)
                    .and_then(|(_, by)| by.clone());
                let state = match (refused, by, self.activities.scan(dir)) {
                    (Some(reason), ..) => {
                        InstalledState::Fixed(DirectoryState::Refused(reason.clone()))
                    }
                    (None, Some(by), _) => InstalledState::Fixed(DirectoryState::Covered { by }),
                    (None, None, Some(scan)) => InstalledState::Scan(scan.progress.clone()),
                    (None, None, None) => InstalledState::Fixed(
                        self.directories
                            .ended
                            .get(dir)
                            .cloned()
                            .unwrap_or(DirectoryState::Starting),
                    ),
                };
                InstalledDirectory {
                    dir: dir.clone(),
                    role: role_of(&role),
                    state,
                }
            })
            .collect();
        list.extend(
            self.activities
                .scans()
                .filter(|scan| matches!(scan.role, ScanRole::Adding { .. }))
                .map(|scan| InstalledDirectory {
                    dir: scan.dir.clone(),
                    role: DirectoryRole::Adding,
                    state: InstalledState::Scan(scan.progress.clone()),
                }),
        );
        self.diagnostics.install_shared_directories(list);
    }
}

const fn role_of(role: &ScanRole) -> DirectoryRole {
    match role {
        ScanRole::DownloadDirectory => DirectoryRole::DownloadDirectory,
        ScanRole::Added => DirectoryRole::Added,
        ScanRole::Adding { .. } => DirectoryRole::Adding,
    }
}
