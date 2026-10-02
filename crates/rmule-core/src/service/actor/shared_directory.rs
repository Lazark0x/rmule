//! The **Shared Directory List** on the actor (ADR-0100, "Shared
//! Directories"): the download directory the front end names, the
//! directories the operator added, and which of them are scanned. An add is
//! guarded, then scanned asking; the operator's yes stores it. A remove
//! unshares its files at once through the path every leaving row takes, and
//! sets their hashes aside. Every list change reconciles the scans with the
//! outermost entries and installs the list on the diagnostics level.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::directory_scan::{
    HashTurn, InstalledDirectory, InstalledState, admit, canonical, covering,
};
use crate::service::activity::ScanRole;
use crate::service::{ScanEvent, ServeEvent};
use crate::store::registry::SetAsideRuling;
use crate::{DirectoryRefusal, DirectoryRole, DirectoryState, ShareGuards};

use super::{CoreActor, send_event};

/// What the actor holds of the list besides its scans.
#[derive(Debug, Default)]
pub(super) struct DirectoryList {
    /// Entry 0, as the front end's preference names it.
    pub(super) download_dir: Option<PathBuf>,
    /// The operator's entries, by canonical path, in the order added.
    pub(super) added: Vec<PathBuf>,
    /// Why an entry with no scan has none: declined or unlistable. Cleared
    /// when its scan starts again.
    pub(super) ended: BTreeMap<PathBuf, DirectoryState>,
    /// The one turn to read a file, shared by every scan.
    pub(super) turn: HashTurn,
    /// What the guards refuse beyond the filesystem's own facts.
    pub(super) guards: ShareGuards,
}

/// One list entry: the directory its scan walks, its canonical form, what
/// kind it is.
struct Entry {
    dir: PathBuf,
    canonical: PathBuf,
    role: ScanRole,
}

impl DirectoryList {
    fn entries(&self) -> Vec<Entry> {
        self.download_dir
            .iter()
            .map(|dir| Entry {
                dir: dir.clone(),
                canonical: canonical(dir),
                role: ScanRole::DownloadDirectory,
            })
            .chain(self.added.iter().map(|dir| Entry {
                dir: dir.clone(),
                canonical: dir.clone(),
                role: ScanRole::Added,
            }))
            .collect()
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
    /// Read the operator's entries from the store and scan them: the
    /// prologue's last step, once the Registry Check runs.
    pub(super) async fn start_shared_directories(&mut self) {
        match self.wiring.registry.shared_directories() {
            Ok(added) => self.directories.added = added,
            Err(error) => {
                tracing::warn!(%error, "shared directories unreadable; only the download directory is scanned");
            }
        }
        self.reconcile().await;
        self.install_directories();
    }

    /// The front end names the download directory (`ScanCommand::Start`):
    /// the old one's scan stops, and the new one is scanned unless an added
    /// entry covers it. A start for the directory already scanned is a
    /// no-op, but one whose watch did not hold runs a fresh pass.
    pub(super) async fn download_directory(&mut self, dir: PathBuf) {
        if let Some(old) = self.directories.download_dir.replace(dir.clone())
            && old != dir
            && !self.directories.added.contains(&old)
        {
            self.stop_scan(&old).await;
            self.directories.ended.remove(&old);
        }
        self.directories.ended.remove(&dir);
        let covered = self
            .directories
            .covered()
            .into_iter()
            .any(|(entry, by)| entry.role == ScanRole::DownloadDirectory && by.is_some());
        if !covered {
            self.start_scan(dir, ScanRole::DownloadDirectory).await;
        }
        self.reconcile().await;
        self.install_directories();
    }

    /// Scan every outermost entry that has no scan and did not end, and
    /// stop the scan of every entry now covered.
    async fn reconcile(&mut self) {
        for (entry, by) in self.directories.covered() {
            let scanned = self.activities.scans.contains_key(&entry.dir);
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
        let listed: Vec<PathBuf> = self
            .directories
            .entries()
            .into_iter()
            .map(|entry| entry.canonical)
            .chain(
                self.activities
                    .scans
                    .values()
                    .filter(|scan| matches!(scan.role, ScanRole::Adding { .. }))
                    .map(|scan| scan.dir.clone()),
            )
            .collect();
        let dir = match admit(&path, &listed, &self.directories.guards) {
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
            self.stop_scan(child).await;
        }
        if let Some(scan) = self.activities.scans.get_mut(&dir) {
            scan.role = ScanRole::Added;
        }
        self.release_consent(&dir, true);
        self.scans_changed();
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
            .download_dir
            .iter()
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
        let mut list: Vec<InstalledDirectory> = self
            .directories
            .covered()
            .into_iter()
            .map(|(entry, by)| {
                let state = match (by, self.activities.scans.get(&entry.dir)) {
                    (Some(by), _) => InstalledState::Fixed(DirectoryState::Covered { by }),
                    (None, Some(scan)) => InstalledState::Scan(scan.progress.clone()),
                    (None, None) => InstalledState::Fixed(
                        self.directories
                            .ended
                            .get(&entry.dir)
                            .cloned()
                            .unwrap_or(DirectoryState::Starting),
                    ),
                };
                InstalledDirectory {
                    dir: entry.dir,
                    role: role_of(&entry.role),
                    state,
                }
            })
            .collect();
        list.extend(
            self.activities
                .scans
                .values()
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
