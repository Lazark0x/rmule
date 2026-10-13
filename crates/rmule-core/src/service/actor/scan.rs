//! The **Download Directory Scan** activities (ADR-0100, built per its
//! "Building the scan", "The watch" and "Shared Directories" sections): one
//! per scanned directory of the **Shared Directory List**, each with its
//! start, its one retire, and the arm that applies what its worker reports.
//! Each worker passes over its directory and then watches it, on a
//! blocking-pool thread; the actor alone writes the registry and fires the
//! share-set triggers, and answers the worker's reads of the registry in
//! channel order, so a read never misses a change the worker sent before it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::adapters::{
    KadRuntimeFactory, NotifyWatchStarter, PeerTransferService, ServeRuntimeService,
    SourceLookupService,
};
use crate::directory_scan::{
    Consent, FsDirectorySource, Known, PartFiles, ProgressCell, ScanEnd, ScanReport, ScanSeams,
    run_scan,
};
use crate::registry::SharedFileRegistry;
use crate::registry_check::{CheckInput, WithheldReason};
use crate::service::activity::{ScanActivity, ScanRole, ScanStop};
use crate::service::{ScanCommand, ScanEvent, ServeEvent};

use super::registry_check::RegistryMessage;
use super::{CoreActor, send_event};

/// What a scan worker sends the actor, tagged with the start it ran under.
#[derive(Debug)]
pub(super) struct ScanMessage {
    generation: u64,
    kind: ScanMessageKind,
}

#[derive(Debug)]
enum ScanMessageKind {
    /// The disclosure guard is waiting on the operator.
    ConsentRequested(crate::DirectoryOffer),
    /// A registry change to make, or the first pass's end.
    Report(ScanReport),
    /// The watch wants what is known as it stands after every change sent
    /// before this message.
    RowsWanted(std::sync::mpsc::Sender<Known>),
    /// The worker returned.
    Ended(ScanEnd),
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Enact one scan command.
    pub(super) async fn on_scan_command(&mut self, command: ScanCommand) {
        match command {
            ScanCommand::Answer { dir, share } => self.answer(dir, share).await,
            ScanCommand::AddSharedDirectory { path } => self.add_shared_directory(path).await,
            ScanCommand::RemoveSharedDirectory { path } => {
                self.remove_shared_directory(path).await;
            }
        }
    }

    /// The operator's answer for `dir`: a directory being added is stored or
    /// dropped; the download directory's is recorded durably.
    async fn answer(&mut self, dir: PathBuf, share: bool) {
        if let Some(scan) = self.activities.scan(&dir)
            && let ScanRole::Adding { replaces } = &scan.role
        {
            let replaces = replaces.clone();
            if share {
                return self.confirm_add(dir, replaces).await;
            }
            return self.release_consent(&dir, false);
        }
        if let Err(error) = self.wiring.registry.record_directory_answer(&dir, share) {
            tracing::warn!(dir = %dir.display(), %error, "could not record the answer");
        }
        self.directories.ended.remove(&dir);
        self.release_consent(&dir, share);
    }

    /// Free a worker waiting on the disclosure guard for `dir`.
    pub(super) fn release_consent(&mut self, dir: &Path, share: bool) {
        if let Some(scan) = self.activities.scan_mut(dir)
            && let Some(consent_tx) = scan.consent_tx.take()
        {
            let _ = consent_tx.send(share);
        }
    }

    /// Start the scan of `dir` in `role`, unless one runs there and is
    /// watched, or it is a download directory the guards refused. The
    /// download directory asks its first-share question from its recorded
    /// answer; an added one is confirmed; one being added always asks.
    pub(super) async fn start_scan(&mut self, dir: PathBuf, role: ScanRole) {
        if self
            .activities
            .scan(&dir)
            .is_some_and(|scan| !scan.unwatched)
            || (role == ScanRole::DownloadDirectory && self.directories.download_refused.is_some())
        {
            return;
        }
        self.stop_scan(&dir).await;
        let consent_given = match role {
            ScanRole::DownloadDirectory => match self.wiring.registry.directory_answer(&dir) {
                Ok(Some(false)) => {
                    self.directories
                        .ended
                        .insert(dir.clone(), crate::DirectoryState::Declined);
                    self.install_directories();
                    send_event(&self.evt_tx, ScanEvent::Declined { dir }.into()).await;
                    return;
                }
                Ok(answer) => Some(answer.is_some()),
                Err(error) => {
                    tracing::warn!(dir = %dir.display(), %error, "scan not started: answer unreadable");
                    return;
                }
            },
            ScanRole::Added => Some(true),
            ScanRole::Adding { .. } => None,
        };
        self.directories.ended.remove(&dir);
        self.activity_generation += 1;
        let generation = self.activity_generation;
        let stop = Arc::new(AtomicBool::new(false));
        let progress: ProgressCell = Arc::new(Mutex::new(None));
        let (consent_tx, consent_rx) = std::sync::mpsc::channel();
        let ask: crate::directory_scan::Ask = {
            let tx = self.scan_tx.clone();
            Box::new(move |offer| {
                let _ = tx.send(RegistryMessage::Scan(ScanMessage {
                    generation,
                    kind: ScanMessageKind::ConsentRequested(offer),
                }));
                // A dropped sender is a stop: nothing is shared.
                consent_rx.recv().unwrap_or(false)
            })
        };
        let consent = match consent_given {
            Some(true) => Consent::Given,
            Some(false) => Consent::Ask(ask),
            None => Consent::Confirm(ask),
        };
        let handle = tokio::task::spawn_blocking({
            let (tx, stop, progress, dir) = (
                self.scan_tx.clone(),
                Arc::clone(&stop),
                Arc::clone(&progress),
                dir.clone(),
            );
            let turn = self.directories.turn.clone();
            let missing_look = self.wiring.config.missing_directory_look;
            move || {
                let send = |kind| {
                    let _ = tx.send(RegistryMessage::Scan(ScanMessage { generation, kind }));
                };
                let end = run_scan(
                    ScanSeams {
                        source: &FsDirectorySource,
                        watcher: &mut NotifyWatchStarter,
                        rows: &mut || rows_now(&send, &stop),
                        report: &mut |report| send(ScanMessageKind::Report(report)),
                        turn,
                        missing_look,
                    },
                    &dir,
                    consent,
                    &stop,
                    &progress,
                );
                send(ScanMessageKind::Ended(end));
            }
        });
        self.activities.scan_started(ScanActivity {
            generation,
            dir,
            stop: ScanStop(stop),
            consent_tx: Some(consent_tx),
            answered: consent_given != Some(false),
            unwatched: false,
            missing: false,
            role,
            progress,
            handle,
        });
        self.scans_changed();
    }

    /// Stop the scan of `dir`, if any, and retire it (ADR-0093): raise its
    /// flag, free a worker waiting on the guard, join it within the grace.
    pub(super) async fn stop_scan(&mut self, dir: &Path) {
        let Some(scan) = self.activities.take_scan(dir) else {
            return;
        };
        self.scans_changed();
        scan.stop().await;
    }

    /// Stop every scan: quit's step. Every flag is raised before the first
    /// join, so each lets go within one read of the same moment.
    pub(super) async fn stop_scans(&mut self) {
        let scans = self.activities.take_scans();
        self.scans_changed();
        for scan in &scans {
            scan.stop.raise();
        }
        for scan in scans {
            scan.stop().await;
        }
    }

    /// Apply one worker message. One from a scan the ledger no longer holds
    /// moves nothing.
    pub(super) async fn on_scan_message(&mut self, message: ScanMessage) {
        let Some(scan) = self.activities.scan_of(message.generation) else {
            return;
        };
        let dir = scan.dir.clone();
        match message.kind {
            ScanMessageKind::ConsentRequested(offer) => {
                let (adding, replaces) = match &scan.role {
                    ScanRole::Adding { replaces } => (true, replaces.clone()),
                    _ => (false, Vec::new()),
                };
                send_event(
                    &self.evt_tx,
                    ScanEvent::ConsentRequested {
                        dir,
                        offer,
                        adding,
                        replaces,
                    }
                    .into(),
                )
                .await;
            }
            ScanMessageKind::Report(report) => self.on_scan_report(dir, report).await,
            ScanMessageKind::RowsWanted(reply) => match self.known() {
                Ok(known) => {
                    let _ = reply.send(known);
                }
                // A dropped reply ends the pass, or the watch with the operator told.
                Err(error) => tracing::warn!(%error, "registry unreadable for the scan"),
            },
            ScanMessageKind::Ended(ScanEnd::Unwatched(reason)) => {
                if let Some(scan) = self.activities.scan_mut(&dir) {
                    scan.unwatched = true;
                }
                // An unwatched directory's rows are the Registry Check's.
                self.scans_changed();
                send_event(
                    &self.evt_tx,
                    ScanEvent::WatchUnavailable { dir, reason }.into(),
                )
                .await;
            }
            ScanMessageKind::Ended(end) => self.retire_ended_scan(dir, end).await,
        }
    }

    /// Apply one registry change or fact a worker reported for `dir`.
    async fn on_scan_report(&mut self, dir: PathBuf, report: ScanReport) {
        match report {
            ScanReport::Share(entry) => {
                let file_hash = entry.file_hash;
                match self.wiring.registry.share(entry) {
                    Ok(()) => {
                        send_event(&self.evt_tx, ServeEvent::FileShared { file_hash }.into()).await;
                        self.row_shared(file_hash);
                    }
                    Err(error) => tracing::warn!(%error, "scanned file not shared"),
                }
            }
            ScanReport::Moved {
                file_hash,
                from,
                to,
            } => match self.wiring.registry.relocate(file_hash, &from, &to) {
                Ok(true) => {
                    send_event(&self.evt_tx, ServeEvent::FileShared { file_hash }.into()).await;
                    self.row_shared(file_hash);
                }
                Ok(false) => {}
                Err(error) => tracing::warn!(%error, "shared file not moved to its new path"),
            },
            ScanReport::Spare(spare) => {
                if let Err(error) = self.wiring.registry.record_spare(&spare) {
                    tracing::warn!(%error, "spare copy not recorded; it is read again at the next start");
                }
            }
            ScanReport::SpareLeft(path) => {
                if let Err(error) = self.wiring.registry.forget_spare(&path) {
                    tracing::warn!(%error, "spare copy record not dropped");
                }
            }
            ScanReport::SetAsideLeft(path) => {
                if let Err(error) = self.wiring.registry.forget_set_aside(&path) {
                    tracing::warn!(%error, "set-aside row not dropped");
                }
            }
            ScanReport::Identified {
                file_hash,
                path,
                identity,
            } => {
                if let Err(error) = self.wiring.registry.identify(file_hash, &path, identity) {
                    tracing::warn!(%error, "file identity not recorded");
                }
            }
            ScanReport::Held { file_hash, path } => {
                self.withhold(file_hash, Some(&path), WithheldReason::Missing)
                    .await;
            }
            ScanReport::Unreadable {
                file_hash,
                path,
                kind,
            } => {
                self.withhold(file_hash, Some(&path), WithheldReason::Unreadable(kind))
                    .await;
            }
            ScanReport::Unshare(file_hash) => {
                let left = self.wiring.registry.unshare(file_hash);
                self.row_left(file_hash, left).await;
            }
            ScanReport::Gone { file_hash, path } => {
                let left = self.wiring.registry.gone(file_hash, &path);
                self.row_left(file_hash, left).await;
            }
            ScanReport::Finished(summary) => {
                // Finishing without an answer on record means the operator
                // said yes, or there was nothing to disclose: either way the
                // directory is now shared, and its later files are not asked
                // about again. Only the download directory keeps answers; an
                // added directory's answer is its place in the list.
                if let Some(scan) = self.activities.scan_mut(&dir)
                    && !scan.answered
                    && scan.role == ScanRole::DownloadDirectory
                {
                    scan.answered = true;
                    if let Err(error) = self.wiring.registry.record_directory_answer(&dir, true) {
                        tracing::warn!(dir = %dir.display(), %error, "could not record the answer");
                    }
                }
                send_event(&self.evt_tx, ScanEvent::Finished { dir, summary }.into()).await;
            }
            ScanReport::RootMissing { since } => self.directory_missing(dir, since).await,
            ScanReport::RootReturned => {
                // A directory missing when it was guarded is judged again as
                // it appears, before its pass reads anything: the worker's
                // next message waits on the actor.
                if !self.returned_root_admitted(&dir).await {
                    return;
                }
                if let Some(scan) = self.activities.scan_mut(&dir) {
                    scan.missing = false;
                }
                self.scans_changed();
                self.registry_check.tell(CheckInput::RecheckWithheld);
                send_event(&self.evt_tx, ScanEvent::DirectoryReturned { dir }.into()).await;
            }
            ScanReport::WatchInterrupted(reason) => {
                send_event(
                    &self.evt_tx,
                    ScanEvent::WatchInterrupted { dir, reason }.into(),
                )
                .await;
            }
            ScanReport::WatchRestored => {
                send_event(&self.evt_tx, ScanEvent::WatchRestored { dir }.into()).await;
            }
            ScanReport::PathUnwatched { path, reason } => {
                send_event(
                    &self.evt_tx,
                    ScanEvent::PathUnwatched { dir, path, reason }.into(),
                )
                .await;
            }
            ScanReport::NotHashed {
                path,
                kind,
                os_code,
            } => {
                send_event(
                    &self.evt_tx,
                    ScanEvent::FileNotHashed {
                        dir,
                        path,
                        kind,
                        os_code,
                    }
                    .into(),
                )
                .await;
            }
            ScanReport::LeftoverParts(paths) => {
                tracing::info!(
                    count = paths.len(),
                    "part files left by ended downloads; not shared"
                );
                send_event(&self.evt_tx, ScanEvent::LeftoverParts { dir, paths }.into()).await;
            }
        }
    }

    /// The scanned directory `dir` is not there: every row under it is
    /// withheld as its folder missing, never Had, and the Registry Check
    /// holds them until it is back.
    async fn directory_missing(&mut self, dir: PathBuf, since: std::time::SystemTime) {
        if let Some(scan) = self.activities.scan_mut(&dir) {
            scan.missing = true;
        }
        self.scans_changed();
        let under: Vec<_> = match self.wiring.registry.list() {
            Ok(rows) => rows
                .into_iter()
                .filter(|row| row.path.starts_with(&dir))
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "rows under a missing directory not withheld here; the Registry Check will");
                Vec::new()
            }
        };
        for row in under {
            self.withhold(
                row.file_hash,
                Some(&row.path),
                WithheldReason::FolderMissing,
            )
            .await;
        }
        send_event(
            &self.evt_tx,
            ScanEvent::DirectoryMissing { dir, since }.into(),
        )
        .await;
    }

    /// What the scan may know without reading a file: the registry, the
    /// part files the download rows name, the spare copies and the set-aside
    /// rows.
    fn known(&self) -> Result<Known, crate::CoreError> {
        Ok(Known {
            rows: self.wiring.registry.list()?,
            parts: PartFiles::of(self.wiring.store.part_files()?),
            spares: self.wiring.registry.spares()?,
            identities: self.wiring.registry.identities()?,
            set_aside: self
                .wiring
                .registry
                .set_asides()?
                .into_iter()
                .map(|aside| (aside.entry.path.clone(), aside))
                .collect(),
        })
    }

    /// The worker ended on its own (a death, ADR-0093): retire the activity
    /// through its own stop, which a returning worker answers at once, and
    /// say how it ended.
    async fn retire_ended_scan(&mut self, dir: PathBuf, end: ScanEnd) {
        let Some(scan) = self.activities.take_scan(&dir) else {
            return;
        };
        let role = scan.role.clone();
        scan.stop().await;
        let event = match end {
            ScanEnd::Declined => {
                if role == ScanRole::DownloadDirectory {
                    self.directories
                        .ended
                        .insert(dir.clone(), crate::DirectoryState::Declined);
                }
                ScanEvent::Declined { dir }
            }
            ScanEnd::Unlistable => {
                self.directories
                    .ended
                    .insert(dir.clone(), crate::DirectoryState::Unlistable);
                ScanEvent::Unlistable { dir }
            }
            ScanEnd::Stopped | ScanEnd::Unwatched(_) => {
                self.scans_changed();
                return;
            }
        };
        self.scans_changed();
        send_event(&self.evt_tx, event.into()).await;
    }

    /// The scans changed: the Registry Check learns which directories live,
    /// watched scans own, and the diagnostics level shows the list again.
    pub(super) fn scans_changed(&self) {
        let owned = self
            .activities
            .scans()
            .filter(|scan| {
                !scan.unwatched && !scan.missing && !matches!(scan.role, ScanRole::Adding { .. })
            })
            .map(|scan| scan.dir.clone())
            .collect();
        self.registry_check.tell(CheckInput::ScanOwns(owned));
        self.install_directories();
    }
}

/// The registry as the actor stands after every message the worker sent
/// before asking; `None` once the scan is stopping or the actor cannot read
/// it. Waits in slices so a raised stop flag is seen.
fn rows_now(send: &dyn Fn(ScanMessageKind), stop: &AtomicBool) -> Option<Known> {
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    send(ScanMessageKind::RowsWanted(reply_tx));
    loop {
        match reply_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(rows) => return Some(rows),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if !stop.load(Ordering::Relaxed) => {}
            Err(_) => return None,
        }
    }
}
