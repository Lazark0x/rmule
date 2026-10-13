//! The **Offer Check** (ADR-0113 §"A paused download"): after a restart a
//! queued or paused download is a Served Download with an empty Verified
//! Range — probes answered, nothing offered — until every part it recorded is
//! read again and hashed against its record. Resume's own walk
//! ([`walk_verified_parts`]), with Resume's effect: a part that no longer
//! holds loses its record and is said; a part file gone or unreadable leaves
//! the download paused and unoffered, for its Resume to say why. The parts
//! that held become the range and the handle the walk read through becomes
//! the Part File Identity, so the download is offered if it otherwise would
//! be.
//!
//! The checks start once the Registry Check's start look is done and run on
//! the blocking pool one download at a time, each taking the hashing turn the
//! scans share, so none reads beside a scan's hashing. The worker only walks;
//! the actor applies a result, and only while the check was not stopped: a
//! Resume stops a pending or running check of its row, and the run's own
//! revalidation takes over.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmule_primitives::FileHash;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::content::{Revalidation, walk_verified_parts};
use crate::directory_scan::HashTurn;
use crate::service::DownloadId;
use crate::storage::DownloadRepository;
use crate::{DownloadLifecycle, DownloadPaths, VerifiedPartRecord};

use super::CoreActor;
use super::registry_check::{RegistryMessage, RegistrySender};

/// One download waiting for its check: where its part file is and the parts
/// it recorded.
struct Waiting {
    download_id: DownloadId,
    file_hash: FileHash,
    paths: DownloadPaths,
    parts: Vec<VerifiedPartRecord>,
    stop: Arc<AtomicBool>,
}

/// A check's walk, for the actor to apply.
#[derive(Debug)]
pub(super) struct OfferChecked {
    download_id: DownloadId,
    file_hash: FileHash,
    revalidation: Revalidation,
}

/// The checks the actor started and has not applied or stopped, each with
/// the flag that stops its walk.
#[derive(Debug, Default)]
pub(super) struct OfferChecks {
    started: bool,
    checking: HashMap<DownloadId, Arc<AtomicBool>>,
}

impl OfferChecks {
    /// Stop `download_id`'s check, waiting or running: its walk ends before
    /// its next part, and a result it already sent is not applied.
    pub(super) fn stop(&mut self, download_id: DownloadId) {
        if let Some(stop) = self.checking.remove(&download_id) {
            stop.store(true, Ordering::Relaxed);
        }
    }

    /// Stop every check, at quit.
    pub(super) fn stop_all(&mut self) {
        for (_, stop) in self.checking.drain() {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Walk each waiting download in order, under the hashing turn, and report
/// each walk that ran to its end. A stopped check reports nothing.
async fn run_checks(waiting: Vec<Waiting>, turn: HashTurn, reports: RegistrySender) {
    for check in waiting {
        let Waiting {
            download_id,
            file_hash,
            paths,
            parts,
            stop,
        } = check;
        if stop.load(Ordering::Relaxed) {
            continue;
        }
        let turn = turn.clone();
        let walked = tokio::task::spawn_blocking(move || {
            let _turn = turn.take(&stop)?;
            walk_verified_parts(&paths, &parts, &stop)
        })
        .await
        .ok()
        .flatten();
        let Some(revalidation) = walked else {
            continue;
        };
        let report = OfferChecked {
            download_id,
            file_hash,
            revalidation,
        };
        if reports.send(RegistryMessage::OfferChecked(report)).is_err() {
            return;
        }
    }
}

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Start the Offer Check of every queued or paused download whose Served
    /// Download the actor holds and that recorded a part — once, after the
    /// Registry Check's start look. One that recorded none costs nothing.
    pub(super) fn start_offer_checks(&mut self) {
        if std::mem::replace(&mut self.offer_checks.started, true) {
            return;
        }
        let records = match self.wiring.store.live_downloads() {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error, "the downloads to check before offering them could not be read");
                return;
            }
        };
        let mut waiting = Vec::new();
        for record in records {
            let (download_id, file_hash) = (record.id(), record.file_hash());
            if !matches!(
                record.lifecycle(),
                DownloadLifecycle::Queued | DownloadLifecycle::Paused
            ) || !self
                .wiring
                .served_downloads
                .held_by_actor(file_hash, download_id)
            {
                continue;
            }
            let parts = match self.wiring.store.verified_parts(download_id) {
                Ok(parts) if !parts.is_empty() => parts,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(download_id = download_id.as_u64(), %error, "a download's parts could not be read to check them");
                    continue;
                }
            };
            let stop = Arc::new(AtomicBool::new(false));
            self.offer_checks
                .checking
                .insert(download_id, Arc::clone(&stop));
            waiting.push(Waiting {
                download_id,
                file_hash,
                paths: record.paths().clone(),
                parts,
                stop,
            });
        }
        if waiting.is_empty() {
            return;
        }
        tokio::spawn(run_checks(
            waiting,
            self.directories.turn.clone(),
            self.scan_tx.clone(),
        ));
    }

    /// Apply a check's walk, unless the check was stopped or the actor no
    /// longer holds the download's Served Download: a damaged part loses its
    /// record and is said, the parts that held become the range read through
    /// the walk's handle, and the one trigger fires. A part file that backs
    /// nothing leaves the download paused and unoffered, its lifecycle
    /// untouched.
    pub(super) async fn on_offer_checked(&mut self, report: OfferChecked) {
        let OfferChecked {
            download_id,
            file_hash,
            revalidation,
        } = report;
        if self.offer_checks.checking.remove(&download_id).is_none()
            || !self
                .wiring
                .served_downloads
                .held_by_actor(file_hash, download_id)
        {
            return;
        }
        let (progress, damaged) = match revalidation {
            Revalidation::Restored { progress, damaged } => (progress, damaged),
            Revalidation::Condemned(fault) => {
                tracing::info!(download_id = download_id.as_u64(), %fault, "a download's part file backs none of its parts; it is not offered until it is resumed");
                return;
            }
        };
        if let Err(error) = self.wiring.store.drop_parts(download_id, &damaged) {
            tracing::warn!(download_id = download_id.as_u64(), %error, "the parts a check found damaged could not be dropped; the download is not offered");
            return;
        }
        let Ok(record) = self.wiring.store.load_download(download_id) else {
            return;
        };
        self.drop_damaged(download_id, &record, damaged).await;
        let (Some(identity), Ok(held)) = (
            progress.read_through(),
            self.wiring.store.verified_parts(download_id),
        ) else {
            return;
        };
        if self
            .wiring
            .served_downloads
            .offer_checked(file_hash, download_id, &held, identity)
        {
            self.served_moved().await;
        }
    }
}

#[cfg(test)]
mod tests;
