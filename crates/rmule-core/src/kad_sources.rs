//! The Kad source **Discovery Channel** (ADR-0043, Core integration): the second
//! **Source Discovery Policy** channel beside the server-UDP global sweep
//! (ADR-0051), as a [`SourceDiscovery`](crate::source_discovery) adapter. It
//! searches Kad for every due download's sources, routing each projected source
//! batch to the matching download. It drives the live node only through the
//! [`KadSourceChannel`] seam (projected vocabulary), so Core correctness tests
//! fake the channel with no socket.
//!
//! Publishing shared files is *not* discovery: it is registry-driven, runs even
//! with zero active downloads, and so lives in its own [`KadPublisher`] Core
//! task rather than on the discovery sweep. Both drive the one node —
//! the engine searches + receives, the publisher publishes — sharing it through
//! an `Arc<C>` (the seam's `&self` methods are `Sync`).

use std::collections::HashMap;
use std::sync::Arc;

use rmule_primitives::{FileHash, SourceLookupTarget, SourceSighting};
use tokio::sync::mpsc;

use crate::adapters::KadSourceChannel;
use crate::registry::SharedFileRegistry;
use crate::registry_check::WithheldRows;
use crate::source_discovery::{DiscoveryChannel, DiscoveryRegistry};

/// A Kad answer routed to a download: each row's **Source Sighting**, as the
/// sealed projection made it ([`rmule_kad::KadSourceCandidate::sighting`]). The
/// runner feeds it to `DownloadState::on_sightings` (`Channel::Kad`).
pub type KadAnswer = Vec<SourceSighting>;

/// The active-download registry, in the shared engine's shape: file hash →
/// (file size, sink). The size rides along because a Kad source search carries
/// it on the wire.
pub(crate) type KadSourceRegistry = DiscoveryRegistry<KadAnswer>;

/// The Kad **Discovery Channel** adapter over a [`KadSourceChannel`] seam: it
/// maps the engine's due-batch `ask` onto per-target Kad source searches and its
/// answer receive onto the node's projected source batches. Publishing lives in
/// [`KadPublisher`], not here.
pub(crate) struct KadDiscoveryChannel<C> {
    channel: C,
}

impl<C: KadSourceChannel> KadDiscoveryChannel<C> {
    pub(crate) fn new(channel: C) -> Self {
        Self { channel }
    }
}

impl<C: KadSourceChannel> DiscoveryChannel for KadDiscoveryChannel<C> {
    type Answer = KadAnswer;

    async fn ask(&self, targets: &[SourceLookupTarget]) {
        for target in targets {
            self.channel.search_sources(*target).await;
        }
    }

    async fn next_answer(&self) -> Option<(FileHash, KadAnswer)> {
        self.channel.next_sources().await
    }
}

/// The **Kad Publisher** (`crates/rmule-core/CONTEXT.md`): the small Core task
/// that keeps the Kad node's publications equal to the offered rows of the
/// **Shared File Registry** — the node owns the 5-hour republish. It is
/// registry-driven, not download-driven, so it keeps running with zero active
/// downloads — which is why it is its own task rather than part of Kad
/// discovery. It sweeps the offered rows once at start and again on every
/// share-set notification — the serve-announce pattern — publishing each file
/// newly offered and withdrawing each file no longer offered, so the node never
/// republishes a file rmule cannot serve (ADR-0100, "The registry against the
/// disk"). Kad has no unpublish: what storers already hold ages out.
pub(crate) struct KadPublisher<C> {
    channel: C,
    /// The Core-owned **Shared File Registry**, shared with the actor (every
    /// method is `&self`, ADR-0083).
    shared_files: Arc<dyn SharedFileRegistry>,
    /// The **Withheld Row**s, which are not offered and so not published.
    withheld: WithheldRows,
    /// Fires once per share-set change (share, unshare, withhold, or offer);
    /// a `None` recv means every notifier dropped (Core shutting down), which
    /// ends the task.
    share_changed_rx: mpsc::Receiver<()>,
}

impl<C: KadSourceChannel> KadPublisher<C> {
    pub(crate) fn new<R: SharedFileRegistry>(
        channel: C,
        shared_files: Arc<R>,
        withheld: WithheldRows,
        share_changed_rx: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            channel,
            shared_files,
            withheld,
            share_changed_rx,
        }
    }

    pub(crate) async fn run(mut self) {
        // What the node holds for publication, held here for the task's life.
        let mut published: HashMap<FileHash, SourceLookupTarget> = HashMap::new();
        // Publish the offer as of Kad start, then re-sweep on every share-set
        // change (the serve-announce pattern). A sweep that could not read the
        // registry is retried after `SWEEP_RETRY` unless a change comes first.
        let mut unswept = !self.sweep(&mut published).await;
        loop {
            let changed = if unswept {
                tokio::select! {
                    changed = self.share_changed_rx.recv() => changed,
                    () = tokio::time::sleep(SWEEP_RETRY) => Some(()),
                }
            } else {
                self.share_changed_rx.recv().await
            };
            if changed.is_none() {
                break;
            }
            unswept = !self.sweep(&mut published).await;
        }
    }

    /// Publish every offered file not yet published, and withdraw every
    /// published file no longer offered. `false` when the registry could not
    /// be read: an unread registry says nothing about what is offered, so the
    /// publications stand as they are.
    async fn sweep(&self, published: &mut HashMap<FileHash, SourceLookupTarget>) -> bool {
        let listed = match self.shared_files.list() {
            Ok(listed) => listed,
            Err(error) => {
                tracing::warn!(%error, "shared file registry unreadable; Kad publications kept");
                return false;
            }
        };
        let offered: HashMap<FileHash, SourceLookupTarget> = self
            .withheld
            .offered(listed)
            .into_iter()
            .map(|entry| {
                let target = SourceLookupTarget::new(entry.file_hash, entry.file_size);
                (entry.file_hash, target)
            })
            .collect();
        let withdrawn: Vec<FileHash> = published
            .keys()
            .filter(|file_hash| !offered.contains_key(file_hash))
            .copied()
            .collect();
        for file_hash in withdrawn {
            if let Some(target) = published.remove(&file_hash) {
                self.channel.withdraw_source(target).await;
            }
        }
        for (file_hash, target) in offered {
            if published.insert(file_hash, target).is_none() {
                self.channel.publish_source(target).await;
            }
        }
        true
    }
}

/// How long the **Kad Publisher** waits to sweep again after a sweep that
/// could not read the registry, when no share-set change comes first.
const SWEEP_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
mod tests;
