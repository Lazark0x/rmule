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

use rmule_kad::KadBuddyContact;
use rmule_primitives::{
    FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, PeerSource, SourceCryptOptions,
    SourceLookupTarget, UserHash,
};
use tokio::sync::mpsc;

use crate::adapters::KadSourceChannel;
use crate::registry::SharedFileRegistry;
use crate::registry_check::WithheldRows;
use crate::source_discovery::{DiscoveryChannel, DiscoveryRegistry};

/// One Kad source row as the download brain reads it — the core-side face of
/// `rmule_kad::KadSourceCandidate`.
///
/// It exists so the brain keeps its own vocabulary while still seeing every
/// rung-1 fact a row carries: the channel was once a bare
/// `Vec<PeerSource>`, which could say only "dialable" and therefore dropped
/// every firewalled row along with its buddy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KadSource {
    /// The dialable endpoint, when the row projected to one (a direct High-ID
    /// row, or an `ip6`-rescued one). `None` for a buddy-reachable row.
    pub direct: Option<PeerSource>,
    /// The publisher's User Hash — always present on a decoded row, because
    /// the row's 16-byte source ID *is* the hash (ADR-0043).
    pub user_hash: Option<UserHash>,
    /// Where a `0x95` direct callback would go: the storer's observation of
    /// the publish sender, paired with the published `SOURCEUPORT`.
    pub kad_udp: Option<Ipv4Endpoint>,
    /// The row's `TAG_ENCRYPTION` connect-options byte.
    pub connect_options: Option<SourceCryptOptions>,
    /// The publisher's serving buddy, from a type-3/5 row.
    pub buddy: Option<KadBuddyContact>,
    /// The row is a type-6 **Direct UDP Callback** source: firewalled, bit 3
    /// stated, and [`Self::kad_udp`] observed — the sealed projection's
    /// verdict ([`rmule_kad::KadSourceCandidate::direct_udp_callback`]), never
    /// re-derived from the byte, because only type 6 makes aMule keep the
    /// address a `0x95` needs.
    pub direct_udp_callback: bool,
    /// The published eD2k TCP port.
    pub tcp_port: u16,
    /// The row's `ip6` endpoint (ADR-0087), wherever the row holds it — the
    /// shape [`ExchangedSource::ipv6`](rmule_primitives::ExchangedSource::ipv6)
    /// reads: the **IPv6 Half** beside a High-ID [`Self::direct`] (the Dial
    /// Chooser picks between the two, `dialable::resolve_kad_family`) or beside
    /// a callback road (rung 0 dials it), or the address of an `ip6`-rescued
    /// row, whose [`Self::direct`] it already is.
    pub ipv6: Option<Ipv6Endpoint>,
}

impl KadSource {
    /// Project a decoded candidate into the brain's vocabulary.
    #[must_use]
    pub fn from_candidate(candidate: &rmule_kad::KadSourceCandidate) -> Self {
        let facts = candidate.facts();
        Self {
            direct: candidate.peer_source(),
            user_hash: facts.map(|facts| facts.user_hash),
            kad_udp: facts.and_then(|facts| facts.kad_udp),
            connect_options: facts.and_then(|facts| facts.connect_options),
            buddy: candidate.buddy(),
            direct_udp_callback: candidate.direct_udp_callback().is_some(),
            tcp_port: facts.map_or(0, |facts| facts.tcp_port),
            ipv6: facts.and_then(|facts| facts.ipv6),
        }
    }

    /// A bare dialable row — the shape a test drives the brain with, and what
    /// every Kad row once was.
    #[must_use]
    pub const fn dialable(source: PeerSource) -> Self {
        Self {
            direct: Some(source),
            user_hash: None,
            kad_udp: None,
            connect_options: None,
            buddy: None,
            direct_udp_callback: false,
            tcp_port: 0,
            ipv6: None,
        }
    }

    /// The endpoint an IP filter judges this row by: the dialable one when
    /// there is one, else the publisher's observed Kad UDP address. aMule
    /// filters on the row's `SOURCEIP` before it branches on source type
    /// (`CDownloadQueue::KademliaSearchFile`, `src/DownloadQueue.cpp:1713`), so
    /// a firewalled row is filtered on the same address a direct one is.
    #[must_use]
    pub fn filter_endpoint(&self) -> Option<PeerEndpoint> {
        self.direct
            .and_then(PeerSource::as_peer_endpoint)
            .or_else(|| self.kad_udp.map(PeerEndpoint::V4))
    }
}

/// A Kad answer routed to a download: a projected source batch. The runner
/// feeds it to `DownloadState::on_kad_sources`.
pub type KadAnswer = Vec<KadSource>;

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
