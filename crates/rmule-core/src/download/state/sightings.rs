//! The brain's one entry for sources: every channel's **Source Sightings**
//! reach the **Source Book** through [`DownloadState::on_sightings`], behind
//! the intake gate the caller lends for the call (ADR-0090). A channel's
//! quirks are the [`Channel`]'s; what a sighting did is counted in a
//! [`Tally`], whose numbers the runner reports.

use std::ops::Add;
use std::time::Instant;

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, SourceSighting};

use crate::download::source_book::{Blocked, Gate, MergeEnd, Sighted};
use crate::service::{DownloadEvent, PeerRetirementReason};

use super::{Decision, DownloadState};

/// Where a batch of sightings came from, and what that channel adds to the
/// book's one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    /// A link's own sources, the first link's or a later one's (ADR-0089).
    Link,
    /// The download's **Source Seeds** (ADR-0109): a pooled one keeps its
    /// origin on its record, for the run to rank.
    Seed,
    /// The connected server's answer, the run's first or a later session's
    /// (ADR-0097): a Low-ID row is in that server's namespace.
    Server,
    /// Server-UDP global sources from this server (ADR-0051): a Low-ID row is
    /// called back through `source_server` only — low ids are unique per
    /// server.
    Global(Ipv4Endpoint),
    /// Kad sources (ADR-0043): a buddy or type-6 row becomes a callback
    /// candidate, its rung-0 `ip6` half judged like any other.
    Kad,
    /// What a connected source answered to our source-exchange ask
    /// (ADR-0055); the answer is reported as an event naming it, and each
    /// Low-ID row is read in the server it names.
    Exchanged(PeerEndpoint),
    /// A peer that asked us about the file, from its hello's source
    /// coordinate (ADR-0113): taken only while the file holds fewer than
    /// [`PROBER_SOURCE_CAP`] sources, as aMule's `CheckAndAddKnownSource`
    /// is reached (`ClientTCPSocket.cpp:449-455`).
    Prober,
}

/// aMule's default `MaxSourcesPerFile` (stock 2.3.3 `Preferences.cpp:1027`):
/// a file holding this many sources takes no prober as one more
/// (`ClientTCPSocket.cpp:452`).
pub(crate) const PROBER_SOURCE_CAP: u32 = 300;

impl Channel {
    /// The server whose namespace `sighting`, a Low-ID row of this channel,
    /// is minted in, with `ours` the server we are logged into: a global
    /// answer's own server; a source-exchange row's own, the one the row
    /// names (aMule `CPartFile::AddClientSources`, stock 2.3.3
    /// `PartFile.cpp:2771`, `:2815`); else ours — a Kad row's is ignored, it
    /// is in none.
    const fn source_server(
        self,
        sighting: &SourceSighting,
        ours: Option<Ipv4Endpoint>,
    ) -> Option<Ipv4Endpoint> {
        match self {
            Self::Global(server) => Some(server),
            Self::Exchanged(_) => sighting.server(),
            _ => ours,
        }
    }
}

/// What a batch of sightings did, counted once per sighting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Sightings handed in.
    pub(crate) received: usize,
    /// Those that passed the gate: neither filtered nor of an unreachable
    /// family.
    pub(crate) admitted: usize,
    /// Admitted sightings with a dialable address — a High ID or an IPv6 one.
    pub(crate) dialable: usize,
    /// Sightings that pooled a record the book did not hold.
    pub(crate) fresh: usize,
    /// Sightings that folded into a record the book held.
    merged: usize,
    /// Merged sightings with a dialable address.
    merged_dialable: usize,
    /// Sightings dropped for an address family this node cannot dial from.
    pub(crate) family_unreachable: usize,
}

impl Tally {
    /// Admitted sightings that named a source not already counted in this
    /// tally: a source two channels name is one.
    pub(crate) const fn distinct(self) -> usize {
        self.admitted - self.merged
    }

    /// [`Self::distinct`], counting only those with a dialable address.
    pub(crate) const fn distinct_dialable(self) -> usize {
        self.dialable - self.merged_dialable
    }
}

impl Add for Tally {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            received: self.received + other.received,
            admitted: self.admitted + other.admitted,
            dialable: self.dialable + other.dialable,
            fresh: self.fresh + other.fresh,
            merged: self.merged + other.merged,
            merged_dialable: self.merged_dialable + other.merged_dialable,
            family_unreachable: self.family_unreachable + other.family_unreachable,
        }
    }
}

/// What taking a batch yields: the decisions for the runner to enact, and the
/// counts to report.
#[derive(Debug)]
pub(crate) struct Taken {
    /// Ordered effects: a merge's ended worker or callback, then free slots
    /// filled.
    pub(crate) decisions: Vec<Decision>,
    /// What each sighting did.
    pub(crate) tally: Tally,
}

impl DownloadState {
    /// Take one channel's `sightings` into the **Source Book**, behind `gate`
    /// (the IP filter's view and our Dial Position, lent for this call), map
    /// what each did to decisions, then fill free slots. A run not yet started
    /// only pools; [`Self::start`] fills.
    ///
    /// A pooled High ID is dialable for the seeds. A merge that proved two held
    /// records one peer ends what the one that gave way had in flight — the
    /// newer worker, its endpoint unspent, or its callback, whose slot frees.
    pub(crate) fn on_sightings(
        &mut self,
        now: Instant,
        channel: Channel,
        sightings: impl IntoIterator<Item = SourceSighting>,
        gate: &Gate<'_>,
    ) -> Taken {
        // aMule stamps both clocks on any answer, empty or not (stock 2.3.3
        // `ClientTCPSocket.cpp:1513-1515`, ADR-0108).
        if let Channel::Exchanged(peer) = channel {
            self.sources.answered(peer, now);
        }
        let mut decisions = Vec::new();
        let mut tally = Tally::default();
        let mut seeded = Vec::new();
        for sighting in sightings {
            if channel == Channel::Prober && self.sources.counts().known >= PROBER_SOURCE_CAP {
                tally.received += 1;
                continue;
            }
            let dialable = sighting.as_peer_endpoint();
            let namespace = channel.source_server(&sighting, self.callback_capability.server());
            let sighted = self.sources.sight(sighting, namespace, gate);
            tally.received += 1;
            match sighted {
                Sighted::Blocked(Blocked::FamilyUnreachable) => tally.family_unreachable += 1,
                Sighted::Blocked(Blocked::IpFiltered) => {}
                _ => {
                    tally.admitted += 1;
                    tally.dialable += usize::from(dialable.is_some());
                    seeded.extend(dialable);
                }
            }
            match sighted {
                Sighted::Pooled(pooled) => {
                    tally.fresh += 1;
                    if let Some(endpoint) = pooled {
                        self.seeds.dialable(endpoint);
                        if channel == Channel::Seed {
                            self.sources.remember(endpoint);
                        }
                    }
                }
                Sighted::Merged(ended) => {
                    tally.merged += 1;
                    tally.merged_dialable += usize::from(dialable.is_some());
                    self.end_merged(now, ended, &mut decisions);
                }
                Sighted::Blocked(_) => {}
            }
        }
        if channel == Channel::Seed {
            self.seed_dials_admit(seeded);
        }
        if let Channel::Exchanged(peer) = channel {
            decisions.insert(
                0,
                Decision::Emit(DownloadEvent::SourcesExchanged {
                    download_id: self.download_id,
                    peer,
                    received: tally.received,
                    admitted: tally.admitted,
                }),
            );
        }
        if self.started {
            self.fill(now, &mut decisions);
        }
        if matches!(channel, Channel::Exchanged(_)) {
            self.settle_seed_dials(&mut decisions);
        }
        Taken { decisions, tally }
    }

    /// End what the record that gave way in a merge had in flight.
    fn end_merged(&mut self, now: Instant, ended: Option<MergeEnd>, out: &mut Vec<Decision>) {
        match ended {
            Some(MergeEnd::Worker(peer)) => {
                out.push(Decision::Emit(DownloadEvent::PeerRetired {
                    download_id: self.download_id,
                    peer,
                    reason: PeerRetirementReason::SameSource,
                }));
                self.release(now, peer, PeerRetirementReason::SameSource, out);
            }
            Some(MergeEnd::Callback(key)) => {
                if let Some(slot) = self.callback_slots.remove(&key) {
                    out.push(Decision::EndCallback { key });
                    self.free_slots.insert(slot.as_usize());
                }
            }
            None => {}
        }
    }
}
