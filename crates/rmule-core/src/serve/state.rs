//! The synchronous, sans-I/O core of the serve activity.
//!
//! [`ServeState`] is the **Serve State**, the serve-side mirror of
//! [`DownloadState`](crate::download): it owns every clock-free serve
//! decision — probe/status/hash-set answers from a **Shared File Registry**
//! snapshot, slot admission via the **Upload Slot Queue** it contains, block
//! sends with served-range subtraction, AICH tree building from round-tripped
//! byte reads, credit recording, and **Secured Identity** binding — and
//! returns an ordered `Vec<`[`ServeDecision`]`>` that the `ServeTask` enacts.
//! It never touches a socket, a clock, the registry, the content store, or an
//! `mpsc` channel; byte reads are fallible effects that round-trip through
//! [`ServeState::on_read_result`], the read-side twin of
//! `DownloadState::on_persist_result`, and time and credit modifiers arrive
//! as explicit parameters (the [`UploadSlotQueue`] contract).
//!
//! This split is what makes every serve policy path assertable as a plain
//! decision sequence instead of only through a live `ServeTask` loopback rig.

mod connection;
mod reask;
#[cfg(test)]
mod tests;
mod transfer;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rmule_ed2k::OfferedFile;
use rmule_peer::{PartBitmap, ServedSourcesVersion};
use rmule_primitives::{
    AichHashSet, Ed2kText, ExchangedSource, FileHash, PeerEndpoint, PeerSource, UserHash,
};

use crate::WaiterLeaveCause;
use crate::adapters::ServeConnCommand;
use crate::client_udp::PeerUdpCryptTarget;
use crate::registry::SharedFileEntry;
use crate::serve::source_exchange::{
    ServedFileKind, SourceExchangeThrottle, SxCandidate, SxRequester, held_parts, select_sources,
};
use crate::service::ServeEvent;
use crate::upload_queue::{Promotion, UploadSlotQueue};

/// One effect the serve task must enact, drained in order from a
/// [`ServeState`] entry point. Everything that touches I/O, a clock, a
/// channel, the credit ledger, or the content store is data here, not an
/// inline `await`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ServeDecision {
    /// Send a command down `peer`'s live connection.
    Send {
        peer: PeerEndpoint,
        command: ServeConnCommand,
    },
    /// Forward a serve fact to the core event stream.
    Emit(ServeEvent),
    /// Credit `user_hash` for serving `bytes`; the enactor holds the
    /// ledger lock.
    RecordCredit { user_hash: UserHash, bytes: u64 },
    /// Bind `public_key` as `user_hash`'s **Secured Identity** (ADR-0041).
    /// The enactor (ledger-holder) performs the store's atomic
    /// compare-and-set; a `Mismatch` denies the claim (theft fact), never
    /// overwriting the key — the mirror of the download runner's arm.
    BindIdentity {
        user_hash: UserHash,
        public_key: Vec<u8>,
    },
    /// Read `len` bytes at `offset` from the shared file at `path`. A
    /// fallible effect: the enactor feeds the outcome back through
    /// [`ServeState::on_read_result`] with this same `purpose`.
    ReadRange {
        peer: PeerEndpoint,
        path: PathBuf,
        offset: u64,
        len: u64,
        purpose: ReadPurpose,
    },
    /// Announce the snapshot's offer list via `OP_OFFERFILES`.
    Announce(Vec<OfferedFile>),
    /// Count one upload request `file_hash` drew (aMule's `AddRequest`,
    /// `amule-kno/src/UploadQueue.cpp:519-522`) in its per-file serve counters.
    CountUploadRequest { file_hash: FileHash },
    /// A read of this shared file failed: the **Registry Check** looks at its
    /// row (ADR-0106, "The registry against the disk").
    ReadFailed(FileHash),
    /// Send a reask reply datagram to `to` over the shared client-UDP socket
    /// (ADR-0057): `OP_REASKACK` / `OP_FILENOTFOUND` / `OP_QUEUEFULL`. The
    /// enactor forwards it to the client-UDP send half, which applies the
    /// ADR-0046 crypt gate at the socket boundary — `crypt_target` is the
    /// resolved waiter's identity when we hold one, and `None` for a stranger
    /// (aMule answers an unknown pinger plaintext by construction).
    ///
    /// `to` is the ping's own source, in the family it arrived in: the quartet
    /// packs no address and is byte-identical over IPv6 (ADR-0087), so the
    /// answer simply goes back the way the question came.
    SendClientUdp {
        to: PeerEndpoint,
        datagram: Vec<u8>,
        crypt_target: Option<PeerUdpCryptTarget>,
    },
    /// Dial `peer`'s TCP endpoint and grant it `file_hash`'s upload slot
    /// (`OP_ACCEPTUPLOADREQ` on connect) — promotion of a **disconnected**
    /// waiter (ADR-0057 dial-back grant), a serve-side outbound dial riding the
    /// ADR-0031 dialed-serve seam. The outbound serve-dial machinery lands with
    /// the live front; the promotion decision is deterministic here.
    DialBackGrant {
        peer: PeerEndpoint,
        file_hash: FileHash,
    },
}

/// Why a [`ServeDecision::ReadRange`] was issued — the resumption context
/// [`ServeState::on_read_result`] needs to turn the bytes into an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadPurpose {
    /// Serve the bytes to a granted slot as a `SendBlock` for this range.
    Block {
        file_hash: FileHash,
        start: u64,
        end: u64,
    },
    /// Build + cache the file's AICH tree (a whole-file read, ADR-0038),
    /// then answer the requested part's recovery data.
    AichRecovery { file_hash: FileHash, part: u16 },
    /// Build + cache the file's AICH tree, then answer the master root.
    AichMasterRoot { file_hash: FileHash },
}

impl ReadPurpose {
    /// The file the read is of.
    pub(super) const fn file_hash(self) -> FileHash {
        match self {
            Self::Block { file_hash, .. }
            | Self::AichRecovery { file_hash, .. }
            | Self::AichMasterRoot { file_hash } => file_hash,
        }
    }
}

/// Our own position as the serve brain needs it — the half of the **Low-ID
/// abuse guard** (ADR-0031 amendment) that is about *us* rather than
/// about the asker.
///
/// It arrives as an explicit input, like the clock and the credit modifiers,
/// because the brain reads no cell: the enactor projects it from the
/// session's self-facts and hands it in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ServeSelfPosition {
    /// We hold no High-ID on a live server session (eMule
    /// `CServerConnect::IsLowID()`). The default — `false` — is the
    /// un-firewalled posture, so a brain nobody told anything never refuses on
    /// this ground.
    pub(super) low_id: bool,
    /// The server our live session is on, in the form a peer's hello encodes.
    /// `None` between sessions, and also for a DNS-named server, whose host no
    /// peer can be proven to share.
    pub(super) server: Option<rmule_primitives::Ipv4Endpoint>,
}

/// The sans-I/O serving brain. See the module docs.
pub(super) struct ServeState {
    /// The **Shared File Registry** snapshot every probe answers from,
    /// replaced by [`ServeState::on_share_set`] on the share-changed trigger
    /// — no per-probe registry round trips.
    shared: HashMap<FileHash, SharedFileEntry>,
    queue: UploadSlotQueue,
    /// `user_hash` per identified peer: keys credit recording and tells the
    /// enactor whose modifiers to supply.
    identified: HashMap<PeerEndpoint, UserHash>,
    /// The client each identified peer's hello named, kept exactly as long as
    /// `identified` so a waiter's row names its client across its hang-up.
    software: HashMap<PeerEndpoint, rmule_peer::ClientSoftware>,
    /// Ranges already decided for a granted flow, so a re-request serves only
    /// the missing subranges.
    served_ranges: HashMap<(PeerEndpoint, FileHash), Vec<(u64, u64)>>,
    /// Lazily-built AICH trees per shared file (ADR-0038), built from the
    /// first round-tripped whole-file read and reused after — a cache hit
    /// answers with no [`ServeDecision::ReadRange`]. Durable persistence
    /// (known2.met) is deferred.
    aich_cache: HashMap<FileHash, AichHashSet>,
    /// Each identified peer's advertised UDP contact `(client udp port, udp
    /// version)` from its hello, stamped onto its wait-list entry when it
    /// queues so an inbound `OP_REASKFILEPING` matches by IP + UDP port
    /// (ADR-0057). A `0` port means the peer advertised none.
    udp_contacts: HashMap<PeerEndpoint, (u16, u8)>,
    /// Each identified peer's claimed extended-requests version, from its
    /// hello (aMule `m_byExtendedRequestsVer`). A peer absent here claimed
    /// none — aMule's default `0` — and the part status it writes is
    /// discarded (`record_part_status`).
    extended_requests: HashMap<PeerEndpoint, u8>,
    /// Each identified peer's own source coordinate — its advertised
    /// `(client id, listen port)` as an [`ExchangedSource`] (ADR-0055 §Serving).
    /// The source-exchange serve pool for a complete shared file is built from
    /// these: a peer engaged in an upload relationship for a file is a live
    /// source for it.
    sx_sources: HashMap<PeerEndpoint, ExchangedSource>,
    /// The parts each peer holds of a file we share, from the part status its
    /// last name ask or UDP reask wrote (read through `held_parts`, ADR-0055 §Serving)
    /// — aMule's per-client `m_upPartStatus`. Read twice
    /// by a source-exchange answer: the asker's own entry is the needed-part
    /// filter's reference, and each pooled source's entry is what it offers. A peer or file absent
    /// here is of unknown status. Shed with `sx_sources`.
    sx_part_status: HashMap<(PeerEndpoint, FileHash), PartBitmap>,
    /// Each identified peer's **peer-UDP crypt target** — its user hash plus the
    /// crypt stance its hello advertised (ADR-0046). The reask reply matrix
    /// attaches it to a datagram addressed at that peer so the socket boundary
    /// can obfuscate it; a peer absent here is a stranger, answered plaintext
    /// (aMule's `GetWaitingClientByIP_UDP` returning NULL).
    crypt_targets: HashMap<PeerEndpoint, PeerUdpCryptTarget>,
    /// The per-peer source-exchange serve throttle (40/160-minute reask gate,
    /// ADR-0055) — shared by standalone and multipacket-sub asks.
    sx_throttle: SourceExchangeThrottle,
    /// Each identified peer's claimed connected server, from its hello — the
    /// "is it on *our* server" half of the **Low-ID abuse guard**. `None` for
    /// a peer whose hello encoded `0.0.0.0:0`, which can never match ours.
    peer_servers: HashMap<PeerEndpoint, Option<rmule_primitives::Ipv4Endpoint>>,
    /// Our own position, refreshed by the enactor (see [`ServeSelfPosition`]).
    ours: ServeSelfPosition,
}

impl ServeState {
    pub(super) fn new(queue: UploadSlotQueue) -> Self {
        Self {
            shared: HashMap::new(),
            queue,
            identified: HashMap::new(),
            software: HashMap::new(),
            served_ranges: HashMap::new(),
            aich_cache: HashMap::new(),
            udp_contacts: HashMap::new(),
            extended_requests: HashMap::new(),
            sx_sources: HashMap::new(),
            sx_part_status: HashMap::new(),
            crypt_targets: HashMap::new(),
            sx_throttle: SourceExchangeThrottle::default(),
            peer_servers: HashMap::new(),
            ours: ServeSelfPosition::default(),
        }
    }

    /// Refresh our own position (see [`ServeSelfPosition`]). A level, not an
    /// event: the enactor republishes it as often as it likes and the brain
    /// simply reads the latest one at its next decision.
    pub(super) fn on_self_position(&mut self, ours: ServeSelfPosition) {
        self.ours = ours;
    }

    /// The peers whose credit modifiers the entry points expect: every
    /// identified peer — a superset of the waiting set, which is all the
    /// queue needs.
    pub(super) fn identified_peers(&self) -> &HashMap<PeerEndpoint, UserHash> {
        &self.identified
    }

    /// Replace the share-set snapshot and announce it. Fed the offered
    /// registry rows at serve start and on every share-changed trigger. A
    /// file that left the offer stops being served at once
    /// ([`stop_serving`](Self::stop_serving)).
    pub(super) fn on_share_set(
        &mut self,
        entries: Vec<SharedFileEntry>,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let leaving: Vec<FileHash> = self
            .shared
            .keys()
            .filter(|file_hash| !entries.iter().any(|entry| entry.file_hash == **file_hash))
            .copied()
            .collect();
        let mut decisions = Vec::new();
        for file_hash in leaving {
            decisions.extend(self.stop_serving(file_hash, now, modifiers));
        }
        let files = entries
            .iter()
            .map(|entry| {
                OfferedFile::new(
                    entry.file_hash,
                    entry.file_size,
                    Ed2kText::from_utf8(entry.name.as_str()),
                )
            })
            .collect();
        self.shared = entries
            .into_iter()
            .map(|entry| (entry.file_hash, entry))
            .collect();
        decisions.push(ServeDecision::Announce(files));
        decisions
    }

    /// Keep the part status `peer` just wrote for `file_hash` — its name ask's
    /// or its UDP reask's: one reader ([`held_parts`]) and one rule for both,
    /// as aMule's `ProcessExtendedInfo` serves both (ADR-0055 §Serving).
    /// A status this file cannot read leaves the peer's parts unknown,
    /// as aMule clears it; so does any status from a peer whose hello claimed
    /// extended requests `0` — aMule clears it and returns before reading
    /// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:400-406`).
    fn record_part_status(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        file_size: u64,
        wire: Option<PartBitmap>,
    ) {
        let claims_status = self.extended_requests.get(&peer).is_some_and(|&v| v > 0);
        match wire
            .filter(|_| claims_status)
            .and_then(|wire| held_parts(file_size, &wire))
        {
            Some(held) => self.sx_part_status.insert((peer, file_hash), held),
            None => self.sx_part_status.remove(&(peer, file_hash)),
        };
    }

    /// Answer a peer's source-exchange request (ADR-0055 §Serving): build the
    /// candidate pool for `file_hash`, apply the per-peer throttle, filter it
    /// (LowID / self skip, needed-chunk, 500 cap), and — if anything survives —
    /// frame an `OP_ANSWERSOURCES(2)` plus a served-sources event. A file we do
    /// not share, a throttled ask, or an empty result all send nothing (aMule's
    /// `NULL` reply packet).
    ///
    /// Only a complete shared file has an engaged-client pool here; an
    /// in-progress download's source list lives in `DownloadState` (not owned
    /// by the serve brain), so serving partials' sources rides rmule's
    /// partial-file sharing (the [`ServedFileKind::InProgress`] pool rules are
    /// modelled and tested in `serve::source_exchange`, unwired here).
    fn answer_source_exchange(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        version: ServedSourcesVersion,
    ) -> Vec<ServeDecision> {
        if !self.shared.contains_key(&file_hash) {
            return Vec::new();
        }
        let candidates: Vec<SxCandidate> = self
            .queue
            .engaged_peers(file_hash)
            .into_iter()
            .filter_map(|engaged| {
                let source = *self.sx_sources.get(&engaged)?;
                Some(SxCandidate {
                    source,
                    part_status: self.sx_part_status.get(&(engaged, file_hash)).cloned(),
                })
            })
            .collect();
        // Rarity (rare vs common reask gate) follows how many sources we know
        // for the file — the engaged-client count, aMule's `GetSourceCount`.
        if !self.sx_throttle.admit(peer, now, candidates.len()) {
            return Vec::new();
        }
        // The needed-chunk gate reads the requester's own last status (name ask or UDP reask);
        // without one only sources holding a
        // part, plus the unknowns, are offered. The self-skip compares source identity, so the requester's
        // *own* source coordinate (its advertised id + listen port, not the
        // ephemeral socket) is what we exclude.
        let requester = SxRequester {
            endpoint: self
                .sx_sources
                .get(&peer)
                .and_then(|source| source.as_peer_endpoint()),
            part_status: self.sx_part_status.get(&(peer, file_hash)).cloned(),
        };
        let mut sources = select_sources(ServedFileKind::Complete, &requester, &candidates);
        // A classic entry has one 32-bit id field and no address block, so an
        // IPv6-only source reaches only a requester answered in ExtSX
        // (ADR-0087's `HasEd2kWireForm`). Dropped here rather than at framing,
        // so a pool of nothing else answers nothing — aMule's `NULL` reply —
        // instead of an empty list.
        if !matches!(version, ServedSourcesVersion::Ext { .. }) {
            sources.retain(|source| !matches!(source.peer_source(), PeerSource::Ipv6(_)));
        }
        if sources.is_empty() {
            return Vec::new();
        }
        let count = sources.len();
        vec![
            ServeDecision::Send {
                peer,
                command: ServeConnCommand::AnswerSources {
                    file_hash,
                    sources,
                    version,
                },
            },
            ServeDecision::Emit(ServeEvent::SourcesServed {
                peer,
                file_hash,
                count,
            }),
        ]
    }

    /// Re-rank idle waiters by live credit and report the changed positions.
    pub(super) fn on_rerank_tick(
        &mut self,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let reranked = self.queue.rerank(now, modifiers);
        rank_updates(&self.queue, &self.software, reranked)
    }

    /// Purge waiters whose reask heartbeat is silent past `purge_after` (aMule
    /// `MAX_PURGEQUEUETIME`, 1 h) or whose file is no longer shared, then
    /// re-rank the survivors (ADR-0057). Deterministic in `now` — the serve
    /// task's periodic tick, aMule's `CUploadQueue::Process` reap.
    pub(super) fn on_purge(
        &mut self,
        now: Instant,
        purge_after: Duration,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let shared = &self.shared;
        let purge = self.queue.purge(
            now,
            purge_after,
            |hash| shared.contains_key(&hash),
            modifiers,
        );
        for peer in &purge.removed {
            self.identified.remove(peer);
            self.software.remove(peer);
            self.udp_contacts.remove(peer);
            self.extended_requests.remove(peer);
            self.sx_sources.remove(peer);
            self.sx_part_status
                .retain(|(held_by, _), _| held_by != peer);
            self.crypt_targets.remove(peer);
            self.peer_servers.remove(peer);
            self.sx_throttle.forget(*peer);
        }
        let mut decisions = Vec::new();
        // A dropped wait-list entry never held a slot, so it gets the purge's
        // own event — never `UploadSlotReleased`, which stays reserved for the
        // reclaimed dial-back grant below.
        for peer in &purge.removed {
            if purge.reclaimed != Some(*peer) {
                decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                    peer: *peer,
                    cause: WaiterLeaveCause::Purged,
                }));
            }
        }
        if let Some(peer) = purge.reclaimed {
            // A pending dial-back grant whose dial never connected: its slot is
            // reclaimed, so surface the release before the promotion that fills
            // it (`promotion_decisions` carries the grant + rank shifts).
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
        }
        decisions.extend(self.promotion_decisions(purge.promotion));
        decisions
    }

    /// Grant (or dial-back) the promoted waiter plus any rank shifts — the
    /// shared tail of a slot-freeing event. A promotion of a **disconnected**
    /// waiter is a `DialBackGrant` (rmule dials it), not a `GrantSlot` over a
    /// dead socket (ADR-0057).
    fn promotion_decisions(&self, promotion: Promotion) -> Vec<ServeDecision> {
        let mut decisions = Vec::new();
        if let Some((promoted, file_hash)) = promotion.granted {
            decisions.push(if promotion.dial_back {
                ServeDecision::DialBackGrant {
                    peer: promoted,
                    file_hash,
                }
            } else {
                ServeDecision::Send {
                    peer: promoted,
                    command: ServeConnCommand::GrantSlot { file_hash },
                }
            });
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: promoted,
                file_hash,
                software: self.software.get(&promoted).cloned(),
            }));
        }
        decisions.extend(rank_updates(
            &self.queue,
            &self.software,
            promotion.reranked,
        ));
        decisions
    }
}

/// Project changed queue ranks into the `SetQueueRank` + `PeerQueued` decision
/// pair each carries (shared by the rerank tick, purge, and promotion).
fn rank_updates(
    queue: &UploadSlotQueue,
    software: &HashMap<PeerEndpoint, rmule_peer::ClientSoftware>,
    reranked: Vec<(PeerEndpoint, u16)>,
) -> Vec<ServeDecision> {
    reranked
        .into_iter()
        .flat_map(|(queued, rank)| {
            let send = ServeDecision::Send {
                peer: queued,
                command: ServeConnCommand::SetQueueRank { rank },
            };
            let emit = queue.waiting_file(queued).map(|file_hash| {
                ServeDecision::Emit(ServeEvent::PeerQueued {
                    peer: queued,
                    rank,
                    file_hash,
                    software: software.get(&queued).cloned(),
                })
            });
            std::iter::once(send).chain(emit)
        })
        .collect()
}
