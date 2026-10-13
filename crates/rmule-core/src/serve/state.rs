//! The synchronous, sans-I/O core of the serve activity.
//!
//! [`ServeState`] is the **Serve State**, the serve-side mirror of
//! [`DownloadState`](crate::download): it owns every clock-free serve
//! decision — probe/status/hash-set answers from a **Shared File Registry**
//! snapshot and its copy of the **Served Downloads** (ADR-0113), slot
//! admission via the **Upload Slot Queue** it contains, block
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
mod served;
#[cfg(test)]
mod tests;
mod transfer;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rmule_ed2k::{FileCompleteness, OfferedFile};
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_peer::{ClientSoftware, PartBitmap, PeerIdentity, ServerCommand};
use rmule_primitives::{AichHashSet, Ed2kText, FileHash, PeerEndpoint, SourceSighting, UserHash};

use crate::WaiterLeaveCause;
use crate::registry::SharedFileEntry;
use crate::serve::source_exchange::{
    SourceExchangeThrottle, SxCandidate, SxRequester, select_sources,
};
use crate::served_downloads::{PartFileIdentity, PartialEnd, ReadCheck, ServedLook};
use crate::service::ServeEvent;
use crate::upload_queue::{Promotion, UploadSlotQueue};

/// One effect the serve task must enact, drained in order from a
/// [`ServeState`] entry point. Everything that touches I/O, a clock, a
/// channel, the credit ledger, or the content store is data here, not an
/// inline `await`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ServeDecision {
    /// Send a Server Capability command down `peer`'s live connection.
    Send {
        peer: PeerEndpoint,
        command: ServerCommand,
    },
    /// Close `peer`'s connection.
    Disconnect { peer: PeerEndpoint },
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
    /// [`ServeState::on_read_result`] with this same `purpose`. A Served
    /// Download's read carries its `check`: the handle the enactor opens must
    /// be the file its **Part File Identity** names before a byte is read,
    /// and a path that names nothing gives way to the other once (ADR-0113
    /// §"Reading a part file"); a registry row's carries none.
    ReadRange {
        peer: PeerEndpoint,
        path: PathBuf,
        offset: u64,
        len: u64,
        purpose: ReadPurpose,
        check: Option<ReadCheck>,
    },
    /// A read of `file_hash`'s Served Download, checked against `checked`,
    /// found its file changed or unreadable: its **Verified Range** empties
    /// in the cell for `cause`, whoever holds it (ADR-0113).
    EmptyRange {
        file_hash: FileHash,
        checked: Option<PartFileIdentity>,
        cause: PartialEnd,
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
    /// Hand `sighting`, a peer that asked about `file_hash`, to the run of
    /// the download serving it as a candidate source (ADR-0113). The run
    /// takes it under its own source cap; a full inbox drops it.
    KeepAsker {
        file_hash: FileHash,
        sighting: SourceSighting,
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
    /// The brain's copy of the **Served Downloads** (ADR-0113): every
    /// download answering probes, refreshed by [`ServeState::on_served`].
    served: HashMap<FileHash, ServedLook>,
    /// Entries the cell no longer holds, answering from their last copy
    /// until the next share trigger drops them.
    ended: HashSet<FileHash>,
    /// The **Partial Share**s: the Served Downloads offered at the last share
    /// trigger whose content no registry row offers whole. With the rows,
    /// the share set.
    partials: HashSet<FileHash>,
    queue: UploadSlotQueue,
    /// The identity each connected peer's session read off its hello and
    /// keeps current (ADR-0055 §Serving): its User Hash keys credit
    /// recording and names whose modifiers the enactor supplies, its software
    /// names its rows, and its reask contact, extended-requests claim, crypt
    /// target, own source coordinate and "on our server" claim are read off
    /// it where they are needed. Taken whole at `Identified` and at every
    /// `IdentityRevised`; kept across a waiter's hang-up while it holds its
    /// queue standing, and shed in one place ([`Self::forget`]) when it
    /// holds none.
    identities: HashMap<PeerEndpoint, PeerIdentity>,
    /// Ranges already decided for a granted flow, so a re-request serves only
    /// the missing subranges.
    served_ranges: HashMap<(PeerEndpoint, FileHash), Vec<(u64, u64)>>,
    /// Lazily-built AICH trees per shared file (ADR-0038), built from the
    /// first round-tripped whole-file read and reused after — a cache hit
    /// answers with no [`ServeDecision::ReadRange`]. Durable persistence
    /// (known2.met) is deferred.
    aich_cache: HashMap<FileHash, AichHashSet>,
    /// The parts each peer holds of a file we share, from the part status its
    /// last name ask or UDP reask wrote (read through `PartBitmap::advertised_parts`, ADR-0055 §Serving)
    /// — aMule's per-client `m_upPartStatus`. Read twice
    /// by a source-exchange answer: the asker's own entry is the needed-part
    /// filter's reference, and each pooled source's entry is what it offers. A peer or file absent
    /// here is of unknown status. Shed with the peer's identity.
    sx_part_status: HashMap<(PeerEndpoint, FileHash), PartBitmap>,
    /// The per-peer source-exchange serve throttle (40/160-minute reask gate,
    /// ADR-0055) — shared by standalone and multipacket-sub asks.
    sx_throttle: SourceExchangeThrottle,
    /// Our own position, refreshed by the enactor (see [`ServeSelfPosition`]).
    ours: ServeSelfPosition,
}

impl ServeState {
    pub(super) fn new(queue: UploadSlotQueue) -> Self {
        Self {
            shared: HashMap::new(),
            served: HashMap::new(),
            ended: HashSet::new(),
            partials: HashSet::new(),
            queue,
            identities: HashMap::new(),
            served_ranges: HashMap::new(),
            aich_cache: HashMap::new(),
            sx_part_status: HashMap::new(),
            sx_throttle: SourceExchangeThrottle::default(),
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
    /// queue needs — by the identity its session keeps.
    pub(super) fn identities(&self) -> &HashMap<PeerEndpoint, PeerIdentity> {
        &self.identities
    }

    /// The software `peer`'s identity names, for the row it earns.
    fn software_of(&self, peer: PeerEndpoint) -> Option<ClientSoftware> {
        software_of(&self.identities, peer)
    }

    /// Shed everything kept about `peer` once it holds no queue standing: its
    /// identity and the part statuses it wrote.
    fn forget(&mut self, peer: PeerEndpoint) {
        self.identities.remove(&peer);
        self.sx_part_status
            .retain(|(held_by, _), _| *held_by != peer);
    }

    /// Replace the share-set snapshot and announce it. Fed the offered
    /// registry rows at serve start and on every share-changed trigger, with
    /// the Served Downloads as last refreshed: the Partial Shares are those
    /// offered then that no row offers whole. A file that left the offer —
    /// a row or a Partial Share — stops being served at once
    /// ([`stop_serving`](Self::stop_serving)).
    pub(super) fn on_share_set(
        &mut self,
        entries: Vec<SharedFileEntry>,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        for file_hash in self.ended.drain() {
            self.served.remove(&file_hash);
        }
        let rows: HashSet<FileHash> = entries.iter().map(|entry| entry.file_hash).collect();
        let partials: HashSet<FileHash> = self
            .served
            .iter()
            .filter(|(file_hash, look)| look.offered && !rows.contains(file_hash))
            .map(|(file_hash, _)| *file_hash)
            .collect();
        let mut leaving: Vec<FileHash> = self
            .shared
            .keys()
            .chain(&self.partials)
            .filter(|file_hash| !rows.contains(file_hash) && !partials.contains(file_hash))
            .copied()
            .collect();
        leaving.sort_unstable();
        leaving.dedup();
        let mut decisions = Vec::new();
        for file_hash in leaving {
            decisions.extend(self.stop_serving(file_hash, now, modifiers));
        }
        // The rows whole, then each Partial Share as incomplete under its
        // download's name and size (ADR-0113 §"Announce and Kad").
        let mut partial_files: Vec<OfferedFile> = partials
            .iter()
            .filter_map(|file_hash| Some((*file_hash, self.served.get(file_hash)?)))
            .map(|(file_hash, look)| {
                OfferedFile::new(
                    file_hash,
                    look.served.file_size,
                    Ed2kText::from_utf8(look.served.name.as_str()),
                )
                .with_completeness(FileCompleteness::Incomplete)
            })
            .collect();
        partial_files.sort_unstable_by_key(OfferedFile::file_hash);
        let files = entries
            .iter()
            .map(|entry| {
                OfferedFile::new(
                    entry.file_hash,
                    entry.file_size,
                    Ed2kText::from_utf8(entry.name.as_str()),
                )
            })
            .chain(partial_files)
            .collect();
        self.shared = entries
            .into_iter()
            .map(|entry| (entry.file_hash, entry))
            .collect();
        self.partials = partials;
        decisions.push(ServeDecision::Announce(files));
        decisions
    }

    /// Keep the part status `peer` just wrote for `file_hash` — its name ask's
    /// or its UDP reask's: one reader ([`PartBitmap::advertised_parts`], the
    /// one every status goes through) and one rule for both, as aMule's
    /// `ProcessExtendedInfo` serves both (ADR-0055 §Serving). aMule's uploader
    /// clears a status whose count is not the file's (`UploadClient.cpp:418-421`)
    /// and so does this; it reads a count of zero as all-zero
    /// (`UploadClient.cpp:415-416`), which would drop a complete source from
    /// every answer, where this reads the writer's meaning, every part.
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
        let claims_status = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.extended_requests_version() > 0);
        match wire
            .filter(|_| claims_status)
            .and_then(|wire| wire.advertised_parts(file_size))
        {
            Some(held) => self.sx_part_status.insert((peer, file_hash), held),
            None => self.sx_part_status.remove(&(peer, file_hash)),
        };
    }

    /// Answer a peer's source-exchange request (ADR-0055 §Serving): build the
    /// candidate pool for `file_hash`, apply the per-peer throttle, filter it
    /// (LowID / self skip, needed-chunk, 500 cap), and — if anything survives —
    /// frame an `OP_ANSWERSOURCES(2)` plus a served-sources event. A file we do
    /// not offer, a throttled ask, or an empty result all send nothing
    /// (aMule's `NULL` reply packet).
    ///
    /// A registry row's pool is its upload-engaged clients; a Partial Share's
    /// is its download's own, as the run published it from its Source Book
    /// (ADR-0113): the sources it downloads from or waits at that are not
    /// queue-full, of which [`ServedFileKind::InProgress`](crate::serve::source_exchange::ServedFileKind::InProgress) keeps only those
    /// whose parts are known.
    fn answer_source_exchange(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let Some((kind, pool)) = self.asked(file_hash).and_then(|asked| asked.exchange()) else {
            return Vec::new();
        };
        let (candidates, known): (Vec<SxCandidate>, usize) = match pool {
            Some(pool) => (
                pool.sources
                    .iter()
                    .map(|(source, parts)| SxCandidate {
                        source: *source,
                        part_status: parts.clone(),
                    })
                    .collect(),
                usize::try_from(pool.known).unwrap_or(usize::MAX),
            ),
            None => {
                let engaged: Vec<SxCandidate> = self
                    .queue
                    .engaged_peers(file_hash)
                    .into_iter()
                    .filter_map(|engaged| {
                        let source = self.identities.get(&engaged)?.source_coordinate();
                        Some(SxCandidate {
                            source,
                            part_status: self.sx_part_status.get(&(engaged, file_hash)).cloned(),
                        })
                    })
                    .collect();
                let known = engaged.len();
                (engaged, known)
            }
        };
        // Rarity (rare vs common reask gate) follows how many sources we know
        // for the file — aMule's `GetSourceCount`: a row's engaged clients, a
        // download's every source.
        if !self.sx_throttle.admit(peer, now, known) {
            return Vec::new();
        }
        // The needed-chunk gate reads the requester's own last status (name ask or UDP reask);
        // without one only sources holding a
        // part, plus the unknowns, are offered. The self-skip compares source identity, so the requester's
        // *own* source coordinate (its advertised id + listen port, not the
        // ephemeral socket) is what we exclude.
        let requester = SxRequester {
            endpoint: self
                .identities
                .get(&peer)
                .and_then(|identity| identity.source_coordinate().as_peer_endpoint()),
            part_status: self.sx_part_status.get(&(peer, file_hash)).cloned(),
        };
        // Which of these the answer's wire form can carry is the peer
        // session's call: a classic answer leaves an IPv6-only source out, and
        // one left empty sends nothing (ADR-0087).
        let sources = select_sources(kind, &requester, &candidates);
        if sources.is_empty() {
            return Vec::new();
        }
        vec![ServeDecision::Send {
            peer,
            command: ServerCommand::AnswerSources { file_hash, sources },
        }]
    }

    /// Re-rank idle waiters by live credit and report the changed positions.
    pub(super) fn on_rerank_tick(
        &mut self,
        now: Instant,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        let reranked = self.queue.rerank(now, modifiers);
        rank_updates(&self.queue, &self.identities, reranked)
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
        let (shared, partials) = (&self.shared, &self.partials);
        let purge = self.queue.purge(
            now,
            purge_after,
            |hash| shared.contains_key(&hash) || partials.contains(&hash),
            modifiers,
        );
        for &peer in &purge.removed {
            self.forget(peer);
            self.sx_throttle.forget(peer);
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
                    command: ServerCommand::GrantSlot { file_hash },
                }
            });
            decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: promoted,
                file_hash,
                software: self.software_of(promoted),
            }));
        }
        decisions.extend(rank_updates(
            &self.queue,
            &self.identities,
            promotion.reranked,
        ));
        decisions
    }
}

/// Project changed queue ranks into the `SetQueueRank` + `PeerQueued` decision
/// pair each carries (shared by the rerank tick, purge, and promotion).
fn rank_updates(
    queue: &UploadSlotQueue,
    identities: &HashMap<PeerEndpoint, PeerIdentity>,
    reranked: Vec<(PeerEndpoint, u16)>,
) -> Vec<ServeDecision> {
    reranked
        .into_iter()
        .flat_map(|(queued, rank)| {
            let send = ServeDecision::Send {
                peer: queued,
                command: ServerCommand::SetQueueRank { rank },
            };
            let emit = queue.waiting_file(queued).map(|file_hash| {
                ServeDecision::Emit(ServeEvent::PeerQueued {
                    peer: queued,
                    rank,
                    file_hash,
                    software: software_of(identities, queued),
                })
            });
            std::iter::once(send).chain(emit)
        })
        .collect()
}

/// The software `peer`'s identity names, if the serve side holds one.
fn software_of(
    identities: &HashMap<PeerEndpoint, PeerIdentity>,
    peer: PeerEndpoint,
) -> Option<ClientSoftware> {
    identities
        .get(&peer)
        .map(|identity| identity.software().clone())
}
