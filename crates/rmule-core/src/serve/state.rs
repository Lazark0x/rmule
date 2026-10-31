//! The synchronous, sans-I/O core of the serve activity.
//!
//! [`ServeState`] is the **Serve State**, the serve-side mirror of
//! [`DownloadState`](crate::download): it owns every clock-free serve
//! decision — probe/status/hash-set answers from a **Shared File Registry**
//! snapshot and its copy of the **Served Downloads** (ADR-0113), slot
//! admission via the **Upload Slot Queue** it contains, block
//! sends with served-range subtraction, which AICH tree is built when and
//! who is answered from it, credit recording, and **Secured Identity** binding — and
//! returns an ordered `Vec<`[`ServeDecision`]`>` that the `ServeTask` enacts.
//! It never touches a socket, a clock, the registry, the content store, or an
//! `mpsc` channel; byte reads are fallible effects that round-trip through
//! [`ServeState::on_read_result`], the read-side twin of
//! `DownloadState::on_persist_result`, and time and credit modifiers arrive
//! as explicit parameters (the [`UploadSlotQueue`] contract).
//!
//! This split is what makes every serve policy path assertable as a plain
//! decision sequence instead of only through a live `ServeTask` loopback rig.

mod aich;
mod connection;
mod dial_back;
mod exchange;
mod flow;
mod reask;
mod relink;
mod served;
#[cfg(test)]
mod tests;
mod transfer;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rmule_ed2k::{FileCompleteness, OfferedFile};
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_peer::{ClientSoftware, PartBitmap, PeerIdentity, ServerCommand};
use rmule_primitives::{Ed2kText, FileHash, PeerEndpoint, SourceSighting, UserHash};

pub(super) use self::aich::AichBuilt;
use self::aich::AichTrees;
use self::flow::ServeFlow;
use crate::WaiterLeaveCause;
use crate::adapters::{DialBack, FarEnd};
use crate::serve::ask_pace::AskPace;
use crate::serve::hash_track::HashTrack;
use crate::registry::SharedFileEntry;
use crate::serve::source_exchange::SourceExchangeThrottle;
use crate::served_downloads::{PartFileIdentity, PartialEnd, ServedLook};
use crate::service::{DialBackEnd, GrantRoad, ServeEvent};
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
    /// Credit `user_hash` at `at` for `bytes` that left for the socket, if
    /// its ledger row pays there (ADR-0041).
    RecordCredit {
        user_hash: UserHash,
        at: IpAddr,
        bytes: u64,
    },
    /// Count `bytes` of `file_hash` as sent to `peer` (ADR-0077).
    CountSent {
        peer: PeerEndpoint,
        file_hash: FileHash,
        bytes: u64,
    },
    /// Ban `peer`'s address: its hello named the User Hash of an identified
    /// client still linked from another IPv4 address (aMule bans it,
    /// "Userhash invalid", `ClientList.cpp:384-392`), or its session proved
    /// another key under that hash (ADR-0107).
    Ban { peer: PeerEndpoint },
    /// Send `block`'s `bytes` down `peer`'s link for `flow`, unless the flow
    /// has ended by the time the link's task reaches them. With `deflate` that
    /// task deflates them first, off the async runtime and off this loop, and
    /// sends the stream when that is smaller (ADR-0031).
    SendBlock {
        peer: PeerEndpoint,
        flow: u64,
        block: BlockRead,
        bytes: Vec<u8>,
        deflate: bool,
    },
    /// `peer`'s slot is over: what `flow` has under way is for nobody.
    EndFlow { peer: PeerEndpoint, flow: u64 },
    /// Read `block` of the shared file at `path`, never longer than three
    /// blocks (ADR-0031), away from the serve loop. A fallible effect: the end
    /// comes back as an input, the bytes through
    /// [`ServeState::on_read_result`] with this same `flow` and `block`, and a
    /// failed read through [`ServeState::on_read_failed`]. A Served
    /// Download's read is aimed by the enactor at the read's turn: the handle
    /// it opens must be the file the entry's **Part File Identity** names then
    /// before a byte is read, and a path that names nothing gives way to the
    /// other once (ADR-0113 §"Reading a part file"); a registry row's is read
    /// from its path, unchecked.
    ReadRange {
        peer: PeerEndpoint,
        flow: u64,
        from: ReadFrom,
        block: BlockRead,
    },
    /// Build the AICH tree of the `file_size`-byte shared file at `path`, away
    /// from the serve loop and one block at a time (ADR-0038, ADR-0031). One
    /// is out at a time; its end comes back through
    /// [`ServeState::on_aich_landed`].
    BuildAichTree {
        file_hash: FileHash,
        path: PathBuf,
        file_size: u64,
    },
    /// Tell the build out to stop before its next block: its file left the
    /// share set (ADR-0038).
    StopAichBuild,
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
    /// Dial back a waiter promoted while no link of it was up — the
    /// **Dial-Back Grant** (ADR-0057). The serve adapter dials and says how
    /// it ended ([`ServeState::on_dial_back_linked`],
    /// [`ServeState::on_dial_back_failed`]).
    DialBack(DialBack),
    /// Hand `sighting`, a peer that asked about `file_hash`, to the run of
    /// the download serving it as a candidate source (ADR-0113). The run
    /// takes it under its own source cap; a full inbox drops it.
    KeepAsker {
        file_hash: FileHash,
        sighting: SourceSighting,
    },
}

/// Where a [`ServeDecision::ReadRange`] takes its bytes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadFrom {
    /// A registry row's file, at the row's path.
    Row(PathBuf),
    /// A Served Download's, wherever its entry names when the read takes its
    /// turn (ADR-0113 §"Reading a part file").
    Download,
}

/// The block a [`ServeDecision::ReadRange`] reads for a granted flow: the
/// range `start..end` of `file_hash`, which [`ServeState::on_read_result`]
/// sends as a `SendBlock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BlockRead {
    pub(super) file_hash: FileHash,
    pub(super) start: u64,
    pub(super) end: u64,
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
    /// We hold a live server session under a Low ID: aMule's
    /// `IsConnected() && IsLowID()` (`UploadQueue.cpp:403`), so a node with no
    /// session has nothing to guard. The default — `false` — is the
    /// un-firewalled posture, so a brain nobody told anything never refuses on
    /// this ground.
    pub(super) low_id: bool,
    /// The server our live session is on, in the form a peer's hello encodes.
    /// `None` between sessions, and also for a DNS-named server, whose host no
    /// peer can be proven to share.
    pub(super) server: Option<rmule_primitives::Ipv4Endpoint>,
}

/// What the node holds of the address an input came from: read by the enactor
/// before each input, as the brain reads no cell. The default is a stranger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ServeAsker {
    /// The address is banned (ADR-0064).
    pub(super) banned: bool,
    /// The address is a source of ours, connected or queued at: aMule's
    /// `GetDownloadState() != DS_NONE`, which the Low-ID guard reads and
    /// which no ban lands on (ADR-0055 divergence 7).
    pub(super) our_source: bool,
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
    /// The links whose client is **identified**: its Secure User
    /// Identification proved the hello's User Hash and the link bound the key
    /// in the credit ledger (ADR-0041) — aMule's `IS_IDENTIFIED`. Shed with
    /// the identity.
    identified: HashSet<PeerEndpoint>,
    /// The live links rmule dialed — a download's, or a dial-back's — whose
    /// hello takes no client from a live link of its own: aMule moves a
    /// client to a new socket only at the hello of one the peer opened
    /// (`ClientTCPSocket.cpp:391`, ADR-0057). Each with what its driver sees
    /// of its far end, read before the client's own link is let go for it
    /// (ADR-0107 invariant 7). Shed at the link's close.
    dialed: HashMap<PeerEndpoint, FarEnd>,
    /// Ranges already decided for a granted flow, so a re-request serves only
    /// the missing subranges.
    served_ranges: HashMap<(PeerEndpoint, FileHash), Vec<(u64, u64)>>,
    /// Each slot holder's **Serve Flow** (ADR-0031).
    flows: HashMap<PeerEndpoint, ServeFlow>,
    /// How many flows have begun, which numbers the next.
    flows_begun: u64,
    /// The file and blocks each slot holder's last `OP_REQUESTPARTS` named:
    /// all it has pending, read again when its slot moves to a link it kept
    /// (ADR-0107 invariant 7).
    last_ask: HashMap<PeerEndpoint, (FileHash, rmule_peer::PartRanges)>,
    /// The AICH trees of the files peers asked about, and the one being built
    /// (ADR-0038).
    aich: AichTrees,
    /// The parts each peer holds of a file we share, from the part status its
    /// last name ask or UDP reask wrote (read through
    /// `PartBitmap::advertised_parts`, ADR-0055 §Serving) — aMule's
    /// per-client `m_upPartStatus`. Read twice by a source-exchange answer:
    /// the asker's own entry is the needed-part filter's reference, and each
    /// pooled source's entry is what it offers. A peer or file absent here is
    /// of unknown status. Shed with the peer's identity.
    sx_part_status: HashMap<(PeerEndpoint, FileHash), PartBitmap>,
    /// The per-peer source-exchange serve throttle (40/160-minute reask gate,
    /// ADR-0055) — shared by standalone and multipacket-sub asks.
    sx_throttle: SourceExchangeThrottle,
    /// Our own position, refreshed by the enactor (see [`ServeSelfPosition`]).
    ours: ServeSelfPosition,
    /// What the node holds of the current input's address, refreshed by the
    /// enactor (see [`ServeAsker`]).
    asker: ServeAsker,
    /// The **Ask Pace** (ADR-0055 divergence 7).
    asks: AskPace,
    /// The **Hash Track** of who proved a key where.
    hashes: HashTrack,
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
            identified: HashSet::new(),
            dialed: HashMap::new(),
            served_ranges: HashMap::new(),
            flows: HashMap::new(),
            flows_begun: 0,
            last_ask: HashMap::new(),
            aich: AichTrees::default(),
            sx_part_status: HashMap::new(),
            sx_throttle: SourceExchangeThrottle::default(),
            ours: ServeSelfPosition::default(),
            asker: ServeAsker::default(),
            asks: AskPace::default(),
            hashes: HashTrack::default(),
        }
    }

    /// Refresh our own position (see [`ServeSelfPosition`]). A level, not an
    /// event: the enactor republishes it as often as it likes and the brain
    /// simply reads the latest one at its next decision.
    pub(super) fn on_self_position(&mut self, ours: ServeSelfPosition) {
        self.ours = ours;
    }

    /// Refresh what the node holds of the next input's address (see
    /// [`ServeAsker`]).
    pub(super) fn on_asker(&mut self, asker: ServeAsker) {
        self.asker = asker;
    }

    /// `peer` is a link rmule dialed, whose hello is still to come, and
    /// `far_end` what its driver sees of its far end: it takes only a
    /// standing whose link has ended (ADR-0057, "A client on a new link keeps
    /// its standing").
    pub(super) fn on_link_dialed(&mut self, peer: PeerEndpoint, far_end: FarEnd) {
        self.dialed.insert(peer, far_end);
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
        self.identified.remove(&peer);
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
                OfferedFile::new(file_hash, look.served.file_size, look.served.name.clone())
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
        decisions.extend(self.reads_after_trigger());
        decisions
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
        // [`Self::in_share_set`], read by field: the queue is borrowed
        // mutably beside it.
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
        // A dropped wait-list entry gets the purge's own event; the reclaimed
        // dial-back grant below gets its lapse instead.
        for peer in &purge.removed {
            if purge.reclaimed != Some(*peer) {
                decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                    peer: *peer,
                    cause: WaiterLeaveCause::Purged,
                }));
            }
        }
        if let Some(peer) = purge.reclaimed {
            // A pending dial-back grant whose client never linked: its slot is
            // reclaimed, so surface the lapse before the promotion that fills
            // it (`promotion_decisions` carries the grant + rank shifts).
            decisions.push(ServeDecision::Emit(ServeEvent::UploadDialBackFailed {
                peer,
                cause: DialBackEnd::Lapsed,
            }));
        }
        decisions.extend(self.promotion_decisions(purge.promotion));
        decisions
    }

    /// Grant the promoted waiter on its link, or reach it when it has none
    /// ([`reach_promoted`](Self::reach_promoted)), plus any rank shifts — the
    /// shared tail of a slot-freeing event (ADR-0057).
    fn promotion_decisions(&mut self, promotion: Promotion) -> Vec<ServeDecision> {
        let mut decisions = Vec::new();
        if let Some((promoted, file_hash)) = promotion.granted {
            if promotion.dial_back {
                decisions.extend(self.reach_promoted(promoted, file_hash));
            } else {
                decisions.push(ServeDecision::Send {
                    peer: promoted,
                    command: ServerCommand::GrantSlot { file_hash },
                });
                decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                    peer: promoted,
                    file_hash,
                    software: self.software_of(promoted),
                    road: GrantRoad::Linked,
                }));
            }
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
