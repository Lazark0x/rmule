//! The upload slot queue (ADR-0031): who is admitted, where they rank, who is
//! promoted when a slot frees, and who is purged for going silent. Rank is
//! aMule's credit-weighted score, so a peer that has given more waits less; the
//! serve brain enacts what this queue decides and never reorders it itself.

use std::cmp::{Ordering, Reverse};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_primitives::{AccountingKey, FileHash, PeerEndpoint};

mod reask;
mod session;

/// How many **waiting** entries one accounting key may hold at once — the
/// per-address queue cap (ADR-0088).
///
/// Three, the reference count, and it counts the wait list only: a granted
/// slot is not a queue place. eMule 0.70b `srchybrid/UploadQueue.cpp:603-613`
/// counts the waiting list entries sharing the requester's IP (`cSameIP`) and
/// refuses at `>= 3`; aMule `src/UploadQueue.cpp:493-516` counts the requester
/// itself plus every in-scope client its `IsOnUploadQueue`
/// (`src/UploadQueue.cpp:341`, the waiting list alone) reports, and refuses at
/// `> 3` — the same three waiters, written from the other side.
///
/// The key is [`AccountingKey`], so one IPv4 address is one budget and one
/// IPv6 `/64` is one budget. That is the kno fork's `RateLimitScope`
/// (`src/PeerAddressing.h:225`, `src/ClientList.cpp:990`) in rmule's
/// vocabulary: an IPv4 host is roughly a host, an IPv6 `/128` is not, so a
/// per-`/128` cap counts to one forever and caps nothing.
pub const MAX_WAITING_PER_ADDRESS: usize = 3;

/// How long the wait list must already be before a firewalled node stops
/// admitting strangers at all — the **Low-ID abuse guard**'s threshold
/// (eMule `srchybrid/UploadQueue.cpp:535-545`, aMule
/// `src/UploadQueue.cpp:403-409`, at `irwir/eMule@13983526` and
/// `kno/amule@ab483654`).
///
/// Fifty, in both references, and it is a *strictly greater than*: a wait list
/// of exactly fifty still admits. The number is not about fairness but about
/// scarcity — a firewalled node can only ever be reached by a callback, so
/// every place it sells to a stranger is a place it cannot give to a peer that
/// is already in a relationship with it.
pub const LOW_ID_ABUSE_WAIT_LIST_THRESHOLD: usize = 50;

/// The four facts the **Low-ID abuse guard** decides on, each read where it is
/// already known rather than re-derived here (ADR-0031 amendment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LowIdAbuseFacts {
    /// We hold a live server session under a Low ID: both references read
    /// `IsConnected() && IsLowID()`, so a node with no session does not
    /// guard (`UploadQueue.cpp:403`).
    pub(crate) we_are_low_id: bool,
    /// The asker is a source of ours, connected or queued at: aMule's
    /// `GetDownloadState() != DS_NONE` (`UploadQueue.cpp:405`). Refusing it
    /// could cost us a source.
    pub(crate) our_source: bool,
    /// The asker is on our friend list. rmule has no friend list, so this is
    /// **always false** today; it is a named input rather than a silent
    /// omission so that adding friends later fills a hole instead of
    /// discovering one.
    pub(crate) is_friend: bool,
    /// The asker's hello named the server our own live session is on. An
    /// unproven server on either side (a DNS-named host encodes `0.0.0.0:0`)
    /// reads as false, which refuses rather than admits.
    pub(crate) on_our_server: bool,
    /// How many peers already wait.
    pub(crate) waiting: usize,
}

/// The **Low-ID abuse guard**: a firewalled node refuses a stranger's slot ask
/// outright once its wait list is over
/// [`LOW_ID_ABUSE_WAIT_LIST_THRESHOLD`].
///
/// Pure, and deliberately an `AND` of all five: any one of them false means
/// the ask is ordinary and goes to [`UploadSlotQueue::admit`]. Both references
/// `return` here without framing a packet, so the caller answers with silence
/// — the same silence the two queue caps answer with (ADR-0088).
pub(crate) const fn refuses_as_low_id_abuse(facts: &LowIdAbuseFacts) -> bool {
    facts.we_are_low_id
        && !facts.our_source
        && !facts.is_friend
        && !facts.on_our_server
        && facts.waiting > LOW_ID_ABUSE_WAIT_LIST_THRESHOLD
}

/// The outcome of admitting a requester (ADR-0031: core owns rank + budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// A slot was free; the peer holds it now.
    Granted,
    /// All slots busy; the peer waits at this 1-based queue position.
    Queued {
        /// The peer's 1-based position in the wait list.
        rank: u16,
    },
    /// Slots busy and the wait list is at `max_queue_len`; turn the peer away.
    ///
    /// Answered with **silence**, like [`RefusedAddressCap`](Self::RefusedAddressCap):
    /// aMule `src/UploadQueue.cpp:534-537` and eMule
    /// `srchybrid/UploadQueue.cpp:639-656` both `return` at the cap before a
    /// packet is framed. `OP_OUTOFPARTREQS` is not this answer — to the
    /// requester it ends an upload session — and `OP_QUEUEFULL 0x93` is the
    /// UDP reask reply (`srchybrid/ClientUDPSocket.cpp:299-305`).
    Refused,
    /// [`MAX_WAITING_PER_ADDRESS`] peers from this requester's accounting key
    /// already wait, so it is not admitted (ADR-0088).
    ///
    /// Distinct from [`Refused`](Self::Refused) because the **answer** is
    /// distinct: the reference sends nothing at all here — both eMule
    /// (`srchybrid/UploadQueue.cpp:608-613`) and aMule
    /// (`src/UploadQueue.cpp:510-516`) return before any packet is framed, so
    /// the requester learns only that its `OP_STARTUPLOADREQ` went unanswered.
    RefusedAddressCap,
}

/// What changed when a peer left the queue or released a slot: an optional
/// newly-granted head plus the queued peers whose rank moved. The queue reports
/// **only changed** ranks (it remembers each entry's last-reported rank), so the
/// serve task never re-sends an unchanged `OP_QUEUERANKING`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Promotion {
    /// The waiter that just took the freed slot and the file it waited for, or
    /// `None` when nobody was waiting.
    pub granted: Option<(PeerEndpoint, FileHash)>,
    /// The promoted waiter had no live TCP serve connection (disconnected
    /// standing, ADR-0057), so its grant is a **dial-back**: rmule dials its
    /// TCP endpoint and sends `OP_ACCEPTUPLOADREQ` on connect, rather than
    /// granting over a dead socket. Meaningful only when `granted` is `Some`.
    pub dial_back: bool,
    /// Waiters whose 1-based rank changed, and their new rank. Only changed
    /// ranks appear, so this is exactly the set of `OP_QUEUERANKING` messages
    /// the serve task must send.
    pub reranked: Vec<(PeerEndpoint, u16)>,
}

/// What a TCP disconnect did to the queue (ADR-0057 disconnected standing): a
/// *granted* peer frees its slot (and may promote a waiter); a *waiting* peer
/// keeps its position and is simply marked disconnected — its standing now
/// rides the reask heartbeat, not a socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Disconnect {
    /// The peer held a granted slot that this disconnect freed (⇒ the serve
    /// side emits `UploadSlotReleased`). `false` for a waiting or unknown peer.
    pub slot_released: bool,
    pub promotion: Promotion,
}

/// Where an inbound `OP_REASKFILEPING`'s UDP source resolves against the wait
/// list — aMule `CUploadQueue::GetWaitingClientByIP_UDP` (ADR-0057).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaskResolution {
    /// A waiter matched by exact IP + UDP port, the unique-IP fallback (aMule
    /// ignores the port when exactly one waiter shares the IP), or a peer
    /// holding a pending dial-back grant (a promoted disconnected top-waiter,
    /// still queued at the head until the dial-back connects).
    Known {
        /// The waiter, as the queue knows it — its TCP endpoint, not the UDP
        /// source that resolved it.
        peer: PeerEndpoint,
        /// The file the waiter is queued for — the uploader silent-drops a
        /// reask whose hash names a different file (hash mismatch).
        file_hash: FileHash,
        /// Its current 1-based queue position, which the ack carries back.
        rank: u16,
        /// Its advertised peer-UDP version, which decides whether the ack may
        /// carry our part status.
        udp_version: u8,
    },
    /// Multiple waiters share the pinger's IP on different UDP ports — the
    /// port-mapping ambiguity that forces a TCP full ask (silent drop).
    AmbiguousIp,
    /// No waiter from the pinger's IP — an unknown pinger.
    Unknown,
}

/// Why a waiter left the upload wait list without a slot
/// (`ServeEvent::WaiterLeft`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiterLeaveCause {
    /// The purge sweep reaped it (ADR-0057): its reask heartbeat went silent
    /// past `MAX_PURGEQUEUETIME`, or its file is no longer shared.
    Purged,
    /// It sent `OP_CANCELTRANSFER` while waiting (ADR-0056): a canceller keeps
    /// no queue standing.
    Cancelled,
    /// Another client asked under its User Hash and it was not identified
    /// (ADR-0107; aMule `UploadQueue.cpp:432-447`).
    UserHashClash,
    /// Its address is banned (`UploadQueue.cpp:98`).
    Banned,
}

/// What a purge sweep removed, reclaimed, and promoted (ADR-0057).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Purge {
    /// Peers dropped: waiters whose reask heartbeat went silent past
    /// `MAX_PURGEQUEUETIME` or whose file is no longer shared, plus any
    /// `reclaimed` dial-back grant. The serve side clears their per-peer state.
    pub removed: Vec<PeerEndpoint>,
    /// A pending dial-back grant whose client never linked within
    /// `MAX_PURGEQUEUETIME`, so its slot was reclaimed (⇒ the serve side emits
    /// `UploadDialBackFailed`). Also present in `removed`.
    pub reclaimed: Option<PeerEndpoint>,
    /// The waiter promoted into a slot freed by the reclaim, plus rank shifts.
    pub promotion: Promotion,
}

#[derive(Clone, Copy, Debug)]
struct Queued {
    peer: PeerEndpoint,
    file_hash: FileHash,
    enqueued_at: Instant,
    last_reported_rank: u16,
    /// The waiter's advertised client UDP port, for matching its inbound
    /// `OP_REASKFILEPING` by IP + port (ADR-0057). `None` when it advertised
    /// none — it can only reask over TCP and is never UDP-reask-matched.
    udp_port: Option<u16>,
    /// The waiter's advertised UDP version — gates our part status in the
    /// `OP_REASKACK` reply (included only for a UDPv4, i.e. `> 3`, waiter).
    udp_version: u8,
    /// When the waiter last reasked (TCP admit or UDP `0x90`): the purge
    /// clock. A waiter is dropped once this is silent past
    /// `MAX_PURGEQUEUETIME`.
    last_reask: Instant,
    /// Whether a live TCP serve connection to this waiter exists. Cleared on
    /// disconnect (the entry survives — disconnected standing); a promotion of
    /// a disconnected waiter dials back rather than granting over a dead socket.
    connected: bool,
    /// Whether a dial reaches the waiter once it hangs up: its hello names a
    /// High ID or an IPv6 (ADR-0057). Until its contact is stamped a waiter
    /// counts as dialable; the serve side stamps every waiter from its hello
    /// as it queues.
    dialable: bool,
    /// The **Next-Connection Mark**: it hung up under a Low ID and ranked
    /// above the best waiter the queue could reach at the last sort, so its
    /// slot ask on the link it comes back on is granted (aMule
    /// `m_bAddNextConnect`, `UploadQueue.cpp:126-149`, `:410-425`).
    next_connection: bool,
}

/// How a waiter is reached, read off its hello (ADR-0057).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaiterContact {
    /// Its advertised client UDP port, matching its `OP_REASKFILEPING` by IP
    /// and port; `None` when it advertised none — it can only reask over TCP.
    pub udp_port: Option<u16>,
    /// Its advertised UDP version, which gates our part status in the
    /// `OP_REASKACK` reply.
    pub udp_version: u8,
    /// Whether a dial reaches it once it hangs up — a High ID at its link's
    /// address, or an IPv6. A Low ID is reached only on its next connection.
    pub dialable: bool,
}

/// What [`UploadSlotQueue::relink`] moved onto the new link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relinked {
    /// A wait-list place, its wait and its file.
    Waiter,
    /// A pending dial-back grant, live on the new link from now on: the
    /// serve side grants it there at once (ADR-0057).
    HeldGrant {
        /// The file the slot serves.
        file_hash: FileHash,
    },
    /// A live slot, riding on over the new link: aMule's client keeps its
    /// upload when a newer socket replaces its own (`ClientList.cpp:400-403`).
    Slot {
        /// The file the slot serves.
        file_hash: FileHash,
    },
}

/// Global, cross-connection upload queue: a slot budget, a wait-list cap, and
/// credit/reputation ranking. A waiting peer's score is
/// `wait_seconds * modifier`, where `modifier` comes from the caller's credit
/// store and is supplied per call — the queue stays sans-I/O and storage-free
/// (ADR-0031), the serve-side sibling of `DownloadScheduler` (ADR-0026).
///
/// Waiting entries survive a TCP disconnect (ADR-0057 disconnected standing):
/// an entry dies only when its reask heartbeat stops (purge at
/// `MAX_PURGEQUEUETIME`) or its file stops being shared — [`on_disconnect`]
/// keeps a waiting peer, [`resolve_reask`]/[`refresh_reask`] answer and refresh
/// its heartbeat, and [`purge`] reaps the silent.
///
/// [`on_disconnect`]: Self::on_disconnect
/// [`resolve_reask`]: Self::resolve_reask
/// [`refresh_reask`]: Self::refresh_reask
/// [`purge`]: Self::purge
pub struct UploadSlotQueue {
    budget: usize,
    max_queue_len: u16,
    granted: Vec<GrantedSlot>,
    waiting: Vec<Queued>,
    /// Whether a waiter with the **Next-Connection Mark** may take one slot
    /// over the budget: the last slot went to a waiter the queue could reach.
    /// aMule's `lastupslotHighID` (`UploadQueue.cpp:70`, `:147`, `:417-424`).
    extra_slot_open: bool,
    /// When an **Upload Session** last ended at its bound: one a second.
    last_session_end: Option<Instant>,
}

/// One occupied upload slot.
#[derive(Clone, Copy, Debug)]
struct GrantedSlot {
    peer: PeerEndpoint,
    file_hash: FileHash,
    /// `Some(t)` while this is a **pending dial-back** grant: the promoted
    /// waiter was disconnected, so the slot was granted for an outbound serve
    /// dial (ADR-0057) that has not yet reached it. Cleared to `None` the
    /// moment a link of the client is up — the dialed one or one it came back
    /// on ([`UploadSlotQueue::relink`]), or its own ask
    /// ([`UploadSlotQueue::admit`]) — turning it into an ordinary live grant.
    /// One whose client never links within `MAX_PURGEQUEUETIME` is reclaimed
    /// by [`UploadSlotQueue::purge`], so no grant holds the slot forever.
    dial_back_since: Option<Instant>,
    /// The peer's advertised UDP version, carried over from its wait-list entry
    /// at promotion. A promoted dial-back grantee keeps reasking over UDP, and
    /// its `OP_REASKACK` must include our part status when it advertised `> 3`
    /// — the `0x91` field presence is keyed on this version on **both** ends,
    /// so a rank-only reply to a v4 waiter is unparseable there (it reads the
    /// rank as a part count and drops the datagram).
    udp_version: u8,
    /// When the slot was granted, the start of its **Upload Session**.
    session_start: Instant,
    /// Bytes of the **Upload Session** that have left for the socket.
    session_sent: u64,
}

impl UploadSlotQueue {
    /// Create a queue granting up to `budget` concurrent slots (clamped to a
    /// minimum of 1) and holding at most `max_queue_len` waiting peers.
    #[must_use]
    pub fn new(budget: usize, max_queue_len: u16) -> Self {
        Self {
            budget: budget.max(1),
            max_queue_len,
            granted: Vec::new(),
            waiting: Vec::new(),
            extra_slot_open: true,
            last_session_end: None,
        }
    }

    /// The configured wait-list cap — the `thePrefs::GetQueueSize()` the
    /// uploader's `waiting + 50 > queue-size` `OP_QUEUEFULL` test reads
    /// (ADR-0057).
    #[must_use]
    pub fn max_queue_len(&self) -> u16 {
        self.max_queue_len
    }

    /// The current number of waiting peers — `GetWaitingUserCount`.
    #[must_use]
    pub fn waiting_len(&self) -> usize {
        self.waiting.len()
    }

    /// Whether `peer` currently holds a slot or a wait-list position.
    #[must_use]
    pub fn contains(&self, peer: PeerEndpoint) -> bool {
        self.granted.iter().any(|g| g.peer == peer) || self.waiting.iter().any(|q| q.peer == peer)
    }

    /// Whether `peer` currently holds a **granted** slot — the narrower
    /// sibling of [`contains`](Self::contains), which also counts a
    /// wait-list position. A cancel (ADR-0056) checks this before crediting
    /// itself with a release: only a granted holder's cancel actually frees
    /// a slot.
    #[must_use]
    pub fn is_granted(&self, peer: PeerEndpoint) -> bool {
        self.granted.iter().any(|g| g.peer == peer)
    }

    /// The file of `peer`'s live slot: granted, its dial-back grant delivered.
    #[must_use]
    pub fn live_slot_file(&self, peer: PeerEndpoint) -> Option<FileHash> {
        self.granted
            .iter()
            .find(|g| g.peer == peer && g.dial_back_since.is_none())
            .map(|g| g.file_hash)
    }

    /// The peers engaged in an upload relationship for `file_hash` — a granted
    /// slot or a wait-list position — i.e. aMule's `m_ClientUploadList`
    /// filtered to the file. This is the candidate pool a complete shared
    /// file's source-exchange answer draws from (ADR-0055 §Serving): every such
    /// peer is a client we are (or will be) uploading `file_hash` to, so it is
    /// a live source for it.
    #[must_use]
    pub fn engaged_peers(&self, file_hash: FileHash) -> Vec<PeerEndpoint> {
        self.granted
            .iter()
            .filter(|g| g.file_hash == file_hash)
            .map(|g| g.peer)
            .chain(
                self.waiting
                    .iter()
                    .filter(|q| q.file_hash == file_hash)
                    .map(|q| q.peer),
            )
            .collect()
    }

    /// How many waiting entries share `key` — the per-address cap's count
    /// (ADR-0088). Granted slots are excluded: the reference counts the wait
    /// list alone (aMule `IsOnUploadQueue`, `src/UploadQueue.cpp:341`).
    #[must_use]
    pub fn waiting_from(&self, key: AccountingKey) -> usize {
        self.waiting
            .iter()
            .filter(|q| AccountingKey::of(q.peer.ip()) == key)
            .count()
    }

    /// Admit `peer` for `file_hash` at `now`. Grants immediately when a slot is
    /// free; otherwise the peer joins the wait list, stamped with `now`. A
    /// newcomer has ~zero elapsed wait, so its score is the lowest and it always
    /// joins at the tail — no existing waiter's rank changes. A repeat request
    /// from an existing waiter refreshes its reask clock and marks it connected
    /// again (a reconnect) while keeping its position.
    ///
    /// A newcomer is turned away with [`Admission::RefusedAddressCap`] once
    /// [`MAX_WAITING_PER_ADDRESS`] peers from its accounting key already wait.
    /// The cap is tested **after** the two idempotent paths, exactly where the
    /// reference tests it: a peer that already holds a slot or a place keeps it,
    /// so a reask can never be counted as a fourth arrival and never loses the
    /// place it is reasking for (ADR-0057).
    #[must_use]
    pub fn admit(&mut self, peer: PeerEndpoint, file_hash: FileHash, now: Instant) -> Admission {
        // A repeat request keeps the peer's standing and moves it to the file
        // it names: aMule's client has one upload file, which the slot ask
        // sets (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:606-618`), and a
        // client already queued keeps its place (`UploadQueue.cpp:401-431`).
        if let Some(slot) = self.granted.iter_mut().find(|g| g.peer == peer) {
            // A re-ask means the peer is present, so a slot that was granted as a
            // pending dial-back is now a live grant — clear the reclaim marker.
            slot.dial_back_since = None;
            slot.file_hash = file_hash;
            return Admission::Granted;
        }
        if let Some(index) = self.waiting.iter().position(|q| q.peer == peer) {
            // A marked waiter's ask on the link it came back on takes its
            // slot, one over the budget when the last slot went to a waiter
            // the queue could reach (`UploadQueue.cpp:410-425`). A slot left
            // free because nobody could be reached was filled already when
            // the asker's link came up (`fill_free_slot`).
            let marked = self.waiting[index].next_connection;
            let room = self.budget + usize::from(marked && self.extra_slot_open);
            if self.granted.len() < room {
                let entry = self.waiting.remove(index);
                self.granted.push(GrantedSlot {
                    peer,
                    file_hash,
                    dial_back_since: None,
                    udp_version: entry.udp_version,
                    session_start: now,
                    session_sent: 0,
                });
                self.extra_slot_open = !marked;
                return Admission::Granted;
            }
            // Refreshing its heartbeat (a reconnect re-asks over TCP).
            self.waiting[index].connected = true;
            self.waiting[index].last_reask = now;
            self.waiting[index].file_hash = file_hash;
            return Admission::Queued {
                rank: rank_at(index),
            };
        }
        if self.waiting_from(AccountingKey::of(peer.ip())) >= MAX_WAITING_PER_ADDRESS {
            // Ahead of the free-slot grant, as in both references: a key that
            // already fills its share of the wait list buys no place by the
            // budget happening to be open.
            return Admission::RefusedAddressCap;
        }
        if self.granted.len() < self.budget {
            // A peer asking in person is connected — an ordinary live grant.
            // Its UDP version is unknown here (and never consulted: only a
            // pending dial-back grant resolves reasks).
            self.granted.push(GrantedSlot {
                peer,
                file_hash,
                dial_back_since: None,
                udp_version: 0,
                session_start: now,
                session_sent: 0,
            });
            return Admission::Granted;
        }
        if self.waiting.len() >= usize::from(self.max_queue_len) {
            return Admission::Refused;
        }
        let rank = rank_at(self.waiting.len());
        self.waiting.push(Queued {
            peer,
            file_hash,
            enqueued_at: now,
            last_reported_rank: rank,
            udp_port: None,
            udp_version: 0,
            last_reask: now,
            connected: true,
            dialable: true,
            next_connection: false,
        });
        Admission::Queued { rank }
    }

    /// Move a waiting `peer` to `file_hash`, the file it last asked about by
    /// name or status: aMule's client has one upload file, which every such
    /// ask sets (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:462`, `:521`,
    /// `:1103`), and its UDP reask must name that file (`ClientUDPSocket.cpp:197`).
    /// A slot holder keeps its slot's file until it asks a slot for another
    /// (ADR-0031: a slot serves one file). A no-op for a peer not waiting.
    ///
    /// Returns the waiter's rank when its file moved, so the move can be
    /// reported; `None` for a peer not waiting or already on that file.
    pub fn follow_asked_file(&mut self, peer: PeerEndpoint, file_hash: FileHash) -> Option<u16> {
        let index = self.waiting.iter().position(|q| q.peer == peer)?;
        let entry = &mut self.waiting[index];
        if entry.file_hash == file_hash {
            return None;
        }
        entry.file_hash = file_hash;
        Some(rank_at(index))
    }

    /// The rank a client holding `peer`'s standing is answered with on
    /// another of its links (ADR-0107): its place, or 1 while it holds a slot,
    /// with nobody ahead of it.
    #[must_use]
    pub fn standing_rank(&self, peer: PeerEndpoint) -> Option<u16> {
        if self.granted.iter().any(|g| g.peer == peer) {
            return Some(1);
        }
        let index = self.waiting.iter().position(|q| q.peer == peer)?;
        Some(rank_at(index))
    }

    /// The file `peer` waits for, when it is on the wait list.
    #[must_use]
    pub fn waiting_file(&self, peer: PeerEndpoint) -> Option<FileHash> {
        self.waiting
            .iter()
            .find(|q| q.peer == peer)
            .map(|q| q.file_hash)
    }

    /// The waiters in rank order, each with whether the link it waits on is
    /// up — `false` once it hung up and its standing rides its reask
    /// (ADR-0057).
    pub fn waiters(&self) -> impl Iterator<Item = (PeerEndpoint, bool)> + '_ {
        self.waiting.iter().map(|q| (q.peer, q.connected))
    }

    /// Every standing the queue holds — a slot, a pending dial-back grant
    /// (ADR-0057), a wait-list place — each with whether a live link holds
    /// it: the slots first, then the waiters in rank order.
    pub fn standings(&self) -> impl Iterator<Item = (PeerEndpoint, bool)> + '_ {
        self.granted
            .iter()
            .map(|g| (g.peer, g.dial_back_since.is_none()))
            .chain(self.waiters())
    }

    /// Whether `peer` holds a standing with no link under it: a waiter that
    /// hung up, or a pending dial-back grant.
    #[must_use]
    pub fn is_unlinked(&self, peer: PeerEndpoint) -> bool {
        self.waiting.iter().any(|q| q.peer == peer && !q.connected)
            || self
                .granted
                .iter()
                .any(|g| g.peer == peer && g.dial_back_since.is_some())
    }

    /// Move the standing of `from` to the link `to` the same client is on: a
    /// wait-list entry keeps its place, its wait, its file and its mark and
    /// is marked linked, as aMule's queue holds the client, not its socket
    /// (`UploadQueue.cpp:395-431`); a pending dial-back grant moves with it
    /// and is live from now on, as aMule grants a client it promoted
    /// unconnected on whichever link its hellos finish first
    /// (`BaseClient.cpp:1707-1716`); a live slot rides on over `to`. Returns
    /// what moved — never onto a `to` that already holds a slot or a place.
    pub fn relink(&mut self, from: PeerEndpoint, to: PeerEndpoint) -> Option<Relinked> {
        if from == to || self.contains(to) {
            return None;
        }
        if let Some(entry) = self.waiting.iter_mut().find(|q| q.peer == from) {
            entry.peer = to;
            entry.connected = true;
            return Some(Relinked::Waiter);
        }
        let slot = self.granted.iter_mut().find(|g| g.peer == from)?;
        slot.peer = to;
        let file_hash = slot.file_hash;
        Some(match slot.dial_back_since.take() {
            Some(_) => Relinked::HeldGrant { file_hash },
            None => Relinked::Slot { file_hash },
        })
    }

    /// Fill a slot left free because no waiter could be reached, now that a
    /// waiter's link came up: the best waiter the queue can reach takes it,
    /// as aMule's `Process` fills a free slot within its next second
    /// (`UploadQueue.cpp:255-258`). A slot frees promoting any waiter a dial
    /// reaches, so only a link coming up — a relink onto a live one — makes
    /// a waiter reachable, and the one it promotes is the one linked: no
    /// dial (ADR-0057). Then reports the wait list's changed ranks.
    #[must_use]
    pub fn fill_free_slot(&mut self, now: Instant, modifiers: &dyn ScoreModifiers) -> Promotion {
        if self.granted.len() >= self.budget || self.waiting.is_empty() {
            return Promotion::default();
        }
        let mut promotion = match self.sort_and_mark(now, modifiers) {
            Some(index) => self.promote(index, now),
            None => Promotion::default(),
        };
        promotion.reranked = self.collect_rank_changes();
        promotion
    }

    /// The file of the pending dial-back grant `peer` holds, if it holds one.
    #[must_use]
    pub fn pending_grant(&self, peer: PeerEndpoint) -> Option<FileHash> {
        self.granted
            .iter()
            .find(|g| g.peer == peer && g.dial_back_since.is_some())
            .map(|g| g.file_hash)
    }

    /// Whether `peer` waits with the **Next-Connection Mark**, so its slot
    /// ask is granted (see [`admit`](Self::admit)).
    #[must_use]
    pub fn marked_for_next_connection(&self, peer: PeerEndpoint) -> bool {
        self.waiting
            .iter()
            .any(|q| q.peer == peer && q.next_connection)
    }

    /// Record how `peer` is reached on its wait-list entry (from the hello):
    /// its UDP contact, so an inbound `OP_REASKFILEPING` from that IP + port
    /// matches it, and whether a dial reaches it once it hangs up (ADR-0057).
    /// A no-op when the peer holds a slot or is not queued.
    pub fn set_contact(&mut self, peer: PeerEndpoint, contact: WaiterContact) {
        if let Some(entry) = self.waiting.iter_mut().find(|q| q.peer == peer) {
            entry.udp_port = contact.udp_port;
            entry.udp_version = contact.udp_version;
            entry.dialable = contact.dialable;
        }
    }

    /// Remove `peer` (granted or queued). If a granted slot frees, promote the
    /// **highest-score** waiter the queue can reach at `now` (see
    /// `sort_and_mark`); then report the remaining wait list's changed ranks.
    /// A promoted waiter with no live connection flags the promotion as a
    /// dial-back (ADR-0057).
    #[must_use]
    pub fn release(
        &mut self,
        peer: PeerEndpoint,
        now: Instant,
        modifiers: &dyn ScoreModifiers,
    ) -> Promotion {
        let was_granted = self.granted.iter().any(|g| g.peer == peer);
        self.granted.retain(|g| g.peer != peer);
        self.waiting.retain(|q| q.peer != peer);

        let best = self.sort_and_mark(now, modifiers);
        let mut promotion = Promotion::default();
        if was_granted
            && self.granted.len() < self.budget
            && let Some(index) = best
        {
            promotion = self.promote(index, now);
        }
        promotion.reranked = self.collect_rank_changes();
        promotion
    }

    /// Fold a TCP disconnect into the queue (ADR-0057 disconnected standing). A
    /// *waiting* peer keeps its position and is marked disconnected — its
    /// standing now rides the reask heartbeat. A *granted* peer frees its slot
    /// exactly as [`release`](Self::release), possibly promoting (and
    /// dial-backing) a waiter.
    #[must_use]
    pub fn on_disconnect(
        &mut self,
        peer: PeerEndpoint,
        now: Instant,
        modifiers: &dyn ScoreModifiers,
    ) -> Disconnect {
        if let Some(entry) = self.waiting.iter_mut().find(|q| q.peer == peer) {
            entry.connected = false;
            return Disconnect::default();
        }
        let was_granted = self.granted.iter().any(|g| g.peer == peer);
        let promotion = self.release(peer, now, modifiers);
        Disconnect {
            slot_released: was_granted,
            promotion,
        }
    }

    /// Drop waiters whose reask heartbeat is silent past `purge_after`
    /// (aMule `MAX_PURGEQUEUETIME`, 1 h) or whose file `is_shared` no longer
    /// reports, then re-rank the survivors (ADR-0057). Deterministic in `now`.
    #[must_use]
    pub fn purge(
        &mut self,
        now: Instant,
        purge_after: Duration,
        is_shared: impl Fn(FileHash) -> bool,
        modifiers: &dyn ScoreModifiers,
    ) -> Purge {
        let mut removed = Vec::new();
        self.waiting.retain(|q| {
            let silent = now.saturating_duration_since(q.last_reask) > purge_after;
            let unshared = !is_shared(q.file_hash);
            if silent || unshared {
                removed.push(q.peer);
                false
            } else {
                true
            }
        });

        // Reclaim a pending dial-back grant whose client never linked within
        // the window — the counterpart to reaping a silent waiter. Without it the slot leaks: no `Disconnected` ever
        // arrives for a peer that never held a socket, and the wait-list purge
        // above never touches `granted`. One per sweep keeps the return a single
        // `Promotion`; a periodic sweep drains any backlog and never leaks.
        let mut reclaimed = None;
        let mut promotion = Promotion::default();
        let best = self.sort_and_mark(now, modifiers);
        if let Some(index) = self.granted.iter().position(|g| {
            g.dial_back_since
                .is_some_and(|since| now.saturating_duration_since(since) > purge_after)
        }) {
            let stale = self.granted.remove(index);
            removed.push(stale.peer);
            reclaimed = Some(stale.peer);
            // Fill the freed slot from the wait list, exactly as `release` does,
            // preserving "every slot that frees promotes the next waiter".
            if self.granted.len() < self.budget
                && let Some(head) = best
            {
                promotion = self.promote(head, now);
            }
        }

        promotion.reranked = self.collect_rank_changes();
        Purge {
            removed,
            reclaimed,
            promotion,
        }
    }

    /// The slot holders with a link: every grant but a dial-back still out.
    pub fn linked_holders(&self) -> impl Iterator<Item = PeerEndpoint> + '_ {
        self.granted
            .iter()
            .filter(|grant| grant.dial_back_since.is_none())
            .map(|grant| grant.peer)
    }

    /// Re-rank the wait list by current score at `now` and report the entries
    /// whose 1-based rank changed. The periodic re-rank tick calls this so a
    /// waiter's reported position tracks both elapsed wait and any credit it
    /// gained while queued.
    #[must_use]
    pub fn rerank(
        &mut self,
        now: Instant,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<(PeerEndpoint, u16)> {
        let _ = self.sort_and_mark(now, modifiers);
        self.collect_rank_changes()
    }

    /// Move the waiter at `index` into a granted slot, flagging a **dial-back**
    /// when it has no live connection (ADR-0057) and stamping the reclaim marker
    /// so one whose client never links can be reaped by [`purge`](Self::purge).
    /// The slot went to a waiter the queue could reach, so a marked Low ID may
    /// take one over the budget again. Shared by [`release`](Self::release),
    /// the purge reclaim and [`fill_free_slot`](Self::fill_free_slot). Does
    /// not re-rank — the caller collects any rank shifts.
    fn promote(&mut self, index: usize, now: Instant) -> Promotion {
        let head = self.waiting.remove(index);
        let dial_back = !head.connected;
        self.extra_slot_open = true;
        self.granted.push(GrantedSlot {
            peer: head.peer,
            file_hash: head.file_hash,
            dial_back_since: dial_back.then_some(now),
            udp_version: head.udp_version,
            session_start: now,
            session_sent: 0,
        });
        Promotion {
            granted: Some((head.peer, head.file_hash)),
            dial_back,
            reranked: Vec::new(),
        }
    }

    /// Sort the wait list by descending score at `now` (ties: oldest first),
    /// then mark for its next connection every waiter ranked ahead of the
    /// first one the queue can reach — linked, or dialable — that only its
    /// next connection reaches: hung up under a Low ID. Every waiter after
    /// that first reachable one loses the mark. aMule's `SortGetBestClient`
    /// (`UploadQueue.cpp:126-149`). Returns the first reachable waiter's
    /// index, the one a free slot promotes.
    fn sort_and_mark(&mut self, now: Instant, modifiers: &dyn ScoreModifiers) -> Option<usize> {
        // One reading per waiter: a modifier takes the credit and held-place
        // locks, so it is read once a sort, not once a comparison.
        self.waiting.sort_by_cached_key(|entry| {
            (
                Reverse(Score(score(entry, now, modifiers))),
                entry.enqueued_at,
            )
        });
        let mut best = None;
        for (index, entry) in self.waiting.iter_mut().enumerate() {
            let reachable = entry.connected || entry.dialable;
            entry.next_connection = best.is_none() && !reachable;
            if best.is_none() && reachable {
                best = Some(index);
            }
        }
        best
    }

    /// Reassign 1-based ranks in wait-list order and collect the entries
    /// whose rank changed since it was last reported.
    fn collect_rank_changes(&mut self) -> Vec<(PeerEndpoint, u16)> {
        let mut changed = Vec::new();
        for (index, entry) in self.waiting.iter_mut().enumerate() {
            let new_rank = rank_at(index);
            if entry.last_reported_rank != new_rank {
                entry.last_reported_rank = new_rank;
                changed.push((entry.peer, new_rank));
            }
        }
        changed
    }
}

/// The 1-based rank of place `index`. The wait list holds at most a `u16` of
/// peers, so every place has its rank.
fn rank_at(index: usize) -> u16 {
    u16::try_from(index + 1).unwrap_or(u16::MAX)
}

/// `wait_seconds * modifier` for one waiting entry.
fn score(entry: &Queued, now: Instant, modifiers: &dyn ScoreModifiers) -> f64 {
    let wait = now
        .saturating_duration_since(entry.enqueued_at)
        .as_secs_f64();
    wait * modifiers.modifier(entry.peer)
}

/// A score, ordered as a number. A wait and a modifier are finite.
#[derive(Clone, Copy, PartialEq)]
struct Score(f64);

impl Eq for Score {}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

/// What a waiter's score is multiplied by. Read only when a queue ranks, which
/// almost no serve input does.
pub trait ScoreModifiers {
    /// `peer`'s modifier; the neutral `1.0` for one it does not know.
    fn modifier(&self, peer: PeerEndpoint) -> f64;
}

impl ScoreModifiers for HashMap<PeerEndpoint, f64> {
    fn modifier(&self, peer: PeerEndpoint) -> f64 {
        self.get(&peer).copied().unwrap_or(1.0)
    }
}

#[cfg(test)]
mod modifier_readings {
    use std::cell::Cell;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    #[derive(Default)]
    struct Counted(Cell<usize>);

    impl ScoreModifiers for Counted {
        fn modifier(&self, _peer: PeerEndpoint) -> f64 {
            self.0.set(self.0.get() + 1);
            1.0
        }
    }

    /// A reading takes node-wide locks: a sort reads each waiter once, not
    /// once per comparison.
    #[test]
    fn a_sort_reads_each_waiter_once() {
        let mut queue = UploadSlotQueue::new(0, 100);
        let now = Instant::now();
        for port in 1..=50 {
            let peer = PeerEndpoint::V4(Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(45, 55, 0, port),
                4662,
            ));
            let _ = queue.admit(peer, FileHash::from_bytes([1; 16]), now);
        }
        let readings = Counted::default();

        let _ = queue.rerank(now, &readings);

        assert_eq!(readings.0.get(), queue.waiting_len());
    }
}

#[cfg(test)]
mod low_id_abuse_tests {
    use super::*;

    /// The guard refusing, and each of its five conditions on its own being
    /// enough to admit — which is what makes it a guard against *abuse* rather
    /// than a second queue cap.
    #[test]
    fn every_condition_must_hold_for_the_guard_to_refuse() {
        let refusing = LowIdAbuseFacts {
            we_are_low_id: true,
            our_source: false,
            is_friend: false,
            on_our_server: false,
            waiting: LOW_ID_ABUSE_WAIT_LIST_THRESHOLD + 1,
        };
        assert!(refuses_as_low_id_abuse(&refusing));

        for (why, relaxed) in [
            (
                "a High-ID node can be dialed directly, so it guards nothing",
                LowIdAbuseFacts {
                    we_are_low_id: false,
                    ..refusing
                },
            ),
            (
                "a source of ours is in a relationship, not a stranger",
                LowIdAbuseFacts {
                    our_source: true,
                    ..refusing
                },
            ),
            (
                "a friend is admitted by name (rmule keeps no friend list yet)",
                LowIdAbuseFacts {
                    is_friend: true,
                    ..refusing
                },
            ),
            (
                "a peer on our server can reach us through it",
                LowIdAbuseFacts {
                    on_our_server: true,
                    ..refusing
                },
            ),
            (
                "at exactly the threshold the wait list is not yet over it",
                LowIdAbuseFacts {
                    waiting: LOW_ID_ABUSE_WAIT_LIST_THRESHOLD,
                    ..refusing
                },
            ),
        ] {
            assert!(!refuses_as_low_id_abuse(&relaxed), "{why}");
        }
    }
}
