//! The **Remote-Queued Pool** and its source-reask scheduler (ADR-0057).
//!
//! When a download worker earns a queue position at a remote uploader and then
//! hangs up, the source is not retired: it moves here, holding its standing
//! *without a socket* (CONTEXT: Remote-Queued Pool). Per pooled source, on the
//! aMule reask clock, the pool keeps that standing alive with a heartbeat —
//! **UDP ping first**, **TCP full ask as the fallback**:
//!
//! - At [`FILE_REASK_TIME`] − [`UDP_REASK_LEAD`] since the last reask, when the
//!   gates pass, emit `OP_REASKFILEPING` (`0x90`) to the source's client-UDP
//!   endpoint and set the one-in-flight latch (aMule
//!   `CUpDownClient::UDPReaskForDownload`, `DownloadClient.cpp`).
//! - At [`FILE_REASK_TIME`], emit the **TCP full ask** — dial the source and
//!   re-run the ask cycle — refreshing the clock and resetting the latch (aMule
//!   `PartFile.cpp`). A lost UDP datagram therefore costs the 20 s grace, never
//!   the standing.
//! - A reply refreshes the clock and clears the latch: `0x91` records the rank
//!   and clears the queue-full flag; `0x93` sets the queue-full flag (rank 0),
//!   keeping the source deprioritized; `0x92` drops the source dead.
//! - A **no-needed-parts** source reasks at ×[`NO_NEEDED_PARTS_MULTIPLIER`] the
//!   period and forces a TCP recheck (no UDP), aMule `PartFile.cpp`.
//!
//! This is the sans-I/O sibling of the uploader's [`UploadSlotQueue`]: every
//! time-dependent method takes an explicit [`Instant`], so the whole cadence —
//! UDP-first timing, the 20 s grace, the latch, the reply effects — is asserted
//! as plain values with no clock or socket. The gates fold in the advert
//! truths: with no bound client-UDP socket our UDP advert stays off and peer
//! UDP contacts thread as `0/0`, so every reask falls to the TCP full ask; the
//! UDP path is exercised here with injected contacts either way.
//!
//! [`UploadSlotQueue`]: crate::upload_queue::UploadSlotQueue

use std::time::{Duration, Instant};

use rmule_peer::{ClientUdpOpcode, ReaskAck};
use rmule_primitives::{Capabilities, CryptStance, PeerEndpoint};

use crate::adapters::advertises_complete;
use crate::service::IgnoredReaskReply;

/// aMule `FILEREASKTIME` (`Constants.h`): 1,300,000 ms — the source-reask
/// period, ≈ 21.7 minutes. A pooled source's standing is refreshed once per
/// period by the UDP ping (or the TCP full ask when a datagram cannot fly).
pub(crate) const FILE_REASK_TIME: Duration = Duration::from_millis(1_300_000);

/// The UDP ping leads the TCP full ask by 20 s (aMule `DownloadClient.cpp`: the
/// UDP reask fires at `FILEREASKTIME − 20 s`, the TCP full ask at
/// `FILEREASKTIME`). This is the grace a lost reply burns before the fallback.
pub(crate) const UDP_REASK_LEAD: Duration = Duration::from_secs(20);

/// A no-needed-parts source reasks at ×2 the period, then forces a TCP recheck
/// (aMule `PartFile.cpp`): it holds no parts we want, so it is polled half as
/// often and always over TCP (a full status recheck), never a UDP ping.
pub(crate) const NO_NEEDED_PARTS_MULTIPLIER: u32 = 2;

/// A pooled source's advertised client-UDP contact — the destination for our
/// `OP_REASKFILEPING` and the match key for its replies. Absent when the peer
/// hello threads no real UDP port (`0/0`), which keeps such a source TCP-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UdpContact {
    /// The source's client-UDP endpoint: its address and advertised client-UDP
    /// port, in the source's own **Address Family**. The reask quartet packs
    /// no address in any of its bodies, so an IPv6 source reasks over IPv6 on
    /// byte-identical wire (ADR-0087) — the endpoint is both the `0x90`
    /// destination and the reply-match key, and matching it whole is what
    /// keeps two sources in one `/64` distinct.
    pub(crate) endpoint: PeerEndpoint,
    /// The source's UDP version — gates the `0x90` body extras (aMule
    /// `DownloadClient.cpp`: version `> 3` → our part-status bitfield, `> 2` →
    /// our complete-source count). The runner reads it to build the ping body.
    pub(crate) version: u8,
}

/// One reask the scheduler emits for a pooled source at a [`RemoteQueuedPool::tick`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReaskAction {
    /// Send `OP_REASKFILEPING` (`0x90`) to `udp_endpoint`. The runner encodes
    /// the version-gated body (using `udp_version`) with the download's file
    /// hash and rides it out the client-UDP send. The pool has already set the
    /// one-in-flight latch, so no re-ping fires until the reply lands or the
    /// TCP full ask resets it.
    UdpPing {
        peer: PeerEndpoint,
        udp_endpoint: PeerEndpoint,
        udp_version: u8,
    },
    /// Fire the **TCP full ask**: dial the source's TCP endpoint and re-run the
    /// ask cycle. The UDP fallback (silence past the 20 s grace) and the direct
    /// path for a UDP-incapable, firewalled, source-exchange-due, or
    /// no-needed-parts source all converge here. The pool has refreshed the
    /// clock and reset the latch.
    TcpFullAsk { peer: PeerEndpoint },
}

/// What consuming one reask reply did to the pool (ADR-0057): the downloader
/// half of the `0x91`/`0x92`/`0x93` quartet. The runner maps each to a
/// `DownloadEvent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyOutcome {
    /// `0x91 OP_REASKACK`: the rank was recorded, the queue-full flag cleared,
    /// and the heartbeat refreshed — the source keeps its standing. `complete`
    /// is what a UDPv4 reply's part status says of the source (ADR-0108):
    /// `None` when the reply carried none.
    RankRecorded {
        peer: PeerEndpoint,
        rank: u16,
        complete: Option<bool>,
    },
    /// `0x93 OP_QUEUEFULL`: the queue-full flag was set (rank 0) and the
    /// heartbeat refreshed — the source is kept but deprioritized.
    QueueFull { peer: PeerEndpoint },
    /// `0x92 OP_FILENOTFOUND`: the source no longer shares the file — it was
    /// dropped from the pool.
    Dropped { peer: PeerEndpoint },
    /// The datagram changed nothing, for `reason`.
    Ignored { reason: IgnoredReaskReply },
}

/// One source holding a remote queue position without a socket.
#[derive(Clone, Copy, Debug)]
struct PooledSource {
    /// The source's TCP endpoint — its identity, and the TCP-full-ask dial target.
    peer: PeerEndpoint,
    /// Its client-UDP contact, or `None` when it advertised none (TCP-only).
    udp_contact: Option<UdpContact>,
    /// The last queue rank we learned (0 when unknown / queue-full).
    rank: u16,
    /// The `0x93` queue-full flag: kept, but deprioritized.
    queue_full: bool,
    /// aMule `DS_NONEEDEDPARTS`: the source holds no parts we want, so it reasks
    /// at ×[`NO_NEEDED_PARTS_MULTIPLIER`] the period, TCP-only.
    no_needed_parts: bool,
    /// The ADR-0055 source-exchange ask is due for this source, so a TCP full
    /// ask is preferred over a UDP ping (the TCP session carries source-exchange
    /// value a datagram cannot) — aMule's `IsSourceRequestAllowed` gate.
    sx_due: bool,
    /// The reask clock: the instant of the last reask (enter, reply, or TCP full
    /// ask). The UDP ping fires at `period − lead` past it, the TCP full ask at
    /// `period`.
    last_reask: Instant,
    /// The one-in-flight UDP latch (aMule `DownloadClient.cpp`): set when a UDP
    /// ping flies, cleared by a reply or the TCP full ask. Stops a second ping
    /// while one is pending.
    udp_pending: bool,
}

impl PooledSource {
    /// The reask period for this source: the base [`FILE_REASK_TIME`], doubled
    /// for a no-needed-parts source.
    fn period(&self) -> Duration {
        if self.no_needed_parts {
            FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER
        } else {
            FILE_REASK_TIME
        }
    }
}

/// The downloader-side **Remote-Queued Pool**: sources holding a remote queue
/// position without a socket, and the reask scheduler that keeps that standing
/// alive (ADR-0057). Sans-I/O — every clock read is an injected [`Instant`],
/// mirroring [`UploadSlotQueue`](crate::upload_queue::UploadSlotQueue). Sources
/// keep insertion order, so a [`tick`](Self::tick) sweep is deterministic.
pub(crate) struct RemoteQueuedPool {
    /// Whether our own client-UDP advert is live (ADR-0047). Off while no
    /// client-UDP socket is bound (the advert then stays 0), which suppresses
    /// the UDP ping path so every reask falls to the TCP full ask.
    our_udp_enabled: bool,
    /// The UDP version our hello advertised — what a source read when it
    /// decided whether to ride its part status in the `0x91` reply, so the
    /// reply decode gates on it (aMule writes its status only to a UDPv4
    /// waiter, stock 2.3.3 `ClientUDPSocket.cpp:213-219`).
    our_udp_version: u8,
    sources: Vec<PooledSource>,
}

impl RemoteQueuedPool {
    /// Build an empty pool. `our_udp_enabled` — a client-UDP socket is bound —
    /// gates every UDP ping, beside the reachability [`tick`](Self::tick) is
    /// handed at each sweep. It is also what lights the UDP-version nibble of
    /// every hello we send, so the version the pool decodes replies by is read
    /// from the same registry value the hello states, never passed in.
    pub(crate) fn new(our_udp_enabled: bool) -> Self {
        let our_udp_version = if our_udp_enabled {
            Capabilities::shipped(CryptStance::disabled()).peer_udp_version()
        } else {
            0
        };
        Self {
            our_udp_enabled,
            our_udp_version,
            sources: Vec::new(),
        }
    }

    /// Enter a source into the pool: a rank arrived and its worker hung up, so
    /// its standing now rides the reask heartbeat (CONTEXT: Remote-Queued Pool).
    /// Stamped with `now` as the reask clock; a repeat enter refreshes the clock
    /// and rank, clears the latch and queue-full flag, and keeps its UDP contact.
    pub(crate) fn enter(
        &mut self,
        peer: PeerEndpoint,
        udp_contact: Option<UdpContact>,
        rank: u16,
        now: Instant,
    ) {
        if let Some(existing) = self.sources.iter_mut().find(|s| s.peer == peer) {
            existing.udp_contact = udp_contact.or(existing.udp_contact);
            existing.rank = rank;
            existing.queue_full = false;
            existing.last_reask = now;
            existing.udp_pending = false;
            return;
        }
        self.sources.push(PooledSource {
            peer,
            udp_contact,
            rank,
            queue_full: false,
            no_needed_parts: false,
            sx_due: false,
            last_reask: now,
            udp_pending: false,
        });
    }

    /// Mark whether the ADR-0055 source-exchange ask is due for `peer`: when due,
    /// its next reask prefers the TCP full ask over a UDP ping (a no-op for an
    /// unpooled peer). The runner re-reads it from the **Source Ask Clock**
    /// before every sweep (ADR-0108).
    pub(crate) fn set_sx_due(&mut self, peer: PeerEndpoint, sx_due: bool) {
        if let Some(source) = self.sources.iter_mut().find(|s| s.peer == peer) {
            source.sx_due = sx_due;
        }
    }

    /// `peer`'s due `0x90` could not leave this sweep — another download's
    /// ping to the same endpoint is unanswered (ADR-0107). Release the latch
    /// without touching the clock, so the next sweep inside the window tries
    /// again and the TCP full ask still falls due on time.
    pub(crate) fn defer_udp_ping(&mut self, peer: PeerEndpoint) {
        if let Some(source) = self.sources.iter_mut().find(|s| s.peer == peer) {
            source.udp_pending = false;
        }
    }

    /// Mark whether `peer` holds no parts we need: when set, it reasks at ×2 the
    /// period, TCP-only (a no-op for an unpooled peer).
    pub(crate) fn set_no_needed_parts(&mut self, peer: PeerEndpoint, no_needed_parts: bool) {
        if let Some(source) = self.sources.iter_mut().find(|s| s.peer == peer) {
            source.no_needed_parts = no_needed_parts;
        }
    }

    /// Remove `peer` from the pool — it was granted a slot (the uploader dialed
    /// back) or the download finished. Returns whether it was pooled.
    pub(crate) fn remove(&mut self, peer: PeerEndpoint) -> bool {
        let before = self.sources.len();
        self.sources.retain(|s| s.peer != peer);
        self.sources.len() != before
    }

    /// Every pooled source, in insertion order.
    pub(crate) fn peers(&self) -> impl Iterator<Item = PeerEndpoint> + '_ {
        self.sources.iter().map(|s| s.peer)
    }

    /// The reask sweep at `now`: for each pooled source, in insertion order,
    /// decide whether a UDP ping or the TCP full ask is due and mutate the
    /// source's clock/latch accordingly (ADR-0057). The UDP ping fires first, in
    /// the `[period − lead, period)` window, only when every gate passes; the TCP
    /// full ask fires at `period`, the fallback for silence and the direct path
    /// for a source no UDP ping can reach.
    ///
    /// `our_reachable` is **Self Reach**'s `!firewalled()` — aMule's
    /// `!IsFirewalled()` (`DownloadClient.cpp:1269`, `4e8f2b3c`): a server High
    /// ID or an open Kad TCP verdict, read by the caller at the sweep.
    /// A source cannot reply by UDP to a downloader neither route
    /// reaches, so an unreachable sweep stays TCP-only.
    pub(crate) fn tick(&mut self, now: Instant, our_reachable: bool) -> Vec<ReaskAction> {
        let our_udp_enabled = self.our_udp_enabled;
        let mut actions = Vec::new();
        for source in &mut self.sources {
            let period = source.period();
            let elapsed = now.saturating_duration_since(source.last_reask);
            if elapsed >= period {
                // The TCP full ask: the UDP-silence fallback and the direct path
                // for a UDP-incapable / firewalled / SX-due / NNP source. Refresh
                // the clock and reset the one-in-flight latch.
                source.last_reask = now;
                source.udp_pending = false;
                actions.push(ReaskAction::TcpFullAsk { peer: source.peer });
                continue;
            }
            // UDP ping first, in the 20 s window before the TCP full ask. Gates
            // (ADR-0057, reachability rewired per ADR-0060): our UDP enabled, we
            // are reachable (server-High-ID or Kad-open), the source's UDP
            // contact is known, TCP is not preferred (no source-exchange due),
            // and the source needs parts (an NNP source is TCP-only). The latch
            // keeps at most one ping in flight per window.
            let udp_ready = our_udp_enabled
                && our_reachable
                && !source.udp_pending
                && !source.sx_due
                && !source.no_needed_parts;
            if udp_ready
                && elapsed >= period.saturating_sub(UDP_REASK_LEAD)
                && let Some(contact) = source.udp_contact
            {
                source.udp_pending = true;
                actions.push(ReaskAction::UdpPing {
                    peer: source.peer,
                    udp_endpoint: contact.endpoint,
                    udp_version: contact.version,
                });
            }
        }
        actions
    }

    /// Consume one reask reply datagram from `udp_src` at `now` (ADR-0057
    /// downloader side). Dispatches on the opcode — `0x91`/`0x92`/`0x93` — and
    /// matches the source by its UDP contact, mirroring aMule
    /// `CClientUDPSocket`'s `FindClientByIP_UDP`. Any reply refreshes the
    /// heartbeat and clears the latch (bar `0x92`, which drops the source); an
    /// unmatched, misframed, or unexpected datagram is [`Ignored`] with the
    /// reason.
    ///
    /// [`Ignored`]: ReplyOutcome::Ignored
    pub(crate) fn on_reply_datagram(
        &mut self,
        now: Instant,
        udp_src: PeerEndpoint,
        datagram: &[u8],
    ) -> ReplyOutcome {
        let ignored = |reason| ReplyOutcome::Ignored { reason };
        if datagram.len() < 2 {
            return ignored(IgnoredReaskReply::Runt);
        }
        match ClientUdpOpcode::try_from_u8(datagram[1]) {
            Some(ClientUdpOpcode::ReaskAck) => {
                let ours = self.our_udp_version;
                let Some(source) = self.match_udp_src(udp_src) else {
                    return ignored(IgnoredReaskReply::NoPooledSource);
                };
                // The uploader writes its status only to a UDPv4 pinger
                // (stock 2.3.3 `4e8f2b3c` `ClientUDPSocket.cpp:214`), and
                // aMule's pinger reads one only from a UDPv4 uploader
                // (`:258-259`): the body carries it when both ends are.
                let theirs = source.udp_contact.map_or(0, |contact| contact.version);
                let Ok(ack) = ReaskAck::decode_udp(datagram, ours.min(theirs)) else {
                    return ignored(IgnoredReaskReply::Misframed);
                };
                source.rank = ack.rank;
                source.queue_full = false;
                source.last_reask = now;
                source.udp_pending = false;
                ReplyOutcome::RankRecorded {
                    peer: source.peer,
                    rank: ack.rank,
                    complete: ack.part_status.as_ref().map(advertises_complete),
                }
            }
            Some(ClientUdpOpcode::QueueFull) => {
                let Some(source) = self.match_udp_src(udp_src) else {
                    return ignored(IgnoredReaskReply::NoPooledSource);
                };
                source.rank = 0;
                source.queue_full = true;
                source.last_reask = now;
                source.udp_pending = false;
                ReplyOutcome::QueueFull { peer: source.peer }
            }
            Some(ClientUdpOpcode::FileNotFound) => match self.match_udp_src(udp_src) {
                Some(source) => {
                    let peer = source.peer;
                    self.sources.retain(|s| s.peer != peer);
                    ReplyOutcome::Dropped { peer }
                }
                None => ignored(IgnoredReaskReply::NoPooledSource),
            },
            _ => ignored(IgnoredReaskReply::UnexpectedOpcode),
        }
    }

    /// The pooled source whose UDP contact matches `udp_src` (its IP + client-UDP
    /// port), the reply-routing key aMule keys on.
    fn match_udp_src(&mut self, udp_src: PeerEndpoint) -> Option<&mut PooledSource> {
        self.sources
            .iter_mut()
            .find(|s| s.udp_contact.is_some_and(|c| c.endpoint == udp_src))
    }

    /// Whether `peer` is pooled (test affordance).
    #[cfg(test)]
    fn contains(&self, peer: PeerEndpoint) -> bool {
        self.sources.iter().any(|s| s.peer == peer)
    }

    /// The number of pooled sources (test affordance).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.sources.len()
    }

    /// `peer`'s last known rank, or `None` when unpooled (test affordance).
    #[cfg(test)]
    fn rank(&self, peer: PeerEndpoint) -> Option<u16> {
        self.sources.iter().find(|s| s.peer == peer).map(|s| s.rank)
    }

    /// Whether `peer`'s queue-full flag is set, or `None` when unpooled (test
    /// affordance).
    #[cfg(test)]
    fn is_queue_full(&self, peer: PeerEndpoint) -> Option<bool> {
        self.sources
            .iter()
            .find(|s| s.peer == peer)
            .map(|s| s.queue_full)
    }

    /// Whether `peer`'s one-in-flight UDP latch is set, or `None` when unpooled
    /// (test affordance).
    #[cfg(test)]
    fn udp_pending(&self, peer: PeerEndpoint) -> Option<bool> {
        self.sources
            .iter()
            .find(|s| s.peer == peer)
            .map(|s| s.udp_pending)
    }
}

#[cfg(test)]
mod tests;
