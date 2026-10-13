//! The queue standing a source's record carries (ADR-0057, ADR-0090): the rank
//! a remote uploader gave us, the source's client-UDP contact and peer-UDP
//! crypt target as the identity it queued under stated them, the reask clock
//! and its one-ping latch, and the queue-full and no-needed-parts marks. A
//! record that holds one and has no worker waits in the RemoteQueued stage —
//! the **Remote-Queued Pool** — where the brain's tick keeps it alive:
//!
//! - At [`FILE_REASK_TIME`] − [`UDP_REASK_LEAD`] since the last reask, when the
//!   gates pass, a `0x90` goes to the source's client-UDP endpoint and the latch
//!   is set (aMule `CUpDownClient::UDPReaskForDownload`, `DownloadClient.cpp`).
//! - At [`FILE_REASK_TIME`], the **TCP full ask**: the record leaves the stage
//!   for its road, the latch reset with the standing (aMule `AskForDownload`,
//!   `DownloadClient.cpp:139-160`). A lost datagram costs the 20 s grace, never
//!   the standing.
//! - A reply refreshes the clock and clears the latch: `0x91` records the rank
//!   and clears the queue-full mark, and its part status, when it holds no
//!   part we lack, sets the no-needed-parts mark; `0x93` sets the queue-full
//!   mark (rank 0); `0x92` drops the source dead.
//! - A queue-full source is reasked on the same cadence; it and a
//!   no-needed-parts source are among those the book lets go as the file
//!   nears its source limit (the purges, aMule `CPartFile::Process`).
//! - A **no-needed-parts** source reasks at ×[`NO_NEEDED_PARTS_MULTIPLIER`] the
//!   period, over TCP only (aMule `PartFile.cpp`).
//!
//! Every clock read is an instant the brain hands in.

use std::time::{Duration, Instant};

use rmule_peer::PeerIdentity;
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_primitives::PeerEndpoint;

use super::SourceBook;
use super::purge::PurgeKind;
use super::record::{Lane, Live, RecordId, Stage};

/// aMule `FILEREASKTIME` (`Constants.h`): 1,300,000 ms — the source-reask
/// period, ≈ 21.7 minutes, and the spent endpoints' period (ADR-0090).
pub(crate) const FILE_REASK_TIME: Duration = Duration::from_millis(1_300_000);

/// The UDP ping leads the TCP full ask by 20 s (aMule `DownloadClient.cpp`: the
/// UDP reask fires at `FILEREASKTIME − 20 s`, the TCP full ask at
/// `FILEREASKTIME`). This is the grace a lost reply burns before the fallback.
pub(crate) const UDP_REASK_LEAD: Duration = Duration::from_secs(20);

/// A no-needed-parts source reasks at ×2 the period, then forces a TCP recheck
/// (aMule `PartFile.cpp`): it holds no parts we want, so it is polled half as
/// often and always over TCP (a full status recheck), never a UDP ping.
pub(crate) const NO_NEEDED_PARTS_MULTIPLIER: u32 = 2;

/// How soon a ping that was due but could not leave — we were unreachable, a
/// source ask was due, or another download's ping held the endpoint — is
/// looked at again inside its window: aMule re-reads the gate on its
/// once-a-second `Process`.
pub(crate) const REASK_RECHECK: Duration = Duration::from_secs(1);

/// A source's advertised client-UDP contact — the destination for our
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
    /// our complete-source count) and the shape of its reply.
    pub(crate) version: u8,
}

/// What a worker's identity says a queue standing it earns carries past it
/// (ADR-0057): where the source is UDP-reasked, and the crypt target the
/// `0x90` is obfuscated toward when its stance accepts that.
pub(super) struct ReaskFacts {
    /// The client-UDP contact its hello advertised, at the address the worker
    /// reached it on; `None` when it advertised none. A called-back Low-ID
    /// peer has one too: aMule pings any source with a UDP port at
    /// `GetConnectIP()`, the address its connection came from, with no
    /// `HasLowID` gate (stock 2.3.3 `DownloadClient.cpp:1269-1296`).
    pub(super) contact: Option<UdpContact>,
    /// Its User Hash and stance (ADR-0046).
    pub(super) crypt: PeerUdpCryptTarget,
}

impl ReaskFacts {
    /// What `identity`, read by the worker `live`, gives a standing.
    pub(super) fn of(live: Live, identity: &PeerIdentity) -> Self {
        let contact = identity
            .client_udp_reask()
            .map(|(port, version)| UdpContact {
                // Its address family's own endpoint at the port its hello
                // advertised: the client-UDP surface is a Family Pair
                // (ADR-0085) and the reask quartet is byte-identical over
                // IPv6 (ADR-0087).
                endpoint: live.endpoint.with_port(port),
                version,
            });
        Self {
            contact,
            crypt: identity.udp_crypt_target(),
        }
    }
}

/// One record's queue standing at a remote uploader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Standing {
    /// The last queue rank we learned (0 when unknown or queue-full).
    rank: u16,
    /// The source's client-UDP contact, or `None` when it advertised none.
    contact: Option<UdpContact>,
    /// The source's peer-UDP crypt target from the identity it queued under
    /// (ADR-0046): kept for as long as the standing lives, past the worker
    /// whose identity stated it, so the `0x90` is obfuscated toward a stance
    /// that accepts it (aMule `ShouldReceiveCryptUDPPackets`,
    /// `BaseClient.cpp:2631-2633`).
    crypt: Option<PeerUdpCryptTarget>,
    /// The reask clock: the instant of the last reask — the rank arriving, a
    /// reply. The UDP ping falls due at `period − lead` past it, the TCP full
    /// ask at `period`.
    last_reask: Instant,
    /// The one-in-flight UDP latch (aMule `m_bUDPPending`): set when a ping
    /// leaves, cleared by a reply or the TCP full ask.
    udp_pending: bool,
    /// When a ping that was due but held is looked at again.
    recheck_at: Option<Instant>,
    /// The `0x93` mark: reasked as any standing is, and let go when the file
    /// nears its source limit.
    queue_full: bool,
    /// aMule `DS_NONEEDEDPARTS`: the source holds no parts we want.
    no_needed_parts: bool,
}

impl Standing {
    /// Whether it is a place a source-exchange answer may name: not
    /// queue-full (`IsRemoteQueueFull`), and not holding nothing we need
    /// (`DS_NONEEDEDPARTS` is no queue state).
    pub(super) const fn names_a_place(&self) -> bool {
        !self.queue_full && !self.no_needed_parts
    }

    /// The peer-UDP crypt target the identity it queued under stated.
    pub(super) const fn crypt(&self) -> Option<PeerUdpCryptTarget> {
        self.crypt
    }

    /// Take what a revised identity of the live worker states: a contact
    /// replaces the one held, silence keeps it, and the crypt target is the
    /// identity's.
    pub(super) fn restate(&mut self, facts: ReaskFacts) {
        self.contact = facts.contact.or(self.contact);
        self.crypt = Some(facts.crypt);
    }

    /// The reask period: the base [`FILE_REASK_TIME`], doubled for a
    /// no-needed-parts source.
    fn period(&self) -> Duration {
        if self.no_needed_parts {
            FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER
        } else {
            FILE_REASK_TIME
        }
    }

    /// Whether a UDP ping could ever reach this source this period, gates
    /// that move aside: a contact, parts we need, no ping already out.
    fn pingable(&self, socket: bool) -> bool {
        socket && self.contact.is_some() && !self.no_needed_parts && !self.udp_pending
    }

    /// Which purge may let this standing go: a no-needed-parts source first —
    /// aMule's `DS_NONEEDEDPARTS` is its own state, read before the
    /// queue-full mark of a `DS_ONQUEUE` one — then a queue-full one.
    pub(super) const fn purge_mark(&self) -> Option<PurgeKind> {
        if self.no_needed_parts {
            Some(PurgeKind::NoNeededParts)
        } else if self.queue_full {
            Some(PurgeKind::QueueFull)
        } else {
            None
        }
    }

    /// When this standing next wants a look.
    fn wake(&self, socket: bool) -> Instant {
        let full_ask = self.last_reask + self.period();
        if !self.pingable(socket) {
            return full_ask;
        }
        let window = full_ask - UDP_REASK_LEAD;
        self.recheck_at
            .map_or(window, |recheck| recheck.min(full_ask))
    }
}

/// What the brain's own position says of the UDP ping this tick.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReaskGates {
    /// A client-UDP socket is bound, so our UDP advert is live (ADR-0047).
    pub(crate) socket: bool,
    /// Self Reach's `!firewalled()` — aMule's `!IsFirewalled()`
    /// (`DownloadClient.cpp:1269`): a source cannot answer by UDP a
    /// downloader no route reaches.
    pub(crate) reachable: bool,
}

/// One reask the sweep found due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reask {
    /// Send `OP_REASKFILEPING` to the source at `peer` over `contact`; its
    /// latch is set.
    Ping {
        /// The record's endpoint.
        peer: PeerEndpoint,
        /// Where the ping goes, and the version it is framed for.
        contact: UdpContact,
        /// Whom the ping may be obfuscated toward, when the standing's
        /// identity stated it.
        crypt: Option<PeerUdpCryptTarget>,
    },
    /// The TCP full ask: the record at `peer` left the RemoteQueued stage for
    /// its road, its standing ended.
    FullAsk {
        /// The endpoint it stood at.
        peer: PeerEndpoint,
    },
}

/// What a reply said to the standing it matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `0x91`: the rank, recorded; the queue-full mark cleared; and, when the
    /// answer carried a part status, whether it holds a part we lack — the
    /// no-needed-parts mark set or cleared (stock 2.3.3
    /// `DownloadClient.cpp:487-491`).
    Rank {
        /// The 1-based queue position.
        rank: u16,
        /// `Some(false)` when its part status holds no part we lack;
        /// `None` when the answer carried no status.
        parts_needed: Option<bool>,
    },
    /// `0x93`: the queue-full mark set, rank 0.
    QueueFull,
}

impl SourceBook {
    /// The live worker at `endpoint` was queued at `rank` at `now`: its record
    /// earns its standing, or refreshes it — the clock restarted, the latch
    /// and queue-full mark cleared — with the UDP contact and crypt target the
    /// identity it queued under stated.
    pub(crate) fn queued(&mut self, endpoint: PeerEndpoint, rank: u16, now: Instant) {
        let Some(record) = self.live_record_mut(endpoint) else {
            return;
        };
        let stated = record
            .live_at(endpoint)
            .zip(record.stage.identity())
            .map(|(live, identity)| ReaskFacts::of(live, identity));
        let held = record.standing;
        let no_needed_parts = held.is_some_and(|standing| standing.no_needed_parts);
        let (contact, crypt) = match stated {
            Some(stated) => (stated.contact, Some(stated.crypt)),
            None => (None, None),
        };
        record.standing = Some(Standing {
            rank,
            contact: contact.or(held.and_then(|standing| standing.contact)),
            crypt: crypt.or(held.and_then(|standing| standing.crypt)),
            last_reask: now,
            udp_pending: false,
            recheck_at: None,
            queue_full: false,
            no_needed_parts,
        });
    }

    /// The live worker at `endpoint`'s source holds no part we need: its
    /// standing reasks at twice the period, over TCP — earned at rank 0 at
    /// `now` when it held none, as a rank earns one (ADR-0112).
    pub(crate) fn no_needed_parts(&mut self, endpoint: PeerEndpoint, now: Instant) {
        if self
            .live_record_mut(endpoint)
            .is_some_and(|record| record.standing.is_none())
        {
            self.queued(endpoint, 0, now);
        }
        if let Some(standing) = self
            .live_record_mut(endpoint)
            .and_then(|record| record.standing.as_mut())
        {
            standing.no_needed_parts = true;
        }
    }

    /// The standing of the record at `endpoint` ends: a grant or transfer on
    /// its worker, or a retirement that keeps none.
    pub(crate) fn end_standing(&mut self, endpoint: PeerEndpoint) {
        if let Some(record) = self.live_record_mut(endpoint) {
            record.standing = None;
        }
    }

    /// The rank the record at `endpoint` stands at, if it holds a standing.
    pub(crate) fn rank(&self, endpoint: PeerEndpoint) -> Option<u16> {
        self.record_at(endpoint)?
            .standing
            .map(|standing| standing.rank)
    }

    /// The reask sweep at `now`, over every record in the RemoteQueued stage
    /// in the order the book first held them. The TCP full ask falls due at
    /// the period — the silence fallback and the direct road for a source no
    /// ping can reach; before it, in the `[period − lead, period)` window, the
    /// ping goes when every gate passes: our socket, our reachability, the
    /// source's contact, parts we need, no ping already out, and no source ask
    /// due, which the TCP ask carries (`DownloadClient.cpp:1269-1273`,
    /// ADR-0108). A ping the moving gates held is looked at again
    /// [`REASK_RECHECK`] later.
    pub(crate) fn sweep(&mut self, now: Instant, gates: ReaskGates) -> Vec<Reask> {
        let mut queued: Vec<RecordId> = self
            .records
            .iter()
            .filter(|(_, record)| matches!(record.stage, Stage::RemoteQueued(_)))
            .map(|(&id, _)| id)
            .collect();
        queued.sort_unstable();
        let mut due = Vec::new();
        for id in queued {
            let sx_due = self.source_ask_due(id, now);
            let Some(record) = self.records.get_mut(&id) else {
                continue;
            };
            let (&Stage::RemoteQueued(peer), Some(standing)) =
                (&record.stage, record.standing.as_mut())
            else {
                continue;
            };
            let period = standing.period();
            let elapsed = now.saturating_duration_since(standing.last_reask);
            if elapsed >= period {
                self.full_ask(id, peer);
                due.push(Reask::FullAsk { peer });
                continue;
            }
            let Some(contact) = standing.contact.filter(|_| standing.pingable(gates.socket)) else {
                continue;
            };
            if elapsed < period.saturating_sub(UDP_REASK_LEAD) {
                continue;
            }
            if gates.reachable && !sx_due {
                standing.udp_pending = true;
                standing.recheck_at = None;
                due.push(Reask::Ping {
                    peer,
                    contact,
                    crypt: standing.crypt,
                });
            } else {
                standing.recheck_at = Some(now + REASK_RECHECK);
            }
        }
        due
    }

    /// The ping to the source at `peer` could not leave at `now` — another
    /// download's ping to the same endpoint is unanswered (ADR-0107): the
    /// latch opens without touching the clock, so the window is looked at
    /// again and the TCP full ask still falls due on time.
    pub(crate) fn ping_held(&mut self, peer: PeerEndpoint, now: Instant) {
        if let Some(standing) = self
            .record_at_mut(peer)
            .filter(|record| matches!(record.stage, Stage::RemoteQueued(_)))
            .and_then(|record| record.standing.as_mut())
        {
            standing.udp_pending = false;
            standing.recheck_at = Some(now + REASK_RECHECK);
        }
    }

    /// The endpoint each record in the RemoteQueued stage stands at.
    pub(crate) fn remote_queued(&self) -> impl Iterator<Item = PeerEndpoint> + '_ {
        self.records
            .values()
            .filter_map(|record| match record.stage {
                Stage::RemoteQueued(at) => Some(at),
                _ => None,
            })
    }

    /// When the earliest standing next wants a look; `socket` says whether
    /// any ping can leave at all.
    pub(crate) fn next_reask(&self, socket: bool) -> Option<Instant> {
        self.records
            .values()
            .filter(|record| matches!(record.stage, Stage::RemoteQueued(_)))
            .filter_map(|record| record.standing)
            .map(|standing| standing.wake(socket))
            .min()
    }

    /// The source a reply from the client-UDP endpoint `from` answers: the
    /// RemoteQueued record whose contact is `from` — aMule matches by
    /// `FindClientByIP_UDP` — with its endpoint and UDP version.
    pub(crate) fn reask_source(&self, from: PeerEndpoint) -> Option<(PeerEndpoint, u8)> {
        self.records.values().find_map(|record| {
            let Stage::RemoteQueued(peer) = record.stage else {
                return None;
            };
            let contact = record.standing?.contact?;
            (contact.endpoint == from).then_some((peer, contact.version))
        })
    }

    /// The source at `peer` answered its ping at `now`: the clock refreshed,
    /// the latch cleared, and what the answer said recorded.
    pub(crate) fn reask_answered(&mut self, peer: PeerEndpoint, answer: Answer, now: Instant) {
        if let Some(standing) = self
            .record_at_mut(peer)
            .and_then(|record| record.standing.as_mut())
        {
            match answer {
                Answer::Rank { rank, parts_needed } => {
                    standing.rank = rank;
                    standing.queue_full = false;
                    if let Some(needed) = parts_needed {
                        standing.no_needed_parts = !needed;
                    }
                }
                Answer::QueueFull => {
                    standing.rank = 0;
                    standing.queue_full = true;
                }
            }
            standing.last_reask = now;
            standing.udp_pending = false;
            standing.recheck_at = None;
        }
    }

    /// The source at `peer` no longer shares the file (`0x92`): its record is
    /// spent under every name it holds and leaves the book, as a TCP no-file
    /// answer's does (ADR-0090), and a fact a sighting attached to its
    /// standing — another family's half — goes with it.
    pub(crate) fn reask_dropped(&mut self, peer: PeerEndpoint) {
        if let Some(id) = self.aliases.endpoint(peer)
            && self
                .records
                .get(&id)
                .is_some_and(|record| matches!(record.stage, Stage::RemoteQueued(_)))
        {
            self.spend_lacking(id);
        }
    }

    /// The TCP full ask for `id`, standing at `peer`: aMule's `AskForDownload`
    /// re-asks the source as it first reached it, so a High ID goes back to
    /// the High-ID lane at its endpoint, and a called-back source — which kept
    /// its candidate and `CallbackKey` — to its Low-ID lane, where the next
    /// fill opens the road a fresh candidate would take: rung 0, a callback,
    /// its buddy or a punch (`TryToConnect`, `BaseClient.cpp:1395`). The
    /// connection that answers is the same record, and its next rank is the
    /// standing again.
    fn full_ask(&mut self, id: RecordId, peer: PeerEndpoint) {
        let candidate = self.records.get(&id).and_then(|record| record.candidate);
        let lane = match candidate {
            Some(candidate) => {
                self.keep_only_endpoint(id, candidate.ipv6.map(PeerEndpoint::V6));
                Lane::of(&candidate, self.own_server)
            }
            None => Lane::HighId,
        };
        let Some(record) = self.records.get_mut(&id) else {
            return;
        };
        record.standing = None;
        if lane == Lane::HighId {
            record.endpoints.retain(|&held| held != peer);
            record.endpoints.insert(0, peer);
        }
        record.stage = Stage::Pooled(lane);
        self.lanes.push_back(lane, id);
    }
}
