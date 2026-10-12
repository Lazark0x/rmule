//! **Buddy recruitment**: the FINDBUDDY walk a firewalled node runs to acquire
//! the open node that will relay for it, and the verified `0x5A` answer that
//! fills the slot.
//!
//! Its refusal matrix, read in aMule's own guard order
//! ([`ClientList.cpp#L693`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L693)):
//! Kad down → [`KadNotConnected`](RecruitRefusal::KadNotConnected); our TCP
//! surface reachable → [`TcpOpen`](RecruitRefusal::TcpOpen) (an open node needs
//! no buddy); our UDP surface open → [`UdpOpen`](RecruitRefusal::UdpOpen) (that
//! node consumes `0x95` directly instead) or unverified →
//! [`UdpUnverified`](RecruitRefusal::UdpUnverified) (we do not yet know we need
//! one); the slot already filled →
//! [`AlreadyHaveBuddy`](RecruitRefusal::AlreadyHaveBuddy); crypt required →
//! [`CryptRequired`](RecruitRefusal::CryptRequired) (callback requests are not
//! obfuscatable, aMule's own limitation); and the pacing not yet due →
//! [`PacingNotDue`](RecruitRefusal::PacingNotDue), which a walk already in
//! flight also reads. Only both surfaces firewalled recruits, and the walk
//! targets `~ourKadID`.
//!
//! The rule is a [`Recruiter`] the Kad pump's brain holds beside the recheck
//! clock it reads (ADR-0061): it never touches the slot, only the
//! [`BuddySnapshot`] the Firewalled Front publishes of it, and its own walk
//! and refusal leave as the [`RecruitStatus`] it publishes in turn. The
//! `0x5A` that answers a walk is the front's to adopt.

use std::time::{Duration, Instant};

use rmule_kad::KadId;
use rmule_primitives::Ipv4Endpoint;

use super::link::BuddySnapshot;
use super::{FirewalledNode, inverted};
use crate::buddy::BuddyUdpPosture;
use crate::reachability::TcpReachability;

/// The FindBuddy pacing tick (aMule `MIN2MS(20)`,
/// [`ClientList.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L693)):
/// a firewalled node re-attempts recruitment at most every 20 minutes.
pub(super) const FIND_BUDDY_INTERVAL: Duration = Duration::from_secs(20 * 60);

/// How long recruitment stays clear of a firewall recheck (aMule `MIN2MS(5)`,
/// ADR-0058): a recheck may flip our firewalled verdict, so we do not recruit a
/// buddy we might not need until the recheck has settled for 5 minutes.
pub(super) const POST_RECHECK_GUARD: Duration = Duration::from_secs(5 * 60);

/// Our own position the recruitment gate reads (ADR-0058
/// [`Reachability`](crate::reachability)), beside the slot/pacing state the node
/// already owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecruitContext {
    /// Kad is connected — a buddy is reachable and useful only then.
    pub(crate) kad_connected: bool,
    /// Our TCP verdict: recruitment needs it **firewalled** (`!is_reachable`).
    pub(crate) tcp: TcpReachability,
    /// Our UDP verdict: recruitment needs it **firewalled** — an `Open` UDP
    /// surface takes the cheaper direct-callback path instead, an `Unverified`
    /// one is not yet known to need a buddy.
    pub(crate) udp: BuddyUdpPosture,
    /// When our last firewall recheck started (ADR-0058), or `None` — the
    /// recheck guard keeps recruitment ≥5 minutes clear of it.
    pub(crate) last_recheck: Option<Instant>,
    /// Crypt is required on this node: aMule cannot obfuscate callback requests,
    /// so it recruits no buddy while crypt is mandatory (kept, documented).
    pub(crate) crypt_required: bool,
}

/// What [`Recruiter::consider`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecruitDecision {
    /// Recruit: kick off the FINDBUDDY walk toward `walk_target` (`~ourKadID`).
    Recruit { walk_target: KadId },
    /// Do not recruit — with the precise reason (aMule's guarded conditions).
    Refuse { reason: RecruitRefusal },
}

/// Why recruitment did not fire (each a distinct row of the trigger's truth
/// table over our position). Surfaced in diagnostics so a
/// `BuddyState::None` names why, rather than looking merely un-recruited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecruitRefusal {
    /// Kad is not connected — no buddy can be found or used.
    KadNotConnected,
    /// Our TCP surface reads reachable — an open node needs no buddy at all.
    TcpOpen,
    /// Our UDP surface is open — the direct-callback (`0x95`) path serves this
    /// node; a third-party buddy relay is unnecessary (cheaper for the network).
    UdpOpen,
    /// Our UDP surface is not yet verified — we do not yet know we need a buddy.
    UdpUnverified,
    /// We already hold a buddy (the single slot).
    AlreadyHaveBuddy,
    /// Crypt is required — callback requests are not obfuscatable (aMule limit).
    CryptRequired,
    /// The FindBuddy pacing (20-minute tick / 5-minute post-recheck guard) is
    /// not yet due.
    PacingNotDue,
}

/// The `KADEMLIA_FINDBUDDY_RES` (`0x5A`) answer the recruitment walk yields, as
/// [`adopt_buddy`](FirewalledNode::adopt_buddy) reads it. The Kad wire decode
/// rides the deferred Kad `0x51`/`0x5A` front; this is the parsed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FindBuddyRes {
    /// The buddy-ID the answer echoes — the walk target (`~ourKadID`), verified
    /// by XOR-inversion against our KadID.
    pub(crate) buddy_id: KadId,
    /// The answering open node's endpoint — our buddy link.
    pub(crate) buddy_endpoint: Ipv4Endpoint,
}

/// What [`adopt_buddy`](FirewalledNode::adopt_buddy) did with a `0x5A` answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdoptOutcome {
    /// The XOR-inversion verify passed and the slot now holds this buddy.
    Adopted,
    /// The answer's buddy-ID did not invert to our KadID — a stray or spoofed
    /// `0x5A`; the slot is left untouched.
    Rejected,
    /// The answer verified, but the buddy's connect-options byte and our
    /// policy cannot meet ([`PeerCrypt::outbound`](rmule_primitives::PeerCrypt::outbound)
    /// reads [`Incompatible`](rmule_primitives::OutboundCrypt::Incompatible)):
    /// the link could never be dialled, so the slot is left untouched.
    /// aMule's `RequestBuddy` seats the byte (`SetConnectOptions`,
    /// `ClientList.cpp:1144`) and the dial's `CheckContactPreconditions`
    /// then deletes the client, "CryptLayer-Settings (Obfuscation)
    /// incompatible" (`BaseClient.cpp:1913-1919`). Only the enacted slot
    /// returns it; the pure node knows no stances.
    CryptIncompatible,
}

/// What the Kad pump publishes of its recruit rule — the **Recruit Status**:
/// whether a FINDBUDDY walk is in flight, and why the most recent recruit
/// tick refused to walk. The Kad Pump State is its one writer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecruitStatus {
    /// A FINDBUDDY walk is in flight — the diagnostics' `walking`, and the
    /// guard that keeps one recruit tick from starting a second walk.
    pub(crate) walking: bool,
    /// Why the most recent recruit tick refused, or `None` on the one tick
    /// that launched a walk — a level, refreshed on every tick. Most
    /// informative beside `BuddyState::None`: `CryptRequired` there means
    /// this node will never hold a buddy, not merely that the last tick found
    /// nothing due (`PacingNotDue`).
    pub(crate) refusal: Option<RecruitRefusal>,
}

/// The ADR-0061 recruit rule as the Kad pump holds it: the FindBuddy pacing
/// stamp, the walk in flight, and the status it publishes. It reads the slot
/// only through the [`BuddySnapshot`] its owner publishes — whether a buddy is
/// held, and when the last one was lost — and decides with an explicit
/// `Instant`.
pub(crate) struct Recruiter {
    /// Our own Kad ID: the walk targets its inverse.
    our_kad_id: KadId,
    /// When the last FINDBUDDY walk started; `None` before the first.
    last_walk: Option<Instant>,
    status: RecruitStatus,
}

impl Recruiter {
    /// The rule of a node that has just started: no walk yet, so the first
    /// tick that finds the node eligible walks at once.
    pub(crate) fn new(our_kad_id: KadId) -> Self {
        Self {
            our_kad_id,
            last_walk: None,
            status: RecruitStatus::default(),
        }
    }

    /// Consider recruiting a buddy against our position, the slot as its
    /// owner last published it, and the FindBuddy pacing. Recruits **only
    /// when both TCP and UDP are firewalled** (with Kad up, no buddy, crypt
    /// not required, no walk in flight and pacing due), stamping the pacing
    /// clock; a precise refusal otherwise.
    pub(crate) fn consider(
        &mut self,
        ctx: &RecruitContext,
        slot: &BuddySnapshot,
        now: Instant,
    ) -> RecruitDecision {
        let decision = self.decide(ctx, slot, now);
        match decision {
            RecruitDecision::Recruit { .. } => {
                self.last_walk = Some(now);
                self.status = RecruitStatus {
                    walking: true,
                    refusal: None,
                };
            }
            RecruitDecision::Refuse { reason } => self.status.refusal = Some(reason),
        }
        decision
    }

    /// The FINDBUDDY walk is over, or never started. Only the walk moves:
    /// whether to try again sooner than the 20-minute tick is the pacing's to
    /// decide, and re-arming on an empty walk would start one per tick on a
    /// node whose routing table is simply cold.
    pub(crate) fn walk_ended(&mut self) {
        self.status.walking = false;
    }

    /// What this rule publishes now.
    pub(crate) fn status(&self) -> RecruitStatus {
        self.status
    }

    /// aMule's guard order: a walk already in flight (the pacing clock was
    /// stamped when it started), Kad up, then our own surface firewalled on
    /// *both* halves (an open TCP node needs no buddy; a UDP-open node takes
    /// the direct-callback path), then the slot free, crypt not required, and
    /// the pacing due — else recruit toward `~ourKadID`.
    fn decide(&self, ctx: &RecruitContext, slot: &BuddySnapshot, now: Instant) -> RecruitDecision {
        let refuse = |reason| RecruitDecision::Refuse { reason };
        if self.status.walking {
            return refuse(RecruitRefusal::PacingNotDue);
        }
        if !ctx.kad_connected {
            return refuse(RecruitRefusal::KadNotConnected);
        }
        if ctx.tcp.is_reachable() {
            return refuse(RecruitRefusal::TcpOpen);
        }
        match ctx.udp {
            BuddyUdpPosture::Firewalled => {}
            BuddyUdpPosture::Open => return refuse(RecruitRefusal::UdpOpen),
            BuddyUdpPosture::Unverified => return refuse(RecruitRefusal::UdpUnverified),
        }
        if slot.holds_buddy() {
            return refuse(RecruitRefusal::AlreadyHaveBuddy);
        }
        if ctx.crypt_required {
            return refuse(RecruitRefusal::CryptRequired);
        }
        if !self.pacing_due(now, ctx.last_recheck, slot.lost_at) {
            return refuse(RecruitRefusal::PacingNotDue);
        }
        RecruitDecision::Recruit {
            walk_target: inverted(&self.our_kad_id),
        }
    }

    /// The FindBuddy pacing: the 20-minute tick *and* the ≥5-minute clearance
    /// from the last firewall recheck. A buddy lost after the last walk began
    /// satisfies the tick at once — aMule resets its FindBuddy tick on buddy
    /// loss — and the recheck guard still applies.
    fn pacing_due(
        &self,
        now: Instant,
        last_recheck: Option<Instant>,
        lost_at: Option<Instant>,
    ) -> bool {
        let interval_due = self.last_walk.is_none_or(|last| {
            now.saturating_duration_since(last) >= FIND_BUDDY_INTERVAL
                || lost_at.is_some_and(|lost| lost > last)
        });
        let recheck_clear = last_recheck
            .is_none_or(|last| now.saturating_duration_since(last) >= POST_RECHECK_GUARD);
        interval_due && recheck_clear
    }
}

impl FirewalledNode {
    /// The `0x5A` verify (aMule `check.XOR(true); check == GetKADID()`,
    /// `KademliaUDPListener.cpp:1751-1753`): the echoed buddy-ID must invert to
    /// our own KadID — otherwise it is a stray or spoofed answer to a walk we
    /// did not run.
    pub(crate) fn answers_our_walk(&self, res: &FindBuddyRes) -> bool {
        inverted(&res.buddy_id) == self.our_kad_id
    }

    /// Verify a `KADEMLIA_FINDBUDDY_RES` (`0x5A`) by XOR-inversion against our
    /// KadID and, on success, fill the slot. A mismatch leaves the slot untouched.
    pub(crate) fn adopt_buddy(&mut self, res: &FindBuddyRes) -> AdoptOutcome {
        if !self.answers_our_walk(res) {
            return AdoptOutcome::Rejected;
        }
        self.buddy = Some(res.buddy_endpoint);
        AdoptOutcome::Adopted
    }

    /// Free the slot on buddy loss. The instant recruit aMule arms on a loss
    /// is the enacted slot's to publish (the Buddy Snapshot's `lost_at`),
    /// because the rule that reads it runs on the Kad pump.
    pub(crate) fn on_buddy_lost(&mut self) {
        self.buddy = None;
    }
}
