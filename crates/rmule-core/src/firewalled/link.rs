//! The **enacted firewalled slot**: the sans-I/O
//! [`FirewalledNode`] paired with the buddy TCP link *we* dialed, and with the
//! ADR-0091 [`ActingPath`] whose only live carrier is that link.
//!
//! The mirror of [`buddy_link`](crate::buddy_link), and asymmetric with it in
//! exactly one way — **who dials**. aMule's open node never dials its
//! firewalled client (the client cannot be reached); the firewalled client
//! dials its buddy on the `0x5A` and keeps that connection alive
//! ([`ClientList.cpp#L877`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L877)).
//! So where `BuddySlot` *attaches* an accepted connection, this slot holds the
//! command half of one we opened, and its loss is ours to notice.
//!
//! One shared instance (`Core::builder`, the [`SharedBuddySlot`] ownership
//! pattern) meets three surfaces:
//!
//! - the **Kad pump**: the recruit trigger over the live ADR-0058 verdicts, and
//!   the verified `0x5A` that fills the slot;
//! - the **firewalled front** (`super::front`): the dial, the keepalive, and
//!   everything that arrives on the held link;
//! - the **client-UDP front**: a standalone `0xC5 0xA0` and an inbound `0x95`,
//!   both routed to the front rather than decided here.
//!
//! Everything below is a decision with an explicit `Instant`; nothing here
//! awaits, opens a socket or sends a datagram. A `std::sync::Mutex` guards it
//! for `BuddySlot`'s reason: every section is a map update that never crosses
//! an `.await`.
//!
//! [`SharedBuddySlot`]: crate::buddy_link::SharedBuddySlot

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_kad::KadId;
use rmule_peer::PeerCommand;
use rmule_peer::natt::RendezvousBody;
use rmule_primitives::{
    CryptStance, Ipv4Endpoint, OutboundCrypt, PeerCrypt, PeerEndpoint, UserHash,
};
use tokio::sync::mpsc;

use super::FirewalledNode;
use super::direct_callback::{DirectCallbackConsume, DirectCallbackContext, DirectCallbackVerdict};
use super::recruit::{AdoptOutcome, FindBuddyRes, RecruitContext, RecruitDecision, RecruitRefusal};
use super::relayed_callback::{CallbackConsume, CallbackVerdict};
use crate::natt::acting::{
    ActingContext, ActingPath, ActingRefusal, ActingVerdict, RendezvousCarrier,
};

/// The one core-owned enacted firewalled slot, created by `Core::builder` and
/// cloned into the Kad pump, the firewalled front and the client-UDP front.
pub(crate) type SharedFirewalledSlot = Arc<FirewalledSlot>;

/// How often the firewalled node pings the buddy link it dialed
/// (`OP_BUDDYPING`, [`BaseClient.cpp#L2544`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L2544)).
///
/// **aMule's own period, read off the pinned source.** The per-second
/// `CClientList::Process` sweep pings only when `SendBuddyPingPong()` — the
/// stamp is in the past — and `SetLastBuddyPingPongTime()` sets that stamp
/// **ten minutes ahead** on every ping and every pong, so the emit fires once
/// per ten minutes
/// ([updownclient.h#L487-L489](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/updownclient.h#L487),
/// [ClientList.cpp#L661](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L661)).
///
/// A shorter period is not merely overhead: the answering side's
/// `AllowIncomeingBuddyPingPong()` ignores any ping inside **thirteen** minutes
/// of its last pong, so every ping rmule sent before the tenth minute was
/// dropped unanswered by an aMule buddy — five pings per answer, teaching the
/// link nothing. The link's own timeout is generous enough for the slower
/// period: `KS_CONNECTED_BUDDY` adds `MIN2MS(15)` to `CheckTimeOut`, and any
/// packet on the link resets it.
pub(crate) const BUDDY_PING_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The buddy a verified `0x5A` named — everything the enactment needs that the
/// sans-I/O node does not hold.
///
/// [`FirewalledNode`] keeps only the buddy's **UDP** endpoint, because that is
/// the one a source publish advertises and the one the acting path's carrier
/// gate compares against. The TCP endpoint is where we dial, the user hash is
/// the identity that link presents, and the crypt stance is how that dial is
/// made; all are enactment facts, so they live here rather than widening a
/// pure type with fields its decisions never read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecruitedBuddy {
    /// Where the `0x5A` answered from — the acting path's carrier subject.
    pub(crate) udp: Ipv4Endpoint,
    /// The buddy's advertised eD2k port: the link we dial and hold.
    pub(crate) tcp: Ipv4Endpoint,
    /// Its user hash, as the `0x5A` carried it.
    pub(crate) hash: UserHash,
    /// The stance its `0x5A` connect-options byte stated (Kad v7+ appends it,
    /// `KademliaUDPListener.cpp:1756-1761`); `None` for a legacy `0x5A` that
    /// carried no byte at all — silence, not a stated "off" (ADR-0049;
    /// the read-at-the-dial fold to all-lights-dark lives in
    /// [`PeerCrypt::stance`], not here). aMule seats a stated byte on the
    /// buddy's client (`RequestBuddy` → `SetConnectOptions(connectOptions,
    /// true, false)`, `ClientList.cpp:1144`, `BaseClient.cpp:4049-4054`).
    pub(crate) crypt: Option<CryptStance>,
}

impl RecruitedBuddy {
    /// The buddy's crypt side for the dial: the stance its `0x5A` stated, or
    /// silence when it carried no byte, keyed on the hash the `0x5A` carried
    /// — aMule's `RequestBuddy` sets both on the client it then dials
    /// (`ClientList.cpp:1141-1144`).
    pub(crate) const fn peer_crypt(self) -> PeerCrypt {
        match self.crypt {
            Some(stance) => PeerCrypt::new(stance, Some(self.hash)),
            None => PeerCrypt::from_record(None, Some(self.hash)),
        }
    }
}

/// What the slot did with one inbound `OP_REASKCALLBACKTCP` (`0x9A`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReaskRelayConsume {
    /// An ordinary relayed reask: answer the forwarded tail through the
    /// ADR-0057 reply matrix, to `requester`, over the client-UDP socket.
    Reask {
        /// Where the answer goes — the endpoint our buddy injected.
        requester: PeerEndpoint,
        /// The reask body, verbatim (no `[0xC5][0x90]` header).
        forwarded: Vec<u8>,
    },
    /// The forwarded tail carried the `OP_RENDEZVOUS` marker: the acting path
    /// ruled on it (ADR-0091).
    Rendezvous(ActingVerdict),
    /// The tail claimed the marker and was malformed. Never answered as a
    /// reask — that would forward a null file hash for us to answer.
    MalformedRendezvous,
    /// No link is held, so nothing could have been relayed to us.
    NoHeldLink,
}

/// The link we dialed and hold: the buddy's endpoint as we addressed it, and a
/// command sender into that connection's driver.
struct HeldLink {
    remote: PeerEndpoint,
    commands: mpsc::Sender<PeerCommand>,
    /// The buddy's IPv6 as [`buddy_ipv6`] settled it when the link was held.
    buddy_ipv6: Option<std::net::Ipv6Addr>,
    /// When the link was first held — the diagnostics' `held since`.
    since: Instant,
    /// When the last `OP_BUDDYPING` left, so the front's tick can pace them.
    last_ping: Instant,
}

/// The buddy's IPv6 our source publishes name as `bi6` (ADR-0087's Kad
/// row): the address the held link **verified** when that link
/// runs over IPv6 — eMuleAI's rule, the serving buddy's own connected address
/// (`Search.cpp:920-923`, `a2f05dc8`) — otherwise the buddy's own
/// `CT_MOD_IP_V6` on that link, which is what emule-qt publishes
/// (`KadSearch.cpp:1419-1421` from the hello read at `UpDownClient.cpp:1007-1018`,
/// `73fff714`).
///
/// Today the second is the only one that can fire: the link is dialed at the
/// `0x5A`'s IPv4 endpoint because Kad contacts are IPv4 (ADR-0085). The claim
/// is still the buddy's word about *its own* reachability, which every writer
/// states only once its own verification passed (rmule's chooser, kno's
/// `MayAdvertiseIPv6`, emule-qt's `shouldAdvertisePublicIPv6`); what rmule
/// adds is that the claimant is the buddy — the link is held only after its
/// user hash matched the `0x5A` — and that the address is a usable identity.
fn buddy_ipv6(
    remote: PeerEndpoint,
    claimed: Option<std::net::Ipv6Addr>,
) -> Option<std::net::Ipv6Addr> {
    match remote {
        PeerEndpoint::V6(endpoint) if rmule_primitives::is_usable_tag_identity(endpoint.ip) => {
            Some(endpoint.ip)
        }
        _ => claimed,
    }
}

struct Inner {
    node: FirewalledNode,
    /// The ADR-0091 acting path and its own limiter. Owned here because its
    /// carrier gate reads the very buddy slot beside it, and a second owner of
    /// either would be a second answer to "is this from our buddy".
    acting: ActingPath,
    buddy: Option<RecruitedBuddy>,
    link: Option<HeldLink>,
    /// The buddy a dial is in flight for, from [`begin_dial`] until that
    /// dial lands on [`hold_link`] or [`on_dial_failed`] — the
    /// guard that keeps a second `BuddyAdopted` from dialing the same buddy
    /// twice.
    ///
    /// [`begin_dial`]: FirewalledSlot::begin_dial
    /// [`hold_link`]: FirewalledSlot::hold_link
    /// [`on_dial_failed`]: FirewalledSlot::on_dial_failed
    dialing: Option<RecruitedBuddy>,
    /// A FINDBUDDY walk is in flight — the diagnostics' `walking`, and the
    /// guard that keeps one recruit tick from starting a second walk.
    walking: bool,
    /// Why the most recent recruit tick refused to walk, or
    /// `None` on the one tick that launched a walk — a level, refreshed on
    /// every tick, mirroring `buddy_state`'s own single-writer discipline.
    /// Most informative alongside `BuddyState::None`: `CryptRequired` there
    /// means this node will never hold a buddy, not merely that the last tick
    /// found nothing due (`PacingNotDue`).
    last_recruit_refusal: Option<RecruitRefusal>,
}

impl Inner {
    /// A dial to `dialed` landed: its claim on [`dialing`](Self::dialing)
    /// ends, whatever the landing then decides. Another buddy's claim is left
    /// alone — a dial for a buddy since let go lands while its successor's is
    /// still in flight.
    fn end_dial(&mut self, dialed: RecruitedBuddy) {
        if self.dialing == Some(dialed) {
            self.dialing = None;
        }
    }

    /// The pure tier's verdict with the held link's `bi6` folded in: `None`
    /// until a link is held, and gone with it.
    fn publish_buddy_info(&self, firewalled: bool) -> Option<super::BuddyPublish> {
        let buddy_ipv6 = self.link.as_ref().and_then(|link| link.buddy_ipv6);
        self.node
            .publish_buddy_info(firewalled)
            .map(|publish| super::BuddyPublish {
                buddy_ipv6,
                ..publish
            })
    }
}

/// aMule's `m_pBuddy` seen from the firewalled side: the [`FirewalledNode`]
/// decision slot paired with the buddy link we dialed. See the module doc.
pub(crate) struct FirewalledSlot {
    inner: Mutex<Inner>,
    /// **Self Reach** (ADR-0060), installed once by the core
    /// actor that weaves it: the hello's buddy tags ask its
    /// `IsFirewalled()` union at every hello. Empty — no tags — until then,
    /// as an unstarted core claims no buddy.
    reach: std::sync::OnceLock<crate::reachability::SharedSelfReach>,
}

/// What the diagnostics snapshot says about our buddy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuddyState {
    /// No buddy and no walk — the posture of a reachable node, and of a
    /// firewalled one between recruit attempts.
    #[default]
    None,
    /// A FINDBUDDY walk is in flight.
    Walking,
    /// A `0x5A` verified and we are dialing, or the dial failed and the slot
    /// is waiting for the next recruit tick to clear it.
    Recruited,
    /// The buddy link is up and carrying relays.
    Held,
}

impl Default for FirewalledSlot {
    /// The slot a core is woven with, before any Kad node has named this
    /// node's place in the keyspace: the all-zero Kad ID. Nothing can be
    /// adopted against it — a `0x5A` verifies by inverting the echoed ID and
    /// no answer inverts to zero unless it echoed all-ones, which no walk of
    /// ours ever asked for — so an unstarted core holds no buddy by
    /// construction rather than by a flag. [`reset`](Self::reset) seats the
    /// real ID when a node starts.
    fn default() -> Self {
        Self::new(KadId::from_bytes([0; KadId::BYTE_LEN]))
    }
}

impl FirewalledSlot {
    /// A fresh slot for a node whose Kad ID is `our_kad_id`.
    pub(crate) fn new(our_kad_id: KadId) -> Self {
        Self {
            inner: Mutex::new(Inner {
                node: FirewalledNode::new(our_kad_id),
                acting: ActingPath::default(),
                buddy: None,
                link: None,
                dialing: None,
                walking: false,
                last_recruit_refusal: None,
            }),
            reach: std::sync::OnceLock::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("firewalled slot mutex")
    }

    /// Re-seat the slot on a Kad (re)start: a new node ID, no buddy, no link,
    /// no pacing history — the [`BuddySlot::reset`] discipline, and for the
    /// same reason (a restarted node must not inherit a slot it can no longer
    /// verify a `0x5A` against).
    ///
    /// [`BuddySlot::reset`]: crate::buddy_link::BuddySlot::reset
    pub(crate) fn reset(&self, our_kad_id: KadId) {
        let mut inner = self.lock();
        inner.node = FirewalledNode::new(our_kad_id);
        inner.acting = ActingPath::default();
        inner.buddy = None;
        inner.link = None;
        inner.dialing = None;
        inner.walking = false;
        inner.last_recruit_refusal = None;
    }

    /// The recruit trigger (ADR-0061): the sans-I/O refusal matrix, plus the
    /// one enactment fact it cannot see — a walk already in flight. A walk is
    /// refused as [`PacingNotDue`](super::recruit::RecruitRefusal::PacingNotDue)
    /// while one runs, because the trigger's own clock was already stamped when
    /// that walk started.
    pub(crate) fn consider_recruitment(
        &self,
        ctx: &RecruitContext,
        now: Instant,
    ) -> RecruitDecision {
        let mut inner = self.lock();
        if inner.walking {
            let decision = RecruitDecision::Refuse {
                reason: RecruitRefusal::PacingNotDue,
            };
            inner.last_recruit_refusal = Some(RecruitRefusal::PacingNotDue);
            return decision;
        }
        let decision = inner.node.consider_recruitment(ctx, now);
        match decision {
            RecruitDecision::Recruit { .. } => {
                inner.walking = true;
                inner.last_recruit_refusal = None;
            }
            RecruitDecision::Refuse { reason } => inner.last_recruit_refusal = Some(reason),
        }
        decision
    }

    /// The FINDBUDDY walk ended. Only the walking flag moves: whether to try
    /// again sooner than the 20-minute tick is the trigger's pacing to decide,
    /// and re-arming on an empty walk would start one per tick on a node whose
    /// routing table is simply cold.
    pub(crate) fn on_walk_ended(&self) {
        self.lock().walking = false;
    }

    /// Verify a `0x5A` and, on success, fill the slot with the buddy it named
    /// — unless the buddy's stance and `ours` (the stance this node runs
    /// under) cannot meet, when it is refused unseated and undialled
    /// ([`AdoptOutcome::CryptIncompatible`]). The walk that
    /// produced it is over either way.
    pub(crate) fn adopt_buddy(
        &self,
        res: &FindBuddyRes,
        buddy: RecruitedBuddy,
        ours: CryptStance,
    ) -> AdoptOutcome {
        let mut inner = self.lock();
        inner.walking = false;
        if inner.node.answers_our_walk(res)
            && buddy.peer_crypt().outbound(ours) == OutboundCrypt::Incompatible
        {
            return AdoptOutcome::CryptIncompatible;
        }
        let outcome = inner.node.adopt_buddy(res);
        if outcome == AdoptOutcome::Adopted {
            inner.buddy = Some(buddy);
        }
        outcome
    }

    /// The buddy the slot holds, if any — what the front dials, and what the
    /// diagnostics name.
    pub(crate) fn buddy(&self) -> Option<RecruitedBuddy> {
        self.lock().buddy
    }

    /// Claim the dial to `buddy`: `true` when the front may start it, `false`
    /// when a dial to that very buddy is already in flight. A
    /// second `BuddyAdopted` — a re-adopt after a recruit tick, a duplicate
    /// `0x5A` — must not open a second connection to the buddy the first is
    /// still dialing: both would land `Held`, and one of them could only be
    /// shut. The claim ends when that dial lands, held or failed, refused or
    /// not.
    pub(crate) fn begin_dial(&self, buddy: RecruitedBuddy) -> bool {
        let mut inner = self.lock();
        if inner.dialing == Some(buddy) {
            return false;
        }
        inner.dialing = Some(buddy);
        true
    }

    /// Hold the link we dialed to `dialed`: `commands` frames the keepalive
    /// on it, `remote` is the identity a close is matched on, and
    /// `claimed_ipv6` is the `CT_MOD_IP_V6` the buddy's hello carried on this
    /// link (already past `IsUsableTagIdentity`), which [`buddy_ipv6`] weighs
    /// against `remote`.
    ///
    /// Refused — `false`, nothing held — unless the slot still holds `dialed`:
    /// a dial runs on its own task, and the buddy it was for may have been
    /// released (we became reachable, Kad stopped) or replaced while it was in
    /// flight. Holding it anyway would report `Held` with no buddy behind it
    /// and keep a socket open that nothing relays down; the caller shuts it.
    ///
    /// Refused too while a link is already held: one buddy, one
    /// link. The first stays — it is the one the keepalive, the relays and
    /// the diagnostics already name — and the caller shuts the second, as it
    /// does a stale one.
    pub(crate) fn hold_link(
        &self,
        dialed: RecruitedBuddy,
        remote: PeerEndpoint,
        commands: mpsc::Sender<PeerCommand>,
        claimed_ipv6: Option<std::net::Ipv6Addr>,
        now: Instant,
    ) -> bool {
        let mut inner = self.lock();
        inner.end_dial(dialed);
        if inner.buddy != Some(dialed) || inner.link.is_some() {
            return false;
        }
        inner.link = Some(HeldLink {
            remote,
            commands,
            buddy_ipv6: buddy_ipv6(remote, claimed_ipv6),
            since: now,
            last_ping: now,
        });
        true
    }

    /// The held link closed (the buddy hung up, or we let it go): free the
    /// slot **and** arm an instant recruit, exactly as aMule resets its
    /// FindBuddy tick on buddy loss. Reports whether a link was actually held,
    /// so a stale close says nothing.
    pub(crate) fn on_link_closed(&self, remote: PeerEndpoint) -> bool {
        let mut inner = self.lock();
        if !matches!(&inner.link, Some(link) if link.remote == remote) {
            return false;
        }
        inner.link = None;
        inner.buddy = None;
        inner.node.on_buddy_lost();
        true
    }

    /// A dial for `dialed` failed before any link was held: the buddy is one
    /// we cannot reach, so free the slot and arm an instant recruit, as a lost
    /// link does. Reports whether it did.
    ///
    /// Refused — `false`, nothing touched — unless the slot still holds
    /// `dialed` with no link up, [`hold_link`](Self::hold_link)'s rule for the
    /// other outcome: the dial ran on its own task, and while it was in flight
    /// its buddy may have been released and **another adopted**. Releasing
    /// then would let buddy A's late failure throw away buddy B.
    pub(crate) fn on_dial_failed(&self, dialed: RecruitedBuddy) -> bool {
        let mut inner = self.lock();
        inner.end_dial(dialed);
        if inner.buddy != Some(dialed) || inner.link.is_some() {
            return false;
        }
        inner.buddy = None;
        inner.node.on_buddy_lost();
        true
    }

    /// Release the buddy because we no longer need one — we became reachable,
    /// or Kad stopped. Hands back the held link's command half so the front can
    /// shut that connection down; the slot is empty either way.
    pub(crate) fn release(&self) -> Option<mpsc::Sender<PeerCommand>> {
        let mut inner = self.lock();
        inner.buddy = None;
        inner.walking = false;
        inner.node.on_buddy_lost();
        inner.link.take().map(|link| link.commands)
    }

    /// The keepalive due on the held link, or `None` — no link, or the last
    /// ping is younger than [`BUDDY_PING_INTERVAL`]. Stamps the clock, so one
    /// due tick yields one ping.
    pub(crate) fn due_keepalive(&self, now: Instant) -> Option<mpsc::Sender<PeerCommand>> {
        let mut inner = self.lock();
        let link = inner.link.as_mut()?;
        if now.saturating_duration_since(link.last_ping) < BUDDY_PING_INTERVAL {
            return None;
        }
        link.last_ping = now;
        Some(link.commands.clone())
    }

    /// Consume an `OP_CALLBACK` (`0x99`) that arrived on the held link — the
    /// Kad-running, buddy-ID XOR and file-known gates (ADR-0061). A `0x99`
    /// with no link held cannot have come from our buddy: that is this node's
    /// own state, not a counterparty error, so it is dropped as
    /// [`NoBuddyHeld`](super::relayed_callback::CallbackDrop::NoBuddyHeld)
    /// rather than the genuine-mismatch
    /// [`NotForUs`](super::relayed_callback::CallbackDrop::NotForUs).
    pub(crate) fn consume_callback(
        &self,
        req: &CallbackConsume,
        kad_running: bool,
    ) -> CallbackVerdict {
        let inner = self.lock();
        if inner.link.is_none() {
            return CallbackVerdict::Drop {
                reason: super::relayed_callback::CallbackDrop::NoBuddyHeld,
            };
        }
        inner.node.consume_callback(req, kad_running)
    }

    /// Consume an `OP_REASKCALLBACKTCP` (`0x9A`) that arrived on the held link.
    ///
    /// The split is the forwarded tail's own marker, read exactly as the
    /// open-node relay reads it (`client_udp::engine`): a tail that claims
    /// `OP_RENDEZVOUS` is a different *service* with its own gates, and one
    /// that does not is an ordinary reask whose answer leaves by the
    /// client-UDP socket.
    pub(crate) fn consume_reask_relay(
        &self,
        relay: rmule_peer::ReaskCallbackTcp,
        serves_quic: bool,
        is_own_interface: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> ReaskRelayConsume {
        let mut inner = self.lock();
        let Some(link) = inner.link.as_ref().map(|link| link.remote) else {
            return ReaskRelayConsume::NoHeldLink;
        };
        match RendezvousBody::from_forwarded(&relay.forwarded) {
            Some(Ok(body)) => {
                // The requester endpoint the buddy injected is what a `0x9A`
                // carries and the precedence rule's `observed` arm; an IPv6 one
                // rides the Sentinel form this codec reads but rmule's relay
                // never writes (ADR-0085/0087), and it has no `Ipv4Endpoint`
                // form for the rule to use — so it resolves to nothing.
                let Some(observed) = relay.requester.as_v4() else {
                    return ReaskRelayConsume::Rendezvous(ActingVerdict::Refuse(
                        ActingRefusal::NoUsableTarget,
                    ));
                };
                let our_buddy = inner.buddy.map(|buddy| buddy.udp);
                let verdict = inner.acting.consume(
                    &body,
                    RendezvousCarrier::BuddyTcp {
                        link_peer: link,
                        observed,
                    },
                    ActingContext {
                        our_buddy,
                        serves_quic,
                        // Arm 3 of the precedence rule reads the endpoint we
                        // already hold for the peer a claim identifies. This
                        // node holds none: a rendezvous relayed to us names a
                        // requester we have never spoken to (that is why it
                        // went through a buddy), so there is nothing to
                        // corroborate a claim against.
                        known_peer: |_| None,
                        is_own_interface,
                    },
                    now,
                );
                ReaskRelayConsume::Rendezvous(verdict)
            }
            Some(Err(_)) => ReaskRelayConsume::MalformedRendezvous,
            None => ReaskRelayConsume::Reask {
                requester: relay.requester,
                forwarded: relay.forwarded,
            },
        }
    }

    /// Rule on a **standalone** `0xC5 0xA0` from the client-UDP front — kno's
    /// branch's emit form (ADR-0091). The carrier gate holds it to our buddy's
    /// **whole** UDP endpoint: a datagram has no connection behind it, so
    /// forgeable attribution is all it carries. And, as for the `0x9A`
    /// carrier, the buddy relation must be live — the link held — before
    /// anything from it is acted on.
    pub(crate) fn consume_standalone_rendezvous(
        &self,
        body: &RendezvousBody,
        from: PeerEndpoint,
        serves_quic: bool,
        is_own_interface: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> ActingVerdict {
        let mut inner = self.lock();
        if inner.link.is_none() {
            return ActingVerdict::Refuse(ActingRefusal::NotFromOurBuddy);
        }
        let our_buddy = inner.buddy.map(|buddy| buddy.udp);
        inner.acting.consume(
            body,
            RendezvousCarrier::Standalone { from },
            ActingContext {
                our_buddy,
                serves_quic,
                known_peer: |_| None,
                is_own_interface,
            },
            now,
        )
    }

    /// Consume an `OP_DIRECTCALLBACKREQ` (`0x95`) (ADR-0061 route 2): the
    /// per-source-IP rate limit and the still-firewalled / Kad-running gates.
    pub(crate) fn consume_direct_callback(
        &self,
        req: &DirectCallbackConsume,
        ctx: &DirectCallbackContext,
        now: Instant,
    ) -> DirectCallbackVerdict {
        self.lock().node.consume_direct_callback(req, ctx, now)
    }

    /// The buddy info our Kad source publishes carry while firewalled
    /// (ADR-0061 → ADR-0043): the buddy's UDP endpoint and the relationship ID
    /// the pure tier decides, and the buddy's IPv6 (`bi6`) from
    /// the link this slot holds — `None` until the link is held, and gone
    /// with it. `firewalled` is Self Reach's `IsFirewalled()` union
    /// ([`SharedSelfReach::firewalled`](crate::reachability::SharedSelfReach::firewalled)),
    /// not the Kad TCP verdict alone.
    pub(crate) fn publish_buddy_info(&self, firewalled: bool) -> Option<super::BuddyPublish> {
        self.lock().publish_buddy_info(firewalled)
    }

    /// Install **Self Reach**, once: the owner the hello's
    /// buddy tags ask. A second install is ignored — one owner per core.
    pub(crate) fn install_reach(&self, reach: crate::reachability::SharedSelfReach) {
        let _ = self.reach.set(reach);
    }

    /// The hello's `MiscOptions2` direct-callback bit: Self
    /// Reach's answer, read per hello through the owner installed here —
    /// dark until one is.
    pub(crate) fn hello_direct_udp_callback(&self) -> bool {
        self.reach
            .get()
            .is_some_and(crate::reachability::SharedSelfReach::hello_direct_udp_callback)
    }

    /// The buddy our hello names (ADR-0061/0087): `CT_EMULE_BUDDYIP` +
    /// `CT_EMULE_BUDDYUDP` from the held link's IPv4 and the `0x5A`'s UDP port
    /// `CT_EMULE_SERVINGBUDDYIPV6` from the same fact the source
    /// publish carries as `bi6` — one read, one verdict, so the
    /// three tags and the Kad row never disagree about the buddy.
    ///
    /// Gated like emule-qt's hello (`sendBuddyTags`: firewalled **and** a
    /// buddy, `UpDownClient.cpp:1197-1210`), where "a buddy" is the **held
    /// link**: aMule and emule-qt link `m_pBuddy` only once the buddy's
    /// handshake completes (`KS_CONNECTED_BUDDY`, aMule `ClientList.cpp:807-816`,
    /// emule-qt `ClientList.cpp:567-571`), not on the `0x5A` adopt.
    ///
    /// Read under the one lock that holds the link, per hello: a link held or
    /// lost on the front's task shows in the very next hello, where the Kad
    /// row trails it by at most one recruit tick.
    pub(crate) fn serving_buddy(&self) -> Option<rmule_peer::ServingBuddyAdvert> {
        let inner = self.lock();
        let (Some(link), Some(buddy)) = (&inner.link, inner.buddy) else {
            return None;
        };
        // aMule's `GetBuddy() && IsFirewalled()` (`BaseClient.cpp:1031`,
        // `4e8f2b3c`): the owner's union, read per hello.
        let firewalled = self
            .reach
            .get()
            .is_some_and(crate::reachability::SharedSelfReach::firewalled);
        let publish = inner.publish_buddy_info(firewalled)?;
        // The address the link runs to — today always the `0x5A`'s IPv4, the
        // endpoint `front::dial_buddy` dials; an IPv6 link would still have
        // been recruited at that IPv4.
        let ip = match link.remote {
            PeerEndpoint::V4(endpoint) => endpoint.ip,
            PeerEndpoint::V6(_) => buddy.tcp.ip,
        };
        Some(rmule_peer::ServingBuddyAdvert {
            buddy_udp: Ipv4Endpoint::new(ip, publish.buddy_udp.port),
            ipv6: publish.buddy_ipv6,
        })
    }

    /// What the diagnostics snapshot reports: the slot's state and, while a
    /// link is held, since when.
    pub(crate) fn state(&self) -> (BuddyState, Option<Instant>) {
        let inner = self.lock();
        match (&inner.link, inner.buddy, inner.walking) {
            (Some(link), _, _) => (BuddyState::Held, Some(link.since)),
            (None, Some(_), _) => (BuddyState::Recruited, None),
            (None, None, true) => (BuddyState::Walking, None),
            (None, None, false) => (BuddyState::None, None),
        }
    }

    /// Why the most recent recruit tick refused to walk. Read
    /// beside [`state`](Self::state): most informative while it reports
    /// `BuddyState::None`, where `CryptRequired` means this node will never
    /// recruit and `PacingNotDue` means only that the next tick is not yet
    /// due.
    pub(crate) fn recruit_refusal(&self) -> Option<RecruitRefusal> {
        self.lock().last_recruit_refusal
    }
}

#[cfg(test)]
mod tests;
