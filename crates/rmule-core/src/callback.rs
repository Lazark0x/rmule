//! The core-side **callback route chooser** (ADR-0061, execution breakdown 1):
//! the one sans-I/O selector every dial path asks to reach a peer. A HighID peer
//! is dialed straight; a LowID peer — firewalled, unreachable by a plain dial —
//! takes one of four callback routes in aMule's `TryToConnect` order
//! ([`BaseClient.cpp#L1453`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1453)):
//! drop a LowID→LowID, a direct `0x95` UDP callback, a server callback, or a Kad
//! buddy callback.
//!
//! **Rung 1 is no longer a drop** (ADR-0091): a LowID↔LowID pair whose target
//! speaks NAT-T and can be introduced by a **Rendezvous coordinator** takes
//! the [`NatTraversal`](CallbackRoute::NatTraversal) route instead, and a
//! HighID↔LowID pair falls to it after
//! [`CALLBACK_SILENCE_FALLBACK`] of callback silence
//! ([`select_natt_fallback`]). There is no NAT-type gate: rmule holds no
//! symmetric verdict, RFC 8489 says not to build one, and the
//! [`RendezvousSchedule`](rmule_peer::natt::RendezvousSchedule) bounds what a
//! pair that can never succeed costs.
//!
//! **The pair decides the road**: a LowID↔LowID pair punches *now*
//! — there is no callback to wait twelve seconds on, because every callback
//! asks the target to dial us and a Low-ID node cannot be dialed — while a
//! HighID↔LowID pair calls back first and falls only when that callback says
//! nothing. Both roads reach rung 1 through [`select_natt_for_download`], which
//! is the [`CallbackSilence`] the download measured turned into a route.
//!
//! It is the sibling of [`broker_dial_back`](crate::reachability): a pure
//! decision over a candidate's facts (its ID class, direct-callback advert + Kad
//! UDP endpoint, whether it shares our connected server, its buddy contact) and
//! our own position (the ADR-0058 [`Reachability`](crate::reachability) verdict:
//! are we reachable at all, is our UDP surface up, is Kad running). Every caller
//! the ADR names — the download worker, an ADR-0055 LowID source-exchange
//! candidate, and the ADR-0057 **LowID grant dial-back** (promoting a
//! disconnected LowID upload waiter) — builds a [`CallbackTarget`] and asks this
//! one selector, so a LowID waiter never gets a dead TCP dial-back.
//!
//! Both live callers reach it through [`callback_target`], which is the only
//! place a [`PeerReach`] becomes a [`CallbackTarget`]: the core actor's reach
//! arm for a `ReachPeer`, and the same arm again for a download's Low-ID
//! candidate (a [`DownloadReach`], which the download brain raises and the
//! runner forwards). One target builder, one selector.
//!
//! Enactment is deferred, the reachability pattern: the `0x95` datagram rides the
//! client-UDP send half ([`direct_callback_datagram`](crate::client_udp)), the
//! server callback is the built [`CallbackRequest`](rmule_ed2k::CallbackRequest)
//! (`0x1C`, ADR-0039), and the buddy `0x52` + Kad walk are the Kad-surface emit
//! (ADR-0061). This module is the route decision, proven deterministically.

use std::time::Duration;

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::{ClientId, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint};
use tokio::sync::mpsc;

use crate::adapters::CallbackKey;
use crate::dialable::{DialPosition, choose_dial};
use crate::service::PeerReach;

use rmule_kad::KadId;

/// The facts about a reach candidate the chooser reads (aMule
/// `CUpDownClient::TryToConnect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallbackTarget {
    /// The candidate's server-assigned client ID — its LowID/HighID class, and
    /// (when LowID) the id a server callback names.
    pub(crate) id: ClientId,
    /// The candidate's dialable TCP endpoint — used only for the HighID
    /// [`Direct`](CallbackRoute::Direct) route; a LowID candidate has no plain
    /// dial, so callers may pass its last-seen endpoint (never read).
    pub(crate) tcp: PeerEndpoint,
    /// The candidate advertised `SupportsDirectUDPCallback` (ADR-0047): it can
    /// be reached by a `0x95` to its Kad UDP port.
    pub(crate) supports_direct_udp_callback: bool,
    /// The candidate's Kad UDP endpoint — the `0x95` destination. `None` when it
    /// advertised no Kad port, which forecloses the direct route even if the bit
    /// is set.
    pub(crate) kad_udp: Option<Ipv4Endpoint>,
    /// The candidate is on the server we are connected to — a server callback
    /// (`0x1C`) can relay to it.
    pub(crate) on_our_server: bool,
    /// The candidate's buddy contact (ADR-0061), or `None` when it advertised no
    /// buddy — no buddy-ID forecloses the buddy route.
    pub(crate) buddy: Option<BuddyContact>,
    /// The candidate's usable IPv6, when it named one (`CT_MOD_IP_V6`, an
    /// ExtSX record's tag, or a Kad `ip6`) — rung 0's half of the AND.
    /// Already past `IsUsableTagIdentity`, so this site does not re-test it.
    pub(crate) ipv6: Option<Ipv6Endpoint>,
    /// The candidate speaks eMuleAI's NAT-T — `CT_MOD_MISCOPTIONS` bit 1 in
    /// its hello, or the uTP bit of a source record's connect options
    /// (ADR-0091). Without it a punch would open a path nothing can use.
    pub(crate) supports_natt: bool,
}

impl CallbackTarget {
    /// The target's half of rung 1's condition — see [`NattFacts`].
    pub(crate) const fn natt_facts(&self) -> NattFacts {
        NattFacts {
            on_our_server: self.on_our_server,
            supports_natt: self.supports_natt,
            buddy: self.buddy,
            advertised_udp: match self.kad_udp {
                Some(kad_udp) => Some(kad_udp.port),
                None => None,
            },
        }
    }
}

/// The three facts a **Rendezvous coordinator** needs *from the candidate*
/// (ADR-0091), split out from [`CallbackTarget`] because one caller holds them
/// without holding a target.
///
/// A download's Low-ID candidate has no address — that is what makes it Low-ID
/// — so it cannot be a `CallbackTarget` until the runner projects it into one.
/// It still has to answer "could this callback ever fall to a punch?" before
/// arming the 12 s deadline, and answering it with a second copy of the rung's
/// condition is how the two drift apart. So the condition is stated once, here,
/// and both sides read it: [`natt_coordinator`] ANDs each half with our own
/// position, and the brain asks [`Self::admits_coordinator`] alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NattFacts {
    /// The candidate is on our connected server, which can introduce us.
    pub(crate) on_our_server: bool,
    /// The candidate advertised NAT-T — the buddy coordinator's only voucher
    /// for it (the server needs none: it holds the target's own `0xF9`).
    pub(crate) supports_natt: bool,
    /// The candidate's buddy contact, the second coordinator's address.
    pub(crate) buddy: Option<BuddyContact>,
    /// The client-UDP port the candidate advertised (its hello's
    /// `CT_EMULE_UDPPORTS`, a Kad row's `TAG_SOURCEUPORT`, an SX record) — the
    /// half of the **Peer Mapping** a coordinator's observation is compared
    /// with (ADR-0091's amendment). Never a coordinator's input.
    pub(crate) advertised_udp: Option<u16>,
}

impl NattFacts {
    /// Whether *some* coordinator could introduce us to this candidate, judged
    /// on the candidate's facts alone. Our own position (client-UDP up, the
    /// server's `0xF9` keepalive, Kad running) is not read here, so a `true`
    /// means "worth asking the selector", never "a punch will happen".
    pub(crate) const fn admits_coordinator(&self) -> bool {
        self.on_our_server || (self.supports_natt && self.buddy.is_some())
    }
}

/// A candidate's Kad buddy, from its source info: the buddy's Kad ID (the `0x52`
/// walk/verify target) and its UDP endpoint when the candidate carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuddyContact {
    pub(crate) buddy_id: KadId,
    /// The buddy's UDP endpoint when known (`0x52` straight to it); `None`
    /// means the buddy-callback road walks toward `buddy_id` first
    /// — the *only* road that does. The punch coordinator this same
    /// fact feeds ([`NattFacts::buddy`]) has no such walk.
    pub(crate) buddy_udp: Option<Ipv4Endpoint>,
}

impl BuddyContact {
    /// The other spelling of the row's `TAG_BUDDYHASH`, when it names a
    /// different ID — rmule-kad's one rule
    /// ([`KadBuddyContact::fallback_buddy_id`](rmule_kad::KadBuddyContact::fallback_buddy_id)).
    pub(crate) fn fallback_buddy_id(&self) -> Option<KadId> {
        rmule_kad::KadBuddyContact {
            buddy_id: self.buddy_id,
            buddy_udp: self.buddy_udp,
            buddy_ipv6: None,
            buddy_udp_ipv6: None,
        }
        .fallback_buddy_id()
    }
}

/// Our own network position the chooser gates on (ADR-0058 `Reachability`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelfReach {
    /// We are reachable — HighID / TCP-open. A firewalled node cannot be dialed
    /// back, so it can reach a LowID peer only through the server relay when
    /// both share that server.
    pub(crate) reachable: bool,
    /// Our client-UDP surface is up — the direct `0x95` route needs it.
    pub(crate) udp_on: bool,
    /// Kad is running — the buddy route needs it (both the known-endpoint emit
    /// and the FINDSOURCE walk).
    pub(crate) kad_running: bool,
    /// Our own half of the family question — the **Advertised IPv6** the Dial
    /// Chooser reads. Rung 0 fires only when this holds an address.
    pub(crate) dial: DialPosition,
    /// Our connected server session advertised `CT_EMULE_UDPPORTS` at login
    /// and its `0x9F` keepalive is running (ADR-0091) — the server can
    /// introduce us. Whether the *server* speaks the punch is not knowable in
    /// advance: one that does not ignores the `0x60`, and the attempt's own
    /// timeout moves on to the next coordinator.
    pub(crate) server_punch: bool,
}

/// How to reach a candidate — the chooser's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackRoute {
    /// A HighID peer: dial its TCP endpoint straight, no callback.
    Direct { tcp: PeerEndpoint },
    /// Direct UDP callback (route 2): emit `OP_DIRECTCALLBACKREQ` (`0x95`) to
    /// the target's Kad UDP endpoint.
    DirectUdp { target_kad_udp: Ipv4Endpoint },
    /// Server callback (route 3): emit `OP_CALLBACKREQUEST` (`0x1C`) naming
    /// `low_id` to our connected server (ADR-0039).
    Server { low_id: ClientId },
    /// Kad buddy callback (route 4): reach the target through its buddy.
    Buddy {
        buddy_id: KadId,
        /// The buddy's UDP endpoint for a straight `0x52`, or `None` — a
        /// FINDSOURCE walk toward `buddy_id`, emitting `0x52` at convergence.
        buddy_udp: Option<Ipv4Endpoint>,
    },
    /// NAT traversal (ADR-0091, rung 1): be introduced by `coordinator`,
    /// punch, and raise a Tunnel the ordinary peer session runs inside.
    NatTraversal { coordinator: NattCoordinator },
    /// Unreachable — drop the candidate.
    Drop { reason: CallbackDrop },
}

/// Who introduces the two sides of a punch — ADR-0091's *two Rendezvous
/// coordinators*, in the order they are tried.
///
/// **The server goes first.** Its introduction names an endpoint the server
/// *observed* — for both sides — where a buddy-relayed one carries a claim the
/// precedence rule must then judge; it needs no Kad and no buddy; and its
/// keepalive leaves rmule's client-UDP socket, so the mapping it advertises is
/// the one a Tunnel rides even while Kad and client-UDP are two sockets. The
/// buddy is what is left when the target is on another server, or ours does
/// not speak the punch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NattCoordinator {
    /// Our connected server: an `OP_LOWID_HOLEPUNCH_REQUEST` naming the
    /// target's Low-ID. The target's NAT-T support is **not** required to be
    /// known — a source the server handed us has no hello yet — because the
    /// server knows it (the target's own `0xF9`) and refuses with a reason
    /// when it is absent.
    Server { low_id: ClientId },
    /// The target's Kad serving buddy: an `OP_RENDEZVOUS` embedded in an
    /// `OP_REASKCALLBACKUDP` addressed to it.
    Buddy {
        buddy_id: KadId,
        /// The buddy's UDP endpoint for a straight emit, or `None` — the
        /// rendezvous has no dialect-sanctioned walk to resolve it with
        /// (`OP_REASKCALLBACKUDP` never gets a `FINDSOURCE`
        /// fallback; only the buddy-callback road's `0x52` walks). A candidate
        /// named by ID alone retires here at once
        /// (`AttemptRetirement::CoordinatorEndpointUnknown`) instead.
        buddy_udp: Option<Ipv4Endpoint>,
    },
}

/// Why a LowID candidate is unreachable (aMule's `DS_LOWTOLOWIP` and the
/// no-buddy fall-through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackDrop {
    /// LowID→LowID, not on our server, **and no NAT traversal possible**: the
    /// target does not speak it, our client-UDP surface is down, or no
    /// coordinator can introduce us.
    LowToLow,
    /// No usable buddy route: Kad is down, or the candidate advertised no buddy
    /// (no valid buddy-ID to walk toward).
    NoBuddy,
}

/// Choose the route to reach `target` given our own position `ours` (ADR-0061
/// route tree, aMule `TryToConnect` order). Pure and clock-free — the emit /
/// dial is the enactment.
pub(crate) fn select_callback_route(target: &CallbackTarget, ours: &SelfReach) -> CallbackRoute {
    // Rung 0 (ADR-0087): the peer named a usable IPv6 *and* we hold a Known
    // one, so it is dialed directly in that family — ahead of everything,
    // Low ID included. The classic "Low ID ⇒ callback" rule governs the peer's
    // *IPv4 identity*; its IPv6 address stands on its own, and a firewalled
    // peer that has one needs no broker at all. The AND is what makes it safe:
    // dialing from an address we cannot corroborate would break reply
    // attribution and dial-back.
    if let Some(tcp) = choose_dial(None, target.ipv6, ours.dial) {
        return CallbackRoute::Direct { tcp };
    }
    // A HighID peer is reachable by a plain dial — never the callback tree.
    if target.id.is_high_id() {
        return CallbackRoute::Direct { tcp: target.tcp };
    }
    // The candidate is LowID from here — the four-route callback tree.
    //
    // 1. LowID→LowID: we are firewalled too, so no callback can work — every
    //    one of them asks the target to dial *us*. This was aMule's
    //    `DS_LOWTOLOWIP` drop; it is the NAT-T attempt now (ADR-0091), and a
    //    drop only when no punch is possible.
    //
    //    A target on our own server used to skip this rung for the server
    //    callback below. It still does when no coordinator can introduce us —
    //    that route is ADR-0061's and is left as it was — but a punch the
    //    server can coordinate is tried first, because it is the only one of
    //    the two that can succeed between two firewalled peers.
    if !ours.reachable {
        if let Some(coordinator) = natt_coordinator(target, ours) {
            return CallbackRoute::NatTraversal { coordinator };
        }
        if !target.on_our_server {
            return CallbackRoute::Drop {
                reason: CallbackDrop::LowToLow,
            };
        }
    }
    // 2. Direct UDP callback: the target advertises it and our UDP is up. The
    //    `0x95` goes to its Kad UDP port, so a target that advertised none
    //    cannot take this route.
    if target.supports_direct_udp_callback
        && ours.udp_on
        && let Some(target_kad_udp) = target.kad_udp
    {
        return CallbackRoute::DirectUdp { target_kad_udp };
    }
    // 3. Server callback: the target is on our connected server, which relays
    //    the invitation (`0x1C`, ADR-0039).
    if target.on_our_server {
        return CallbackRoute::Server { low_id: target.id };
    }
    // 4. Kad buddy callback: with Kad up and a buddy contact, `0x52` to the
    //    buddy's UDP (or a walk toward its ID); otherwise the candidate is
    //    unreachable.
    if ours.kad_running
        && let Some(buddy) = target.buddy
    {
        return CallbackRoute::Buddy {
            buddy_id: buddy.buddy_id,
            buddy_udp: buddy.buddy_udp,
        };
    }
    CallbackRoute::Drop {
        reason: CallbackDrop::NoBuddy,
    }
}

/// The first coordinator that can introduce us to `target`, if a punch is
/// possible at all. Nothing is possible without our client-UDP surface: the
/// punch and the Tunnel both ride it.
fn natt_coordinator(target: &CallbackTarget, ours: &SelfReach) -> Option<NattCoordinator> {
    server_coordinator(target, ours).or_else(|| buddy_coordinator(&target.natt_facts(), ours))
}

/// Our server can introduce us: the target is on it, and our session
/// advertised and keeps alive the UDP port a punch would land on.
fn server_coordinator(target: &CallbackTarget, ours: &SelfReach) -> Option<NattCoordinator> {
    (ours.udp_on && ours.server_punch && target.natt_facts().on_our_server)
        .then_some(NattCoordinator::Server { low_id: target.id })
}

/// The target's Kad serving buddy can: the target speaks NAT-T — nobody else
/// vouches for it on this path — and its buddy is either at a known endpoint,
/// or Kad is running.
///
/// The second half is **not** a walk: `OP_REASKCALLBACKUDP` has none
/// — an endpoint-less buddy is admitted here only so the attempt opens
/// and the enactment side can retire it at once with a stated reason
/// (`AttemptRetirement::CoordinatorEndpointUnknown`) rather than the
/// candidate being silently unavailable.
///
/// Keyed on [`NattFacts`] rather than a whole [`CallbackTarget`] because the
/// buddy rung reads nothing else about the candidate, and its second caller —
/// the **Traversal Attempt** falling through from the server coordinator — is
/// a punch in flight, not a reach candidate: it holds the facts and no
/// address.
fn buddy_coordinator(facts: &NattFacts, ours: &SelfReach) -> Option<NattCoordinator> {
    if !facts.supports_natt || !ours.udp_on {
        return None;
    }
    let buddy = facts.buddy?;
    (buddy.buddy_udp.is_some() || ours.kad_running).then_some(NattCoordinator::Buddy {
        buddy_id: buddy.buddy_id,
        buddy_udp: buddy.buddy_udp,
    })
}

/// Build the selector's input from the public counterparty-facts record — the
/// one adapter between [`PeerReach`] and [`CallbackTarget`], so the two callers
/// of the route tree (a `ReachPeer` command and a [`DownloadReach`]) cannot
/// read the same peer differently.
pub(crate) fn callback_target(peer: &PeerReach) -> CallbackTarget {
    CallbackTarget {
        id: peer.id,
        tcp: peer.tcp,
        supports_direct_udp_callback: peer.supports_direct_udp_callback,
        kad_udp: peer.kad_udp,
        on_our_server: peer.on_our_server,
        // The peer's IPv6 as it named one — its hello tag, an ExtSX record, or
        // a Kad `ip6` row; each has already passed `IsUsableTagIdentity`. A
        // dual-stack peer keeps both halves here, because which one gets dialed
        // is the Dial Chooser's call.
        ipv6: peer.ipv6.or_else(|| peer.tcp.as_v6()),
        supports_natt: peer.supports_natt,
        buddy: peer.buddy.map(|buddy| BuddyContact {
            buddy_id: buddy.buddy_id,
            buddy_udp: buddy.buddy_udp,
        }),
    }
}

/// A download's Low-ID candidate handed to the route tree — the second caller
/// of the selector (ADR-0091 rung 1).
///
/// The download brain raises it and the runner forwards it to the core actor,
/// the only holder of our own half of the decision.
///
/// **It carries its own answer channel**, because the ask can fail on *our*
/// facts — no live server punch, no buddy — and the caller that has to hear
/// about it is the download, which is two tasks away. Beside a callback the
/// news is optional (that road is still open and its 30 s still governs the
/// slot); for a candidate whose only road was this one it is the difference
/// between failing fast and holding a slot for thirty seconds on an attempt
/// that was never opened. The channel is the one already built for a
/// retirement, so a refusal to *start* and a failure to *finish* reach the brain
/// by one path.
#[derive(Clone, Debug)]
pub(crate) struct DownloadReach {
    /// The candidate's facts, exactly as the channel that named it gave them.
    pub(crate) peer: PeerReach,
    /// Which road the brain opened: the buddy callback, or rung 1 with what
    /// was measured before asking.
    pub(crate) ask: DownloadAsk,
    /// The pending callback this candidate is held under — the key the brain,
    /// the deadline heap and the routing index all share, and the only key a
    /// candidate with no **User Hash** has at all (the claim table is keyed by
    /// the hash, so it cannot carry this news).
    pub(crate) callback: CallbackKey,
    /// Where a **Traversal Attempt** that was never opened is reported, exactly
    /// as one that retired is.
    pub(crate) retire_tx: mpsc::Sender<(CallbackKey, crate::diagnostics::NattRetirement)>,
}

/// Which road a [`DownloadReach`] asks the core actor to enact. The brain has
/// already decided it; the actor holds only our half of the facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DownloadAsk {
    /// ADR-0061 route 2: the `0x95` to the candidate's own Kad
    /// UDP endpoint — no server or buddy involved. Not a selector question
    /// either: `LowIdRoad::of` has already read the candidate's own bit 3
    /// plus its own endpoint, ahead of the buddy and the server relay, and
    /// this ask carries no extra fact the actor's projected [`PeerReach`]
    /// does not already hold.
    DirectUdp,
    /// ADR-0061 route 4: the `0x52` to the candidate's buddy,
    /// naming the file the target must recognise before it dials us back. Not
    /// a selector question: a Kad candidate's id is its address read as a
    /// [`ClientId`], which the route tree would take for a High-ID.
    BuddyCallback {
        file_hash: rmule_primitives::FileHash,
    },
    /// ADR-0091 rung 1, asked of [`select_natt_for_download`].
    Traversal(CallbackSilence),
}

/// What a download measured before asking the route tree for a punch
/// (ADR-0091). **The pair decides the road.**
///
/// A HighID↔LowID pair takes its callback first and arrives here only after
/// [`CALLBACK_SILENCE_FALLBACK`] of nothing. A LowID↔LowID pair never takes one
/// — every callback asks the target to dial *us*, and a Low-ID node cannot be
/// dialed — so it has no silence to measure and arrives at once, with rung 1 as
/// its first road rather than its fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackSilence {
    /// A callback was taken and has said nothing for `elapsed`. `taken` is what
    /// [`select_natt_fallback`] refuses to fall back from when it was never a
    /// callback in the first place.
    After {
        taken: CallbackRoute,
        elapsed: Duration,
    },
    /// No callback was possible for this candidate at all: we are Low-ID, or no
    /// inbound listener is bound. There is nothing to wait for, so nothing is
    /// waited for.
    NoCallbackPossible,
}

/// **Fallback ordering** between the coordinators (ADR-0091): `failed` could
/// not introduce us — the server refused, or never answered — so who is next.
/// Only the server falls back, and only onto the buddy; a buddy that failed
/// is the [`RendezvousSchedule`](rmule_peer::natt::RendezvousSchedule)'s to
/// retry, and falling *back up* to a server that was already skipped or
/// already failed would loop.
///
/// Its caller is the **Traversal Attempt**, the NAT-T front's
/// record of one introduction end to end: the attempt keeps the candidate's
/// [`NattFacts`] and our position as the route tree measured them, so when the
/// server's `0x62` or its fifteen seconds of silence reach the front, the
/// attempt — not the server session, which holds no facts about the target —
/// asks this function who is next.
pub(crate) fn next_natt_coordinator(
    facts: &NattFacts,
    ours: &SelfReach,
    failed: &NattCoordinator,
) -> Option<NattCoordinator> {
    match failed {
        NattCoordinator::Server { .. } => buddy_coordinator(facts, ours),
        NattCoordinator::Buddy { .. } => None,
    }
}

/// The **callback-silence fallback** (ADR-0091): a callback route was `taken`
/// and the target has not dialed back for `silence`. After
/// [`CALLBACK_SILENCE_FALLBACK`] the pair tries NAT traversal instead — the
/// callback assumed we are reachable, and twelve seconds of nothing is the
/// evidence that, for this target, we are not.
///
/// Only a callback falls back. A plain dial that fails is an ordinary dead
/// source, a drop has nothing to fall back from, and a NAT-T attempt that
/// fails is the [`RendezvousSchedule`](rmule_peer::natt::RendezvousSchedule)'s
/// to retry, not this function's to restart.
///
/// Reached through [`select_natt_for_download`], the one entry the download's
/// two roads share. The brain owns a callback end to end: it requests the
/// callback, arms the 12 s deadline beside the 30 s slot-release one, and on
/// its fire raises a [`DownloadReach`] carrying the candidate's facts. A
/// candidate whose [`NattFacts`] admit no coordinator never arms the deadline,
/// so a legacy target costs nothing.
pub(crate) fn select_natt_fallback(
    target: &CallbackTarget,
    ours: &SelfReach,
    taken: &CallbackRoute,
    silence: Duration,
) -> Option<CallbackRoute> {
    let was_callback = matches!(
        taken,
        CallbackRoute::DirectUdp { .. }
            | CallbackRoute::Server { .. }
            | CallbackRoute::Buddy { .. }
    );
    if !was_callback || silence < CALLBACK_SILENCE_FALLBACK {
        return None;
    }
    natt_coordinator(target, ours).map(|coordinator| CallbackRoute::NatTraversal { coordinator })
}

/// Rung 1 for a download's Low-ID candidate, whichever road the pair took to
/// reach it (ADR-0091) — the one entry the core actor asks for a
/// [`DownloadReach`], so the two roads cannot grow two decisions.
///
/// A measured silence is [`select_natt_fallback`]'s, guard and all. A candidate
/// no callback was ever possible for skips that guard — there is no taken route
/// to refuse falling back from and no span to compare — and asks the same
/// private [`natt_coordinator`] rung 1 of [`select_callback_route`] asks.
///
/// It is *not* `select_callback_route` because the condition that brought the
/// candidate here is already decided: no callback can work for it. Running the
/// full tree would offer routes 2–4, every one of which invites the target to
/// dial a node it cannot reach.
pub(crate) fn select_natt_for_download(
    target: &CallbackTarget,
    ours: &SelfReach,
    silence: &CallbackSilence,
) -> Option<CallbackRoute> {
    match silence {
        CallbackSilence::After { taken, elapsed } => {
            select_natt_fallback(target, ours, taken, *elapsed)
        }
        CallbackSilence::NoCallbackPossible => natt_coordinator(target, ours)
            .map(|coordinator| CallbackRoute::NatTraversal { coordinator }),
    }
}

#[cfg(test)]
mod tests;
