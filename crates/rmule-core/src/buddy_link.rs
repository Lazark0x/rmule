//! The **enacted buddy slot** (socket unification, ADR-0061): aMule's one
//! `m_pBuddy` *together with its persistent socket*.
//!
//! The sans-I/O [`BuddyService`](crate::buddy) decides (refusal matrix, verified
//! relays, keepalive); this module owns the **enactment state** those decisions
//! act through — the buddy's persistent peer-TCP link. aMule never dials its
//! buddy: the firewalled client, on receiving our `0x5A`, **dials us** and keeps
//! that connection alive, and every relay/pong rides it
//! (`buddy->GetSocket()->SendPacket`, `KademliaUDPListener.cpp` `0x99`/`0x9A`;
//! `ClientTCPSocket.cpp#L1665` `OP_BUDDYPING`). So the slot HOLDS the accepted,
//! identified inbound connection's command sender and routes over it — never a
//! fresh dial (a dial reaches only a *dialable* buddy, which a firewalled buddy
//! by definition is not).
//!
//! One shared instance (`Core::builder`, the [`SharedBanStore`] ownership
//! pattern) meets every buddy-touching surface:
//!
//! - the **Kad pump** (`adapters`): `0x51` recruit → [`consider_findbuddy`]
//!   fills the service slot; `0x52` → [`relay_kad_callback`] frames `OP_CALLBACK`
//!   (`0x99`) over the held link;
//! - the **client-UDP front** (`client_udp`): `0x94` → [`relay_reask`] frames
//!   `OP_REASKCALLBACKTCP` (`0x9A`) over the held link;
//! - the **inbound accept path** (`adapters` triage/serve bridge): an identified
//!   inbound peer whose user hash matches the recruited buddy's [`try_attach`]es
//!   as the held link (aMule attaches the incoming socket to the already-known
//!   client by hash); its `OP_BUDDYPING` routes through [`on_buddy_ping`] (pong
//!   back on the same held link, gated to it); its close [`on_link_closed`]s,
//!   freeing the slot at once as aMule does when the buddy socket dies. An
//!   inbound `OP_CALLBACK` on *any* accepted connection routes through
//!   [`consume_callback`] — **not** gated to the held link (aMule's
//!   `OP_CALLBACK` arm carries no such check, unlike `OP_BUDDYPING`'s).
//!
//! Sends are `try_send` fire-and-forget: aMule's `SendPacket` queues into the
//! socket buffer and drops what it cannot deliver; a refused send here (driver
//! gone, inbox full) drops the relay the same way, and the close/staleness
//! paths recycle the slot. Short `std::sync::Mutex` sections, no awaits under
//! the lock.
//!
//! [`SharedBanStore`]: crate::ban_store::SharedBanStore
//! [`consider_findbuddy`]: BuddySlot::consider_findbuddy
//! [`relay_kad_callback`]: BuddySlot::relay_kad_callback
//! [`relay_reask`]: BuddySlot::relay_reask
//! [`try_attach`]: BuddySlot::try_attach
//! [`on_buddy_ping`]: BuddySlot::on_buddy_ping
//! [`on_link_closed`]: BuddySlot::on_link_closed
//! [`consume_callback`]: BuddySlot::consume_callback

use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmule_kad::KadId;
use rmule_peer::{Callback, PeerCommand, ReaskCallbackTcp, SideCommand};
use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::mpsc;

use crate::diagnostics::DiagnosticsState;
use crate::firewalled::relayed_callback::{self, CallbackConsume, CallbackVerdict};
use crate::natt::relay::{RelayAdmission, RelayRefusal};

use crate::buddy::{
    BuddyIdentity, BuddyPingOutcome, BuddyRelayRequest, BuddyServePosture, BuddyService,
    FindBuddyOutcome, FindBuddyReq, RelayKind, RelayReject, RelayVerdict,
};

/// The one core-owned enacted buddy slot, created by `Core::builder` and cloned
/// into the Kad pump, the client-UDP front, and the inbound accept path.
pub(crate) type SharedBuddySlot = Arc<BuddySlot>;

/// What became of one verified relay attempt over the held link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayDisposition {
    /// Verified and queued on the held persistent buddy link.
    Sent,
    /// Verified, but no held link is attached (the buddy has not completed its
    /// TCP dial to us, or its link closed) — dropped, exactly aMule's
    /// `buddy->GetSocket()` absent drop.
    NoHeldLink,
    /// Verified, but the held link refused the send (its driver ended or its
    /// inbox is full) — dropped; the close path recycles the slot.
    LinkSendFailed,
    /// The service rejected the relay (no buddy, or the claimed buddy-ID does
    /// not match the registered buddy — the ADR-0061 tightening).
    Rejected(RelayReject),
}

/// What became of one **rendezvous** relay (ADR-0091). Its own type rather
/// than more [`RelayDisposition`] variants: only a rendezvous passes through
/// admission and only a rendezvous is owed an answer, and the `0x52` relay's
/// exhaustive match should not have to name outcomes it can never see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RendezvousRelay {
    /// Forwarded on the held link. Carries the **hint subject** — the served
    /// buddy's user hash and the UDP mapping observed when it recruited us —
    /// for the `OP_NATT_ENDPOINT_HINT` the requester may have asked for.
    Sent {
        target: UserHash,
        target_udp: Ipv4Endpoint,
    },
    /// Verified and deliverable, but the relay service's admission refused it:
    /// the pending cap or the per-source limit.
    Refused(RelayRefusal),
    /// It never reached admission — one of the ordinary relay's own failures
    /// (never [`RelayDisposition::Sent`]).
    Undelivered(RelayDisposition),
}

/// What became of one `OP_BUDDYPING` routed from an accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PingDisposition {
    /// The ping rode the held buddy link: the keepalive refreshed and the
    /// `OP_BUDDYPONG` is queued back on that same link.
    Ponged,
    /// The ping rode the held link but the pong send was refused (driver gone
    /// or inbox full) — the refresh still counted.
    PongSendFailed,
    /// The ping did not arrive on the held buddy link (a stranger's connection,
    /// or no link is attached) — refused silently, aMule's
    /// `GetBuddy() != client` drop.
    NotBuddyLink,
}

/// The held persistent buddy link: the accepted inbound connection's remote
/// endpoint (the buddy's IP + its dial-out ephemeral port — the connection
/// identity pings and closes are matched on) and a command sender into that
/// connection's driver.
struct HeldLink {
    remote: PeerEndpoint,
    commands: mpsc::Sender<PeerCommand>,
}

struct Inner {
    service: BuddyService,
    link: Option<HeldLink>,
    /// The rendezvous relay service's admission (ADR-0091) — its own limiter,
    /// never shared with the acting path.
    rendezvous_admission: RelayAdmission,
    /// Where the open-node half's facts are counted. `None` until
    /// the actor hands the live state over — the slot is woven before the
    /// actor exists, so its counters are installed the way the tunnel claim
    /// table's are.
    diagnostics: Option<DiagnosticsState>,
}

/// aMule's `m_pBuddy` with its socket: the [`BuddyService`] decision slot paired
/// with the held buddy link every relay/pong rides. See the module doc.
pub(crate) struct BuddySlot {
    inner: Mutex<Inner>,
}

impl Default for BuddySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl BuddySlot {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                service: BuddyService::new(),
                link: None,
                rendezvous_admission: RelayAdmission::default(),
                diagnostics: None,
            }),
        }
    }

    /// Hand the slot the live diagnostics state, once, from the actor (the
    /// `AwaitedInbound` install pattern): the slot is the single writer of
    /// the open-node buddy facts, so it counts them itself rather than leaving
    /// each caller to remember.
    pub(crate) fn install_diagnostics(&self, diagnostics: DiagnosticsState) {
        self.lock().diagnostics = Some(diagnostics);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("buddy slot mutex")
    }

    /// Fresh service, no held link — the Kad pump resets on start so a
    /// re-enabled Kad begins with an empty slot.
    pub(crate) fn reset(&self) {
        let mut inner = self.lock();
        inner.service = BuddyService::new();
        inner.link = None;
        inner.rendezvous_admission = RelayAdmission::default();
    }

    /// The `0x51` recruitment decision (the service's refusal matrix), filling
    /// the slot on accept. The Kad pump answers `0x5A` on `Accept`.
    pub(crate) fn consider_findbuddy(
        &self,
        req: &FindBuddyReq,
        posture: &BuddyServePosture,
        our: BuddyIdentity,
        now: Instant,
    ) -> FindBuddyOutcome {
        self.lock()
            .service
            .consider_findbuddy(req, posture, our, now)
    }

    /// Verify and enact one Kad `0x52` → `OP_CALLBACK` (`0x99`) relay: the
    /// service checks the claimed buddy-ID (the tightening), and the framed
    /// `0x99` — buddy-ID and file-hash echoed, the requester endpoint injected —
    /// is queued on the held persistent link.
    pub(crate) fn relay_kad_callback(
        &self,
        claimed_buddy_id: KadId,
        requester: Ipv4Endpoint,
        file_hash: FileHash,
    ) -> RelayDisposition {
        self.relay(
            BuddyRelayRequest {
                kind: RelayKind::Callback,
                claimed_buddy_id,
                requester,
                // The `0x99` is framed from the structured fields; no opaque tail.
                forwarded: Vec::new(),
            },
            |callback| {
                PeerCommand::Side(SideCommand::SendBuddyCallback(Callback {
                    buddy_id: *claimed_buddy_id.as_bytes(),
                    file_hash,
                    requester: callback.requester,
                }))
            },
        )
    }

    /// Verify and enact one peer-UDP `0x94` → `OP_REASKCALLBACKTCP` (`0x9A`)
    /// relay: the service checks the claimed buddy-ID, and the framed `0x9A` —
    /// the requester's UDP source endpoint injected ahead of the forwarded reask
    /// tail — is queued on the held persistent link.
    ///
    /// `requester` is an [`Ipv4Endpoint`] and not a family-generic one because
    /// the `0x9A` body packs it into `WriteUInt32(ip)` (ADR-0087's
    /// `HasEd2kWireForm`): a type exactly as wide as its wire meaning. The
    /// client-UDP front takes that decision — an IPv6 `0x94` is dropped and
    /// counted there, at the driver — so nothing reaching here has a family to
    /// question.
    pub(crate) fn relay_reask(
        &self,
        claimed_buddy_id: KadId,
        requester: Ipv4Endpoint,
        forwarded: Vec<u8>,
    ) -> RelayDisposition {
        self.relay(
            BuddyRelayRequest {
                kind: RelayKind::ReaskCallback,
                claimed_buddy_id,
                requester,
                forwarded,
            },
            |callback| {
                PeerCommand::Side(SideCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
                    requester: PeerEndpoint::V4(callback.requester),
                    forwarded: callback.forwarded,
                }))
            },
        )
    }

    /// Verify, admit and enact one **rendezvous** relay (ADR-0091): an
    /// `OP_REASKCALLBACKUDP` whose forwarded tail is an embedded
    /// `OP_RENDEZVOUS`. The bytes forwarded are exactly what
    /// [`relay_reask`](Self::relay_reask) would forward — the target reads the
    /// marker itself — so what differs is only what may happen at all.
    ///
    /// The order is the security property: **verify, then deliverable, then
    /// admit**. Admission stamps a limiter and takes a pending slot, and a
    /// datagram naming the wrong buddy, or arriving while no link is held,
    /// must be able to do neither — otherwise junk could fill the pending
    /// table and deny the real requester.
    pub(crate) fn relay_rendezvous(
        &self,
        claimed_buddy_id: KadId,
        requester: Ipv4Endpoint,
        forwarded: Vec<u8>,
        now: Instant,
    ) -> RendezvousRelay {
        let (callback, commands, (target, target_udp)) = {
            let mut inner = self.lock();
            let callback = match inner.service.relay(&BuddyRelayRequest {
                kind: RelayKind::ReaskCallback,
                claimed_buddy_id,
                requester,
                forwarded,
            }) {
                RelayVerdict::Relay { callback, .. } => callback,
                RelayVerdict::Reject { reason } => {
                    return RendezvousRelay::Undelivered(RelayDisposition::Rejected(reason));
                }
            };
            let Some(commands) = inner.link.as_ref().map(|link| link.commands.clone()) else {
                return RendezvousRelay::Undelivered(RelayDisposition::NoHeldLink);
            };
            // A verified relay implies a filled slot, so the subject exists;
            // reading it before admission keeps a refusal from being the only
            // path that skips it.
            let Some(subject) = inner.service.hint_subject() else {
                return RendezvousRelay::Undelivered(RelayDisposition::Rejected(
                    RelayReject::NoBuddy,
                ));
            };
            if let Err(refusal) = inner.rendezvous_admission.admit(requester.ip, now) {
                return RendezvousRelay::Refused(refusal);
            }
            (callback, commands, subject)
        };
        let command = PeerCommand::Side(SideCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
            requester: PeerEndpoint::V4(callback.requester),
            forwarded: callback.forwarded,
        }));
        match commands.try_send(command) {
            Ok(()) => RendezvousRelay::Sent { target, target_udp },
            Err(_) => RendezvousRelay::Undelivered(RelayDisposition::LinkSendFailed),
        }
    }

    /// The shared relay enactment: verify through the service, frame through
    /// `command`, queue on the held link.
    fn relay(
        &self,
        req: BuddyRelayRequest,
        command: impl FnOnce(crate::buddy::RelayedCallback) -> PeerCommand,
    ) -> RelayDisposition {
        let (callback, commands, swapped_spelling, diagnostics) = {
            let inner = self.lock();
            let (callback, swapped_spelling) = match inner.service.relay(&req) {
                RelayVerdict::Relay {
                    callback,
                    swapped_spelling,
                    ..
                } => (callback, swapped_spelling),
                RelayVerdict::Reject { reason } => return RelayDisposition::Rejected(reason),
            };
            let Some(link) = &inner.link else {
                return RelayDisposition::NoHeldLink;
            };
            (
                callback,
                link.commands.clone(),
                swapped_spelling,
                inner.diagnostics.clone(),
            )
        };
        match commands.try_send(command(callback)) {
            Ok(()) => {
                if let Some(diagnostics) = diagnostics.filter(|_| swapped_spelling) {
                    diagnostics.record_buddy_relay_swapped_spelling();
                }
                RelayDisposition::Sent
            }
            Err(_) => RelayDisposition::LinkSendFailed,
        }
    }

    /// Offer an accepted, identified inbound connection as the buddy link: held
    /// iff `peer_hash` is the recruited buddy's user hash (aMule attaches the
    /// incoming socket to the already-known client by hash). A re-dialing buddy
    /// replaces its previous link. Returns whether the link is now held.
    ///
    /// The attach trusts the identify: eD2k user hashes are public and SUI is
    /// best-effort, so a peer that declines SecureIdent yet presents the
    /// recruited buddy's hash can take (or replace) the held link and receive
    /// its relays. That is aMule's own by-hash attach semantics — inherent to
    /// the protocol, mitigated when SUI runs, and scoped to the one recruited
    /// buddy's traffic.
    pub(crate) fn try_attach(
        &self,
        remote: PeerEndpoint,
        peer_hash: UserHash,
        commands: mpsc::Sender<PeerCommand>,
    ) -> bool {
        let (diagnostics, displaced) = {
            let mut inner = self.lock();
            if inner.service.buddy_hash() != Some(peer_hash) {
                return false;
            }
            let displaced = inner.link.replace(HeldLink { remote, commands }).is_some();
            (inner.diagnostics.clone(), displaced)
        };
        if let Some(diagnostics) = diagnostics {
            // A re-dialing buddy's new link is one held; the link it pushed out
            // is one lost, so the two totals stay a pair that balances.
            if displaced {
                diagnostics.record_served_buddy_link(false);
            }
            diagnostics.record_served_buddy_link(true);
        }
        true
    }

    /// An `OP_BUDDYPING` arrived on the accepted connection at `from`: iff that
    /// connection **is** the held buddy link (aMule's `GetBuddy() == client`
    /// socket-identity gate), refresh the keepalive and queue `OP_BUDDYPONG`
    /// back on the same held link; a stranger's ping is refused silently.
    pub(crate) fn on_buddy_ping(&self, from: PeerEndpoint, now: Instant) -> PingDisposition {
        let (commands, diagnostics) = {
            let mut inner = self.lock();
            let diagnostics = inner.diagnostics.clone();
            if !matches!(&inner.link, Some(link) if link.remote == from) {
                Self::count_ping(diagnostics.as_ref(), false);
                return PingDisposition::NotBuddyLink;
            }
            // The connection-identity gate passed; the service refreshes the
            // keepalive (IP-matched — the held link's remote IP is the
            // recruited buddy's).
            match inner.service.on_buddy_ping(from, now) {
                BuddyPingOutcome::Pong => {}
                BuddyPingOutcome::NotOurBuddy => {
                    Self::count_ping(diagnostics.as_ref(), false);
                    return PingDisposition::NotBuddyLink;
                }
            }
            let Some(link) = &inner.link else {
                Self::count_ping(diagnostics.as_ref(), false);
                return PingDisposition::NotBuddyLink;
            };
            (link.commands.clone(), diagnostics)
        };
        let answered = commands
            .try_send(PeerCommand::Side(SideCommand::SendBuddyPong))
            .is_ok();
        Self::count_ping(diagnostics.as_ref(), answered);
        if answered {
            PingDisposition::Ponged
        } else {
            PingDisposition::PongSendFailed
        }
    }

    /// One `OP_BUDDYPING` dispositioned: a pong queued back, or nothing.
    fn count_ping(diagnostics: Option<&DiagnosticsState>, answered: bool) {
        if let Some(diagnostics) = diagnostics {
            diagnostics.record_served_buddy_ping(answered);
        }
    }

    /// Consume an `OP_CALLBACK` (`0x99`) arriving on an accepted connection —
    /// including, but not limited to, the held buddy link.
    ///
    /// Unlike [`on_buddy_ping`](Self::on_buddy_ping), this is **not** gated on
    /// "is this connection the held buddy link": aMule's `OP_CALLBACK` arm
    /// carries no `GetBuddy()`/`IsBuddy` check
    /// ([`ClientTCPSocket.cpp#L1743`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1743)) —
    /// it acts on any `0x99` whose check-ID inverts to *this node's own*
    /// KadID, on whichever socket it arrives. `running_as` is that KadID while
    /// a node runs (the **Kad Presence** the serve bridge reads);
    /// this slot holds no Kad identity of its own. See
    /// [`relayed_callback::apply`] for the one rule both roles share.
    ///
    /// Counted into the relayed-callback diagnostics (counters
    /// shared with the firewalled front's consume — one opcode, one rule, one
    /// ledger). The caller enacts a `Dial`.
    pub(crate) fn consume_callback(
        &self,
        running_as: Option<KadId>,
        req: &CallbackConsume,
    ) -> CallbackVerdict {
        let verdict = relayed_callback::apply(running_as, req);
        if let Some(diagnostics) = self.lock().diagnostics.clone() {
            diagnostics.record_relayed_callback(matches!(verdict, CallbackVerdict::Dial { .. }));
            if let CallbackVerdict::Dial {
                swapped_spelling: true,
                ..
            } = verdict
            {
                diagnostics.record_relayed_callback_swapped_spelling();
            }
        }
        verdict
    }

    /// Whether the connection at `remote` is the held buddy link, which keeps
    /// it up when no download holds it any more (ADR-0107 invariant 9).
    pub(crate) fn holds_link(&self, remote: PeerEndpoint) -> bool {
        self.lock()
            .link
            .as_ref()
            .is_some_and(|link| link.remote == remote)
    }

    /// The accepted connection at `remote` closed: when it was the held buddy
    /// link, drop it and free the service slot at once — aMule frees `m_pBuddy`
    /// when the buddy's socket dies, so a fresh recruit can take the slot.
    /// Returns whether the held link was the one that closed.
    pub(crate) fn on_link_closed(&self, remote: PeerEndpoint) -> bool {
        let diagnostics = {
            let mut inner = self.lock();
            match &inner.link {
                Some(link) if link.remote == remote => {
                    inner.link = None;
                    inner.service.release();
                    inner.diagnostics.clone()
                }
                _ => return false,
            }
        };
        if let Some(diagnostics) = diagnostics {
            diagnostics.record_served_buddy_link(false);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::buddy::BuddyUdpPosture;
    use crate::firewalled::relayed_callback::CallbackDrop;

    fn kad_id(byte: u8) -> KadId {
        KadId::from_bytes([byte; KadId::BYTE_LEN])
    }

    fn endpoint(host: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, host), port)
    }

    /// The same address as a peer's — the link-identity side, which is keyed
    /// by a family-generic endpoint.
    fn peer(host: u8, port: u16) -> PeerEndpoint {
        PeerEndpoint::V4(endpoint(host, port))
    }

    fn open_posture() -> BuddyServePosture {
        BuddyServePosture {
            tcp_reachable: true,
            udp: BuddyUdpPosture::Open,
        }
    }

    fn our_identity() -> BuddyIdentity {
        BuddyIdentity {
            our_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            our_tcp_port: 4662,
        }
    }

    /// Recruit `buddy_id` (hash derived from it) at `requester` into `slot`.
    fn recruit(slot: &BuddySlot, buddy_id: KadId, requester: Ipv4Endpoint) {
        let outcome = slot.consider_findbuddy(
            &FindBuddyReq {
                buddy_id,
                requester_hash: buddy_hash(buddy_id),
                requester,
                requester_udp: requester,
                requester_known: false,
                check_collision: false,
                is_self: false,
            },
            &open_posture(),
            our_identity(),
            Instant::now(),
        );
        assert!(matches!(outcome, FindBuddyOutcome::Accept(_)));
    }

    fn buddy_hash(buddy_id: KadId) -> UserHash {
        UserHash::from_bytes(*buddy_id.as_bytes())
    }

    #[test]
    fn relays_ride_the_held_link_and_drop_without_one() {
        let slot = BuddySlot::new();
        let buddy = kad_id(0x11);
        let recruited = endpoint(1, 4662);
        let requester = endpoint(9, 5099);
        let file_hash = FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]);

        // Before recruitment there is no buddy at all.
        assert_eq!(
            slot.relay_kad_callback(buddy, requester, file_hash),
            RelayDisposition::Rejected(RelayReject::NoBuddy)
        );

        // Recruited but not yet dialed-in: verified, but there is no held
        // socket — aMule's `buddy->GetSocket()` absent drop, never a fresh dial.
        recruit(&slot, buddy, recruited);
        assert_eq!(
            slot.relay_kad_callback(buddy, requester, file_hash),
            RelayDisposition::NoHeldLink
        );

        // The buddy's inbound connection identifies and attaches; both relays
        // now ride the held link as framed session commands.
        let (tx, mut rx) = mpsc::channel(4);
        let dialed_from = peer(1, 61234);
        assert!(slot.try_attach(dialed_from, buddy_hash(buddy), tx));

        assert_eq!(
            slot.relay_kad_callback(buddy, requester, file_hash),
            RelayDisposition::Sent
        );
        assert_eq!(
            rx.try_recv().expect("the 0x99 relay rode the held link"),
            PeerCommand::Side(SideCommand::SendBuddyCallback(Callback {
                buddy_id: *buddy.as_bytes(),
                file_hash,
                requester,
            }))
        );

        let forwarded = vec![0xAB, 0xCD, 0xEF];
        assert_eq!(
            slot.relay_reask(buddy, requester, forwarded.clone()),
            RelayDisposition::Sent
        );
        assert_eq!(
            rx.try_recv().expect("the 0x9A relay rode the held link"),
            PeerCommand::Side(SideCommand::SendReaskCallbackTcp(ReaskCallbackTcp {
                requester: PeerEndpoint::V4(requester),
                forwarded,
            }))
        );

        // A mismatched buddy-ID is rejected on both relays (the tightening) and
        // nothing touches the held link.
        assert_eq!(
            slot.relay_kad_callback(kad_id(0x22), requester, file_hash),
            RelayDisposition::Rejected(RelayReject::BuddyIdMismatch)
        );
        assert_eq!(
            slot.relay_reask(kad_id(0x22), requester, Vec::new()),
            RelayDisposition::Rejected(RelayReject::BuddyIdMismatch)
        );
        assert!(rx.try_recv().is_err(), "rejected relays send nothing");

        // A dead driver (receiver dropped) refuses the send — the relay drops
        // rather than dialing fresh.
        drop(rx);
        assert_eq!(
            slot.relay_kad_callback(buddy, requester, file_hash),
            RelayDisposition::LinkSendFailed
        );
    }

    #[test]
    fn attach_requires_the_recruited_buddys_hash() {
        let slot = BuddySlot::new();
        let (tx, _rx) = mpsc::channel(4);

        // No recruit: nothing to attach to.
        assert!(!slot.try_attach(peer(1, 61000), buddy_hash(kad_id(0x11)), tx.clone()));

        // A stranger's hash never attaches; the recruited hash does.
        recruit(&slot, kad_id(0x11), endpoint(1, 4662));
        assert!(!slot.try_attach(peer(1, 61000), UserHash::from_bytes([0xEE; 16]), tx.clone()));
        assert_eq!(
            slot.relay_kad_callback(
                kad_id(0x11),
                endpoint(9, 5099),
                FileHash::from_bytes([0x01; 16])
            ),
            RelayDisposition::NoHeldLink,
            "a refused attach held nothing"
        );
        assert!(slot.try_attach(peer(1, 61000), buddy_hash(kad_id(0x11)), tx));
    }

    #[test]
    fn pings_pong_only_on_the_held_link_and_close_frees_the_slot() {
        let slot = BuddySlot::new();
        let buddy = kad_id(0x11);
        recruit(&slot, buddy, endpoint(1, 4662));
        let (tx, mut rx) = mpsc::channel(4);
        let dialed_from = peer(1, 61234);
        assert!(slot.try_attach(dialed_from, buddy_hash(buddy), tx));

        // A ping from the held link's exact connection endpoint pongs back on
        // that same link; a stranger connection — even one from the buddy's IP
        // at a different port — is refused (aMule's socket-identity gate).
        let now = Instant::now();
        assert_eq!(
            slot.on_buddy_ping(dialed_from, now),
            PingDisposition::Ponged
        );
        assert_eq!(
            rx.try_recv().expect("the pong rode the held link"),
            PeerCommand::Side(SideCommand::SendBuddyPong)
        );
        assert_eq!(
            slot.on_buddy_ping(peer(1, 62000), now),
            PingDisposition::NotBuddyLink
        );
        assert_eq!(
            slot.on_buddy_ping(peer(7, 61234), now),
            PingDisposition::NotBuddyLink
        );
        assert!(rx.try_recv().is_err(), "refused pings pong nothing");

        // Some other connection closing leaves the held link alone; the held
        // link closing frees BOTH the link and the service slot at once, so a
        // fresh recruit can take it (aMule frees `m_pBuddy` on socket death).
        assert!(!slot.on_link_closed(peer(2, 5000)));
        assert_eq!(
            slot.relay_kad_callback(buddy, endpoint(9, 5099), FileHash::from_bytes([0x01; 16])),
            RelayDisposition::Sent
        );
        assert!(slot.on_link_closed(dialed_from));
        assert_eq!(
            slot.relay_kad_callback(buddy, endpoint(9, 5099), FileHash::from_bytes([0x01; 16])),
            RelayDisposition::Rejected(RelayReject::NoBuddy),
            "the close released the service slot, not just the link"
        );
        recruit(&slot, kad_id(0x22), endpoint(2, 4662));
    }

    /// The bit-inverse of a Kad ID (self-inverse) — the same check both a
    /// `0x52`→`0x99` relay and this consume apply, mirrored from
    /// `crate::firewalled::inverted` since the two modules share no privacy
    /// boundary to reuse it across.
    fn inverted(id: KadId) -> KadId {
        let mut bytes = *id.as_bytes();
        for b in &mut bytes {
            *b = !*b;
        }
        KadId::from_bytes(bytes)
    }

    /// AMule's `OP_CALLBACK` arm carries no buddy/role gate — it
    /// acts on any `0x99` whose check-ID inverts to *its own* KadID, on
    /// whichever connection it arrives. The open node's served link consumes
    /// one exactly like the firewalled node's own held link does (same rule,
    /// `relayed_callback::apply`), with **no held-link requirement**: unlike
    /// `on_buddy_ping`, a stranger connection dispositions identically to the
    /// held link, because aMule's source draws no such line.
    #[test]
    fn a_relayed_callback_on_the_served_link_acts_regardless_of_role_or_attach() {
        let slot = BuddySlot::new();
        let our_kad_id = kad_id(0x99);
        let requester = endpoint(20, 4662);
        let ours = CallbackConsume {
            check_id: inverted(our_kad_id),
            file_shared_or_downloading: true,
            requester,
        };

        // No buddy recruited, no link attached at all — still dials, because
        // the rule reads only the packet's own check-ID, never the slot.
        assert_eq!(
            slot.consume_callback(Some(our_kad_id), &ours),
            CallbackVerdict::Dial {
                requester,
                swapped_spelling: false
            }
        );

        // A buddy recruited and attached changes nothing about the rule — the
        // served link and any other connection disposition the same.
        recruit(&slot, kad_id(0x11), endpoint(1, 4662));
        let (tx, _rx) = mpsc::channel(4);
        assert!(slot.try_attach(peer(1, 61234), buddy_hash(kad_id(0x11)), tx));
        assert_eq!(
            slot.consume_callback(Some(our_kad_id), &ours),
            CallbackVerdict::Dial {
                requester,
                swapped_spelling: false
            }
        );

        // The same three aMule-sourced gates still apply.
        assert_eq!(
            slot.consume_callback(None, &ours),
            CallbackVerdict::Drop {
                reason: CallbackDrop::KadDown
            }
        );
        assert_eq!(
            slot.consume_callback(
                Some(our_kad_id),
                &CallbackConsume {
                    check_id: kad_id(0x44),
                    ..ours
                }
            ),
            CallbackVerdict::Drop {
                reason: CallbackDrop::NotForUs
            }
        );
        assert_eq!(
            slot.consume_callback(
                Some(our_kad_id),
                &CallbackConsume {
                    file_shared_or_downloading: false,
                    ..ours
                }
            ),
            CallbackVerdict::Drop {
                reason: CallbackDrop::FileUnknown
            }
        );
    }
}
