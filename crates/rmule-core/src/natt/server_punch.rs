//! The **server coordinator** (ADR-0091): ed2k-server introducing us to a
//! LowID peer, as a second source of rendezvous beside the Kad serving buddy.
//!
//! It feeds the same machinery and is simpler than the buddy path in the way
//! that matters. An `OP_LOWID_HOLEPUNCH_INFO` arrives on our own
//! authenticated TCP session, so there is no sender gate to pass; and the
//! endpoint in it is one the **server observed**, so the precedence rule has
//! nothing to arbitrate — it is asked only whether that endpoint is somewhere
//! a punch may go. What is left is what every punch needs: a public
//! destination, not ourselves, not already punched this window.
//!
//! **Both sides fire, at once.** The role byte is advisory and rmule ignores
//! it for timing: the server sends INFO to both clients together, so there is
//! no relay round trip to halve, and a side that waited its turn would punch
//! a NAT the other had not opened yet.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmule_ed2k::{
    HolepunchFail, HolepunchFailReason, HolepunchInfo, HolepunchRole, UdpPortsAdvert,
    natt_keepalive_datagram, natt_keepalive_port,
};
use rmule_peer::natt::is_public_punch_address;
use rmule_primitives::{AccountingKey, ClientId, Ipv4Endpoint, PeerEndpoint, UserHash};

use super::acting::{ACTING_MIN_INTERVAL, ACTING_TRACKED_MAX};
use crate::client_udp::ClientUdpSend;
use crate::interval_limiter::IntervalLimiter;

/// How often the `0x9F` keepalive leaves. **A correctness invariant, not a
/// tuning**: the server trusts an observed UDP port for 600 s, and its own
/// documentation names the failure a slower cadence produces — peers that
/// punch fine just after connecting and stop a few minutes later. Sixty
/// seconds is the contract's number and gives a tenfold margin.
pub(crate) const SERVER_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// How often the session re-reads the introduction clock. Finer than
/// [`INTRODUCTION_TIMEOUT`] by an order of magnitude, and one wake-up a second
/// on a connected session costs nothing — silence is the *only* signal a
/// server that does not speak the punch gives, so the whole fall-through to
/// the buddy hangs off this tick.
pub(crate) const INTRODUCTION_POLL: Duration = Duration::from_secs(1);

/// How long a `0x60` waits for either answer. A server that does not speak
/// the punch ignores the opcode entirely, so this silence is the *only*
/// signal there — and the cue to fall back to the buddy coordinator. The same
/// fifteen seconds the buddy path gives its hint.
pub(crate) const INTRODUCTION_TIMEOUT: Duration = super::requester::HINT_TIMEOUT;

/// The login's `0xF9` advert from what is actually bound. `None` without an
/// IPv4 client-UDP bind: the tag's presence claims we can be punched, and the
/// punch is IPv4.
pub(crate) fn udp_ports_advert(
    client_udp_v4_port: Option<u16>,
    kad_udp_port: Option<u16>,
) -> Option<UdpPortsAdvert> {
    client_udp_v4_port.map(|client_udp| UdpPortsAdvert {
        kad_udp: kad_udp_port.unwrap_or(0),
        client_udp,
    })
}

/// One keepalive, addressed to the server's UDP port (TCP + 4) — for the
/// **client-UDP** send half and no other. Its source port is the whole
/// message: the server hands whatever port it arrived from to anyone who
/// asks to punch us. `None` for a server reached over IPv6 (the punch is
/// IPv4, and an IPv6 session's address says nothing about our IPv4 mapping)
/// or whose port leaves no room for + 4.
pub(crate) fn keepalive_send(server: PeerEndpoint, our_hash: &UserHash) -> Option<ClientUdpSend> {
    let server = server.as_v4()?;
    let port = natt_keepalive_port(server.port)?;
    Some(ClientUdpSend::plaintext(
        PeerEndpoint::V4(Ipv4Endpoint::new(server.ip, port)),
        natt_keepalive_datagram(our_hash),
    ))
}

/// What an introduction led to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntroductionVerdict {
    /// Fire the burst at `target` now.
    Punch {
        peer_hash: UserHash,
        target: Ipv4Endpoint,
        /// What the server said, for diagnostics. Never a reason to wait.
        role: HolepunchRole,
    },
    /// Dropped, silently.
    Refuse(IntroductionRefusal),
}

/// Why an introduction was not acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntroductionRefusal {
    /// The endpoint is not publicly routable. A server on the same LAN as a
    /// client observes a private address; a punch there opens nothing.
    NotPublic,
    /// The endpoint is one of our own interfaces.
    SelfPunch,
    /// This destination was punched inside the window — which is also how
    /// the server's own 1.2 s and 3 s re-sends of the same INFO are absorbed.
    Repeat,
}

/// What a refusal or a silence means for the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntroductionFailure {
    /// The server said no. `permanent` reasons end the server path for this
    /// target for the session; the caller asks
    /// [`next_natt_coordinator`](crate::callback::next_natt_coordinator).
    Refused {
        reason: HolepunchFailReason,
        permanent: bool,
    },
    /// Nothing came back in [`INTRODUCTION_TIMEOUT`] — a server that does not
    /// speak the punch, or a lost frame. Indistinguishable, and treated the
    /// same: move on.
    Silence,
}

/// The server coordinator's ledger.
#[derive(Debug)]
pub(crate) struct ServerPunch {
    /// Requests sent and not yet answered, by the Low-ID they named.
    pending: HashMap<ClientId, Instant>,
    /// One burst per destination per window. Its own table — never the relay
    /// service's — for the reason the acting path keeps its own.
    destinations: IntervalLimiter,
}

impl Default for ServerPunch {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            destinations: IntervalLimiter::new(ACTING_MIN_INTERVAL, ACTING_TRACKED_MAX),
        }
    }
}

impl ServerPunch {
    /// A `0x60` naming `target` went out.
    pub(crate) fn on_request(&mut self, target: ClientId, now: Instant) {
        self.pending.insert(target, now);
    }

    /// An `OP_LOWID_HOLEPUNCH_INFO` arrived — asked for or not; the server
    /// sends it to both sides and the target's copy is unsolicited by design.
    ///
    /// INFO names no target ID, so it cannot be matched to a request by
    /// anything it carries. It settles a pending request only when exactly
    /// one is outstanding; with several, each is left to its own timeout
    /// rather than guessed at.
    pub(crate) fn on_info(
        &mut self,
        info: &HolepunchInfo,
        is_own_interface: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> IntroductionVerdict {
        let target = info.peer_udp;
        if target.port == 0 || !is_public_punch_address(target.ip) {
            return IntroductionVerdict::Refuse(IntroductionRefusal::NotPublic);
        }
        if is_own_interface(IpAddr::V4(target.ip)) {
            return IntroductionVerdict::Refuse(IntroductionRefusal::SelfPunch);
        }
        if !self
            .destinations
            .admit(AccountingKey::of(target.ip.into()), now)
        {
            return IntroductionVerdict::Refuse(IntroductionRefusal::Repeat);
        }
        if self.pending.len() == 1 {
            self.pending.clear();
        }
        IntroductionVerdict::Punch {
            peer_hash: info.peer_hash,
            target,
            role: info.role,
        }
    }

    /// An `OP_LOWID_HOLEPUNCH_FAIL` arrived. `None` when it names a target we
    /// have no request outstanding for — a late or stray refusal changes
    /// nothing.
    pub(crate) fn on_fail(&mut self, fail: &HolepunchFail) -> Option<IntroductionFailure> {
        self.pending.remove(&fail.target)?;
        Some(IntroductionFailure::Refused {
            reason: fail.reason,
            permanent: fail.reason.is_permanent(),
        })
    }

    /// Requests that have waited [`INTRODUCTION_TIMEOUT`] with no answer,
    /// each settled as [`IntroductionFailure::Silence`] and forgotten — the
    /// same vocabulary a refusal speaks, so a caller falls back on one type.
    pub(crate) fn overdue(&mut self, now: Instant) -> Vec<(ClientId, IntroductionFailure)> {
        let overdue: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, sent)| now.saturating_duration_since(**sent) >= INTRODUCTION_TIMEOUT)
            .map(|(target, _)| *target)
            .collect();
        overdue
            .into_iter()
            .map(|target| {
                self.pending.remove(&target);
                (target, IntroductionFailure::Silence)
            })
            .collect()
    }

    /// The session ended: every outstanding request died with it. Returns the
    /// targets it was still waiting on, so their attempts hear about it
    /// instead of waiting out a timeout no clock will reach — the session that
    /// owned the clock is the thing that just went away.
    pub(crate) fn on_session_closed(&mut self) -> Vec<ClientId> {
        self.pending.drain().map(|(target, _)| target).collect()
    }
}

/// The server coordinator as the running node holds it: the ledger, the
/// client-UDP send half a burst and the keepalive leave by, and whether the
/// connected session is one the server can introduce us through.
///
/// One cell, cloned to the places that need it — establishment (which
/// advertises, starts the keepalive and records the session it runs on), the
/// session multiplexer (which hears the server's answers and clears that
/// session as it ends); its [`CoordinatorSession`] reaches **Self Reach**
/// (which reads it) and the **NAT-T Front** (which asks an introduction
/// through it). The send half is late-bound for the reason the session's
/// other cells are: the client-UDP socket is bound by the actor, after this
/// cell was woven in.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedServerPunch {
    inner: std::sync::Arc<SharedInner>,
}

#[derive(Debug, Default)]
struct SharedInner {
    ledger: std::sync::Mutex<ServerPunch>,
    client_udp: std::sync::OnceLock<tokio::sync::mpsc::Sender<ClientUdpSend>>,
    /// The session an introduction is asked through, while it can be.
    session: CoordinatorSession,
    /// Where punches and the server's stated refusals are reported. Late-bound
    /// like the send half; absent, nothing is counted and nothing else changes.
    diagnostics: std::sync::OnceLock<crate::diagnostics::DiagnosticsState>,
    /// The **NAT-T Front**'s command half. The burst below is the half this
    /// cell can fire from inside the multiplexer's loop; raising the Tunnel
    /// needs a task, and that task is the front's. Absent, an introduction
    /// still punches — it simply never becomes a transport.
    natt_front: std::sync::OnceLock<super::front::SharedNattFront>,
}

impl SharedServerPunch {
    /// Install the client-UDP send half. Idempotent: the socket is bound once.
    pub(crate) fn install_client_udp(&self, tx: tokio::sync::mpsc::Sender<ClientUdpSend>) {
        let _ = self.inner.client_udp.set(tx);
    }

    /// Install where outcomes are reported.
    pub(crate) fn install_diagnostics(&self, diagnostics: crate::diagnostics::DiagnosticsState) {
        let _ = self.inner.diagnostics.set(diagnostics);
    }

    /// Install the **NAT-T Front**'s command half. Idempotent: one front per
    /// core.
    pub(crate) fn install_natt_front(&self, front: super::front::SharedNattFront) {
        let _ = self.inner.natt_front.set(front);
    }

    /// The client-UDP send half, once bound.
    pub(crate) fn client_udp(&self) -> Option<&tokio::sync::mpsc::Sender<ClientUdpSend>> {
        self.inner.client_udp.get()
    }

    /// Whether the connected session advertised `0xF9` and its keepalive is
    /// running — **Self Reach**'s "Server Coordinator live" family.
    #[cfg(test)]
    pub(crate) fn is_live(&self) -> bool {
        self.inner.session.is_live()
    }

    /// The session cell: what **Self Reach** reads and the **NAT-T Front**
    /// asks an introduction through.
    pub(crate) fn coordinator_session(&self) -> CoordinatorSession {
        self.inner.session.clone()
    }

    /// The keepalive started on `session` (establishment, the family's
    /// writer): we can be introduced through it until it ends.
    pub(crate) fn go_live(&self, session: &crate::server_session::ServerSessionHandle) {
        self.inner
            .session
            .0
            .send_replace(Some(session.coordinator_link()));
    }

    /// The session behind `ended` ended (its own exit, the family's writer):
    /// nothing can be asked through it, and every request it still waited on
    /// has failed. Only the link this session set is cleared: a newer login
    /// may have taken the cell before this exit ran, and that one stays live.
    pub(crate) fn go_dark(&self, ended: &crate::server_session::SessionLink) {
        let cleared = self.inner.session.0.send_if_modified(|held| {
            if held.as_ref().is_some_and(|link| link.is_session(ended)) {
                *held = None;
                true
            } else {
                false
            }
        });
        if !cleared {
            // A newer session owns the cell and the ledger's waits: they are
            // not this exit's to fail.
            return;
        }
        let abandoned = self.ledger().on_session_closed();
        for target in abandoned {
            self.report_failure(target, IntroductionFailure::Silence);
        }
    }

    pub(crate) fn ledger(&self) -> std::sync::MutexGuard<'_, ServerPunch> {
        self.inner.ledger.lock().expect("server punch ledger")
    }

    /// Decide one introduction and, on a punch, put the whole burst on the
    /// client-UDP send half — six at the endpoint the server observed, then
    /// the sweep. `try_send`, never `send`: the multiplexer calls this from
    /// its event loop, and a full send queue must cost a punch, not stall the
    /// server session behind it.
    pub(crate) fn on_info(
        &self,
        info: &HolepunchInfo,
        is_own_interface: impl FnOnce(IpAddr) -> bool,
        now: Instant,
    ) -> IntroductionVerdict {
        let verdict = self.ledger().on_info(info, is_own_interface, now);
        if let (IntroductionVerdict::Punch { target, .. }, Some(tx)) = (verdict, self.client_udp())
        {
            if let Some(diagnostics) = self.inner.diagnostics.get() {
                diagnostics.count_natt_server_punch();
            }
            for endpoint in rmule_peer::natt::punch_burst(target) {
                let send = ClientUdpSend::plaintext(
                    PeerEndpoint::V4(endpoint),
                    rmule_peer::natt::holepunch_datagram(),
                );
                if tx.try_send(send).is_err() {
                    break;
                }
            }
        }
        // The punch is a trigger; the transport over it is the front's. Told
        // after the burst, so the expectation the front records is never older
        // than the datagrams that opened the mapping it describes.
        if let IntroductionVerdict::Punch {
            peer_hash,
            target,
            role,
        } = verdict
        {
            // One branch for both ways this comes to nothing — a full inbox,
            // and a cell no front ever filled. The second was **silent**: an
            // introduction the server delivered, a burst that left, and nothing
            // anywhere saying the transport was never asked for.
            let taken = self.inner.natt_front.get().is_some_and(|front| {
                front.send(super::front::NattCommand::Introduced {
                    peer_hash,
                    target,
                    role,
                    // The `0x61` path's burst left inside this same session
                    // loop, above; the front adopts the role for an endpoint
                    // already punched at.
                    burst: false,
                    // The server saw the peer's UDP source itself.
                    source: rmule_peer::natt::PunchTargetSource::Observed,
                })
            });
            if !taken {
                tracing::warn!(
                    ?target,
                    "the NAT-T front did not take the server introduction; \
                     the burst stands alone and no transport will rise"
                );
            }
        }
        verdict
    }
}

/// The **Server Coordinator**'s session cell (ADR-0060 "Server Coordinator
/// live", ADR-0091): the session we can be introduced through, while one can
/// be. One writer — the server session: set when establishment starts the
/// `0x9F` keepalive, cleared by the session's own exit. A `watch`, so its
/// moves wake the **Reach Generation**; a session that died without its exit
/// reads dark at the next read, because the link it holds is weak.
#[derive(Clone, Debug)]
pub(crate) struct CoordinatorSession(
    std::sync::Arc<tokio::sync::watch::Sender<Option<crate::server_session::SessionLink>>>,
);

impl Default for CoordinatorSession {
    fn default() -> Self {
        Self(std::sync::Arc::new(tokio::sync::watch::Sender::new(None)))
    }
}

impl CoordinatorSession {
    /// Whether a session that advertised `0xF9` holds the cell and still
    /// runs.
    pub(crate) fn is_live(&self) -> bool {
        self.0
            .borrow()
            .as_ref()
            .is_some_and(crate::server_session::SessionLink::is_alive)
    }

    /// Ask the live session's server to introduce us to the Low-ID `target`
    /// (`0x60`), naming `our_udp_port`, reporting whether the request was
    /// queued. Never awaited: no live session, or a full one, is `false`.
    pub(crate) fn request_introduction(&self, target: ClientId, our_udp_port: u16) -> bool {
        self.0
            .borrow()
            .as_ref()
            .is_some_and(|link| link.request_holepunch(target, our_udp_port))
    }

    /// A change subscription: wakes when a session goes live or dark.
    pub(crate) fn subscribe(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<crate::server_session::SessionLink>> {
        self.0.subscribe()
    }
}

impl SharedServerPunch {
    /// Settle one refusal, report its reason, and hand the outcome to the
    /// **Traversal Attempt** that asked. The reason is counted
    /// even for a refusal naming no outstanding request: it is still something
    /// the server said about a target, and the count is of what the server
    /// said.
    pub(crate) fn on_fail(&self, fail: &HolepunchFail) -> Option<IntroductionFailure> {
        if let Some(diagnostics) = self.inner.diagnostics.get() {
            diagnostics.record_natt_server_refusal(fail.reason);
        }
        let outcome = self.ledger().on_fail(fail);
        if let Some(failure) = outcome {
            self.report_failure(fail.target, failure);
        }
        outcome
    }

    /// Read the introduction clock at `now`: every `0x60` that has waited
    /// [`INTRODUCTION_TIMEOUT`] is settled as silence and reported.
    ///
    /// Driven by the session's own loop, because the session is the
    /// introduction's lifetime — the same reason the `0x9F` keepalive's
    /// cadence lives there. Nothing else in the process has a clock over this
    /// ledger, so without this call a server that simply ignores the opcode
    /// would never hand the attempt on to the buddy.
    pub(crate) fn poll_overdue(&self, now: Instant) {
        // The guard is released before anything is reported: reporting reaches
        // the NAT-T front's inbox, and holding a ledger lock across it would
        // order two loops against each other for no reason.
        let overdue = self.ledger().overdue(now);
        for (target, failure) in overdue {
            self.report_failure(target, failure);
        }
    }

    /// Tell the **NAT-T Front** that the introduction naming `target` is over.
    ///
    /// The front holds the attempt — which target hash the id belongs to, the
    /// candidate's facts, and therefore who can be asked next; this cell holds
    /// only what the server session can see. A front that never existed, or
    /// one whose inbox is full, costs the fall-through: said aloud, because
    /// the whole point of the attempt is that an introduction's death is no
    /// longer silent.
    fn report_failure(&self, target: ClientId, failure: IntroductionFailure) {
        let taken = self.inner.natt_front.get().is_some_and(|front| {
            front.send(super::front::NattCommand::IntroductionFailed { target, failure })
        });
        if !taken {
            tracing::warn!(
                target = target.as_u32(),
                ?failure,
                "a settled server introduction did not reach the NAT-T front; \
                 nothing will fall through to the buddy"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn info_at(ip: [u8; 4], port: u16) -> HolepunchInfo {
        HolepunchInfo {
            peer_udp: Ipv4Endpoint::new(ip.into(), port),
            peer_tcp_port: 4662,
            peer_hash: UserHash::from_bytes([0x44; 16]),
            role: HolepunchRole::Responder,
        }
    }

    /// The server's copy to the *target* is unsolicited by design, so an
    /// introduction is acted on with no request outstanding — and at once,
    /// whatever role it was handed. Then the server's own re-sends, 1.2 s and
    /// 3 s later, are absorbed rather than fired as second and third bursts.
    #[test]
    fn an_introduction_is_punched_at_once_and_its_resends_are_absorbed() {
        let mut punch = ServerPunch::default();
        let t0 = Instant::now();
        let info = info_at([45, 55, 200, 7], 31999);
        assert_eq!(
            punch.on_info(&info, |_| false, t0),
            IntroductionVerdict::Punch {
                peer_hash: UserHash::from_bytes([0x44; 16]),
                target: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 31999),
                role: HolepunchRole::Responder,
            }
        );
        for resend in [1200, 3000] {
            assert_eq!(
                punch.on_info(&info, |_| false, t0 + Duration::from_millis(resend)),
                IntroductionVerdict::Refuse(IntroductionRefusal::Repeat)
            );
        }
        assert!(matches!(
            punch.on_info(&info, |_| false, t0 + ACTING_MIN_INTERVAL),
            IntroductionVerdict::Punch { .. }
        ));
    }

    /// The server observed it, so there is no claim to judge — but "observed"
    /// is not "routable": a server beside a client on a LAN observes a
    /// private address, and a null port is a client the server knows no UDP
    /// port for. Neither refusal spends the destination's window.
    #[test]
    fn an_introduction_to_an_unroutable_or_own_endpoint_is_not_punched() {
        let mut punch = ServerPunch::default();
        let t0 = Instant::now();
        for (ip, port) in [([192, 168, 1, 20], 31999), ([45, 55, 200, 7], 0)] {
            assert_eq!(
                punch.on_info(&info_at(ip, port), |_| false, t0),
                IntroductionVerdict::Refuse(IntroductionRefusal::NotPublic)
            );
        }
        let good = info_at([45, 55, 200, 7], 31999);
        assert_eq!(
            punch.on_info(&good, |_| true, t0),
            IntroductionVerdict::Refuse(IntroductionRefusal::SelfPunch)
        );
        assert!(matches!(
            punch.on_info(&good, |_| false, t0),
            IntroductionVerdict::Punch { .. }
        ));
    }

    /// A refusal names its target, so it settles exactly that request and
    /// says whether the server path is over for it; one naming a target we
    /// never asked about settles nothing.
    #[test]
    fn a_refusal_settles_the_request_it_names_and_only_that_one() {
        let mut punch = ServerPunch::default();
        let t0 = Instant::now();
        punch.on_request(ClientId::from_u32(7), t0);
        punch.on_request(ClientId::from_u32(8), t0);

        let stray = HolepunchFail {
            target: ClientId::from_u32(99),
            reason: HolepunchFailReason::TargetNotConnected,
        };
        assert_eq!(punch.on_fail(&stray), None);

        let highid = HolepunchFail {
            target: ClientId::from_u32(7),
            reason: HolepunchFailReason::TargetIsHighId,
        };
        assert_eq!(
            punch.on_fail(&highid),
            Some(IntroductionFailure::Refused {
                reason: HolepunchFailReason::TargetIsHighId,
                permanent: true,
            })
        );
        assert_eq!(punch.on_fail(&highid), None, "settled once");
        assert_eq!(
            punch.overdue(t0 + INTRODUCTION_TIMEOUT),
            vec![(ClientId::from_u32(8), IntroductionFailure::Silence)],
            "the other request is still its own"
        );
    }

    /// A server that does not speak the punch answers nothing at all, so
    /// silence is the only signal. An overdue request is reported once. And
    /// because INFO names no target, it settles a request only when exactly
    /// one is outstanding — with two, neither is guessed at.
    #[test]
    fn silence_is_reported_once_and_an_info_settles_only_an_unambiguous_request() {
        let t0 = Instant::now();
        let mut punch = ServerPunch::default();
        punch.on_request(ClientId::from_u32(7), t0);
        assert!(
            punch
                .overdue(t0 + INTRODUCTION_TIMEOUT - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(
            punch.overdue(t0 + INTRODUCTION_TIMEOUT),
            vec![(ClientId::from_u32(7), IntroductionFailure::Silence)]
        );
        assert!(punch.overdue(t0 + INTRODUCTION_TIMEOUT * 2).is_empty());

        let mut one = ServerPunch::default();
        one.on_request(ClientId::from_u32(7), t0);
        one.on_info(&info_at([45, 55, 200, 7], 31999), |_| false, t0);
        assert!(one.overdue(t0 + INTRODUCTION_TIMEOUT).is_empty());

        let mut two = ServerPunch::default();
        two.on_request(ClientId::from_u32(7), t0);
        two.on_request(ClientId::from_u32(8), t0);
        two.on_info(&info_at([45, 55, 200, 7], 31999), |_| false, t0);
        assert_eq!(two.overdue(t0 + INTRODUCTION_TIMEOUT).len(), 2);
    }

    /// A session that exits after a newer login took the cell clears nothing:
    /// the family stays live on the newer session.
    #[tokio::test]
    async fn a_stale_sessions_exit_leaves_the_newer_coordinator_live() {
        let punch = SharedServerPunch::default();
        let (stale, _stale_events, _stale_sent) = crate::server_session::tests::fake_session(
            crate::server_session::tests::connected(),
            rmule_ed2k::ServerGrants::default(),
        );
        let (newer, _newer_events, _newer_sent) = crate::server_session::tests::fake_session(
            crate::server_session::tests::connected(),
            rmule_ed2k::ServerGrants::default(),
        );
        punch.go_live(&stale);
        punch.go_live(&newer);

        punch.go_dark(&stale.coordinator_link());
        assert!(punch.is_live(), "the newer login is still the coordinator");

        punch.go_dark(&newer.coordinator_link());
        assert!(!punch.is_live());
    }

    /// Live: an introduction becomes the burst on the client-UDP send half —
    /// six empty punches at the observed endpoint, then the sweep — and a
    /// refused one sends nothing. With no send half installed the decision
    /// still stands; there is simply nowhere to fire from.
    #[tokio::test]
    async fn a_punch_verdict_puts_the_whole_burst_on_the_client_udp_socket() {
        let shared = SharedServerPunch::default();
        let info = info_at([45, 55, 200, 7], 31999);
        assert!(matches!(
            SharedServerPunch::default().on_info(&info, |_| false, Instant::now()),
            IntroductionVerdict::Punch { .. }
        ));

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        shared.install_client_udp(tx);
        shared.on_info(&info, |_| false, Instant::now());
        let mut ports = Vec::new();
        while let Ok(send) = rx.try_recv() {
            assert_eq!(send.datagram, [0xC5, 0xA1]);
            assert!(send.crypt_target.is_none());
            ports.push(send.to.port());
        }
        assert_eq!(ports.len(), 6 + 32);
        assert!(ports[..6].iter().all(|port| *port == 31999));

        shared.on_info(&info, |_| false, Instant::now());
        assert!(rx.try_recv().is_err(), "a repeat fires nothing");
    }

    /// The advert exists only with an IPv4 client-UDP bind; a Kad port that
    /// is not running rides as zero rather than suppressing the tag. The
    /// keepalive goes to TCP + 4 over IPv4, and a server reached over IPv6
    /// gets none — its session says nothing about our IPv4 mapping.
    #[test]
    fn the_advert_and_the_keepalive_follow_what_is_actually_bound() {
        assert_eq!(udp_ports_advert(None, Some(4672)), None);
        assert_eq!(
            udp_ports_advert(Some(4665), None).map(UdpPortsAdvert::word),
            Some(4665)
        );
        assert_eq!(
            udp_ports_advert(Some(4665), Some(4672)).map(UdpPortsAdvert::word),
            Some(0x1240_1239)
        );

        let hash = UserHash::from_bytes([0x5A; 16]);
        let v4 = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661));
        let send = keepalive_send(v4, &hash).expect("an IPv4 server");
        assert_eq!(
            send.to,
            PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4665))
        );
        assert_eq!(&send.datagram[..2], &[0xE3, 0x9F]);
        assert!(send.crypt_target.is_none());

        let v6 = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
            "2a01:4f8::1".parse().unwrap(),
            4661,
        ));
        assert!(keepalive_send(v6, &hash).is_none());
    }
}
