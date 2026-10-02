//! **CAPS Negotiation** — the per-endpoint state that decides which transport
//! a tunnel raises, and when it is allowed to start.
//!
//! Two stages, in eMuleAI's order. The hello's `CT_MOD_MISCOPTIONS` bits say
//! what a peer's *build* can do; a CAPS exchange says what this *endpoint*
//! will do now, and overrides the hello view for that endpoint. The gap
//! between them is real: a build ships QUIC code and advertises bit 4, then
//! has no runtime to serve it.
//!
//! Sans-I/O and explicit-time: every method takes the `now` its caller read.
//! The socket, the probe bursts and the retry schedule are elsewhere — the
//! bursts and the ½-RTT schedule belong to the punch and rendezvous layers.

use std::time::{Duration, Instant};

use super::caps::{NattConnectOptions, NattTransport};

/// `DIRECT_NATT_CAPS_LEGACY_TIMEOUT_MS` — how long a CAPS probe may go
/// unanswered before a peer that claimed uTP and **not** QUIC is treated as
/// legacy-uTP-only. This is the cost an optimistic bit 4 imposes on the other
/// side, which is why rmule does not set one.
pub const CAPS_LEGACY_TIMEOUT: Duration = Duration::from_millis(1500);

/// `NAT_TRAVERSAL_QUIC_FAILURE_TTL_MS` — how long one QUIC failure keeps QUIC
/// off an endpoint. Per endpoint, not per peer: a peer behind a NAT that
/// mangles QUIC on one mapping may be fine on the next.
pub const QUIC_FAILURE_TTL: Duration = Duration::from_secs(120);

/// What a peer's hello claimed about NAT-T — `CT_MOD_MISCOPTIONS` bits 1 and
/// 4, read as a pair because the *combination* is what decides whether a
/// silent endpoint may be treated as legacy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelloNattClaim {
    /// Bit 1 `MODMISC_NAT_TRAVERSAL`: uTP NAT traversal.
    pub utp: bool,
    /// Bit 4 `MODMISC_NAT_TRAVERSAL_QUIC`: QUIC NAT traversal.
    pub quic: bool,
}

impl HelloNattClaim {
    /// A peer that claimed uTP and not QUIC — the only shape the 1500 ms
    /// legacy fallback applies to, because for it a CAPS answer could not
    /// have improved on what the hello already said.
    #[must_use]
    pub const fn is_legacy_utp_only(self) -> bool {
        self.utp && !self.quic
    }

    /// Whether the peer claimed any NAT-T at all.
    #[must_use]
    pub const fn claims_any(self) -> bool {
        self.utp || self.quic
    }
}

/// What the negotiation says a caller may do with this endpoint right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportVerdict {
    /// Raise a tunnel on this transport.
    Ready(NattTransport),

    /// A CAPS probe is outstanding and could still name something better. The
    /// peer claimed QUIC, so starting uTP now would throw away the answer it
    /// is about to give; wait out [`CAPS_LEGACY_TIMEOUT`].
    AwaitingCaps,

    /// Neither side offers a transport both can speak.
    Unsupported,
}

/// One endpoint's negotiation state.
///
/// Keyed by endpoint rather than by peer, deliberately: the QUIC blacklist,
/// the probe timer and the caps answer are all facts about a `(ip, port)`
/// mapping, and a peer reached through a fresh punch is a fresh mapping.
#[derive(Clone, Debug)]
pub struct CapsNegotiation {
    hello: HelloNattClaim,
    probe_sent_at: Option<Instant>,
    direct_caps: Option<NattConnectOptions>,
    quic_failed_at: Option<Instant>,
    utp_pinned: bool,
}

impl CapsNegotiation {
    /// A fresh endpoint, knowing only what the peer's hello claimed.
    #[must_use]
    pub const fn new(hello: HelloNattClaim) -> Self {
        Self {
            hello,
            probe_sent_at: None,
            direct_caps: None,
            quic_failed_at: None,
            utp_pinned: false,
        }
    }

    /// Record that a CAPS probe went out at `now`. Re-probing restarts the
    /// window: the peer is being asked again, so it gets the full answer time
    /// again.
    pub const fn probe_sent(&mut self, now: Instant) {
        self.probe_sent_at = Some(now);
    }

    /// Whether a probe is outstanding — no answer yet, and one was sent.
    #[must_use]
    pub const fn probe_outstanding(&self) -> bool {
        self.probe_sent_at.is_some() && self.direct_caps.is_none()
    }

    /// Adopt the connect-options byte a CAPS or CAPS-ACK carried. This
    /// **overrides** the hello view for this endpoint from here on, in both
    /// directions: an endpoint that answers "uTP only" is uTP-only even though
    /// its build advertised QUIC.
    pub const fn caps_answered(&mut self, options: NattConnectOptions) {
        self.direct_caps = Some(options);
    }

    /// Whether this endpoint has proven direct caps — the fact that lets a
    /// QUIC proof refresh a contradicting user hash
    /// ([`QuicProof::judge`](super::QuicProof::judge)).
    #[must_use]
    pub const fn has_direct_caps(&self) -> bool {
        self.direct_caps.is_some()
    }

    /// Blacklist QUIC on this endpoint for [`QUIC_FAILURE_TTL`].
    pub const fn quic_failed(&mut self, now: Instant) {
        self.quic_failed_at = Some(now);
    }

    /// Whether QUIC is currently blacklisted here.
    #[must_use]
    pub fn quic_blacklisted(&self, now: Instant) -> bool {
        self.quic_failed_at
            .is_some_and(|at| now.duration_since(at) < QUIC_FAILURE_TTL)
    }

    /// Pin uTP for this endpoint — what a rendezvous carrying a uTP transport
    /// hint does. A pin is unconditional: the requester already told its
    /// buddy which transport it would punch for, and answering on another one
    /// reaches nothing.
    pub const fn pin_utp(&mut self) {
        self.utp_pinned = true;
    }

    /// The transport to raise, or why not.
    ///
    /// `local` is rmule's own posture — which transports this build will
    /// actually serve. `local.quic` is false by default: rmule is
    /// uTP-only exactly like an eMuleAI build with no QUIC runtime, and both
    /// this flag and `CT_MOD_MISCOPTIONS` bit 4 flip together once a live
    /// handshake is proven (ADR-0091).
    #[must_use]
    pub fn verdict(&self, now: Instant, local: HelloNattClaim) -> TransportVerdict {
        if self.utp_pinned {
            return if local.utp {
                TransportVerdict::Ready(NattTransport::Utp)
            } else {
                TransportVerdict::Unsupported
            };
        }
        let quic_allowed = local.quic && !self.quic_blacklisted(now);
        // A CAPS answer replaces the hello view entirely — for this endpoint
        // it is the more recent and more specific statement.
        if let Some(caps) = self.direct_caps {
            return match caps.preferred_transport(quic_allowed) {
                Some(NattTransport::Quic) => TransportVerdict::Ready(NattTransport::Quic),
                Some(NattTransport::Utp) if local.utp => {
                    TransportVerdict::Ready(NattTransport::Utp)
                }
                _ => TransportVerdict::Unsupported,
            };
        }
        // No answer yet. A peer that claimed QUIC may still be about to say
        // so; starting uTP before it answers would discard that. A peer that
        // claimed only uTP has nothing better to say, so once the window has
        // passed it is legacy-uTP-only and uTP starts.
        if self.probe_outstanding()
            && !self.hello.is_legacy_utp_only()
            && self
                .probe_sent_at
                .is_some_and(|at| now.duration_since(at) < CAPS_LEGACY_TIMEOUT)
        {
            return TransportVerdict::AwaitingCaps;
        }
        let hello_view = NattConnectOptions::advertise(0, self.hello.utp, self.hello.quic);
        match hello_view.preferred_transport(quic_allowed) {
            Some(NattTransport::Quic) => TransportVerdict::Ready(NattTransport::Quic),
            Some(NattTransport::Utp) if local.utp => TransportVerdict::Ready(NattTransport::Utp),
            _ => TransportVerdict::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rmule's shipped posture: uTP served, QUIC dark.
    const UTP_ONLY: HelloNattClaim = HelloNattClaim {
        utp: true,
        quic: false,
    };
    /// What a build with a working QUIC runtime would hold.
    const BOTH: HelloNattClaim = HelloNattClaim {
        utp: true,
        quic: true,
    };

    /// A peer that claimed only uTP is *not* worth waiting on: the CAPS answer
    /// cannot say anything the hello did not, so uTP starts immediately.
    #[test]
    fn a_legacy_utp_only_peer_never_stalls_on_the_caps_probe() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(UTP_ONLY);
        state.probe_sent(now);
        assert_eq!(
            state.verdict(now, UTP_ONLY),
            TransportVerdict::Ready(NattTransport::Utp)
        );
    }

    /// A peer that claimed QUIC is worth 1500 ms — and not a millisecond
    /// more. That bound is the whole reason rmule does not advertise bit 4:
    /// the cost of an optimistic claim falls on the peer, not the claimer.
    #[test]
    fn a_quic_claiming_peer_is_waited_on_for_exactly_the_legacy_timeout() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(BOTH);
        state.probe_sent(now);
        assert_eq!(state.verdict(now, UTP_ONLY), TransportVerdict::AwaitingCaps);
        assert_eq!(
            state.verdict(
                now + CAPS_LEGACY_TIMEOUT - Duration::from_millis(1),
                UTP_ONLY
            ),
            TransportVerdict::AwaitingCaps
        );
        assert_eq!(
            state.verdict(now + CAPS_LEGACY_TIMEOUT, UTP_ONLY),
            TransportVerdict::Ready(NattTransport::Utp)
        );
    }

    /// A CAPS answer overrides the hello in *both* directions — including the
    /// unflattering one, where a build that advertised QUIC admits this
    /// endpoint cannot serve it.
    #[test]
    fn a_caps_answer_overrides_the_hello_view_even_downward() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(BOTH);
        state.probe_sent(now);
        state.caps_answered(NattConnectOptions::advertise(0, true, false));
        assert_eq!(
            state.verdict(now, BOTH),
            TransportVerdict::Ready(NattTransport::Utp)
        );
        assert!(state.has_direct_caps());
        assert!(!state.probe_outstanding());
    }

    /// One QUIC failure demotes the endpoint to uTP for two minutes, then it
    /// is eligible again — a mapping, not a peer, is what failed.
    #[test]
    fn a_quic_failure_demotes_the_endpoint_for_the_blacklist_window() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(BOTH);
        state.caps_answered(NattConnectOptions::advertise(0, true, true));
        assert_eq!(
            state.verdict(now, BOTH),
            TransportVerdict::Ready(NattTransport::Quic)
        );
        state.quic_failed(now);
        assert_eq!(
            state.verdict(now, BOTH),
            TransportVerdict::Ready(NattTransport::Utp)
        );
        assert_eq!(
            state.verdict(now + QUIC_FAILURE_TTL - Duration::from_millis(1), BOTH),
            TransportVerdict::Ready(NattTransport::Utp)
        );
        assert_eq!(
            state.verdict(now + QUIC_FAILURE_TTL, BOTH),
            TransportVerdict::Ready(NattTransport::Quic)
        );
    }

    /// rmule's own posture is a veto, not a preference: with QUIC dark, a
    /// QUIC-capable peer still gets uTP, and that is what "uTP-only like an
    /// eMuleAI build without its QUIC runtime" means on the wire.
    #[test]
    fn a_dark_local_quic_bit_demotes_every_peer_to_utp() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(BOTH);
        state.caps_answered(NattConnectOptions::advertise(0, true, true));
        assert_eq!(
            state.verdict(now, UTP_ONLY),
            TransportVerdict::Ready(NattTransport::Utp)
        );
    }

    /// A uTP pin from a rendezvous is unconditional — the requester already
    /// told its buddy which transport it punched for.
    #[test]
    fn a_rendezvous_utp_pin_overrides_a_quic_capable_endpoint() {
        let now = Instant::now();
        let mut state = CapsNegotiation::new(BOTH);
        state.caps_answered(NattConnectOptions::advertise(0, true, true));
        state.pin_utp();
        assert_eq!(
            state.verdict(now, BOTH),
            TransportVerdict::Ready(NattTransport::Utp)
        );
    }

    /// A peer that claims no NAT-T at all gets no tunnel, probe or no probe.
    #[test]
    fn a_peer_claiming_no_transport_is_unsupported() {
        let now = Instant::now();
        let state = CapsNegotiation::new(HelloNattClaim::default());
        assert!(!HelloNattClaim::default().claims_any());
        assert_eq!(state.verdict(now, BOTH), TransportVerdict::Unsupported);
    }
}
