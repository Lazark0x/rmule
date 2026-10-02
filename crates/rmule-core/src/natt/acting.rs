//! The **acting path**: a rendezvous relayed *to us*, and whether rmule
//! punches because of it.
//!
//! eMuleAI's handler has no sender-identity gate at all — the buddy
//! assumption is a comment on its first line. rmule
//! takes kno's stricter reading: the frame must have come **from our buddy**.
//! The cost is real and recorded: a topology where eMuleAI accepts a
//! third-party forward, rmule refuses.
//!
//! The gates, in the order they are consulted:
//!
//! 1. **carrier** — the `0x9A` arrived on our buddy's TCP link, or the
//!    standalone `0xC5 0xA0` came from our buddy's exact UDP endpoint;
//! 2. **transport** — the requester claims a transport we can raise;
//! 3. **target** — the three-part precedence rule resolves a public endpoint;
//! 4. **self-punch** — that endpoint is not one of our own interfaces;
//! 5. **budget** — that endpoint has not been punched inside the window (the
//!    acting path's own limiter, never the relay service's).
//!
//! The budget is last so that only a rendezvous that would otherwise be
//! honoured stamps the clock: a malformed or unresolvable one cannot spend a
//! legitimate requester's window for it.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmule_peer::natt::{
    NattTransport, PunchTarget, RendezvousBody, RendezvousTrigger, resolve_punch_target,
};
use rmule_primitives::{AccountingKey, FileHash, Ipv4Endpoint, PeerEndpoint, UserHash};

use crate::interval_limiter::IntervalLimiter;

/// Minimum time between two bursts at one destination bucket —
/// eMuleAI's `ESERVERBUDDY_RELAY_REASK_TIME`, the only per-request relay
/// interval its tree publishes. A legitimate requester retries after a relay
/// timeout nearly twice this long, so the window never bites it.
pub(crate) const ACTING_MIN_INTERVAL: Duration = Duration::from_secs(8);

/// Hard cap on tracked destination buckets (see [`IntervalLimiter`]). The
/// carrier gate runs first, so only our own buddy can fill this table — the
/// cap bounds a buddy that misbehaves, not the open internet.
pub(crate) const ACTING_TRACKED_MAX: usize = 1024;

/// Which frame carried the rendezvous. **The frame is the direction** — and
/// the carrier is what the sender gate checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RendezvousCarrier {
    /// Embedded in an `OP_REASKCALLBACKTCP` (`0x9A`) on a peer-TCP link —
    /// eMuleAI's buddy. `link_peer` is that link's remote address and
    /// `observed` the requester endpoint the buddy injected ahead of the tail.
    BuddyTcp {
        link_peer: PeerEndpoint,
        observed: Ipv4Endpoint,
    },
    /// A standalone `0xC5 0xA0` datagram — kno's buddy. `from` is the
    /// datagram's source; nobody observed the requester, so only its claim
    /// can name it.
    Standalone { from: PeerEndpoint },
}

/// Our own facts the acting path reads.
pub(crate) struct ActingContext<K, I> {
    /// Our buddy's UDP endpoint (the firewalled-node slot), or `None` — with
    /// no buddy nothing can have been relayed to us.
    pub(crate) our_buddy: Option<Ipv4Endpoint>,
    /// The transports this node will raise right now.
    pub(crate) serves_quic: bool,
    /// Arm 3 of the precedence rule: the endpoint already held for the peer a
    /// claimed endpoint identifies.
    pub(crate) known_peer: K,
    /// Whether an address is on one of our own interfaces (Address
    /// Learning's interface set).
    pub(crate) is_own_interface: I,
}

/// What the acting path decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActingVerdict {
    /// Punch `target` and try `transport` toward `requester`. The schedule
    /// trigger is always [`RendezvousTrigger::RendezvousAnswer`] — the other
    /// side is punching now, so this is the attempt most worth repeating, and
    /// it is armed immediate rather than jittered.
    Punch {
        requester: UserHash,
        file_hash: Option<FileHash>,
        target: PunchTarget,
        transport: NattTransport,
        trigger: RendezvousTrigger,
    },
    /// Do nothing, silently — the dialect has no failure frame to send.
    Refuse(ActingRefusal),
}

/// Why a relayed rendezvous was not acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActingRefusal {
    /// The frame did not come from our buddy (or we hold none).
    NotFromOurBuddy,
    /// The requester claims no transport we can raise.
    NoCommonTransport,
    /// The resolved endpoint was punched inside the acting path's own
    /// minimum interval.
    RateLimited,
    /// No arm of the precedence rule produced a public endpoint.
    NoUsableTarget,
    /// The resolved endpoint is one of our own interfaces.
    SelfPunch,
}

/// The acting path's one piece of state: its own limiter.
#[derive(Debug)]
pub(crate) struct ActingPath {
    destinations: IntervalLimiter,
}

impl Default for ActingPath {
    fn default() -> Self {
        Self {
            destinations: IntervalLimiter::new(ACTING_MIN_INTERVAL, ACTING_TRACKED_MAX),
        }
    }
}

impl ActingPath {
    /// Decide one relayed rendezvous.
    pub(crate) fn consume<K, I>(
        &mut self,
        body: &RendezvousBody,
        carrier: RendezvousCarrier,
        ctx: ActingContext<K, I>,
        now: Instant,
    ) -> ActingVerdict
    where
        K: FnOnce(Ipv4Endpoint) -> Option<Ipv4Endpoint>,
        I: FnOnce(IpAddr) -> bool,
    {
        let Some(buddy) = ctx.our_buddy else {
            return ActingVerdict::Refuse(ActingRefusal::NotFromOurBuddy);
        };
        let observed = match carrier {
            // A buddy's TCP link is one *it dialed to us*, so its source port
            // is ephemeral: the match is on the address alone, as the buddy
            // ping's is.
            RendezvousCarrier::BuddyTcp {
                link_peer,
                observed,
            } if link_peer.ip() == IpAddr::V4(buddy.ip) => Some(observed),
            // A datagram has no connection behind it, so the whole endpoint
            // must match — the same rule the endpoint hint is held to.
            RendezvousCarrier::Standalone { from } if from == PeerEndpoint::V4(buddy) => None,
            _ => return ActingVerdict::Refuse(ActingRefusal::NotFromOurBuddy),
        };
        let Some(transport) = body.options.preferred_transport(ctx.serves_quic) else {
            return ActingVerdict::Refuse(ActingRefusal::NoCommonTransport);
        };
        let Some(target) = resolve_punch_target(observed, body.claimed_endpoint, ctx.known_peer)
        else {
            return ActingVerdict::Refuse(ActingRefusal::NoUsableTarget);
        };
        if (ctx.is_own_interface)(IpAddr::V4(target.endpoint.ip)) {
            return ActingVerdict::Refuse(ActingRefusal::SelfPunch);
        }
        // Bucketed on where the burst would land, not on who asked: the
        // requester hash is a free claim, and what the limit protects is the
        // address thirty-eight datagrams are about to be sent to.
        if !self
            .destinations
            .admit(AccountingKey::of(target.endpoint.ip.into()), now)
        {
            return ActingVerdict::Refuse(ActingRefusal::RateLimited);
        }
        ActingVerdict::Punch {
            requester: body.requester,
            file_hash: body.file_hash,
            target,
            transport,
            trigger: RendezvousTrigger::RendezvousAnswer,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_peer::natt::{NattConnectOptions, PunchTargetSource};

    use super::*;

    fn at(a: u8, b: u8, c: u8, d: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port)
    }

    fn buddy() -> Ipv4Endpoint {
        at(45, 55, 200, 2, 4672)
    }

    fn requester_seen() -> Ipv4Endpoint {
        at(45, 55, 200, 7, 5000)
    }

    fn body(options: u8, claimed: Option<Ipv4Endpoint>) -> RendezvousBody {
        RendezvousBody {
            requester: UserHash::from_bytes([0x11; 16]),
            options: NattConnectOptions::from_byte(options),
            file_hash: None,
            claimed_endpoint: claimed,
            transport_hint: None,
        }
    }

    fn via_buddy_tcp() -> RendezvousCarrier {
        RendezvousCarrier::BuddyTcp {
            // The buddy's address, an ephemeral port.
            link_peer: PeerEndpoint::V4(at(45, 55, 200, 2, 51123)),
            observed: requester_seen(),
        }
    }

    type Known = fn(Ipv4Endpoint) -> Option<Ipv4Endpoint>;
    type Own = fn(IpAddr) -> bool;

    fn ctx(our_buddy: Option<Ipv4Endpoint>) -> ActingContext<Known, Own> {
        ActingContext {
            our_buddy,
            serves_quic: false,
            known_peer: |_| None,
            is_own_interface: |_| false,
        }
    }

    /// The whole path, eMuleAI's carrier: from our buddy's link, a uTP
    /// claimant, aimed at what the buddy observed rather than what the
    /// requester said, armed as a rendezvous answer.
    #[test]
    fn a_rendezvous_on_our_buddys_link_punches_the_observed_endpoint() {
        let verdict = ActingPath::default().consume(
            &body(0x80, Some(at(45, 55, 200, 66, 9999))),
            via_buddy_tcp(),
            ctx(Some(buddy())),
            Instant::now(),
        );
        assert_eq!(
            verdict,
            ActingVerdict::Punch {
                requester: UserHash::from_bytes([0x11; 16]),
                file_hash: None,
                target: PunchTarget {
                    endpoint: requester_seen(),
                    source: PunchTargetSource::Observed,
                },
                transport: NattTransport::Utp,
                trigger: RendezvousTrigger::RendezvousAnswer,
            }
        );
    }

    /// The sender gate, every way it can fail: no buddy held; a `0x9A` on
    /// some other peer's link; a standalone datagram from a stranger; and one
    /// from our buddy's address but the wrong port — forgeable attribution
    /// (kno's audit finding F3 on amule#1177) is all a datagram has, so it is
    /// held to the whole endpoint.
    #[test]
    fn nothing_is_acted_on_unless_our_buddy_carried_it() {
        let claim = Some(at(45, 55, 200, 66, 9999));
        let refused = ActingVerdict::Refuse(ActingRefusal::NotFromOurBuddy);
        let mut path = ActingPath::default();
        let now = Instant::now();

        assert_eq!(
            path.consume(&body(0x80, claim), via_buddy_tcp(), ctx(None), now),
            refused
        );
        let stranger_link = RendezvousCarrier::BuddyTcp {
            link_peer: PeerEndpoint::V4(at(45, 55, 200, 99, 4662)),
            observed: requester_seen(),
        };
        assert_eq!(
            path.consume(&body(0x80, claim), stranger_link, ctx(Some(buddy())), now),
            refused
        );
        for from in [at(45, 55, 200, 99, 4672), at(45, 55, 200, 2, 4673)] {
            let carrier = RendezvousCarrier::Standalone {
                from: PeerEndpoint::V4(from),
            };
            assert_eq!(
                path.consume(&body(0x80, claim), carrier, ctx(Some(buddy())), now),
                refused
            );
        }
    }

    /// kno's carrier. Nobody observed the requester, so a public claim is all
    /// there is — and a private one resolves to nothing rather than to a
    /// datagram aimed into somebody's LAN.
    #[test]
    fn a_standalone_rendezvous_from_our_buddy_has_only_the_claim_to_go_on() {
        let carrier = RendezvousCarrier::Standalone {
            from: PeerEndpoint::V4(buddy()),
        };
        let mut path = ActingPath::default();
        let now = Instant::now();
        let public = path.consume(
            &body(0x80, Some(at(45, 55, 200, 66, 9999))),
            carrier,
            ctx(Some(buddy())),
            now,
        );
        assert!(matches!(
            public,
            ActingVerdict::Punch {
                target: PunchTarget {
                    source: PunchTargetSource::PublicClaim,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            path.consume(
                &body(0x80, Some(at(10, 0, 0, 5, 9999))),
                carrier,
                ctx(Some(buddy())),
                now
            ),
            ActingVerdict::Refuse(ActingRefusal::NoUsableTarget)
        );
    }

    /// A requester that claims neither transport — or only QUIC while we
    /// serve none — opens a path nothing could use, so no punch is spent.
    #[test]
    fn a_requester_with_no_transport_we_can_raise_is_not_punched() {
        let mut path = ActingPath::default();
        for options in [0x03, 0x40] {
            assert_eq!(
                path.consume(
                    &body(options, None),
                    via_buddy_tcp(),
                    ctx(Some(buddy())),
                    Instant::now()
                ),
                ActingVerdict::Refuse(ActingRefusal::NoCommonTransport)
            );
        }
        let quic = ActingContext {
            serves_quic: true,
            ..ctx(Some(buddy()))
        };
        assert!(matches!(
            path.consume(&body(0x40, None), via_buddy_tcp(), quic, Instant::now()),
            ActingVerdict::Punch {
                transport: NattTransport::Quic,
                ..
            }
        ));
    }

    /// One burst per destination per window — and only an honoured rendezvous
    /// stamps it: an unresolvable one in between costs the requester nothing.
    #[test]
    fn a_destination_is_punched_once_per_window() {
        let mut path = ActingPath::default();
        let t0 = Instant::now();
        let act = |path: &mut ActingPath, at| {
            path.consume(&body(0x80, None), via_buddy_tcp(), ctx(Some(buddy())), at)
        };
        let standalone = RendezvousCarrier::Standalone {
            from: PeerEndpoint::V4(buddy()),
        };
        assert_eq!(
            path.consume(
                &body(0x80, Some(at(10, 0, 0, 5, 1))),
                standalone,
                ctx(Some(buddy())),
                t0
            ),
            ActingVerdict::Refuse(ActingRefusal::NoUsableTarget)
        );
        assert!(matches!(act(&mut path, t0), ActingVerdict::Punch { .. }));
        assert_eq!(
            act(&mut path, t0 + ACTING_MIN_INTERVAL / 2),
            ActingVerdict::Refuse(ActingRefusal::RateLimited)
        );
        assert!(matches!(
            act(&mut path, t0 + ACTING_MIN_INTERVAL),
            ActingVerdict::Punch { .. }
        ));
    }

    /// Correction 4. The guard asks the interface set; a punch aimed at an
    /// address this host holds is refused however it was resolved.
    #[test]
    fn a_punch_is_never_aimed_at_one_of_our_own_interfaces() {
        let own = ActingContext {
            is_own_interface: (|ip| ip == IpAddr::V4(Ipv4Addr::new(45, 55, 200, 7))) as Own,
            ..ctx(Some(buddy()))
        };
        assert_eq!(
            ActingPath::default().consume(&body(0x80, None), via_buddy_tcp(), own, Instant::now()),
            ActingVerdict::Refuse(ActingRefusal::SelfPunch)
        );
    }
}
