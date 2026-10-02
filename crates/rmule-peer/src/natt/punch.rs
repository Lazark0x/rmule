//! Where a **Punch** is aimed, and when (ADR-0091): the three-part precedence
//! rule that turns a rendezvous into a target, the routability test behind it,
//! the burst-and-sweep plan, and the ½-RTT schedule.
//!
//! Rendezvous is the one eD2k path where a node asserts its own address and
//! nothing corrects it — every classic path has a server or a Kad contact
//! observing the address first. So the address in a rendezvous body is a
//! *claim*, and this module is where a claim is allowed to become a
//! destination.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::Ipv4Endpoint;

/// Identical empty `OP_HOLEPUNCH` datagrams fired at the target's nominal
/// endpoint (eMuleAI `BaseClient.cpp:3119-3145`).
pub const PUNCH_BURST: usize = 6;

/// Half-width of the symmetric-NAT sweep: one punch at each of the ±16 ports
/// around the nominal one (`min(NatTraversalPortWindow, NatTraversalSweepWindow)`
/// at eMuleAI's defaults, 512 and 16).
pub const PUNCH_SWEEP: u16 = 16;

/// Whether a punch may be aimed at `ip` — eMuleAI's `CAddress::IsPublicIP`
/// (`Address.cpp:292`), which amule#1177 established as thorough after kno's
/// audit found `127.0.0.1`, `10.0.0.5`, `224.0.0.1` and `255.255.255.255` all
/// accepted as punch targets (kno's audit finding F1).
///
/// This is deliberately **stricter than Address Learning's admissibility
/// rule**, which lets the documentation ranges through because aMule routes
/// them. The two answer different questions. That one asks "could this be
/// *our* address" of a value a third party observed; this one asks "may a
/// stranger's unverified claim make us send datagrams *there*", and for that
/// question a range nobody can legitimately hold is a range nobody should be
/// able to aim us at.
#[must_use]
pub const fn is_public_punch_address(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0 | 10 | 127, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 168, _)
            | (192, 0, 2)
            | (192, 88, 99)
            | (198, 18 | 19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

/// Why a punch is aimed where it is — carried to diagnostics, because "we
/// punched at an address the requester made up" and "we punched at the address
/// its buddy saw" are different events when a traversal fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchTargetSource {
    /// A third party observed it: the endpoint a buddy injected into the
    /// `0x9A` relay, or a believed endpoint hint.
    Observed,
    /// The requester's own claim, adopted because nothing was observed and
    /// the claim is publicly routable.
    PublicClaim,
    /// The claim was not adoptable and served only as a lookup key; this is
    /// the endpoint already held for the peer it resolved to.
    KnownPeer,
}

/// A resolved punch destination and the rule that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunchTarget {
    /// Where the burst is aimed.
    pub endpoint: Ipv4Endpoint,
    /// Which arm of the precedence rule chose it.
    pub source: PunchTargetSource,
}

/// The **three-part precedence rule** (amule#1177 corrections 1, 4 and 5):
///
/// 1. prefer the **observed** source over anything the datagram claims;
/// 2. fall back to the **claimed** endpoint only if it is publicly routable;
/// 3. everywhere else the claim is a **lookup key** into peers already known —
///    so an unresolvable claim does nothing at all.
///
/// `known` answers arm 3: given the claimed endpoint, the endpoint already
/// held for the peer it identifies, if any. It is called only when the first
/// two arms produced nothing.
///
/// Whatever arm fires, the result is public or there is no result: an
/// observed source can be unusable too (a buddy on the same LAN sees a private
/// address), and a punch at an unroutable address opens nothing.
#[must_use]
pub fn resolve_punch_target(
    observed: Option<Ipv4Endpoint>,
    claimed: Option<Ipv4Endpoint>,
    known: impl FnOnce(Ipv4Endpoint) -> Option<Ipv4Endpoint>,
) -> Option<PunchTarget> {
    let usable =
        |endpoint: &Ipv4Endpoint| endpoint.port != 0 && is_public_punch_address(endpoint.ip);
    if let Some(endpoint) = observed.filter(usable) {
        return Some(PunchTarget {
            endpoint,
            source: PunchTargetSource::Observed,
        });
    }
    let claimed = claimed?;
    if usable(&claimed) {
        return Some(PunchTarget {
            endpoint: claimed,
            source: PunchTargetSource::PublicClaim,
        });
    }
    known(claimed).filter(usable).map(|endpoint| PunchTarget {
        endpoint,
        source: PunchTargetSource::KnownPeer,
    })
}

/// Every endpoint one punch burst is sent to, in send order: [`PUNCH_BURST`]
/// copies at the nominal port, then one each at `±1 … ±PUNCH_SWEEP`, nearest
/// first. A swept port that would leave `1..=65535` is skipped, not wrapped —
/// wrapping would aim the far side of the sweep at the well-known ports.
///
/// The sweep is what reaches a NAT that allocates the next port for a new
/// destination; against a random-port symmetric NAT it reaches nothing, and
/// ADR-0091 lets that pair fail honestly.
pub fn punch_burst(target: Ipv4Endpoint) -> impl Iterator<Item = Ipv4Endpoint> {
    let nominal = std::iter::repeat_n(target.port, PUNCH_BURST);
    let sweep = (1..=PUNCH_SWEEP).flat_map(move |offset| {
        [
            target.port.checked_add(offset),
            target.port.checked_sub(offset).filter(|port| *port != 0),
        ]
        .into_iter()
        .flatten()
    });
    nominal
        .chain(sweep)
        .map(move |port| Ipv4Endpoint::new(target.ip, port))
}

/// How long the requester holds its burst after the hint arrives: **half the
/// relay round trip** when it was measured, otherwise no delay.
///
/// This is DCUtR's policy applied with no wire change. The buddy answers the
/// requester and forwards to the target at the same instant, so the hint's
/// arrival marks half a round trip since the target was told; holding for the
/// other half lands both bursts together instead of the requester's arriving
/// at a NAT whose mapping does not exist yet — the timing failure found to be
/// the common one.
#[must_use]
pub fn burst_delay(relay_round_trip: Option<Duration>) -> Duration {
    relay_round_trip.map_or(Duration::ZERO, |round_trip| round_trip / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(a: u8, b: u8, c: u8, d: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port)
    }

    /// kno's audit finding F1 by name — each of these returned `punch=1` before the
    /// fix — plus the ranges eMuleAI's list adds that the standard library's
    /// predicates do not cover, with the boundary neighbours that must pass.
    #[test]
    fn a_punch_is_never_aimed_off_the_public_internet() {
        for refused in [
            [127, 0, 0, 1],
            [10, 0, 0, 5],
            [192, 168, 1, 1],
            [224, 0, 0, 1],
            [255, 255, 255, 255],
            [169, 254, 1, 1],
            [0, 1, 2, 3],
            [100, 64, 0, 1],
            [100, 127, 255, 254],
            [172, 31, 0, 1],
            [192, 0, 2, 9],
            [198, 51, 100, 9],
            [203, 0, 113, 9],
            [192, 88, 99, 1],
            [198, 19, 0, 1],
            [240, 0, 0, 1],
        ] {
            assert!(!is_public_punch_address(refused.into()), "{refused:?}");
        }
        for allowed in [
            [100, 63, 255, 255],
            [100, 128, 0, 1],
            [172, 32, 0, 1],
            [198, 20, 0, 1],
            [192, 0, 3, 1],
            [223, 255, 255, 1],
            [45, 55, 200, 7],
        ] {
            assert!(is_public_punch_address(allowed.into()), "{allowed:?}");
        }
    }

    /// Arm 1. The claim is public and plausible and still loses — and the
    /// lookup is never consulted, which is what keeps an attacker's claim from
    /// even *probing* which peers we know.
    #[test]
    fn an_observed_source_beats_a_public_claim() {
        let target = resolve_punch_target(
            Some(at(45, 55, 200, 7, 4672)),
            Some(at(45, 55, 200, 66, 9999)),
            |_| panic!("the lookup is arm 3's"),
        );
        assert_eq!(
            target,
            Some(PunchTarget {
                endpoint: at(45, 55, 200, 7, 4672),
                source: PunchTargetSource::Observed,
            })
        );
    }

    /// Arm 2. An observed source can be unusable — a buddy on the requester's
    /// LAN sees a private address, a standalone relay carries none — and only
    /// then is a claim adopted, and only a public one.
    #[test]
    fn a_public_claim_stands_in_for_an_unusable_observation() {
        for observed in [
            None,
            Some(at(192, 168, 1, 20, 4672)),
            Some(at(45, 55, 200, 7, 0)),
        ] {
            let target = resolve_punch_target(observed, Some(at(45, 55, 200, 66, 9999)), |_| {
                panic!("the lookup is arm 3's")
            });
            assert_eq!(
                target.map(|t| t.source),
                Some(PunchTargetSource::PublicClaim)
            );
        }
    }

    /// Arm 3. A private claim is never a destination; it may still identify a
    /// peer we hold a public endpoint for. If it identifies nobody — or
    /// somebody we only know privately — nothing happens.
    #[test]
    fn a_private_claim_is_only_ever_a_lookup_key() {
        let claim = at(10, 0, 0, 5, 4672);
        assert_eq!(
            resolve_punch_target(None, Some(claim), |key| {
                assert_eq!(key, claim);
                Some(at(45, 55, 200, 9, 5000))
            }),
            Some(PunchTarget {
                endpoint: at(45, 55, 200, 9, 5000),
                source: PunchTargetSource::KnownPeer,
            })
        );
        assert_eq!(resolve_punch_target(None, Some(claim), |_| None), None);
        assert_eq!(
            resolve_punch_target(None, Some(claim), |_| Some(at(10, 0, 0, 5, 4672))),
            None
        );
        assert_eq!(resolve_punch_target(None, None, |_| panic!("no key")), None);
    }

    /// Six at the nominal port, then the sweep nearest-first: 6 + 32 datagrams
    /// mid-range.
    #[test]
    fn a_burst_is_six_nominal_then_the_sweep_nearest_first() {
        let burst: Vec<_> = punch_burst(at(45, 55, 200, 7, 5000)).collect();
        assert_eq!(burst.len(), PUNCH_BURST + 2 * usize::from(PUNCH_SWEEP));
        assert!(burst[..6].iter().all(|e| e.port == 5000));
        assert_eq!(
            burst[6..10].iter().map(|e| e.port).collect::<Vec<_>>(),
            vec![5001, 4999, 5002, 4998]
        );
        assert!(burst.iter().all(|e| e.ip == Ipv4Addr::new(45, 55, 200, 7)));
    }

    /// At either end of the port space the sweep is clipped, never wrapped:
    /// no port 0, and no low port reached from a high nominal one.
    #[test]
    fn the_sweep_is_clipped_at_the_edges_of_the_port_space() {
        let low: Vec<_> = punch_burst(at(45, 55, 200, 7, 3)).map(|e| e.port).collect();
        assert!(!low.contains(&0));
        assert_eq!(low.len(), PUNCH_BURST + usize::from(PUNCH_SWEEP) + 2);

        let high: Vec<_> = punch_burst(at(45, 55, 200, 7, 65530))
            .map(|e| e.port)
            .collect();
        assert!(high.iter().all(|port| *port >= 65530 - PUNCH_SWEEP));
        assert_eq!(high.len(), PUNCH_BURST + 5 + usize::from(PUNCH_SWEEP));
    }

    #[test]
    fn the_burst_is_held_for_half_a_measured_round_trip() {
        assert_eq!(burst_delay(None), Duration::ZERO);
        assert_eq!(
            burst_delay(Some(Duration::from_millis(180))),
            Duration::from_millis(90)
        );
    }
}
