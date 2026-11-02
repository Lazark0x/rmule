//! The **Dial Chooser** (ADR-0087): the one core-side place that decides which
//! **Address Family** a peer gets dialed in, and whether it can be dialed at
//! all.
//!
//! Its sibling is the Advertised Endpoints chooser
//! ([`address_learning::advertised`](crate::address_learning)): that one settles
//! what rmule *says* about itself, this one what rmule *does* about a peer. Both
//! read the same verdict, published as the
//! [`SharedIpv6Advert`](crate::adapters::SharedIpv6Advert) — so the family rule
//! exists once rather than once per dial site, which is the duplication
//! ADR-0061 collapsed for callbacks and this collapses for families.
//!
//! One rule, stated as an AND: **dial IPv6 when the peer has a usable IPv6 and
//! we hold a Known one.** Preferring IPv6 whenever the peer has one was
//! considered and refused: dialing from an address we cannot corroborate breaks
//! reply attribution and dial-back, so the peer's address alone is not enough.
//! Holding one alone is not enough either. The AND is deliberate.

use rmule_primitives::{Ipv6Endpoint, PeerEndpoint, PeerSource, SourceSighting};

/// Our own half of the family question: the IPv6 the Advertised Endpoints
/// chooser says we hold, or `None`.
///
/// `None` is not a failure state — it is most of the network. An IPv4-only
/// rmule dials IPv4, ignores a peer's IPv6, and drops an IPv6-only source at
/// ingest rather than spending a worker slot on a conversation it cannot start
/// from anywhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DialPosition {
    /// Our Known IPv6, gated by the advert chooser's three tests (the Family
    /// Pair bound, the verdict fresh, no server probe saying otherwise).
    pub(crate) known_ipv6: Option<std::net::Ipv6Addr>,
}

impl DialPosition {
    /// Whether an IPv6 dial is possible at all from here.
    pub(crate) const fn can_dial_ipv6(self) -> bool {
        self.known_ipv6.is_some()
    }
}

/// Choose the endpoint to dial a peer at, given both of its families and our
/// own position — the ADR-0087 dial preference.
///
/// The IPv6 half wins only under the AND. Otherwise the IPv4 half stands, and
/// a peer with neither is not dialable at all (its route is a callback, which
/// is [`select_callback_route`](crate::callback)'s business, not this one's).
pub(crate) fn choose_dial(
    peer_ipv4: Option<PeerEndpoint>,
    peer_ipv6: Option<Ipv6Endpoint>,
    ours: DialPosition,
) -> Option<PeerEndpoint> {
    match peer_ipv6 {
        Some(endpoint) if ours.can_dial_ipv6() => Some(PeerEndpoint::V6(endpoint)),
        _ => peer_ipv4,
    }
}

/// Where a dialable source is dialed: the family [`choose_dial`] picks
/// first, and — for a **dual-stack** source, a High ID with an IPv6 half
/// beside it — the other half, which a first dial that never completes its
/// handshake falls to once (ADR-0087). The pool and every worker are
/// keyed by one endpoint, so the record keeps the second half beside the one
/// dialed rather than inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DialOrder {
    /// The endpoint the first worker dials.
    pub(crate) first: PeerEndpoint,
    /// The same peer's other family, when it named two.
    pub(crate) fallback: Option<PeerEndpoint>,
}

impl DialOrder {
    /// Every address the source may be dialed at, first family first.
    pub(crate) fn halves(self) -> impl Iterator<Item = PeerEndpoint> {
        std::iter::once(self.first).chain(self.fallback)
    }
}

/// The one rule every channel that can name two families settles on — an
/// ExtSX record, a serve client's hello, a Kad row with its `ip6` — so none
/// can drift from another. `None` for a source with no address to dial (a Low
/// ID or a Kad callback row: its half is rung 0 of the callback route tree,
/// which reads it there).
fn settle_dual_stack(
    source: PeerSource,
    ipv6: Option<Ipv6Endpoint>,
    ours: DialPosition,
) -> Option<DialOrder> {
    let first = source.as_peer_endpoint()?;
    let (PeerSource::HighId(v4), Some(v6)) = (source, ipv6) else {
        return Some(DialOrder {
            first,
            fallback: None,
        });
    };
    let v4 = PeerEndpoint::V4(v4);
    let first = choose_dial(Some(v4), Some(v6), ours).unwrap_or(v4);
    let fallback = if first == v4 {
        PeerEndpoint::V6(v6)
    } else {
        v4
    };
    Some(DialOrder {
        first,
        fallback: Some(fallback),
    })
}

/// A sighting's dial order ([`settle_dual_stack`]): a High ID whose IPv6 half
/// rode beside it (ADR-0087) is dialed in the family the chooser picks, its
/// other half kept. A callback road has no dial order — it keeps its half for
/// rung 0 — and an IPv6-only record is its one address.
pub(crate) fn resolve_family(sighting: SourceSighting, ours: DialPosition) -> Option<DialOrder> {
    settle_dual_stack(sighting.peer_source()?, sighting.ipv6(), ours)
}

/// A source's addresses, each judged on its own by `admits` — at ingest, the
/// Reserved Range check against the sighting's Informant and then the IP
/// filter (ADR-0085, ADR-0087): every address that may be dialed is judged
/// before any family or road is chosen.
///
/// - A dual-stack pair: both halves are dialable. A refused IPv6 half is
///   dropped from the record; a refused client id leaves the source on its
///   IPv6 alone; both refused drops it.
/// - A callback source (a Low ID, or a Kad row with no direct address) beside
///   an IPv6 half: the half is rung 0's, the only address it names, and a
///   refused one is dropped — its callback roads stand.
///
/// Anything else passes unchanged, for its one address to be judged as it
/// always was.
fn judge_halves(
    source: Option<PeerSource>,
    ipv6: Option<Ipv6Endpoint>,
    admits: impl Fn(PeerEndpoint) -> bool,
) -> Option<(Option<PeerSource>, Option<Ipv6Endpoint>)> {
    match (source, ipv6) {
        (Some(PeerSource::HighId(v4)), Some(v6)) => {
            match (admits(PeerEndpoint::V4(v4)), admits(PeerEndpoint::V6(v6))) {
                (true, true) => Some((source, ipv6)),
                (true, false) => Some((source, None)),
                (false, true) => Some((Some(PeerSource::Ipv6(v6)), ipv6)),
                (false, false) => None,
            }
        }
        (None | Some(PeerSource::LowId { .. }), Some(v6)) => {
            Some((source, Some(v6).filter(|&v6| admits(PeerEndpoint::V6(v6)))))
        }
        _ => Some((source, ipv6)),
    }
}

/// A sighting with its addresses judged ([`judge_halves`]): a record whose
/// client id is refused keeps its IPv6 half as its one address, and a refused
/// half is dropped from any road. Only an address changes — the road a Kad
/// callback row names and the facts beside it stand.
pub(crate) fn admit_halves(
    sighting: SourceSighting,
    admits: impl Fn(PeerEndpoint) -> bool,
) -> Option<SourceSighting> {
    let (record, half) = judge_halves(sighting.peer_source(), sighting.ipv6(), admits)?;
    let judged = match record {
        Some(record) => sighting.with_record(record),
        None => sighting,
    };
    Some(judged.with_ipv6_half(half))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn v4() -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662))
    }

    fn v6() -> Ipv6Endpoint {
        Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662)
    }

    fn ours() -> DialPosition {
        DialPosition {
            known_ipv6: Some("2001:db8::1".parse().unwrap()),
        }
    }

    /// The chooser matrix: IPv6 wins only under the AND, and the peer's
    /// address alone never carries it.
    #[test]
    fn the_and_decides_the_family_and_nothing_else_does() {
        // Both families, both sides: IPv6.
        assert_eq!(
            choose_dial(Some(v4()), Some(v6()), ours()),
            Some(PeerEndpoint::V6(v6()))
        );
        // The peer has one, we do not: IPv4, the address we can be reached back at.
        assert_eq!(
            choose_dial(Some(v4()), Some(v6()), DialPosition::default()),
            Some(v4())
        );
        // We have one, the peer does not: IPv4.
        assert_eq!(choose_dial(Some(v4()), None, ours()), Some(v4()));
        // IPv6-only peer, and we hold one: the only dial there is.
        assert_eq!(
            choose_dial(None, Some(v6()), ours()),
            Some(PeerEndpoint::V6(v6()))
        );
        // IPv6-only peer and no address of ours: nothing to dial from.
        assert_eq!(choose_dial(None, Some(v6()), DialPosition::default()), None);
        // Neither: a callback's business, not the family chooser's.
        assert_eq!(choose_dial(None, None, ours()), None);
    }

    /// A dual-stack source from source exchange is dialed first on the family
    /// the AND picks, with the other half kept as its one fallback.
    #[test]
    fn a_dual_stack_source_is_dialed_first_on_the_family_the_and_picks() {
        let PeerEndpoint::V4(v4) = v4() else {
            unreachable!()
        };
        let hash = rmule_primitives::UserHash::from_bytes([0x51; 16]);
        let dual = SourceSighting::new(
            PeerSource::HighId(v4),
            Some(hash),
            None,
            rmule_primitives::Informant::Own,
        )
        .with_ipv6_half(Some(v6()));

        assert_eq!(
            resolve_family(dual, ours()),
            Some(DialOrder {
                first: PeerEndpoint::V6(v6()),
                fallback: Some(PeerEndpoint::V4(v4)),
            })
        );
        assert_eq!(
            resolve_family(dual, DialPosition::default()),
            Some(DialOrder {
                first: PeerEndpoint::V4(v4),
                fallback: Some(PeerEndpoint::V6(v6())),
            }),
            "no IPv6 of ours: its IPv4 half stands first, the half is kept, not lost"
        );
    }

    /// The IP filter judges both halves of a dual-stack record: a refused
    /// half leaves the source on the other, and only both refused drop it.
    #[test]
    fn the_ip_filter_judges_each_half_of_a_dual_stack_source() {
        let PeerEndpoint::V4(v4) = v4() else {
            unreachable!()
        };
        let hash = rmule_primitives::UserHash::from_bytes([0x52; 16]);
        let dual = SourceSighting::new(
            PeerSource::HighId(v4),
            Some(hash),
            None,
            rmule_primitives::Informant::Own,
        )
        .with_ipv6_half(Some(v6()));
        let refusing = |refused: PeerEndpoint| move |endpoint| endpoint != refused;

        let v4_only =
            admit_halves(dual, refusing(PeerEndpoint::V6(v6()))).expect("the IPv4 half passes");
        assert_eq!(v4_only.ipv6(), None, "the refused IPv6 half is dropped");
        assert_eq!(
            resolve_family(v4_only, ours()).map(|order| order.fallback),
            Some(None),
            "and never becomes a fallback"
        );

        let v6_only =
            admit_halves(dual, refusing(PeerEndpoint::V4(v4))).expect("the IPv6 half passes");
        assert_eq!(v6_only.peer_source(), Some(PeerSource::Ipv6(v6())));
        assert_eq!(v6_only.user_hash(), Some(hash));

        assert_eq!(admit_halves(dual, |_| false), None);
    }

    /// kno's own `0x3B` (bench run `1790199666`), re-serving a High-ID row
    /// with its `ip6` beside the `SOURCEIP`: one row is one dual-stack source,
    /// dialed first on the family the AND picks — the ExtSX rule, on a Kad
    /// row — its other half kept for the fallback, and the IP filter
    /// judges both.
    #[test]
    fn a_captured_kad_row_with_ip6_is_one_dual_stack_source_on_the_family_the_and_picks() {
        let datagram = include_bytes!(
            "../../rmule-kad/tests/fixtures/ipv6/captured/amule-kno-ab483654-kad-ip6-20260923/amule_kno_search_res_0x3b.bin"
        );
        let rmule_kad::KadDecoded::Plain(envelope) =
            rmule_kad::decode_exact(datagram).expect("kno's datagram decodes")
        else {
            panic!("the bench ran every body crypt-off");
        };
        let rows = rmule_kad::decode_source_result(&envelope).expect("rmule reads kno's answer");
        let [row] = rows.as_slice() else {
            panic!("one published source, one row: {rows:?}");
        };
        let row = row
            .sighting(rmule_primitives::Informant::Own)
            .expect("a direct row is a sighting");
        let high_id = PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4662));
        let half = Ipv6Endpoint::new("3fff:ed2:1::8".parse().unwrap(), 4662);

        assert_eq!(row.peer_source(), Some(high_id));
        assert_eq!(row.ipv6(), Some(half));
        let (high_id, half) = (
            high_id
                .as_peer_endpoint()
                .expect("a High ID has an address"),
            PeerEndpoint::V6(half),
        );

        assert_eq!(
            resolve_family(row, ours()),
            Some(DialOrder {
                first: half,
                fallback: Some(high_id),
            })
        );
        assert_eq!(
            resolve_family(row, DialPosition::default()),
            Some(DialOrder {
                first: high_id,
                fallback: Some(half),
            }),
            "no IPv6 of ours: the row's IPv4 stands, and its half is kept, not lost"
        );
        let refused_half =
            admit_halves(row, |endpoint| endpoint != half).expect("the row's IPv4 passes");
        assert_eq!(refused_half.ipv6(), None, "the filter judged the half too");
    }
}
