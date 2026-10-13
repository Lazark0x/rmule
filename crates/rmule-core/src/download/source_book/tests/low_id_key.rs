//! A Low-ID Candidate Record's key (ADR-0090): its namespace, its id and the
//! port that tells two apart, as aMule's `FindMatchingClient` tells Low IDs
//! apart by IP and Kad port (stock 2.3.3 `ClientList.cpp:264-280`), and the
//! rule for a sighting that names another owner of a held key — it replaces
//! the candidate whole. Asserted through the **Source Book**'s interface.

use rmule_primitives::{SightedBuddy, SourceCryptOptions, SourceRoad};

use super::*;

const OWNER: UserHash = UserHash::from_bytes([0x0A; UserHash::BYTE_LEN]);
const NEWCOMER: UserHash = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);

/// The one address both publishers are observed at, behind one NAT.
fn observed(kad_port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 77), kad_port)
}

/// A type-3/5 Kad row: a firewalled publisher `user_hash` behind its buddy,
/// observed at `kad_udp`.
fn buddy_row(user_hash: UserHash, kad_udp: Ipv4Endpoint) -> SourceSighting {
    SourceSighting::by_road(
        SourceRoad::Buddy {
            buddy: SightedBuddy {
                buddy_id: [0xB0; 16],
                buddy_udp: Some(v4(90)),
            },
            kad_udp,
            tcp_port: 4662,
        },
        Some(user_hash),
        Some(SourceCryptOptions::from_byte(0x01)),
    )
}

/// A type-6 Kad row: a firewalled publisher `user_hash` reached by its own
/// direct UDP callback, observed at `kad_udp` — no buddy, no IPv6 half.
fn direct_row(user_hash: UserHash, kad_udp: Ipv4Endpoint) -> SourceSighting {
    SourceSighting::by_road(
        SourceRoad::DirectUdpCallback {
            kad_udp,
            tcp_port: 4662,
        },
        Some(user_hash),
        Some(SourceCryptOptions::from_byte(0x08)),
    )
}

/// Two firewalled publishers behind one address, told apart by their Kad UDP
/// ports, are two records — not one whose facts the second overwrote.
#[test]
fn two_kad_rows_on_one_address_with_two_kad_ports_stay_two_records() {
    let mut book = empty_book();
    assert_eq!(
        sight(&mut book, buddy_row(OWNER, observed(4672))),
        Sighted::Pooled(None)
    );
    assert_eq!(
        sight(&mut book, buddy_row(NEWCOMER, observed(4673))),
        Sighted::Pooled(None),
        "the second publisher is a source of its own"
    );
    assert_eq!(book.counts().known, 2);

    let keys: Vec<CallbackKey> = std::iter::from_fn(|| match dial(&mut book) {
        Some(NextDial::Callback { candidate, .. }) => Some(candidate.key()),
        _ => None,
    })
    .collect();
    assert_eq!(keys.len(), 2, "each publisher's road opens: {keys:?}");
    assert_ne!(keys[0], keys[1]);
}

/// A row under a held key that names another User Hash is another owner of
/// the key: nothing the older owner's row stated — its buddy, its IPv6 half,
/// its crypt side — rides onto the newcomer, and the half leaves the record.
#[test]
fn another_owner_on_a_held_key_inherits_no_buddy_and_no_ipv6_half() {
    let mut book = empty_book();
    assert_eq!(
        sight(
            &mut book,
            buddy_row(OWNER, observed(4672)).with_ipv6_half(Some(v6(1)))
        ),
        Sighted::Pooled(None)
    );
    assert_eq!(
        sight(&mut book, direct_row(NEWCOMER, observed(4672))),
        Sighted::Merged(None)
    );
    assert_eq!(book.counts().known, 1, "one key, one record");

    let Some(NextDial::Callback { candidate, .. }) = dial(&mut book) else {
        panic!("the newcomer's own road opens, not a rung-0 dial at the old half");
    };
    assert_eq!(candidate.user_hash, Some(NEWCOMER));
    assert_eq!(
        candidate.buddy, None,
        "the older owner's buddy stays its own"
    );
    assert_eq!(candidate.ipv6, None);
    assert_eq!(
        candidate.peer_crypt(),
        rmule_primitives::PeerCrypt::from_record(
            Some(SourceCryptOptions::from_byte(0x08)),
            Some(NEWCOMER)
        ),
        "the crypt side is the newcomer's row's alone"
    );
    assert_eq!(
        sight(&mut book, SourceSighting::plain(PeerSource::Ipv6(v6(1)))),
        Sighted::Pooled(Some(PeerEndpoint::V6(v6(1)))),
        "the older owner's half left the record: a source sighted there is new"
    );
}
