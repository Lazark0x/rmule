//! ADR-0090's invariants asserted through the **Source Book**'s interface: one
//! owner per source, a sighting merges rather than duplicates, one failed dial
//! per endpoint per re-ask period, bad data never re-pooled — and the merge
//! rule's rank when the wire proves two held records one peer.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Instant;

use rmule_primitives::{
    ClientId, CryptStance, Informant, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, PeerSource,
    SourceSighting, UserHash,
};

use super::*;
use crate::dialable::DialPosition;
use crate::download::queue_standings::StandingSeat;
use crate::download::source_book::FILE_REASK_TIME;
use crate::download::state::CallbackCapability;
use crate::hello_facts::HelloFacts;
use crate::ip_filter::IpFilter;

mod frequency;
mod low_id_key;
mod low_id_names;

const BAD: UserHash = UserHash::from_bytes([0xBA; UserHash::BYTE_LEN]);

fn v4(n: u8) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, n), 4662)
}

fn v6(n: u16) -> Ipv6Endpoint {
    Ipv6Endpoint::new(
        std::net::Ipv6Addr::new(0x2a01, 0x4f8, 0, 0, 0, 0, 0, n),
        4662,
    )
}

fn high(n: u8) -> PeerEndpoint {
    PeerEndpoint::V4(v4(n))
}

fn ours() -> DialPosition {
    DialPosition {
        known_ipv6: Some("2001:db8::1".parse().unwrap()),
    }
}

fn empty_book() -> SourceBook {
    book_distrusting(HashSet::new())
}

fn book_distrusting(distrusted: HashSet<UserHash>) -> SourceBook {
    SourceBook::new(distrusted, 3)
}

fn plain(n: u8) -> SourceSighting {
    SourceSighting::plain(PeerSource::HighId(v4(n)), Informant::Own)
}

fn dual(n: u8, half: u16) -> SourceSighting {
    plain(n).with_ipv6_half(Some(v6(half)))
}

fn low_id(id: u32) -> SourceSighting {
    SourceSighting::plain(
        PeerSource::new(ClientId::from_u32(id), 4662),
        Informant::Own,
    )
}

fn sight(book: &mut SourceBook, sighting: SourceSighting) -> Sighted {
    sight_through(book, sighting, &IpFilter::default(), ours())
}

fn sight_through(
    book: &mut SourceBook,
    sighting: SourceSighting,
    filter: &IpFilter,
    dial: DialPosition,
) -> Sighted {
    book.sight(sighting, None, &Gate { filter, dial })
}

/// A filter blocking `45.55.200.<n>` for each `n`.
fn blocking(hosts: &[u8]) -> IpFilter {
    let text: String = hosts
        .iter()
        .map(|n| format!("45.55.200.{n}-45.55.200.{n},0,blocked\n"))
        .collect();
    IpFilter::from_texts(&[text.as_bytes()], 127, true, true).0
}

/// The next dial, under any capability and our Known IPv6.
fn dial(book: &mut SourceBook) -> Option<NextDial> {
    book.next_dial(&CallbackCapability::server_high_id(), ours())
}

/// Dial `book`'s next High ID and complete its handshake.
fn work(book: &mut SourceBook) -> PeerEndpoint {
    let Some(NextDial::Worker(endpoint)) = dial(book) else {
        panic!("a dialable source was pooled");
    };
    book.connected(endpoint);
    endpoint
}

/// Invariant 1: a source is held by one owner at a time — its record's one
/// stage — through a worker, the Remote-Queued Pool and back, and a sighting
/// of the queued source attaches to its record and pools nothing.
#[test]
fn a_source_has_one_owner_from_its_worker_to_its_standing_and_back() {
    let mut book = empty_book();
    assert_eq!(sight(&mut book, plain(1)), Sighted::Pooled(Some(high(1))));
    assert_eq!(work(&mut book), high(1));
    assert!(book.is_connected(high(1)));

    let queued_at = Instant::now();
    book.queued(high(1), 3, queued_at);
    assert_eq!(
        book.counts().known,
        1,
        "a queued source still ending its worker is one record"
    );
    assert_eq!(
        book.end_worker(high(1), false, ours()),
        Some(WorkerEnd::Release(Release::RemoteQueued))
    );
    assert_eq!(book.rank(high(1)), Some(3));
    assert!(
        book.holds(high(1)) && !book.is_pooled_or_live(high(1)),
        "its standing holds it, no worker and no lane"
    );

    assert_eq!(sight(&mut book, plain(1)), Sighted::Merged(None));
    assert_eq!(dial(&mut book), None, "the standing holds it, not a lane");

    let gates = ReaskGates {
        socket: false,
        reachable: false,
    };
    assert_eq!(
        book.sweep(queued_at + FILE_REASK_TIME, gates, &alone()),
        vec![Reask::FullAsk { peer: high(1) }]
    );
    assert_eq!(dial(&mut book), Some(NextDial::Worker(high(1))));
    assert_eq!(dial(&mut book), None, "dialed once");
}

/// Invariant 2: a sighting of a held source merges its facts into the owner's
/// record — a dual-stack source sighted again at either half, a Low-ID
/// candidate sighted again by its key — and the book still holds one record
/// each.
#[test]
fn a_sighting_of_a_held_source_merges_and_never_duplicates() {
    let mut book = empty_book();
    assert_eq!(
        sight(&mut book, dual(1, 1)),
        Sighted::Pooled(Some(PeerEndpoint::V6(v6(1))))
    );
    assert_eq!(sight(&mut book, plain(1)), Sighted::Merged(None));
    let ipv6_only = SourceSighting::plain(PeerSource::Ipv6(v6(1)), Informant::Own);
    assert_eq!(sight(&mut book, ipv6_only), Sighted::Merged(None));

    assert_eq!(sight(&mut book, low_id(7)), Sighted::Pooled(None));
    let key = CallbackKey {
        server: None,
        low_id: ClientId::from_u32(7),
        kad_port: None,
    };
    let hashed = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(7), 4662),
        Some(UserHash::from_bytes([0x5A; UserHash::BYTE_LEN])),
        None,
        Informant::Own,
    );
    assert_eq!(sight(&mut book, hashed), Sighted::Merged(None));
    assert_eq!(book.counts().known, 2);
    // The dual-stack source is dialed first; the candidate's callback next.
    let callback = std::iter::from_fn(|| {
        book.next_dial(
            &CallbackCapability::server_high_id(),
            DialPosition::default(),
        )
    })
    .find_map(|next| match next {
        NextDial::Callback { candidate, .. } => Some(candidate),
        NextDial::Worker(_) => None,
    });
    let candidate = callback.expect("a callable downloader asks for the candidate's callback");
    assert_eq!(
        (candidate.key(), candidate.user_hash),
        (key, Some(UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]))),
        "the hash the second sighting named rides the one record"
    );
}

/// A queued source whose session said it now holds another IPv6 is asked, and
/// dialed, there — on the port it was reached at; one reached over IPv4 is not
/// redirected by the address.
#[test]
fn a_queued_source_is_dialed_at_the_ipv6_its_session_revised() {
    let moved_ip: std::net::Ipv6Addr = "2a01:4f8::99".parse().unwrap();
    let revised = || {
        HelloFacts {
            ipv6: Some(moved_ip),
            ..HelloFacts::of(UserHash::from_bytes([0xCD; UserHash::BYTE_LEN]))
        }
        .identity()
    };
    let gates = ReaskGates {
        socket: false,
        reachable: false,
    };
    let queue = |book: &mut SourceBook, live: PeerEndpoint| {
        assert!(!book.identify(live, revised()));
        let at = Instant::now();
        book.queued(live, 3, at);
        assert_eq!(
            book.end_worker(live, false, ours()),
            Some(WorkerEnd::Release(Release::RemoteQueued))
        );
        at
    };

    let mut book = empty_book();
    let old = PeerEndpoint::V6(v6(1));
    let _ = sight(
        &mut book,
        SourceSighting::plain(PeerSource::Ipv6(v6(1)), Informant::Own),
    );
    assert_eq!(work(&mut book), old);
    let at = queue(&mut book, old);
    let moved = PeerEndpoint::V6(Ipv6Endpoint::new(moved_ip, 4662));
    assert_eq!(book.rank(moved), Some(3));
    assert!(!book.holds(old), "the standing moved off the old address");
    assert_eq!(
        book.sweep(at + FILE_REASK_TIME, gates, &alone()),
        vec![Reask::FullAsk { peer: moved }]
    );

    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    assert_eq!(work(&mut book), high(1));
    let at = queue(&mut book, high(1));
    assert_eq!(
        book.sweep(at + FILE_REASK_TIME, gates, &alone()),
        vec![Reask::FullAsk { peer: high(1) }]
    );
}

/// Invariant 3: a failed dial spends its endpoint for one to two re-ask
/// periods, whichever road dialed it. A dual-stack source falls to its other
/// half once; its second failure falls nowhere.
#[test]
fn a_failed_dial_spends_its_endpoint_for_a_re_ask_period() {
    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    assert_eq!(dial(&mut book), Some(NextDial::Worker(high(1))));
    assert_eq!(
        book.end_worker(high(1), true, ours()),
        Some(WorkerEnd::Dial(DialEnd::Spent))
    );
    assert_eq!(sight(&mut book, plain(1)), Sighted::Blocked(Blocked::Spent));

    let start = Instant::now();
    book.turn_spent(start);
    book.turn_spent(start + FILE_REASK_TIME);
    assert_eq!(
        sight(&mut book, plain(1)),
        Sighted::Blocked(Blocked::Spent),
        "spent through the next period"
    );
    book.turn_spent(start + FILE_REASK_TIME * 2);
    assert_eq!(sight(&mut book, plain(1)), Sighted::Pooled(Some(high(1))));

    let mut book = empty_book();
    let _ = sight(&mut book, dual(2, 2));
    let _ = dial(&mut book);
    let first = PeerEndpoint::V6(v6(2));
    assert_eq!(
        book.end_worker(first, true, ours()),
        Some(WorkerEnd::Dial(DialEnd::FellToOtherHalf(high(2))))
    );
    assert_eq!(dial(&mut book), Some(NextDial::Worker(high(2))));
    assert_eq!(
        book.end_worker(high(2), true, ours()),
        Some(WorkerEnd::Dial(DialEnd::Spent)),
        "one dial per family"
    );
}

/// A worker that completed its handshake reached a live peer: its end spends
/// nothing, and the identity its Worker stage held does not outlive it
/// (ADR-0049).
#[test]
fn a_worker_that_reached_its_peer_spends_nothing_and_keeps_no_identity() {
    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    let peer = work(&mut book);
    let identity = HelloFacts {
        crypt: CryptStance::disabled(),
        ..HelloFacts::of(UserHash::from_bytes([0xCD; UserHash::BYTE_LEN]))
    }
    .identity();
    assert!(!book.identify(peer, identity.clone()));
    assert_eq!(book.identity(peer), Some(&identity));

    assert_eq!(
        book.end_worker(peer, false, ours()),
        Some(WorkerEnd::Release(Release::Gone))
    );
    assert!(!book.is_spent(peer));
    assert_eq!(book.identity(peer), None);
    assert_eq!(book.distrust(peer), None, "no hash left to distrust by");
}

/// An identity for an endpoint no live worker holds states nothing about any
/// record: the book keeps nothing of it.
#[test]
fn an_identity_with_no_worker_is_dropped() {
    let mut book = empty_book();
    assert!(!book.identify(high(1), HelloFacts::of(BAD).identity()));
    let _ = sight(&mut book, plain(1));
    assert_eq!(book.identity(high(1)), None);
}

/// Invariant 4: a proven sender of bad data is distrusted — once, for the brain
/// to persist — and no sighting naming it is pooled again, dialable or Low ID.
/// Distrust the download's record held is in force from the start.
#[test]
fn bad_data_is_never_pooled_again() {
    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    let peer = work(&mut book);
    assert!(!book.identify(peer, HelloFacts::of(BAD).identity()));
    assert_eq!(book.distrust(peer), Some(BAD));
    assert_eq!(book.distrust(peer), None, "a distrust is new once");

    let named = SourceSighting::new(PeerSource::HighId(v4(2)), Some(BAD), None, Informant::Own);
    assert_eq!(
        sight(&mut book, named),
        Sighted::Blocked(Blocked::Distrusted)
    );
    let low = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(7), 4662),
        Some(BAD),
        None,
        Informant::Own,
    );
    assert_eq!(sight(&mut book, low), Sighted::Blocked(Blocked::Distrusted));

    let mut resumed = book_distrusting(HashSet::from([BAD]));
    assert_eq!(
        sight(&mut resumed, named),
        Sighted::Blocked(Blocked::Distrusted)
    );
    let _ = sight(&mut resumed, plain(3));
    let unnamed = work(&mut resumed);
    assert!(
        resumed.identify(unnamed, HelloFacts::of(BAD).identity()),
        "a hello naming it is caught"
    );
}

/// The merge rule: when a dual-stack pairing proves two live workers one peer,
/// the older keeps the record and the newer ends, its endpoint unspent because
/// the peer is alive.
#[test]
fn two_live_records_proven_one_peer_keep_the_older_worker() {
    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    let older = work(&mut book);
    let _ = sight(
        &mut book,
        SourceSighting::plain(PeerSource::Ipv6(v6(1)), Informant::Own),
    );
    let newer = work(&mut book);

    assert_eq!(
        sight(&mut book, dual(1, 1)),
        Sighted::Merged(Some(MergeEnd::Worker(newer)))
    );
    assert!(book.is_connected(older));
    assert!(!book.is_connected(newer), "the newer worker gave way");
    assert!(!book.is_spent(newer));
    assert_eq!(book.counts().known, 1);
}

/// The merge rule's rank: a Low-ID candidate's IPv6 half proves it the same
/// peer as a pooled IPv6 source, and the candidate's callback in flight
/// outranks the pool — the record keeps its road, and the pooled copy's lane
/// entry is gone.
#[test]
fn a_callback_in_flight_outranks_a_pooled_record_of_the_same_peer() {
    let mut book = empty_book();
    let _ = sight(&mut book, low_id(7));
    let Some(NextDial::Callback { candidate, .. }) = book.next_dial(
        &CallbackCapability::server_high_id(),
        DialPosition::default(),
    ) else {
        panic!("a callable downloader asks for a callback");
    };
    let half = PeerEndpoint::V6(v6(7));
    let _ = sight(
        &mut book,
        SourceSighting::plain(PeerSource::Ipv6(v6(7)), Informant::Own),
    );
    assert!(book.is_pooled_or_live(half));

    let with_half = low_id(7).with_ipv6_half(Some(v6(7)));
    assert_eq!(sight(&mut book, with_half), Sighted::Merged(None));
    assert!(
        !book.is_pooled_or_live(half),
        "the pooled copy's lane entry is gone"
    );
    assert_eq!(
        book.callback_candidate(candidate.key())
            .and_then(|held| held.ipv6),
        Some(v6(7)),
        "the callback in flight keeps its road and takes the half"
    );
    assert_eq!(book.counts().known, 1);
    assert_eq!(
        book.next_dial(
            &CallbackCapability::server_high_id(),
            DialPosition::default()
        ),
        None,
        "no second dial of the same peer"
    );
}

/// The intake gate's IP-filter block: a filtered address never pools, and its
/// neighbour does. A dual-stack source is judged per half — a refused client id
/// leaves it on its IPv6 half, a refused IPv6 half (a mapped IPv4 address is
/// filtered as that address) leaves it on its IPv4 one, both refused block it.
/// A Low-ID row has no address to judge and passes.
#[test]
fn the_ip_filter_is_judged_per_half() {
    let filter = blocking(&[1, 3]);
    let mut book = empty_book();
    let through = |book: &mut SourceBook, sighting| sight_through(book, sighting, &filter, ours());

    assert_eq!(
        through(&mut book, plain(1)),
        Sighted::Blocked(Blocked::IpFiltered)
    );
    assert_eq!(through(&mut book, plain(2)), Sighted::Pooled(Some(high(2))));

    assert_eq!(
        through(&mut book, dual(1, 4)),
        Sighted::Pooled(Some(PeerEndpoint::V6(v6(4)))),
        "a refused client id leaves the source on its IPv6 half"
    );
    let mapped = Ipv6Endpoint::new("::ffff:45.55.200.3".parse().unwrap(), 4662);
    assert_eq!(
        through(&mut book, plain(5).with_ipv6_half(Some(mapped))),
        Sighted::Pooled(Some(high(5))),
        "a refused IPv6 half is dropped, the IPv4 one stands"
    );
    assert_eq!(
        through(&mut book, plain(1).with_ipv6_half(Some(mapped))),
        Sighted::Blocked(Blocked::IpFiltered),
        "both halves refused"
    );

    assert_eq!(through(&mut book, low_id(9)), Sighted::Pooled(None));
    let refused_half = low_id(8).with_ipv6_half(Some(mapped));
    assert_eq!(
        through(&mut book, refused_half),
        Sighted::Pooled(None),
        "a refused rung-0 half is dropped, the callback road stands"
    );
    assert_eq!(book.counts().known, 5);
}

/// The intake gate's family block: an IPv6-only source needs an IPv6 of our
/// own to be dialed from, and a dual-stack one without is dialed on its IPv4.
#[test]
fn an_ipv6_only_source_needs_an_ipv6_of_our_own() {
    let filter = IpFilter::default();
    let mut book = empty_book();
    let ipv6_only = SourceSighting::plain(PeerSource::Ipv6(v6(1)), Informant::Own);

    assert_eq!(
        sight_through(&mut book, ipv6_only, &filter, DialPosition::default()),
        Sighted::Blocked(Blocked::FamilyUnreachable)
    );
    assert_eq!(
        sight_through(&mut book, dual(2, 2), &filter, DialPosition::default()),
        Sighted::Pooled(Some(high(2)))
    );
    assert_eq!(
        sight_through(&mut book, ipv6_only, &filter, ours()),
        Sighted::Pooled(Some(PeerEndpoint::V6(v6(1))))
    );
}

/// A seat in a registry no other download shares: the book's own standing
/// is always the holder.
fn alone() -> StandingSeat {
    StandingSeat::alone(crate::service::DownloadId::from_u64(0))
}
