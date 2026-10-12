//! A low id is a name only beside the server that assigned it: aMule matches a
//! Low-ID client by id only when its server IP and port are known and equal
//! (stock 2.3.3 `ClientList.cpp:283-297`). Asserted through the **Source
//! Book**'s interface: one peer's ask facts never reach the same id another
//! server assigned, nor outlive a record minted with no server known.

use super::*;

const SERVER_A: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 201, 1), 4661);
const SERVER_B: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 201, 2), 4661);

fn sight_on(book: &mut SourceBook, id: u32, server: Option<Ipv4Endpoint>) -> Sighted {
    let filter = IpFilter::default();
    book.sight(
        low_id(id),
        server,
        &Gate {
            filter: &filter,
            dial: ours(),
        },
    )
}

/// Call the next candidate back, adopt it at `inbound`, and have it answer a
/// source ask at `now`; its session then ends and it waits in its lane again.
fn answered_after_callback(
    book: &mut SourceBook,
    inbound: PeerEndpoint,
    now: Instant,
) -> CallbackKey {
    let Some(NextDial::Callback { candidate, .. }) = dial(book) else {
        panic!("a callable downloader calls the Low ID back");
    };
    let key = candidate.key();
    assert_eq!(book.adopt(key, inbound), Some(Adopted::Worker));
    book.connected(inbound);
    book.asked(inbound, now);
    book.answered(inbound, now);
    assert!(!book.wants_sources_for(key, now), "it just answered");
    assert_eq!(
        book.end_worker(inbound, false, ours()),
        Some(WorkerEnd::Release(Release::BackToLane))
    );
    key
}

/// The same low id seen on server A, then on server B after a move, is two
/// sources: A's peer answered a moment ago, B's has never been asked.
#[test]
fn one_low_id_on_two_servers_is_two_peers_with_their_own_ask_facts() {
    let now = Instant::now();
    let mut book = empty_book();
    assert_eq!(
        sight_on(&mut book, 7, Some(SERVER_A)),
        Sighted::Pooled(None)
    );
    let on_a = answered_after_callback(&mut book, high(9), now);

    assert_eq!(
        sight_on(&mut book, 7, Some(SERVER_B)),
        Sighted::Pooled(None),
        "B's low id 7 is not A's"
    );
    let on_b = CallbackKey {
        server: Some(SERVER_B),
        low_id: ClientId::from_u32(7),
    };
    assert!(
        !book.wants_sources_for(on_a, now),
        "A's peer keeps its facts"
    );
    assert!(
        book.wants_sources_for(on_b, now),
        "B's peer starts with none of A's"
    );
}

/// A low id minted with no server known names nobody beyond its record: once
/// the record leaves the book, the next sighting of that id starts clean.
#[test]
fn a_low_id_with_no_server_known_keeps_no_facts_past_its_record() {
    let now = Instant::now();
    let mut book = empty_book();
    assert_eq!(sight_on(&mut book, 7, None), Sighted::Pooled(None));
    let key = answered_after_callback(&mut book, high(9), now);
    assert!(matches!(dial(&mut book), Some(NextDial::Callback { .. })));
    assert_eq!(book.end_callback(key, ours()), Some(Release::Gone));

    assert_eq!(sight_on(&mut book, 7, None), Sighted::Pooled(None));
    assert!(
        book.wants_sources_for(key, now),
        "nothing kept under a low id whose server is unknown"
    );
}
