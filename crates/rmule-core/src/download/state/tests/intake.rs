//! The intake gate through the brain's one entry (ADR-0090): every channel's
//! sightings are judged the same way — the IP filter and the address family
//! per half — and each channel keeps its own quirks. Counts come from the
//! outcomes.

use rmule_primitives::{Ipv6Endpoint, PeerSource, SourceCryptOptions};

use super::*;
use crate::ip_filter::IpFilter;

/// A filter blocking `10.0.0.<n>` for each `n`.
fn blocking(hosts: &[u8]) -> IpFilter {
    let text: String = hosts
        .iter()
        .map(|n| format!("10.0.0.{n}-10.0.0.{n},0,blocked\n"))
        .collect();
    IpFilter::from_texts(&[text.as_bytes()], 127, true, true).0
}

/// [`take`] behind `filter` instead of an open one.
fn take_through(
    state: &mut DownloadState,
    channel: Channel,
    sightings: Vec<SourceSighting>,
    filter: &IpFilter,
) -> Taken {
    let gate = Gate {
        filter,
        dial: state.dial,
    };
    state.on_sightings(t0(), channel, sightings, &gate)
}

/// A run that has not started: sightings pool and fill nothing.
fn unstarted(peer_concurrency: usize) -> DownloadState {
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        no_facts(),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
        peer_concurrency,
    )
}

fn every_channel() -> [Channel; 6] {
    [
        Channel::Link,
        Channel::Seed,
        Channel::Server,
        Channel::Global(source_server(9)),
        Channel::Kad,
        Channel::Exchanged(peer(1)),
    ]
}

fn known_ipv6() -> DialPosition {
    DialPosition {
        known_ipv6: Some("2001:db8::1".parse().unwrap()),
    }
}

fn ipv6_only() -> (Ipv6Endpoint, SourceSighting) {
    let endpoint = Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
    (endpoint, SourceSighting::plain(PeerSource::Ipv6(endpoint)))
}

/// A filtered High ID never pools, whichever channel names it, and its
/// admitted neighbour does; the counts say so.
#[test]
fn a_filtered_source_pools_on_no_channel_and_its_neighbour_does() {
    let filter = blocking(&[9]);
    for channel in every_channel() {
        let mut state = pooled_state(file_hash_only_content(ONE_PART), &[], QUIET_POSTURE, 4);

        let taken = take_through(
            &mut state,
            channel,
            plain_sightings(&[peer(9), peer(2)]),
            &filter,
        );

        assert_eq!(spawned(&taken.decisions), [peer(2)], "{channel:?}");
        let tally = taken.tally;
        assert_eq!(
            (
                tally.received,
                tally.admitted,
                tally.fresh,
                tally.family_unreachable
            ),
            (2, 1, 1, 0),
            "{channel:?}"
        );
    }
}

/// An IPv6-only source needs an IPv6 of our own on every channel; without one
/// it is counted as family-unreachable and pools nothing.
#[test]
fn an_ipv6_only_source_pools_on_no_channel_while_we_hold_no_ipv6() {
    let (endpoint, source) = ipv6_only();
    for channel in every_channel() {
        let mut state = pooled_state(file_hash_only_content(ONE_PART), &[], QUIET_POSTURE, 4);
        let taken = take(&mut state, channel, [source]);
        assert!(spawned(&taken.decisions).is_empty(), "{channel:?}");
        assert_eq!(
            (taken.tally.admitted, taken.tally.family_unreachable),
            (0, 1),
            "{channel:?}"
        );

        let posture = SourcingPosture {
            dial: known_ipv6(),
            ..QUIET_POSTURE
        };
        let mut state = pooled_state(file_hash_only_content(ONE_PART), &[], posture, 4);
        let taken = take(&mut state, channel, [source]);
        assert_eq!(
            spawned(&taken.decisions),
            [PeerEndpoint::V6(endpoint)],
            "{channel:?}"
        );
    }
}

/// A Low-ID row has no address to judge and passes the filter on every
/// channel; the channel decides whose server calls it back.
#[test]
fn a_low_id_row_passes_the_filter_and_is_called_back_through_its_channels_server() {
    let filter = blocking(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let row = SourceSighting::plain(PeerSource::new(low(7), 4662));
    for channel in every_channel() {
        let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
        let taken = take_through(&mut state, channel, vec![row], &filter);
        assert_eq!(taken.tally.admitted, 1, "{channel:?}");
        let asked = taken.decisions.iter().find_map(|decision| match decision {
            Decision::RequestCallback { low_id, .. } => Some(connected_key(*low_id)),
            Decision::RequestGlobalCallback {
                low_id,
                source_server,
                ..
            } => Some(CallbackKey {
                server: Some(*source_server),
                low_id: *low_id,
            }),
            _ => None,
        });
        let expected = match channel {
            Channel::Global(server) => CallbackKey {
                server: Some(server),
                low_id: low(7),
            },
            _ => connected_key(low(7)),
        };
        assert_eq!(asked, Some(expected), "{channel:?}: {:?}", taken.decisions);
    }
}

/// A source-exchange row's Low ID is read in the namespace of the server the
/// row itself names (stock 2.3.3 `PartFile.cpp:2771`, `:2815`), never ours:
/// one our server assigned is called back through our server, and one the
/// server we left assigned — a link that outlived our server move — through
/// that server.
#[test]
fn an_exchanged_low_id_row_is_called_back_through_the_server_it_names() {
    let ours = source_server(1);
    let left = source_server(2);
    let logged_in = CallbackCapability::of(
        true,
        Some(crate::own_identity::ConnectedSession {
            server: Some(ours),
            client_id: rmule_primitives::ClientId::from_u32(0x0A00_0001),
        }),
        false,
    );
    for named in [ours, left] {
        let mut state = state_from(
            file_hash_only_content(ONE_PART),
            SourcingPosture {
                callback_capability: logged_in,
                ..QUIET_POSTURE
            },
            1,
            no_facts(),
            Vec::new(),
            Vec::new(),
        );
        let _ = state.start(t0());
        let row = SourceSighting::plain(PeerSource::new(low(7), 4662)).with_server(Some(named));
        let asked: Vec<CallbackKey> = via_exchange(&mut state, peer(1), vec![row])
            .iter()
            .filter_map(|decision| match decision {
                Decision::RequestCallback { low_id, .. } => Some(CallbackKey {
                    server: Some(ours),
                    low_id: *low_id,
                }),
                Decision::RequestGlobalCallback {
                    low_id,
                    source_server,
                    ..
                } => Some(CallbackKey {
                    server: Some(*source_server),
                    low_id: *low_id,
                }),
                _ => None,
            })
            .collect();
        assert_eq!(
            asked,
            vec![CallbackKey {
                server: Some(named),
                low_id: low(7)
            }],
            "a row naming {named}"
        );
    }
}

/// A Kad callback row is judged by the address its publisher was observed at,
/// before it becomes a candidate: a filtered one opens no road.
#[test]
fn a_kad_buddy_row_is_judged_by_its_observed_publisher_address() {
    let row = buddy_callback::row(0x00);
    let observed = "198.51.100.77";
    let blocked = IpFilter::from_texts(
        &[format!("{observed}-{observed},0,blocked\n").as_bytes()],
        127,
        true,
        true,
    )
    .0;

    let mut filtered = callback_state(Vec::new(), Vec::new(), true, 1);
    let taken = take_through(&mut filtered, Channel::Kad, vec![row], &blocked);
    assert_eq!(taken.tally.admitted, 0);
    assert!(taken.decisions.is_empty(), "{:?}", taken.decisions);

    let mut open = callback_state(Vec::new(), Vec::new(), true, 1);
    let taken = take(&mut open, Channel::Kad, [row]);
    assert_eq!(taken.tally.admitted, 1);
    buddy_callback::buddy_key(&taken.decisions);
}

/// The filter's view is lent per call: a reload applies from the next
/// sighting, and a source already pooled is left as it was.
#[test]
fn a_filter_reload_applies_from_the_next_sighting_and_leaves_the_pooled_alone() {
    let mut state = unstarted(1);
    let _ = take(&mut state, Channel::Server, plain_sightings(&[peer(2)]));

    let reloaded = blocking(&[2, 3]);
    let later = take_through(
        &mut state,
        Channel::Kad,
        plain_sightings(&[peer(2), peer(3)]),
        &reloaded,
    );
    assert_eq!(later.tally.admitted, 0);

    assert_eq!(spawned(&state.start(t0())), [peer(2)]);
}

/// A second link naming sources counts what it named, what the gate let
/// through, and which of those the run did not already hold.
#[test]
fn a_later_link_counts_named_admitted_and_fresh() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1)],
        QUIET_POSTURE,
        4,
    );
    assert_eq!(spawned(&state.start(t0())), [peer(1)]);
    let filter = blocking(&[9]);

    let taken = take_through(
        &mut state,
        Channel::Link,
        plain_sightings(&[peer(1), peer(9), peer(2), peer(2)]),
        &filter,
    );

    let tally = taken.tally;
    assert_eq!((tally.received, tally.admitted, tally.fresh), (4, 3, 1));
    assert_eq!(spawned(&taken.decisions), [peer(2)]);
}

/// A spent endpoint is not a new source: a link naming it again joins nothing.
#[test]
fn a_later_link_naming_a_spent_endpoint_adds_nothing() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1)],
        QUIET_POSTURE,
        1,
    );
    let _ = state.start(t0());
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);

    let taken = take(&mut state, Channel::Link, plain_sightings(&[peer(1)]));

    assert_eq!((taken.tally.admitted, taken.tally.fresh), (1, 0));
    assert!(spawned(&taken.decisions).is_empty());
}

/// A source exchange reports its answer: how many sources it carried and how
/// many passed the gate.
#[test]
fn an_exchange_reports_what_it_carried_and_what_passed() {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &[peer(1)],
        QUIET_POSTURE,
        2,
    );
    let _ = state.start(t0());
    let filter = blocking(&[9]);

    let taken = take_through(
        &mut state,
        Channel::Exchanged(peer(1)),
        plain_sightings(&[peer(9), peer(2)]),
        &filter,
    );

    assert!(matches!(
        taken.decisions.first(),
        Some(Decision::Emit(DownloadEvent::SourcesExchanged {
            peer: from,
            received: 2,
            admitted: 1,
            ..
        })) if *from == peer(1)
    ));
    assert_eq!(spawned(&taken.decisions), [peer(2)]);
}

/// A seed keeps its origin on its record: the run ranks it as remembered,
/// while the same endpoint named by a server is not.
#[test]
fn a_seed_keeps_its_origin_and_a_server_answer_does_not() {
    let mut state = pooled_state(file_hash_only_content(ONE_PART), &[], QUIET_POSTURE, 4);
    let _ = take(&mut state, Channel::Seed, plain_sightings(&[peer(1)]));
    let _ = take(&mut state, Channel::Server, plain_sightings(&[peer(2)]));

    assert!(state.is_remembered(peer(1)));
    assert!(!state.is_remembered(peer(2)));
}

/// The run's start sights seeds, then the link, then the server's answer,
/// and fills nothing until it starts: a source two of them name is one, keeps
/// the first's place and the later record's crypt word.
#[test]
fn the_start_pools_seeds_then_link_then_server_and_a_shared_source_once() {
    let mut state = unstarted(8);
    let answered = SourceSighting::new(
        PeerSource::HighId(match peer(3) {
            PeerEndpoint::V4(v4) => v4,
            PeerEndpoint::V6(_) => unreachable!(),
        }),
        Some(UserHash::from_bytes([0x5F; UserHash::BYTE_LEN])),
        Some(SourceCryptOptions::from_byte(0x03)),
    );
    let seeds = take(&mut state, Channel::Seed, plain_sightings(&[peer(1)]));
    let link = take(
        &mut state,
        Channel::Link,
        plain_sightings(&[peer(3), peer(2), peer(3)]),
    );
    let server = take(
        &mut state,
        Channel::Server,
        [plain_sightings(&[peer(4)]), vec![answered]].concat(),
    );

    assert!(
        [&seeds, &link, &server]
            .iter()
            .all(|taken| spawned(&taken.decisions).is_empty()),
        "nothing is filled before the run starts"
    );
    let all = seeds.tally + link.tally + server.tally;
    assert_eq!((all.distinct(), all.distinct_dialable()), (4, 4));
    assert_eq!(
        spawned(&state.start(t0())),
        [peer(1), peer(3), peer(2), peer(4)],
        "seeds first, then the link's order"
    );
    assert_eq!(state.peer_crypt(peer(3)), answered.peer_crypt());
    assert!(state.is_remembered(peer(1)));
}
