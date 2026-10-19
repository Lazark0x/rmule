//! Kad-seam tests: the ed2k->Kad bootstrap handoff gate, the projection of a
//! Kad keyword row onto a search result, the source channel, and the one
//! smoke test of the pump's driver over a real loopback node. The pump's
//! decisions are the Kad Pump State's, tested through its inputs and effects.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rmule_peer::PeerIdentity;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, SearchResultOrigin, UserHash,
};
use tokio::sync::{Mutex, mpsc};

use super::*;

/// The ed2k→Kad handoff broker's core-side decision (ADR-0067): the gate's
/// **running** leg (an empty sink drops the hint) and the projection that
/// pairs the peer's parsed Kad UDP port with the *live connection* IP (the
/// hello carries only the port). The peer-side `KadPort ∧ KadVersion > 1`
/// parse itself is proven in `rmule-peer`.
#[tokio::test]
async fn the_handoff_broker_gates_on_running_and_projects_the_connection_ip() {
    use rmule_peer::{MiscOptions2, PeerHelloBody};
    use rmule_primitives::{Tag, TagName, TagValue};

    let peer_ip = Ipv4Addr::new(198, 51, 100, 7);
    let peer = || PeerEndpoint::V4(Ipv4Endpoint::new(peer_ip, 4662));
    let peer_with_tags = |tags: Vec<Tag>| {
        PeerIdentity::from_hello_body(&PeerHelloBody {
            user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            client_id: ClientId::from_u32(0),
            tcp_port: 4662,
            tags,
            connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
        })
    };
    // A peer advertising a Kad node: CT_EMULE_UDPPORTS kad half 4672 (high
    // 16), client half 4665 (low 16); Kad version 8 in MiscOptions2.
    let kad_peer = || {
        peer_with_tags(vec![
            Tag::new(
                TagName::compact_id(0xF9),
                TagValue::U32((4672u32 << 16) | 4665),
            ),
            MiscOptions2::from_bits(8).to_tag(),
        ])
    };

    let (tx, mut rx) = mpsc::channel::<Ipv4Endpoint>(4);
    let sink = SharedKadBootstrap::default();

    // Kad not running (empty sink): the Kad-carrying peer's hint is dropped.
    broker_peer_kad_handoff(&sink, peer(), &kad_peer()).await;
    assert!(
        rx.try_recv().is_err(),
        "Kad not running ⇒ the hint is dropped"
    );

    // Kad running: install the sender (as the factory does on start). The
    // brokered endpoint is (live connection IP, parsed Kad UDP port).
    sink.install_for_good(tx);
    broker_peer_kad_handoff(&sink, peer(), &kad_peer()).await;
    assert_eq!(
        rx.try_recv().ok(),
        Some(Ipv4Endpoint::new(peer_ip, 4672)),
        "a running node is brokered the peer's (connection IP, Kad UDP port)"
    );

    // A peer carrying no Kad hint is never brokered, even while running.
    broker_peer_kad_handoff(&sink, peer(), &peer_with_tags(Vec::new())).await;
    assert!(rx.try_recv().is_err(), "no Kad hint ⇒ nothing brokered");
}

fn keyword_row(
    complete_sources: Option<u32>,
    file_type: Option<&str>,
) -> rmule_kad::KadKeywordResult {
    rmule_kad::KadKeywordResult {
        file_id: rmule_kad::KadId::from_bytes([0x11; 16]),
        filename: Some("concert.mkv".to_owned()),
        size: Some(65_536),
        file_type: file_type.map(str::to_owned),
        complete_sources,
        publish_info: None,
        aich_roots: Vec::new(),
    }
}

/// A Kad keyword row reaches the app with the counts and the classification
/// the storer served (without them every Kad-discovered row
/// rendered `Sources 0` / `Type —`). The count lands as
/// *availability* because that is what aMule's requester does with it.
#[test]
fn a_projected_kad_keyword_row_carries_its_source_count_and_type() {
    let projected = project_keyword_result(&keyword_row(Some(42), Some("Video")))
        .expect("a named, sized row projects");

    assert_eq!(projected.reported_availability(), Some(42));
    assert_eq!(
        projected.file_type().map(Ed2kText::to_display_string),
        Some("Video".to_owned())
    );
    assert_eq!(projected.origin(), SearchResultOrigin::Kad);
    assert!(
        projected.sources().is_empty(),
        "a keyword row carries a count, never endpoints"
    );
}

/// aMule's rogue-publisher guard (`Search.cpp:1035`): an implausible count
/// is zeroed rather than believed, and a row with no count at all stays
/// count-less so the merge can take another storer's figure.
#[test]
fn an_implausible_kad_availability_is_zeroed_and_a_missing_one_stays_absent() {
    let rogue = project_keyword_result(&keyword_row(Some(65_501), None)).unwrap();
    assert_eq!(rogue.reported_availability(), Some(0));

    let silent = project_keyword_result(&keyword_row(None, None)).unwrap();
    assert_eq!(silent.reported_availability(), None);
}

/// A keyword row the search cannot keep is dropped by its reason, never
/// silently: one above eD2k's 256 GiB limit, one with no name and one with no
/// size each say why, and the rows beside them stand. The rows are made here,
/// not captured.
#[test]
fn a_kad_keyword_row_that_cannot_stand_is_dropped_by_its_reason() {
    let oversize = rmule_kad::KadKeywordResult {
        size: Some(rmule_primitives::MAX_ED2K_FILE_SIZE + 1),
        ..keyword_row(Some(3), None)
    };
    let nameless = rmule_kad::KadKeywordResult {
        filename: None,
        ..keyword_row(None, None)
    };
    let sizeless = rmule_kad::KadKeywordResult {
        size: None,
        ..keyword_row(None, None)
    };
    let (rows, skipped) = project_keyword_rows(&[
        keyword_row(Some(5), None),
        oversize,
        nameless,
        sizeless,
        rmule_kad::KadKeywordResult {
            size: Some(rmule_primitives::MAX_ED2K_FILE_SIZE),
            ..keyword_row(None, None)
        },
    ]);

    assert_eq!(
        rows.iter().map(SearchResult::file_size).collect::<Vec<_>>(),
        [65_536, rmule_primitives::MAX_ED2K_FILE_SIZE]
    );
    assert_eq!(
        skipped,
        [
            SearchResultSkipReason::FileSizeAboveLimit,
            SearchResultSkipReason::MissingFileName,
            SearchResultSkipReason::MissingFileSize,
        ]
    );
}

/// The production channel's `next_sources` survives the discovery
/// sweep's `select!` dropping it mid-await. The call is parked on an empty
/// channel, an answer lands while it waits, the sweep tick wins the race and
/// the pending call is dropped unpolled — and the next call still delivers
/// that answer, so a sweep never costs a batch of sources.
#[tokio::test]
async fn a_next_sources_dropped_mid_await_loses_nothing_and_the_next_call_delivers_it() {
    let (commands, _pump) = mpsc::channel(1);
    let (answers, sources) = mpsc::channel(4);
    let channel = RuntimeKadChannel {
        commands,
        sources: Mutex::new(sources),
    };
    let file_hash = FileHash::from_bytes([0x5B; FileHash::BYTE_LEN]);

    let mut pending = Box::pin(channel.next_sources());
    std::future::poll_fn(|cx| {
        assert!(
            pending.as_mut().poll(cx).is_pending(),
            "nothing sent yet, so the call parks"
        );
        std::task::Poll::Ready(())
    })
    .await;
    answers.send((file_hash, Vec::new())).await.unwrap();
    tokio::select! {
        biased;
        () = std::future::ready(()) => {}
        answer = &mut pending => panic!("the sweep tick is biased to win, got {answer:?}"),
    }
    drop(pending);

    let delivered = tokio::time::timeout(Duration::from_secs(1), channel.next_sources())
        .await
        .expect("the next call does not wait for a second answer");
    assert_eq!(delivered, Some((file_hash, Vec::new())));
}

/// The pump's driver over a real loopback node — the one test that does not
/// stop at the brain's interface. It starts, carries one core command to the
/// node and the node's answering event back out through the brain to the
/// search that asked, and on the stop lever tears down: the cells it filled
/// are empty and the stop is confirmed.
#[tokio::test]
async fn the_driver_starts_round_trips_a_keyword_walk_and_stops() {
    use crate::search::{KadLegNews, kad_keyword_leg};
    use crate::service::{LegNotSent, SearchLegState};

    let cells = crate::adapters::KadCells::detached();
    cells
        .adapters
        .own_identity()
        .set_user_hash(UserHash::from_bytes([0x5B; UserHash::BYTE_LEN]));
    let mut factory = RuntimeKadFactory;
    let inlet = crate::client_udp::SharedKadInlet::default();
    let (shutdown, lever) = KadShutdownSlot::new();
    let channel = factory
        .start(
            &KadEnableConfig {
                bootstrap: Vec::new(),
                contacts: Vec::new(),
                nodes_dat_path: None,
                assume_open_reachability: false,
                kad_capture_dir: None,
                kad_shutdown: Some(shutdown),
            },
            &KadNodeIdentity {
                kad_id: rmule_kad::KadId::from_bytes([0x22; rmule_kad::KadId::BYTE_LEN]),
                peer_credentials: ClientIdentity::new(
                    UserHash::from_bytes([0x5B; UserHash::BYTE_LEN]),
                    Ed2kText::from_utf8("rmule-smoke"),
                    4662,
                    60,
                )
                .into(),
                kad_udp_key: 0,
            },
            ClientUdpBind {
                socket: Arc::new(
                    rmule_net::ed2k::ClientUdpSocket::bind(0)
                        .await
                        .expect("a loopback client-UDP bind"),
                ),
                kad_inlet: inlet.clone(),
                reach: crate::reachability::SharedSelfReach::new(
                    crate::KadReachLevel::published(cells.verdicts.clone()),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
            },
            &cells,
        )
        .await
        .expect("the Kad runtime starts over the bound client-UDP socket");

    // A node with no contacts ends a keyword walk at once: the command goes
    // in, `KeywordSearchComplete` comes out, and the brain's news reaches the
    // search's leg.
    let (sink, mut leg) = kad_keyword_leg();
    channel
        .search_keyword(
            KeywordQuery::new(Ed2kText::from_utf8("ubuntu")).expect("a valid phrase"),
            sink,
        )
        .await;
    let news = tokio::time::timeout(Duration::from_secs(5), leg.next())
        .await
        .expect("the walk's end comes back within budget");
    assert!(
        matches!(
            news,
            KadLegNews::Ended(SearchLegState::NotSent(LegNotSent::NoKadContact))
        ),
        "the node's answer reached the search: {news:?}"
    );

    assert!(
        lever.request_and_wait(Duration::from_secs(5)).await,
        "the pump tears down and confirms"
    );
    assert!(!inlet.is_live());
    assert!(!cells.adapters.kad_pump.is_live());
    assert!(!cells.adapters.kad_bootstrap.is_live());
}
