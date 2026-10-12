//! The **Related-Files Search** at the core seam (ADR-0037):
//! it rides the connected server over TCP and nothing else, completes on that
//! server's answer, and is refused — unsent, undialed — when no session is up
//! or the server does not grant `SRV_TCPFLG_RELATEDSEARCH`. The grant is a
//! level on the diagnostics snapshot a menu reads without sending a command.

use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, RelatedSearchRefusal, SearchEvent, SearchId,
};
use rmule_ed2k::ServerTcpFlags;
use rmule_primitives::{Ed2kText, FileHash, RelatedFilesQuery, SearchQuery, ServerEndpoint};
use rmule_testkit::FakeEd2kServer;
use tokio::net::UdpSocket;

use crate::fixture::{
    StubKad, connect_and_settle, kad_enable_config, next_expected, search_config, search_query,
    start_search, sweep_datagram,
};

const HASH: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn related() -> SearchQuery {
    RelatedFilesQuery::new(
        FileHash::from_bytes(HASH),
        Ed2kText::from_utf8("holiday video.avi"),
    )
    .into()
}

async fn granting_server(flags: Option<u32>) -> FakeEd2kServer {
    let server = FakeEd2kServer::start_scripted().await;
    server
        .set_tcp_flags(flags.map(ServerTcpFlags::from_bits))
        .await;
    server
}

/// The refusal names the search the caller asked for: a front
/// end ties it to its entry by id, never by the order refusals arrive in.
async fn refused_with(core: &mut Core, search_id: SearchId, reason: RelatedSearchRefusal) {
    next_expected(core, "the related search's refusal", |event| {
        assert!(
            !matches!(event, CoreEvent::Search(SearchEvent::SearchStarted { .. })),
            "a refused related search never starts"
        );
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchRefused { search_id: id, reason: got })
                if *id == search_id && *got == reason
        )
    })
    .await;
}

#[tokio::test]
async fn a_related_search_reaches_neither_the_sweep_nor_kad_and_completes_on_the_empty_answer() {
    let server = granting_server(Some(ServerTcpFlags::RELATEDSEARCH)).await;
    let endpoint = server.endpoint();
    let kad = StubKad::new();
    let walks = kad.walks();
    let mut core = Core::builder(
        CoreConfig {
            global_search_tick: Duration::from_millis(5),
            // Only an answer can complete the search inside the event budget:
            // neither the server's answer wait nor the Kad lifetime can.
            search_server_answer_timeout: Duration::from_secs(600),
            search_kad_lifetime: Duration::from_secs(600),
            ..search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .kad(kad)
    .build();
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();
    // A second managed server the sweep would ask: the managed list holds the
    // TCP port, and the server-UDP send adds eD2k's +4.
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let swept = ServerEndpoint::new("127.0.0.1", udp.local_addr().unwrap().port() - 4).unwrap();
    crate::fixture::list_server(&core, &swept).await;
    connect_and_settle(&mut core, &endpoint).await;

    let related_id = start_search(&core, related()).await;
    next_expected(&mut core, "the related search to complete", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted {
                search_id,
                total_results: 0,
            }) if *search_id == related_id
        )
    })
    .await;

    assert_eq!(
        server.search_phrases().await,
        ["related::0123456789ABCDEFFEDCBA9876543210"],
        "the connected server alone is asked, by hash"
    );
    assert!(walks.lock().unwrap().is_empty(), "Kad walked nothing");
    assert_eq!(
        sweep_datagram(&udp, Duration::from_millis(200)).await,
        None,
        "the sweep sent nothing"
    );

    // The same core, the same fakes: a keyword search reaches both, so their
    // silence above was the routing and not a dead seam.
    let keyword_id = start_search(&core, search_query("holiday")).await;
    assert!(
        sweep_datagram(&udp, Duration::from_secs(30))
            .await
            .is_some(),
        "a keyword search is swept"
    );
    next_expected(&mut core, "the keyword search to complete", |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchCompleted { search_id, .. })
                if *search_id == keyword_id
        )
    })
    .await;
    assert_eq!(
        *walks.lock().unwrap(),
        ["holiday"],
        "a keyword search walks Kad"
    );
}

#[tokio::test]
async fn a_related_search_with_no_session_is_refused_and_dials_nothing() {
    let server = granting_server(Some(ServerTcpFlags::RELATEDSEARCH)).await;
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    assert_eq!(
        core.diagnostics_snapshot().related_search_refusal(),
        Some(RelatedSearchRefusal::NotConnected)
    );
    let search_id = start_search(&core, related()).await;

    refused_with(&mut core, search_id, RelatedSearchRefusal::NotConnected).await;
    assert!(
        server.assigned_ids().await.is_empty(),
        "no server was dialed"
    );
}

#[tokio::test]
async fn a_related_search_toward_a_server_without_the_grant_is_refused_unsent() {
    // Lugdunum's observed word without `0x40`.
    let server = granting_server(Some(0x17F9 & !ServerTcpFlags::RELATEDSEARCH)).await;
    let endpoint = server.endpoint();
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    connect_and_settle(&mut core, &endpoint).await;

    assert_eq!(
        core.diagnostics_snapshot().related_search_refusal(),
        Some(RelatedSearchRefusal::NotOffered)
    );
    let search_id = start_search(&core, related()).await;

    refused_with(&mut core, search_id, RelatedSearchRefusal::NotOffered).await;
    assert!(server.search_phrases().await.is_empty(), "nothing was sent");
}

#[tokio::test]
async fn the_grant_level_follows_a_server_switch() {
    let granting = granting_server(Some(ServerTcpFlags::RELATEDSEARCH)).await;
    let withholding = granting_server(None).await;
    let mut core = Core::builder(search_config(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    connect_and_settle(&mut core, &granting.endpoint()).await;
    let snapshot = core.diagnostics_snapshot();
    assert!(snapshot.connected_server_grants.related_search);
    assert_eq!(snapshot.related_search_refusal(), None);

    connect_and_settle(&mut core, &withholding.endpoint()).await;
    let snapshot = core.diagnostics_snapshot();
    assert!(!snapshot.connected_server_grants.related_search);
    assert_eq!(
        snapshot.related_search_refusal(),
        Some(RelatedSearchRefusal::NotOffered)
    );
}
