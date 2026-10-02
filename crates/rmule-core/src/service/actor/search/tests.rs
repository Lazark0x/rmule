//! A keyword search whose session ends as it starts: the ended session counts
//! as none, so with no Server Intent the server leg is not sent, the Kad leg
//! goes out, and the search completes on it (ADR-0034, "The legs are
//! independent", "A server leg's states").

use std::time::Duration;

use rmule_kad::KadId;
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, KeywordQuery, PeerSource, SearchResult, ServerEndpoint,
    SourceLookupTarget,
};

use crate::server_session::ServerSessionHandle;
use crate::{
    ClientUdpBind, Core, CoreCommand, CoreConfig, CoreError, CoreEvent, KadEnableConfig,
    KadKeywordSink, KadRuntimeFactory, KadSource, KadSourceChannel, LegNotSent, SearchCommand,
    SearchEvent, SearchId, SearchLegState,
};

/// A Kad node whose keyword walk answers one row and ends.
#[derive(Clone)]
struct AnsweringKad;

fn kad_row() -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([0xBB; FileHash::BYTE_LEN]),
        1024,
        vec![Ed2kText::from_utf8("linux kad.iso")],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .expect("a valid result")
}

impl KadSourceChannel for AnsweringKad {
    async fn search_sources(&self, _target: SourceLookupTarget) {}
    async fn publish_source(&self, _target: SourceLookupTarget) {}
    async fn next_sources(&self) -> Option<(FileHash, Vec<KadSource>)> {
        std::future::pending().await
    }
    async fn search_keyword(&self, _query: KeywordQuery, results: KadKeywordSink) {
        let _ = results.send(vec![kad_row()]).await;
    }
}

impl KadRuntimeFactory for AnsweringKad {
    type Channel = Self;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _bind: ClientUdpBind,
    ) -> Result<Self, CoreError> {
        Ok(Self)
    }
}

fn kad_config() -> KadEnableConfig {
    KadEnableConfig {
        kad_id: KadId::from_bytes([0x0A; KadId::BYTE_LEN]),
        peer_credentials: rmule_testkit::test_identity(0x42, "rmule-core", 4662).into(),
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_udp_key: 0,
        kad_capture_dir: None,
        kad_shutdown: None,
    }
}

#[tokio::test]
async fn a_session_ending_as_the_search_starts_counts_as_none_and_the_search_completes_on_kad() {
    let builder = Core::builder(
        CoreConfig {
            status_ping_tick: Duration::from_secs(3600),
            search_quiet_timeout: Duration::from_millis(100),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .kad(AnsweringKad);
    let session = builder.shared_server_session();
    let mut core = builder.build();
    core.send(CoreCommand::EnableKad(kad_config()))
        .await
        .expect("core alive");
    // Alive when the search reads the slot; gone before its request is taken.
    *session.slot().lock().await = Some(ServerSessionHandle::ending(
        ServerEndpoint::new("192.0.2.1", 4661).expect("valid endpoint"),
    ));

    let search_id = SearchId::mint();
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id,
        query: KeywordQuery::new(Ed2kText::from_utf8("linux"))
            .expect("a phrase")
            .into(),
    }))
    .await
    .expect("core alive");

    let (legs, total) = tokio::time::timeout(Duration::from_secs(5), async {
        let mut last = None;
        loop {
            match core.next_event().await.expect("event stream open") {
                CoreEvent::Search(SearchEvent::SearchFailed { search_id: id, .. })
                    if id == search_id =>
                {
                    panic!("the search failed whole");
                }
                CoreEvent::Search(SearchEvent::SearchLegsChanged {
                    search_id: id,
                    legs,
                }) if id == search_id => last = Some(legs),
                CoreEvent::Search(SearchEvent::SearchCompleted {
                    search_id: id,
                    total_results,
                }) if id == search_id => return (last, total_results),
                _ => {}
            }
        }
    })
    .await
    .expect("the search completes");
    let legs = legs.expect("the legs were told");
    let not_sent = SearchLegState::NotSent(LegNotSent::NoServer);
    assert_eq!(legs.server, not_sent);
    assert_eq!(legs.sweep, not_sent);
    assert_eq!(legs.kad, SearchLegState::Settled);
    assert_eq!(total, 1, "the Kad row");
}
