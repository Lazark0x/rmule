//! The steps most legs open with: list a server, connect to it, start a
//! search, and the rows a search answers with.

use rmule_core::{
    Core, CoreCommand, CoreEvent, ManagedServer, SearchCommand, SearchEvent, SearchId,
    ServerConnectionEvent, ServerListCommand,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, PeerSource, SearchQuery, SearchResult, ServerEndpoint,
};

use super::next_expected;

/// A result row of `size` bytes named `name`, one loopback source.
pub fn search_result(hash_byte: u8, size: u64, name: &str) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([hash_byte; FileHash::BYTE_LEN]),
        size,
        vec![Ed2kText::from_utf8(name)],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .expect("a valid result")
}

/// Add `server` to the server list.
pub async fn list_server(core: &Core, server: &ServerEndpoint) {
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(server.clone()),
    }))
    .await
    .expect("core accepts the command");
}

/// Ask to connect to `server`; the login presents the core's Core Settings'
/// credentials.
pub async fn connect_server(core: &Core, server: &ServerEndpoint) {
    core.send(CoreCommand::ConnectToServer {
        server: server.clone(),
    })
    .await
    .expect("core accepts the command");
}

/// List `server` and ask to connect to it.
pub async fn list_and_connect(core: &Core, server: &ServerEndpoint) {
    list_server(core, server).await;
    connect_server(core, server).await;
}

/// [`list_and_connect`], then wait until the session to `server` is up.
pub async fn connect_and_settle(core: &mut Core, server: &ServerEndpoint) {
    list_and_connect(core, server).await;
    next_expected(core, "the connect to settle", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(ServerConnectionEvent::Connected { server: up, .. })
                if up == server
        )
    })
    .await;
}

/// Start a search for `query` and return its id without waiting.
pub async fn start_search(core: &Core, query: impl Into<SearchQuery>) -> SearchId {
    let search_id = SearchId::mint();
    core.send(CoreCommand::Search(SearchCommand::StartSearch {
        search_id,
        query: query.into(),
    }))
    .await
    .expect("core accepts the command");
    search_id
}

/// Start a search for `query` and wait for the core to confirm it, naming
/// what the leg waits for.
pub async fn start_search_confirmed(
    core: &mut Core,
    which: &str,
    query: impl Into<SearchQuery>,
) -> SearchId {
    start_search(core, query).await;
    match next_expected(core, which, |event| {
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchStarted { .. })
                | CoreEvent::CommandRejected { .. }
        )
    })
    .await
    {
        CoreEvent::Search(SearchEvent::SearchStarted { search_id }) => search_id,
        other => panic!("expected SearchStarted ({which}), got {other:?}"),
    }
}
