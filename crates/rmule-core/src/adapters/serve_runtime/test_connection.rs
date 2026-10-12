//! Answering a **Test Connection** (ADR-0046 "Test Connections"): a plain
//! dial the listener admitted under `Required` only because a
//! reachability test is awaited from its address.
//!
//! A test proves our port answers; it is not a peer to serve. So the
//! connection does exactly what the test needs and nothing else: the session
//! answers the dialer's hello on its own (a Lugdunum or ed2k-server port test
//! is `OP_HELLO` → `OP_HELLOANSWER`), and a Kad helper's
//! `OP_KAD_FWTCPCHECK_ACK` — the one packet a helper sends after the hello —
//! is counted toward our TCP verdict. Any request to be served (a file, a
//! slot, sources, hashes) ends it; everything else is ignored — the identity
//! proof above all, which an aMule helper runs after the hello and before
//! its ack (closing on it would lose every ack under `Required`). It never
//! enters the inbound triage, so no upload queue, source exchange, callback adoption,
//! buddy link, Kad handoff or address vote can see it.
//!
//! The ack counts only because the Kad node window-guards it by the same
//! helper address the listener admitted on, so a spoofed or shared address
//! gains nothing a Test Connection may not do.

use std::time::Duration;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionEvent, PeerEvent, ServerEvent, SideEvent};

use crate::adapters::kad_runtime::{SharedKadPump, report_kad_firewall_ack};
use crate::service::PortTestEnd;

/// How long a Test Connection is held at most. Every tester closes, or acks,
/// right after the hello answer; this only bounds one that does not.
const TEST_CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

/// Answer one Test Connection to its end, then close it: how it ended.
pub(crate) async fn answer_test_connection(
    mut conn: PeerConnection,
    kad_pump: SharedKadPump,
) -> PortTestEnd {
    let peer = conn.peer_endpoint();
    let end = tokio::time::timeout(TEST_CONNECTION_LIFETIME, async {
        while let Some(event) = conn.next_event().await {
            match event {
                PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => {
                    return PortTestEnd::TesterClosed;
                }
                // The session answered the tester's hello on its own; being
                // identified is the test, not a request.
                PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {}
                PeerEvent::Side(SideEvent::KadFirewallCheckAck) => {
                    report_kad_firewall_ack(&kad_pump, peer)
                }
                PeerEvent::Server(request) if asks_to_be_served(&request) => {
                    tracing::debug!(%peer, "a test connection asked to be served; closed");
                    return PortTestEnd::AskedToBeServed;
                }
                _ => {}
            }
        }
        PortTestEnd::TesterClosed
    })
    .await
    .unwrap_or(PortTestEnd::Lapsed);
    let _ = conn.shutdown().await;
    end
}

/// Whether `request` asks us to serve something — the one thing a Test
/// Connection may not have. Exhaustive, so a new Server request is decided
/// here. Giving up a slot asks for nothing, and neither does a part ask
/// without one, which the session reports and frames nothing for.
const fn asks_to_be_served(request: &ServerEvent) -> bool {
    match request {
        ServerEvent::FileRequested { .. }
        | ServerEvent::FileBundleRequested { .. }
        | ServerEvent::FileIdSet { .. }
        | ServerEvent::HashSetRequested { .. }
        | ServerEvent::SlotRequested { .. }
        | ServerEvent::PartsRequested { .. }
        | ServerEvent::SourcesRequested { .. }
        | ServerEvent::AichRequested { .. }
        | ServerEvent::AichFileHashRequested { .. } => true,
        ServerEvent::TransferCancelled { .. }
        | ServerEvent::PartsWithoutSlot { .. }
        | ServerEvent::SourcesAnswered { .. } => false,
    }
}
