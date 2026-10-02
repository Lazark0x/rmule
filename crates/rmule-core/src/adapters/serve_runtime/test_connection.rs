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
use rmule_peer::PeerEvent;

use super::ServeConnEvent;
use crate::adapters::kad_runtime::{SharedKadPump, report_kad_firewall_ack};
use crate::adapters::serve_projection::serve_event_from_peer;
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
                PeerEvent::Disconnected { .. } => return PortTestEnd::TesterClosed,
                // The session answered the tester's hello on its own; being
                // identified is the test, not a request.
                PeerEvent::PeerIdentified { .. } => {}
                PeerEvent::KadFirewallCheckAck => report_kad_firewall_ack(&kad_pump, peer),
                other => {
                    if serve_event_from_peer(other).is_some_and(|event| asks_to_be_served(&event)) {
                        tracing::debug!(%peer, "a test connection asked to be served; closed");
                        return PortTestEnd::AskedToBeServed;
                    }
                }
            }
        }
        PortTestEnd::TesterClosed
    })
    .await
    .unwrap_or(PortTestEnd::Lapsed);
    let _ = conn.shutdown().await;
    end
}

/// Whether `event` asks us to serve something — the one thing a Test
/// Connection may not have. Exhaustive, so a new serve event is decided here.
/// Being identified, proving an identity (Secure User Identification), and
/// stating software or a reask contact ask for nothing.
const fn asks_to_be_served(event: &ServeConnEvent) -> bool {
    match event {
        ServeConnEvent::FileRequested { .. }
        | ServeConnEvent::FileBundleRequested { .. }
        | ServeConnEvent::FileIdSet { .. }
        | ServeConnEvent::HashSetRequested { .. }
        | ServeConnEvent::SlotRequested { .. }
        | ServeConnEvent::PartsRequested { .. }
        | ServeConnEvent::SourcesRequested { .. }
        | ServeConnEvent::AichRequested { .. }
        | ServeConnEvent::AichFileHashRequested { .. } => true,
        ServeConnEvent::TransferCancelled { .. }
        | ServeConnEvent::Disconnected
        | ServeConnEvent::Identified { .. }
        | ServeConnEvent::IdentityVerified { .. }
        | ServeConnEvent::SoftwareRevised { .. }
        | ServeConnEvent::ReaskContactRevised { .. }
        | ServeConnEvent::Readopted => false,
    }
}
