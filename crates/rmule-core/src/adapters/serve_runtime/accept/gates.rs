//! The **Accept Gates**: what every inbound peer connection meets before the
//! serve loop sees it — the IP filter, then the ban store (ADR-0064), then the
//! Test Connection carve-out (ADR-0046) — in that order, and only here.
//!
//! They run on the producer's side of the accept channel: the accept pump
//! passes each TCP accept through them, the admit seam each Tunnel and
//! callback dial-back. So the channel holds only peers the serve loop will
//! triage, and the loop's `accept` takes one with a bare receive. That is
//! what makes it cancel-safe: the ban check awaits a lock and a refused port
//! test awaits its report, and either await inside the serve loop's `accept`
//! would let its `select!` drop a connection already taken off the channel.

use std::time::Instant;

use rmule_net::peer::Connection as PeerConnection;
use rmule_primitives::UserHash;

use super::AdmittedPeer;
use crate::adapters::kad_runtime::SharedKadPump;
use crate::adapters::serve_runtime::test_connection::answer_test_connection;
use crate::awaited_testers::AwaitedServer;
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;
use crate::service::{LoginStep, PortTestEnd};

/// The three gates' shared state, cloned into every producer that feeds the
/// accept channel. Default/empty off `Core::builder`: nothing is filtered,
/// nothing is banned, and no Kad node counts a test's ack.
#[derive(Clone, Default)]
pub(crate) struct AcceptGates {
    ip_filter: SharedIpFilter,
    ban_store: SharedBanStore,
    /// Where a Test Connection's `OP_KAD_FWTCPCHECK_ACK` is carried.
    kad_pump: SharedKadPump,
}

/// One connection at the gates, before anything decided its fate.
pub(super) struct Arrival {
    pub(super) conn: PeerConnection,
    /// The target a NAT-T punch raised this stream toward, carried through to
    /// the triage (see [`AdmittedPeer`]).
    pub(super) dialed_toward: Option<UserHash>,
    /// A **Test Connection** (ADR-0046): a plain dial the listener admitted
    /// under `Required` only because a reachability test is awaited from its
    /// address. It meets the same gates, is answered by
    /// [`answer_test_connection`] and never reaches the channel — no serving,
    /// no adoption.
    pub(super) test_connection: bool,
    /// The awaited server, when this connection came from its address inside
    /// its port test's window: where the test's end is reported.
    pub(super) awaited_server: Option<AwaitedServer>,
}

impl AcceptGates {
    /// The gates over the core-owned IP filter and ban store, with the Kad
    /// pump a Test Connection's ack is carried to.
    pub(crate) fn new(
        ip_filter: SharedIpFilter,
        ban_store: SharedBanStore,
        kad_pump: SharedKadPump,
    ) -> Self {
        Self {
            ip_filter,
            ban_store,
            kad_pump,
        }
    }

    /// Pass one arrival through the gates, in order. `Some` is a peer for the
    /// serve loop to triage; `None` means the gates took it — refused and
    /// closed, or a Test Connection now answered on a task of its own. A
    /// refused port test's end is reported to its server before this returns.
    pub(super) async fn pass(&self, arrival: Arrival) -> Option<AdmittedPeer> {
        let Arrival {
            conn,
            dialed_toward,
            test_connection,
            awaited_server,
        } = arrival;
        let peer = conn.peer_endpoint();
        // The IP filter, aMule `CClientTCPSocket::InitNetworkData`: an
        // IP-filtered address is refused before any hello — and before the ban
        // gate, aMule's own check order. The verdict is bound first so the read
        // guard never crosses an await.
        let ip_filtered = self
            .ip_filter
            .read()
            .expect("ip filter lock")
            .is_filtered_peer(peer);
        if ip_filtered {
            tracing::debug!(%peer, "refusing an inbound connection from an IP-filtered address");
            refuse(conn, awaited_server, PortTestEnd::IpFiltered).await;
            return None;
        }
        // ADR-0064, peer-TCP enforcement: a flood-offender IP the core
        // `BanStore` still holds is refused post-accept — the point aMule's own
        // client-list ban decides at. Kad's datagram path never consults this
        // store (no Kad ban gate).
        let banned = self
            .ban_store
            .lock()
            .await
            .is_banned(peer.ip(), Instant::now());
        if banned {
            tracing::debug!(%peer, "refusing an inbound connection from a banned IP");
            refuse(conn, awaited_server, PortTestEnd::Banned).await;
            return None;
        }
        // ADR-0046 "Test Connections": past the gates, a test is answered on
        // its own and is never a serve connection.
        if test_connection {
            let kad_pump = self.kad_pump.clone();
            tokio::spawn(async move {
                let end = answer_test_connection(conn, kad_pump).await;
                if let Some(server) = awaited_server {
                    server.report(LoginStep::PortTestEnded { end }).await;
                }
            });
            return None;
        }
        Some(AdmittedPeer {
            conn,
            dialed_toward,
            awaited_server,
        })
    }
}

/// Close a refused peer's connection on a task of its own, then report the
/// refusal to the server whose port test it was, if any.
///
/// The close is spawned because nothing waits on it — the peer is refused
/// either way — while the producer that refused it has the next comer to
/// gate: a burst of filtered or banned peers would otherwise be closed one
/// FIN round trip at a time while admissible peers queued behind them.
async fn refuse(conn: PeerConnection, awaited_server: Option<AwaitedServer>, end: PortTestEnd) {
    tokio::spawn(async move {
        let _ = conn.shutdown().await;
    });
    if let Some(server) = awaited_server {
        server.report(LoginStep::PortTestEnded { end }).await;
    }
}
