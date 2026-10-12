//! Live cross-service composition: bridge `Ed2kEvent::PeerCallbackRequested`
//! from `rmule_net::ed2k` to an outbound `rmule_net::peer::Connection`.
//!
//! The bridge is the point: nothing in `rmule-net` connects the two
//! conversations, so the application reads `client_id` off the live server
//! session, pairs it with the static `ClientIdentity` through
//! `rmule_core::build_peer_handshake_context`, and dials the peer itself.
//!
//! Run with `cargo run --example callback_dial`. Reads:
//! - `RMULE_LIVE_ED2K_ENDPOINT`: `host:port` of an eD2k server.
//! - `RMULE_LOCAL_TCP_PORT`: optional u16, defaults to `4662`.
//!
//! The example exits after the first `Identified` event, or after the
//! ed2k session disconnects.

use std::time::Duration;

use rmule_ed2k::Ed2kEvent;
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_net::peer::{ConnectOptions as PeerOptions, Connection as PeerConnection};
use rmule_peer::{ConnectionEvent, PeerEvent};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, ServerEndpoint, UserHash};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint_str =
        std::env::var("RMULE_LIVE_ED2K_ENDPOINT").expect("RMULE_LIVE_ED2K_ENDPOINT required");
    let tcp_port: u16 = std::env::var("RMULE_LOCAL_TCP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4662);
    let endpoint = ServerEndpoint::parse_host_port(&endpoint_str)?;
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-callback-dial"),
        tcp_port,
        60,
    );

    let mut server = Connection::connect_with_options(
        endpoint.clone(),
        identity.clone(),
        ConnectOptions {
            connect_timeout: Duration::from_secs(10),
            login_timeout: Duration::from_secs(15),
            capture_dir: None,
            obfuscation: None,
            obfuscated_port: None,
            advertised_ipv6: None,
            udp_ports: None,
        },
    )
    .await?;

    let mut client_id: Option<ClientId> = None;
    while let Some(event) = server.next_event().await {
        match event {
            Ed2kEvent::LoginAccepted { client_id: id, .. } => {
                client_id = Some(id);
                println!("login accepted: client_id={}", id.as_u32());
            }
            Ed2kEvent::PeerCallbackRequested { peer, .. } => {
                let Some(id) = client_id else {
                    eprintln!("PeerCallbackRequested before LoginAccepted; skipping");
                    continue;
                };
                let ctx = rmule_core::build_peer_handshake_context(id, &endpoint, &identity);
                let mut peer_conn = PeerConnection::connect(
                    peer,
                    ctx,
                    PeerOptions {
                        connect_timeout: Duration::from_secs(10),
                        hello_timeout: Duration::from_secs(15),
                        capture_dir: None,
                        ..Default::default()
                    },
                )
                .await?;
                while let Some(pe) = peer_conn.next_event().await {
                    if let PeerEvent::Connection(ConnectionEvent::Identified { identity }) = &pe {
                        println!(
                            "peer identified user_hash={} nickname={:?}",
                            identity.user_hash().to_hex_upper(),
                            identity.nickname().map(|n| n.to_display_string()),
                        );
                        break;
                    }
                    if matches!(
                        pe,
                        PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
                    ) {
                        break;
                    }
                }
                let _ = peer_conn.shutdown().await;
                break;
            }
            Ed2kEvent::Disconnected { reason } => {
                println!("server disconnected: {reason:?}");
                break;
            }
            _ => {}
        }
    }
    let _ = server.shutdown().await;
    Ok(())
}
