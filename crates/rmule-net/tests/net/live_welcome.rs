//! Env-gated live test that connects to a real eD2k server, observes the
//! welcome handshake, and disconnects politely.
//!
//! Skipped silently when `RMULE_LIVE_ED2K_ENDPOINT` is unset, so CI without
//! a server stays green. When the env var is set:
//!
//! ```bash
//! RMULE_LIVE_ED2K_CAPTURE_DIR=/tmp/welcome-cap \
//!   RMULE_LIVE_ED2K_ENDPOINT=<host>:<port> \
//!   cargo test -p rmule-net --test live_welcome -- --nocapture
//! ```
//!
//! The test only does what a "polite welcome" allows: observe
//! the welcome burst, optionally write a capture, then shut down. It never
//! emits `OP_SEARCH` or `OP_GETSOURCES`.

use std::path::PathBuf;
use std::time::Duration;

use rmule_ed2k::Ed2kEvent;
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{
    ClientIdentity, Ed2kText, ServerEndpoint, Tag, TagName, TagValue, UserHash,
};

const ENV_ENDPOINT: &str = "RMULE_LIVE_ED2K_ENDPOINT";
const ENV_CAPTURE: &str = "RMULE_LIVE_ED2K_CAPTURE_DIR";

#[tokio::test(flavor = "current_thread")]
async fn live_welcome_burst() {
    let Ok(endpoint_str) = std::env::var(ENV_ENDPOINT) else {
        eprintln!("skipped: {ENV_ENDPOINT} unset — set it to host:port to enable the live test",);
        return;
    };
    let endpoint = ServerEndpoint::parse_host_port(&endpoint_str)
        .unwrap_or_else(|e| panic!("{ENV_ENDPOINT}={endpoint_str:?}: {e}"));

    // Lugdunum-era servers gate "this client is too old" on capability
    // tags, not just CT_VERSION. Add the two tags aMule's
    // `ConnectionEstablished` sends (CT_SERVER_FLAGS, CT_EMULE_VERSION)
    // via the existing `extra_tags` path so the login packet looks
    // modern enough to receive OP_IDCHANGE. Values mirror aMule's
    // `CAPABLE_ZLIB | CAPABLE_AUXPORT | CAPABLE_NEWTAGS | CAPABLE_UNICODE |
    // CAPABLE_LARGEFILES` (= 0x11D) and a coarse "aMule-shaped" version
    // word (compatible-client byte in high octet | packed major.minor).
    const CT_SERVER_FLAGS: u8 = 0x20;
    const CT_EMULE_VERSION: u8 = 0xFB;
    const SERVER_FLAGS: u32 = 0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0100;
    const EMULE_VERSION: u32 = 0x03_06_00_00;
    let extra_tags = vec![
        Tag::new(
            TagName::length_prefixed_id(CT_SERVER_FLAGS),
            TagValue::U32(SERVER_FLAGS),
        ),
        Tag::new(
            TagName::length_prefixed_id(CT_EMULE_VERSION),
            TagValue::U32(EMULE_VERSION),
        ),
    ];

    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-live"),
        4662,
        60,
    )
    .with_extra_tags(extra_tags);

    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(10),
        login_timeout: Duration::from_secs(15),
        capture_dir: std::env::var(ENV_CAPTURE).ok().map(PathBuf::from),
        obfuscation: None,
        obfuscated_port: None,
        // A live bench login stays classic: no IPv6 advert, so no
        // `CT_MOD_IP_V6` and no `SRVCAP_IPV6` on the wire.
        advertised_ipv6: None,
        udp_ports: None,
    };

    let mut conn = Connection::connect_with_options(endpoint, identity, options)
        .await
        .expect("connect to live eD2k server");

    let mut saw_login = false;
    let mut saw_server_message = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let next = tokio::time::timeout(remaining, conn.next_event()).await;
        let Ok(Some(event)) = next else { break };
        match event {
            Ed2kEvent::LoginAccepted { .. } => {
                saw_login = true;
            }
            Ed2kEvent::ServerMessageReceived { .. } => {
                saw_server_message = true;
            }
            Ed2kEvent::Disconnected { .. } => {
                break;
            }
            _ => {}
        }
        if saw_login && saw_server_message {
            break;
        }
    }

    conn.shutdown().await.ok();

    assert!(saw_login, "live server must accept the login");
    assert!(
        saw_server_message,
        "live server is expected to push at least one OP_SERVERMESSAGE in the welcome burst",
    );
}
