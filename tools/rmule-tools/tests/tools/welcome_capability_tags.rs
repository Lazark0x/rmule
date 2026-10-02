//! CLI regression test for the eMule-compat capability advertisement.
//!
//! Production (Lugdunum-era) eD2k servers reject a login that carries
//! only the three canonical tags (CT_NAME / CT_VERSION / CT_PORT) with
//! "your edonkey client is too old" and hang up before sending
//! OP_IDCHANGE. CT_SERVER_FLAGS and CT_EMULE_VERSION therefore ride
//! every login, emitted from the capability registry by
//! `LoginRequest::from_identity` (`crates/rmule-ed2k/src/login.rs`) —
//! the registry is the only source, since a copy of either tag carried
//! on the `ClientIdentity` is dropped by `is_canonical_login_tag`
//! before the frame is built.
//!
//! This test drives the `welcome live` binary against a mock eD2k
//! server that records the login frame, then decodes the frame and
//! asserts the capability tags are on the wire. It is deterministic
//! (no network) so it guards the regression in CI.

use std::time::Duration;

use assert_cmd::Command;
use rmule_ed2k::LoginRequest;
use rmule_primitives::{Packet, PacketProtocol, TagValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;
// What the registry lights: zlib | newtags | unicode | largefiles. The
// `auxport` bit (0x04) is absent because `Capabilities::supports_aux_port()`
// is false — rmule has no UDP aux port to advertise.
const EXPECTED_SERVER_FLAGS: u32 = 0x0001 | 0x0008 | 0x0010 | 0x0100;

fn id_change_bytes() -> Vec<u8> {
    let mut payload = 0x1020_3040u32.to_le_bytes().to_vec(); // HighID client_id
    payload.extend_from_slice(&EXPECTED_SERVER_FLAGS.to_le_bytes());
    Packet::new(PacketProtocol::Edonkey, 0x40, payload).encode()
}

async fn read_frame(sock: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 5];
    sock.read_exact(&mut header).await.unwrap();
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut rest = vec![0u8; len];
    sock.read_exact(&mut rest).await.unwrap();
    let mut frame = header.to_vec();
    frame.extend_from_slice(&rest);
    frame
}

#[tokio::test(flavor = "current_thread")]
async fn welcome_live_login_advertises_capability_tags() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();

    let mock = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let login = read_frame(&mut sock).await;
        let _ = tx.send(login);
        sock.write_all(&id_change_bytes()).await.unwrap();
        // Hold the socket open until the CLI shuts down on --max-seconds.
        let mut sink = [0u8; 256];
        loop {
            match sock.read(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });

    let endpoint = format!("127.0.0.1:{}", bound.port());
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("rmule-tools")
            .unwrap()
            .args([
                "ed2k",
                "server",
                "welcome",
                "live",
                &endpoint,
                "--out",
                out.to_str().unwrap(),
                "--connect-timeout",
                "5",
                "--login-timeout",
                "5",
                "--max-seconds",
                "1",
            ])
            .timeout(Duration::from_secs(15))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let login_bytes = rx.await.expect("mock captured the login frame");
    let (packet, _) = Packet::decode(&login_bytes).expect("login frame decodes");
    let login = LoginRequest::decode_packet(&packet).expect("decodes as LoginRequest");

    let flags = login
        .tags()
        .iter()
        .find(|t| t.name().id() == Some(CT_SERVER_FLAGS))
        .expect("login must carry CT_SERVER_FLAGS so modern servers accept it");
    assert!(
        login
            .tags()
            .iter()
            .any(|t| t.name().id() == Some(CT_EMULE_VERSION)),
        "login must carry CT_EMULE_VERSION so servers don't reject it as 'too old'"
    );
    match flags.value() {
        TagValue::U32(v) => assert_eq!(
            *v, EXPECTED_SERVER_FLAGS,
            "honest server-flags: zlib|newtags|unicode|largefiles, no auxport"
        ),
        other => panic!("CT_SERVER_FLAGS must be a U32, got {other:?}"),
    }

    let _ = mock.await;
}
