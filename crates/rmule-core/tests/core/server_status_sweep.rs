//! The dynamic half of the managed server list (ADR-0080 amendment) over a
//! **real socket**: a running `Core` sweeps its own list, a UDP answerer on the
//! other end returns `OP_GLOBSERVSTATRES`, and the measurement appears on the
//! surfaced row.
//!
//! The in-crate tests pin each half of the round trip against a scripted
//! transport; this one proves the halves are wired to each other and to the
//! bound socket — the `+4` UDP offset, the source-to-server mapping, the
//! challenge gate, and the store write, none of which a scripted transport
//! exercises.

use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, ManagedServer, ServerListCommand, diagnostics::ServerDiagnostics,
};
use rmule_primitives::ServerEndpoint;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// The eD2k server-UDP port offset: rmule sends a status ping to TCP + 4.
const SERVER_UDP_PORT_OFFSET: u16 = 4;

/// A server that answers exactly one thing: `OP_GLOBSERVSTATREQ` (`0x96`) with
/// an `OP_GLOBSERVSTATRES` (`0x97`) echoing the challenge and reporting a fixed
/// load. Anything else (the engine's auto-fired `0xA2` desc-req) is read and
/// ignored, so the run stays a single round trip.
struct FakeStatusServer {
    udp_addr: SocketAddrV4,
    answer: JoinHandle<()>,
}

impl Drop for FakeStatusServer {
    fn drop(&mut self) {
        self.answer.abort();
    }
}

impl FakeStatusServer {
    const USERS: u32 = 123_456;
    const FILES: u32 = 7_890_123;

    async fn start() -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp.local_addr().unwrap().port());
        let answer = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, src)) = udp.recv_from(&mut buf).await {
                let datagram = &buf[..len];
                // [protocol 0xE3][opcode 0x96][challenge u32 LE]
                let Some(challenge) = datagram
                    .strip_prefix(&[0xE3, 0x96][..])
                    .and_then(|body| body.get(..4))
                else {
                    continue;
                };
                let mut reply = vec![0xE3, 0x97];
                reply.extend_from_slice(challenge);
                reply.extend_from_slice(&Self::USERS.to_le_bytes());
                reply.extend_from_slice(&Self::FILES.to_le_bytes());
                let _ = udp.send_to(&reply, src).await;
            }
        });
        Self { udp_addr, answer }
    }

    /// The endpoint to list this server under — the sweep adds the `+4` itself.
    fn listed_as(&self) -> ServerEndpoint {
        ServerEndpoint::new(
            self.udp_addr.ip().to_string(),
            self.udp_addr.port() - SERVER_UDP_PORT_OFFSET,
        )
        .expect("a loopback endpoint below the UDP offset")
    }
}

/// Poll the surfaced row until `settled` accepts it.
async fn settled_row(
    core: &Core,
    listed: &ServerEndpoint,
    settled: impl Fn(&ServerDiagnostics) -> bool,
) -> ServerDiagnostics {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let row = core
                .diagnostics_snapshot()
                .servers
                .into_iter()
                .find(|row| &row.server.endpoint == listed);
            if let Some(row) = row
                && settled(&row)
            {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the sweep completed a round trip")
}

/// One swept round trip end to end: the ping leaves on the bound socket, the
/// reply comes back from the server's UDP port, the gate matches the challenge
/// it minted, and the row shows the measured ping and the reported load with a
/// clean tally.
#[tokio::test]
async fn a_swept_round_trip_fills_the_listed_rows_ping_and_load() {
    let server = FakeStatusServer::start().await;
    let listed = server.listed_as();

    let core = Core::builder(
        CoreConfig {
            // The sweep's first tick fires before the row is added; the next one is
            // this far behind it. Everything else stays at aMule's cadence.
            status_ping_tick: Duration::from_millis(50),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .build();
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(listed.clone()),
    }))
    .await
    .expect("core accepts the add");

    let row = settled_row(&core, &listed, |row| row.ping.is_some()).await;

    assert_eq!(row.users, Some(FakeStatusServer::USERS));
    assert_eq!(row.files, Some(FakeStatusServer::FILES));
    assert_eq!(
        row.server.fail_count, 0,
        "the answer absolved the probe's tally"
    );
    assert!(
        row.ping.expect("measured") < Duration::from_secs(10),
        "the round trip is a loopback measurement, not a stopped clock"
    );
}
