//! Deterministic server-UDP answerer (ADR-0051 seams): on any incoming
//! datagram, reply `OP_GLOBFOUNDSOURCES` with the scripted sources. Models the
//! managed-server side of global source discovery — nothing else. Note the
//! eD2k +4 port offset is rmule's *send*-side contract: configure rmule with
//! `bound_port() - 4` so its adapter lands on this socket.

use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_ed2k::{FoundSources, Opcode};
use rmule_primitives::{FileHash, Packet, PacketProtocol, PeerSource};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// A running fake managed server (UDP only). Drop aborts the answer loop.
pub struct FakeServerUdp {
    local_addr: SocketAddrV4,
    answer: JoinHandle<()>,
}

impl Drop for FakeServerUdp {
    fn drop(&mut self) {
        self.answer.abort();
    }
}

impl FakeServerUdp {
    /// Bind `127.0.0.1:0` and answer every datagram with
    /// `OP_GLOBFOUNDSOURCES { file_hash, sources }`, its body the `0x42`
    /// encoder's — a `PeerSource::Ipv6` as a **Sentinel Source** with its
    /// address inline (ADR-0085).
    ///
    /// # Panics
    /// When `sources` is more than the `u8` count can carry.
    pub async fn start(file_hash: FileHash, sources: Vec<PeerSource>) -> Self {
        let payload = FoundSources::new(file_hash, sources)
            .expect("a scripted source list fits one OP_GLOBFOUNDSOURCES body")
            .encode_packet()
            .payload()
            .to_vec();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp.local_addr().unwrap().port());
        let answer = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((_, src)) = udp.recv_from(&mut buf).await {
                // eD2k server UDP framing: [protocol][opcode][payload], no
                // length prefix.
                let datagram = Packet::new(
                    PacketProtocol::Edonkey,
                    Opcode::GlobFoundSources.as_u8(),
                    payload.clone(),
                )
                .encode_udp();
                let _ = udp.send_to(&datagram, src).await;
            }
        });
        Self { local_addr, answer }
    }

    /// The bound UDP address (see the module note about the −4 offset).
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }
}
