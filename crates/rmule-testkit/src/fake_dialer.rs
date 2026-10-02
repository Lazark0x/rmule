//! Scriptable *dialing* counterparties for inbound-listener tests: each
//! connects to a bound `PeerListener` and opens with `OP_HELLO`, playing the
//! peer that dialed rmule. [`FakeDialer`] is fire-and-forget (handshake-shape
//! assertions, hello-timeout coverage); [`FakeBuddy`] is interactive — the
//! firewalled client that holds its dialed connection as the persistent buddy
//! link and lets the test drive both directions over it.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_peer::{PeerOpcode, PeerPacket};
use rmule_primitives::{Packet, PacketProtocol, UserHash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::framing::next_packet;
use crate::wire;

/// A dialing counterparty that completes the handshake and then just holds the
/// socket — enough to assert what the listener side does, with no state of its
/// own to drive.
pub struct FakeDialer;

impl FakeDialer {
    /// Dial `target`, send `OP_HELLO` as `user_hash`/`nickname`, assert the
    /// reply frame is `OP_HELLOANSWER`, then hold the socket open until the
    /// listener side closes.
    pub fn spawn(target: SocketAddrV4, user_hash: UserHash, nickname: &str) -> JoinHandle<()> {
        let nickname = nickname.to_owned();
        tokio::spawn(async move {
            let mut sock = TcpStream::connect(SocketAddr::V4(target)).await.unwrap();
            sock.write_all(&wire::hello_bytes(user_hash, &nickname))
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            assert!(n > 0, "received reply bytes");
            let (packet, _) = Packet::decode(&buf[..n]).expect("decode reply frame");
            assert_eq!(
                packet.opcode(),
                PeerOpcode::HelloAnswer.as_u8(),
                "inbound session must reply HELLOANSWER, not a premature HELLO",
            );
            // Hold the socket open so the listener side's writes flush cleanly.
            let mut sink = [0u8; 64];
            let _ = sock.read(&mut sink).await;
        })
    }

    /// Dial `target` and never speak: hold the silent socket for `hold`, then
    /// drop it. The accepted session's hello timeout must fire first.
    pub fn spawn_silent(target: SocketAddrV4, hold: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let sock = TcpStream::connect(SocketAddr::V4(target)).await.unwrap();
            tokio::time::sleep(hold).await;
            drop(sock);
        })
    }
}

/// The dial-side fake **buddy** (socket-unification, ADR-0061): the
/// firewalled client that — its `0x51` recruit accepted — dials the open
/// node's TCP port and keeps that one connection alive as the persistent
/// buddy link, exactly as aMule's buddy does after `0x5A`.
///
/// Interactive, unlike [`FakeDialer`]: the test drives it — reading the relay
/// (`OP_CALLBACK` `0x99` / `OP_REASKCALLBACKTCP` `0x9A`) and keepalive-pong
/// (`OP_BUDDYPONG` `0xA0`) frames off its **own dialed socket**, and sending
/// `OP_BUDDYPING` (`0x9F`) up it. Arrival on this socket is the whole
/// held-link proof: the fake buddy listens nowhere, so a fresh dial toward it
/// could deliver nothing.
pub struct FakeBuddy {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl FakeBuddy {
    /// Dial `target`, complete the eD2k hello as `user_hash`/`nickname`
    /// (asserting the accepted session answers `OP_HELLOANSWER`), and hold the
    /// connection — the persistent buddy link.
    pub async fn dial(target: SocketAddrV4, user_hash: UserHash, nickname: &str) -> Self {
        let mut stream = TcpStream::connect(SocketAddr::V4(target)).await.unwrap();
        stream
            .write_all(&wire::hello_bytes(user_hash, nickname))
            .await
            .unwrap();
        let mut buddy = Self {
            stream,
            buf: Vec::new(),
        };
        let answer = buddy
            .next()
            .await
            .expect("the accepted session answers the buddy's hello");
        assert_eq!(
            answer.opcode(),
            PeerOpcode::HelloAnswer.as_u8(),
            "inbound session must reply HELLOANSWER on the buddy link",
        );
        buddy
    }

    /// Send `OP_BUDDYPING` (`0x9F`) up the held link — the buddy keepalive.
    pub async fn send_buddy_ping(&mut self) {
        self.stream
            .write_all(&PeerPacket::BuddyPing.encode().encode())
            .await
            .unwrap();
    }

    /// Read frames off the held link until an eMule-protocol `opcode` arrives,
    /// returning its payload. Panics if the link closes first.
    pub async fn expect_emule(&mut self, opcode: u8) -> Vec<u8> {
        loop {
            let packet = self.next().await.unwrap_or_else(|| {
                panic!("buddy link closed while awaiting eMule opcode 0x{opcode:02X}")
            });
            if packet.protocol() == PacketProtocol::Emule && packet.opcode() == opcode {
                return packet.payload().to_vec();
            }
        }
    }

    async fn next(&mut self) -> Option<Packet> {
        next_packet(&mut self.stream, &mut self.buf).await
    }
}
