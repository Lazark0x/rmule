//! A loopback eD2k server scripted one search answer at a time: it logs the
//! client in, reports every opcode the client sends, and writes each
//! `OP_SEARCHRESULT` only when the leg says so — the stand-in for a server
//! whose answers name no search (ADR-0034).

use rmule_testkit::HANG_GUARD;

use rmule_ed2k::{IdChange, LoginRequest, Opcode, SearchResults};
use rmule_primitives::{ClientId, Packet, PacketProtocol, SearchResult, ServerEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

enum SearchServerAction {
    Results(Vec<SearchResult>, bool),
    MalformedSearchResult,
}

pub struct LoopbackSearchServer {
    /// Where the core dials it.
    pub endpoint: ServerEndpoint,
    action_tx: mpsc::Sender<SearchServerAction>,
    /// Every eDonkey packet the client sent, as opcode and payload, in order.
    packet_rx: mpsc::Receiver<(u8, Vec<u8>)>,
}

impl LoopbackSearchServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (action_tx, action_rx) = mpsc::channel(8);
        let (packet_tx, packet_rx) = mpsc::channel(8);
        tokio::spawn(run_loopback_search_server(listener, action_rx, packet_tx));
        Self {
            endpoint: ServerEndpoint::new("127.0.0.1", addr.port()).unwrap(),
            action_tx,
            packet_rx,
        }
    }

    pub async fn wait_for_search_request(&mut self) {
        self.wait_for_client_opcode(Opcode::SearchRequest).await;
    }

    /// The payload of the next `OP_SEARCHREQUEST` the client sends.
    pub async fn next_search_payload(&mut self) -> Vec<u8> {
        self.wait_for_client_opcode(Opcode::SearchRequest).await
    }

    /// Wait for the client to send `opcode`; its payload. The wait outlasts
    /// the session's two-second search spacing, which a held request waits out.
    pub async fn wait_for_client_opcode(&mut self, opcode: Opcode) -> Vec<u8> {
        timeout(HANG_GUARD, async {
            loop {
                let (seen, payload) = self
                    .packet_rx
                    .recv()
                    .await
                    .expect("search server still running");
                if seen == opcode.as_u8() {
                    break payload;
                }
            }
        })
        .await
        .expect("server observed client packet")
    }

    pub async fn send_results(&self, results: Vec<SearchResult>) {
        self.send_page(results, false).await;
    }

    /// An answer whose more-results byte says whether the server holds more.
    pub async fn send_page(&self, results: Vec<SearchResult>, more_available: bool) {
        self.action_tx
            .send(SearchServerAction::Results(results, more_available))
            .await
            .unwrap();
    }

    pub async fn send_malformed_search_result(&self) {
        self.action_tx
            .send(SearchServerAction::MalformedSearchResult)
            .await
            .unwrap();
    }
}

async fn run_loopback_search_server(
    listener: TcpListener,
    mut action_rx: mpsc::Receiver<SearchServerAction>,
    packet_tx: mpsc::Sender<(u8, Vec<u8>)>,
) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    let login = next_packet(&mut sock, &mut buf).await.expect("login frame");
    let _ = LoginRequest::decode_packet(&login).expect("login decodes");

    let id_change = IdChange {
        client_id: ClientId::from_u32(0x0100_007F),
        tcp_flags: None,
        standard_tcp_port: None,
        public_ip: None,
        obfuscation_tcp_port: None,
        trailing: Vec::new(),
    };
    sock.write_all(&id_change.encode_packet().encode())
        .await
        .unwrap();

    loop {
        tokio::select! {
            packet = next_packet(&mut sock, &mut buf) => {
                let Some(packet) = packet else { break };
                if packet.protocol() == PacketProtocol::Edonkey
                {
                    let _ = packet_tx.send((packet.opcode(), packet.payload().to_vec())).await;
                }
            }
            action = action_rx.recv() => {
                let Some(action) = action else { break };
                let bytes = match action {
                    SearchServerAction::Results(results, more) => SearchResults::new(results)
                        .with_more_available(more)
                        .encode_packet()
                        .encode(),
                    SearchServerAction::MalformedSearchResult => Packet::new(
                        PacketProtocol::Edonkey,
                        Opcode::SearchResult.as_u8(),
                        vec![0x01],
                    )
                    .encode(),
                };
                if sock.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn next_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Packet> {
    loop {
        if let Ok((packet, consumed)) = Packet::decode(buf) {
            buf.drain(..consumed);
            return Some(packet);
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}
