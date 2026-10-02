//! The three listeners the sentinel stimulus runs: the eD2k server session a
//! counterparty logs in to, the server-UDP face it may query, and the **Source
//! Sinks** that catch the dials a decoded source record produces.
//!
//! Nothing here decides anything. Each listener speaks the minimum a real
//! eserver speaks to keep a counterparty engaged, emits the scripted frames the
//! plan holds, and writes both sides into the [`Journal`]. Whether the
//! counterparty behaved is the harness flow's verdict to reach, from the
//! counterparty's own rows.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use rmule_ed2k::{IdChange, LoginRequest, Opcode, ServerMessage, ServerStatus, ServerTcpFlags};
use rmule_primitives::{ClientId, Ed2kText, Packet, PrimitiveError, ServerStatusReport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::Plan;
use super::journal::{Entry, Journal, hex};

/// How often the emit gate is re-checked while a session waits for frames.
const POLL: Duration = Duration::from_millis(250);

/// How long a **Source Sink** waits for the dialler's first frame before
/// recording the dial with whatever it got. A real `OP_HELLO` arrives
/// immediately; the wait only bounds a dialler that connects and says nothing,
/// which is itself worth recording.
const SINK_READ_WINDOW: Duration = Duration::from_secs(3);

/// The grants the stimulus advertises in its `OP_IDCHANGE`: new tags, unicode
/// and large files — the ordinary set. Compression is deliberately **not**
/// advertised: the stimulus never emits a `0xD4` frame, and claiming a
/// capability it does not use would put a shape on the wire no counterparty
/// asked for.
const ADVERTISED_TCP_FLAGS: u32 =
    ServerTcpFlags::NEWTAGS | ServerTcpFlags::UNICODE | ServerTcpFlags::LARGE_FILES;

/// What every listener shares: the scripted frames, the record, and the one UDP
/// socket the packed datagram leaves by.
pub(crate) struct Stimulus {
    /// The scripted emissions.
    pub(crate) plan: Plan,
    /// The written record.
    pub(crate) journal: Journal,
    /// The server-UDP socket (the eserver's TCP port + 4, by convention).
    pub(crate) udp: UdpSocket,
    /// The counterparty UDP port the packed datagram is pushed at, when this
    /// stimulus has not already heard from the counterparty's own server-UDP
    /// socket.
    pub(crate) peer_udp_port: u16,
    /// The last endpoint a datagram arrived from — a counterparty's *own*
    /// server-UDP socket, which beats any assumed port. A client's server-UDP
    /// socket is not always its configured `UDPPort` (aMule 2.3.3 binds it at
    /// its TCP port + 3), so an endpoint it has actually spoken from is the one
    /// fact worth preferring.
    pub(crate) heard_udp: Mutex<Option<SocketAddr>>,
    /// A file whose appearance releases the scripted emission, so the harness
    /// controls the moment rather than a stopwatch.
    pub(crate) emit_trigger_file: Option<PathBuf>,
    /// The backstop: emit this long after a login even if the trigger file
    /// never appears.
    pub(crate) emit_after: Duration,
    /// When the scripted emission fired, which is also the once-guard: an
    /// emission that already happened is never repeated, so the trigger file
    /// and the backstop cannot double-fire.
    pub(crate) emitted_at: Mutex<Option<Instant>>,
}

impl Stimulus {
    /// Emit the scripted frames once: every TCP source list down `stream`, and
    /// the packed UDP datagram at the counterparty's UDP port. A second call is
    /// a no-op, so the trigger file and the backstop cannot double-fire.
    async fn emit(&self, stream: &mut TcpStream, peer: SocketAddr, trigger: &str) {
        {
            let mut emitted_at = self
                .emitted_at
                .lock()
                .expect("sentinel stimulus emit guard");
            if emitted_at.is_some() {
                return;
            }
            *emitted_at = Some(Instant::now());
        }
        for (label, frame) in &self.plan.tcp_frames {
            if stream.write_all(frame).await.is_err() {
                return;
            }
            self.journal.push(Entry::Emitted {
                transport: "tcp",
                peer: peer.to_string(),
                label: label.clone(),
                trigger: trigger.to_owned(),
                bytes: hex(frame),
            });
        }
        let target = self.packed_target(peer);
        for (label, datagram) in &self.plan.packed_datagrams {
            if self.udp.send_to(datagram, target).await.is_err() {
                return;
            }
            self.journal.push(Entry::Emitted {
                transport: "udp",
                peer: target.to_string(),
                label: label.clone(),
                trigger: trigger.to_owned(),
                bytes: hex(datagram),
            });
        }
    }

    /// Where the packed datagram goes: the counterparty's own server-UDP
    /// endpoint when it has spoken from one, else its address at the configured
    /// port.
    fn packed_target(&self, peer: SocketAddr) -> SocketAddr {
        let heard = *self.heard_udp.lock().expect("sentinel stimulus heard udp");
        match heard {
            Some(endpoint) if endpoint.ip() == peer.ip() => endpoint,
            _ => SocketAddr::new(peer.ip(), self.peer_udp_port),
        }
    }

    /// How long ago the scripted emission fired, if it has.
    pub(crate) fn emitted_elapsed(&self) -> Option<Duration> {
        self.emitted_at
            .lock()
            .expect("sentinel stimulus emit guard")
            .map(|at| at.elapsed())
    }

    /// Whether the harness has released the emission.
    fn triggered(&self) -> bool {
        self.emit_trigger_file
            .as_ref()
            .is_some_and(|path| path.exists())
    }
}

/// Serve one counterparty session: answer its login, record every frame it
/// sends, and emit the scripted list when the gate opens.
pub(crate) async fn serve_session(
    stimulus: Arc<Stimulus>,
    mut stream: TcpStream,
    peer: SocketAddr,
) {
    let mut buf = Vec::new();
    let Some(login_packet) = next_packet(&mut stream, &mut buf).await else {
        return;
    };
    let Ok(login) = LoginRequest::decode_packet(&login_packet) else {
        return;
    };
    let assigned = high_id_for(peer.ip());
    stimulus.journal.push(Entry::Login {
        peer: peer.to_string(),
        client_tcp_port: login.tcp_port(),
        user_hash: hex(login.user_hash().as_bytes()),
        assigned_id: describe_id(assigned),
    });
    if write_welcome(&mut stream, assigned).await.is_err() {
        return;
    }

    let backstop = Instant::now() + stimulus.emit_after;
    loop {
        if Instant::now() >= backstop {
            stimulus.emit(&mut stream, peer, "backstop").await;
        } else if stimulus.triggered() {
            stimulus.emit(&mut stream, peer, "trigger-file").await;
        }
        match tokio::time::timeout(POLL, next_packet(&mut stream, &mut buf)).await {
            Ok(Some(packet)) => {
                stimulus.journal.push(Entry::Received {
                    transport: "tcp",
                    peer: peer.to_string(),
                    opcode: packet.opcode(),
                    payload_len: packet.payload().len(),
                });
                // A counterparty's own source request fires the emission only
                // when the harness did not ask to control the moment: aMule
                // sends `OP_GETSOURCES` within seconds of connecting, which is
                // before a flow can attach its tap or queue the rest of the
                // files the emission names. With a trigger file configured, a
                // request is recorded and nothing more.
                if packet.opcode() == Opcode::GetSources.as_u8()
                    && stimulus.emit_trigger_file.is_none()
                {
                    stimulus.emit(&mut stream, peer, "get-sources").await;
                }
            }
            Ok(None) => return,
            Err(_elapsed) => {}
        }
    }
}

/// The login answer a real eserver sends, in its order: a banner, the id
/// assignment (which is what flips a client to "connected"), then the counts.
async fn write_welcome(stream: &mut TcpStream, assigned: ClientId) -> std::io::Result<()> {
    let banner = ServerMessage::new(Ed2kText::from_utf8(
        "rmule sentinel stimulus (ADR-0092) — not a counterparty",
    ))
    .expect("the banner fits the u16 wire ceiling");
    stream.write_all(&banner.encode_packet().encode()).await?;
    let id_change = IdChange {
        client_id: assigned,
        tcp_flags: Some(ServerTcpFlags::from_bits(ADVERTISED_TCP_FLAGS)),
        standard_tcp_port: None,
        public_ip: None,
        obfuscation_tcp_port: None,
        trailing: Vec::new(),
    };
    stream
        .write_all(&id_change.encode_packet().encode())
        .await?;
    let status = ServerStatus::new(ServerStatusReport {
        user_count: 1,
        file_count: 1,
    });
    stream.write_all(&status.encode_packet().encode()).await
}

/// The High ID a real server assigns: the client's own address, packed the way
/// a source record packs one. An IPv6 peer gets `0` — this stimulus's wire is
/// the IPv4 eD2k server protocol, and a made-up id would be a fabricated fact.
fn high_id_for(ip: IpAddr) -> ClientId {
    match ip {
        IpAddr::V4(v4) => ClientId::from_u32(u32::from_le_bytes(v4.octets())),
        IpAddr::V6(_) => ClientId::from_u32(0),
    }
}

/// An assigned id as the dotted quad its bits spell.
fn describe_id(id: ClientId) -> String {
    let [a, b, c, d] = id.as_u32().to_le_bytes();
    format!("{a}.{b}.{c}.{d}")
}

/// A **Source Sink**: accept whatever dials `listener`, record which local
/// endpoint the dial landed on and what the dialler said first, and close.
/// The local endpoint IS the source record the counterparty decoded, so this
/// is the counterparty naming its own read of the list.
pub(crate) async fn run_sink(stimulus: Arc<Stimulus>, listener: TcpListener) {
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            return;
        };
        let local = stream
            .local_addr()
            .map_or_else(|_| "unknown".to_owned(), |addr| addr.to_string());
        let mut first = vec![0u8; 512];
        let read = tokio::time::timeout(SINK_READ_WINDOW, stream.read(&mut first)).await;
        let bytes = match read {
            Ok(Ok(count)) => hex(&first[..count]),
            Ok(Err(_)) | Err(_) => String::new(),
        };
        stimulus.journal.push(Entry::SinkDial {
            local,
            peer: peer.to_string(),
            bytes,
        });
    }
}

/// The server-UDP face: record every datagram, and answer a source query with
/// the same packed datagram the TCP session pushes, addressed back to whoever
/// asked (which is the one way to be sure of the counterparty's UDP port).
pub(crate) async fn serve_udp(stimulus: Arc<Stimulus>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((count, peer)) = stimulus.udp.recv_from(&mut buf).await else {
            return;
        };
        let opcode = buf.get(1).copied().unwrap_or(0);
        *stimulus
            .heard_udp
            .lock()
            .expect("sentinel stimulus heard udp") = Some(peer);
        stimulus.journal.push(Entry::Received {
            transport: "udp",
            peer: peer.to_string(),
            opcode,
            payload_len: count.saturating_sub(2),
        });
        let asked_for_sources =
            opcode == Opcode::GlobGetSources.as_u8() || opcode == Opcode::GlobGetSources2.as_u8();
        if !asked_for_sources {
            continue;
        }
        for (label, datagram) in &stimulus.plan.packed_datagrams {
            if stimulus.udp.send_to(datagram, peer).await.is_err() {
                break;
            }
            stimulus.journal.push(Entry::Emitted {
                transport: "udp",
                peer: peer.to_string(),
                label: label.clone(),
                trigger: "glob-get-sources".to_owned(),
                bytes: hex(datagram),
            });
        }
    }
}

/// Pull one decoded eD2k packet off `stream`, buffering across reads and
/// keeping trailing bytes for the next call. `None` on a closed connection or
/// on bytes that are not eD2k framing — a real server drops such a session too.
///
/// Cancel-safe: `AsyncReadExt::read` reads nothing when cancelled, so the
/// session's poll timeout cannot lose buffered bytes.
async fn next_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Packet> {
    loop {
        match Packet::decode(buf) {
            Ok((packet, consumed)) => {
                buf.drain(..consumed);
                return Some(packet);
            }
            Err(PrimitiveError::TruncatedPacket { .. }) => {}
            Err(_) => return None,
        }
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).await.ok()?;
        if count == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..count]);
    }
}

/// Bind every sink port on `bind_ip`, deduplicated — two records may name the
/// same port on different addresses, and one listener serves both.
///
/// # Errors
/// If a port cannot be bound; a sink that is silently absent would read as a
/// counterparty that never dialled.
pub(crate) async fn bind_sinks(bind_ip: IpAddr, ports: &[u16]) -> Result<Vec<TcpListener>> {
    let mut seen = Vec::new();
    let mut listeners = Vec::new();
    for port in ports {
        if seen.contains(port) {
            continue;
        }
        seen.push(*port);
        listeners.push(TcpListener::bind(SocketAddr::new(bind_ip, *port)).await?);
    }
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_high_id_is_the_clients_own_address_packed_as_a_source_record_packs_one() {
        let id = high_id_for(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)));
        assert_eq!(id.as_u32().to_le_bytes(), [203, 0, 113, 3]);
        assert_eq!(describe_id(id), "203.0.113.3");
        assert!(id.is_high_id(), "a fake-public address earns a High ID");
    }
}
