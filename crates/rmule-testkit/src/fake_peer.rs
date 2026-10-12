//! Scriptable protocol-counterparty peer (**FakePeer**, ADR-0040): the
//! adversarial half of the both-fakes policy. It answers the requester's peer
//! protocol opcode-by-opcode and exists for the misbehavior a real peer cannot
//! produce on command — queueing forever, granting then going silent, dropping
//! mid-part, or never completing the handshake. Happy paths belong on a real
//! serving core (`spawn_serving_core`), not on a script.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_peer::{
    AnswerItem, EMBLOCKSIZE, ExtendedRequests, MiscOptions1, MultiPacketAnswer, MultiPacketRequest,
    PartBitmap, RequestItem,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, PacketProtocol, PartHash, PeerSource, SourceSighting, UserHash,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::framing::next_packet;
use crate::wire;

/// How the peer answers `OP_STARTUPLOADREQ`.
pub enum SlotPolicy {
    /// Grant the slot immediately.
    Grant,
    /// Send these queue ranks, then grant.
    QueueThenGrant(Vec<u16>),
    /// Send these queue ranks, then never grant (the connection stays open so
    /// only the worker's own slot-wait budget can end the wait).
    QueueThenSilence(Vec<u16>),
    /// Pump a decreasing rank forever at `interval`, never granting.
    QueueForever {
        /// The rank the first queue frame claims; each later frame is one
        /// lower, so a waiting downloader sees progress that never arrives.
        start_rank: u16,
        /// How long between queue frames — the gap a rank-refresh wait is
        /// measured against.
        interval: Duration,
    },
}

/// How the peer answers `OP_REQUESTPARTS`.
pub enum ServePolicy {
    /// Serve every requested range from the script's bytes, asserting the
    /// requester never asks for more than `EMBLOCKSIZE` per block.
    Blocks,
    /// Serve exactly the first `EMBLOCKSIZE` of the first request, then close
    /// the connection mid-part.
    FirstBlockThenClose,
    /// Never deliver bytes; keep the connection open (a granted-then-silent
    /// peer, distinguishable from a disconnect).
    Nothing,
}

/// How the peer answers `OP_HASHSETREQUEST`.
pub enum HashSetPolicy {
    /// A zero-count hash set (single chunk relative to `ED2K_PART_SIZE`).
    ZeroPart,
    /// A full per-part hash set.
    Parts(Vec<PartHash>),
}

/// How the peer, as the **uploader**, answers rmule's emitted
/// `OP_MULTIPACKET` / `OP_MULTIPACKET_EXT` file-request bundle — the
/// reverse harness (rmule downloads, so rmule *emits* the bundle, ADR-0054
/// execution breakdown 3). Advertising the capability in the hello is what
/// makes rmule fold its request into a bundle in the first place.
pub enum MultiPacketPolicy {
    /// A pre-multipacket uploader: advertise nothing, so rmule negotiates with
    /// the separate standalone packets (the default; keeps other scripts on the
    /// path they already exercise).
    Unsupported,
    /// Advertise MultiPacket + ExtMultiPacket and answer a received bundle with
    /// one composed `OP_MULTIPACKETANSWER` (`0x93`) — name + part status, the
    /// aMule uploader's reaction that proves rmule's emitted request parsed.
    /// Source subs are answered out-of-band (`0x82`) and AICH is omitted
    /// (no complete hashset), mirroring aMule's `0x93` rules.
    AnswerBundle,
}

/// How the peer answers `OP_REQUESTSOURCES`.
pub enum SourcesPolicy {
    /// Ignore the request — every script predating source exchange.
    Ignore,
    /// Answer with this source list, packed (`0xD4`) — the ADR-0053
    /// peer-inbound-inflate scenario. aMule always packs `OP_ANSWERSOURCES`
    /// regardless of size.
    AnswerPacked(Vec<SourceSighting>),
}

/// One accepted connection's script.
pub struct PeerScript {
    /// The file this peer claims to serve; a request naming any other hash is
    /// not answered from `bytes`.
    pub file_hash: FileHash,
    /// The name answered to a filename probe.
    pub file_name: String,
    /// The file's full content — every served block is cut from this, so it is
    /// also what a completed download must equal.
    pub bytes: Vec<u8>,
    /// How the upload slot is answered.
    pub slot: SlotPolicy,
    /// How part requests are answered.
    pub serve: ServePolicy,
    /// How a hash-set request is answered.
    pub hash_set: HashSetPolicy,
    /// How a source-exchange request is answered.
    pub sources: SourcesPolicy,
    /// Whether this peer admits to understanding a bundled file request, and
    /// how it answers one.
    pub multipacket: MultiPacketPolicy,
    /// The user hash this peer's `HelloAnswer` advertises — the identity a
    /// credit or ban assertion keys on.
    pub hello_user_hash: UserHash,
    /// The nickname this peer's `HelloAnswer` advertises.
    pub hello_nickname: String,
    /// The SX1 nibble this peer's plain `HelloAnswer` advertises: `2` by
    /// default, the lowest aMule asks; `1` or `0` makes a peer no source ask
    /// may be sent to (ADR-0108). The bundle-answering hello keeps rmule's own
    /// advertisement.
    pub hello_source_exchange: u8,
    /// `Some(sx1)`: answer the hello as a pre-0.42 mule — a hello with no
    /// mule tag, then an `OP_EMULEINFO` stating SX version `sx1` after it —
    /// in place of the plain hello answer.
    pub legacy_mule_info: Option<u8>,
}

impl PeerScript {
    /// A well-behaved serving script: grant immediately, serve all blocks,
    /// zero-part hash set.
    pub fn serving(file_hash: FileHash, bytes: Vec<u8>) -> Self {
        Self {
            file_hash,
            file_name: "loopback.bin".into(),
            bytes,
            slot: SlotPolicy::Grant,
            serve: ServePolicy::Blocks,
            hash_set: HashSetPolicy::ZeroPart,
            sources: SourcesPolicy::Ignore,
            multipacket: MultiPacketPolicy::Unsupported,
            hello_user_hash: UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]),
            hello_nickname: "core-loopback-peer".into(),
            hello_source_exchange: 2,
            legacy_mule_info: None,
        }
    }

    /// A handshake-only script: answer the hello as `user_hash`/`nickname`
    /// and nothing else (for connection/handshake tests with no file flow).
    pub fn hello_only(user_hash: UserHash, nickname: &str) -> Self {
        Self {
            hello_user_hash: user_hash,
            hello_nickname: nickname.into(),
            ..Self::serving(FileHash::from_bytes([0u8; 16]), Vec::new())
        }
    }
}

/// The first rmule-emitted `OP_MULTIPACKET` (`0x92`) / `OP_MULTIPACKET_EXT`
/// (`0xA4`) file-request bundle a script saw: its framing opcode, the `size8`
/// (ext form only), and the sub-opcodes in wire order — the live-emit
/// assertion surface for the ADR-0054 bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenMultiPacketRequest {
    /// The framing opcode: `0x92` for the plain bundle, `0xA4` for the ext
    /// form.
    pub opcode: u8,
    /// The 8-byte size the ext form carries, `None` for the plain form — the
    /// field that makes the bundle large-file capable.
    pub size8: Option<u64>,
    /// The bundled sub-opcodes in wire order; order is part of the contract,
    /// not an implementation detail.
    pub sub_opcodes: Vec<u8>,
    /// The part status the asker's `0x58` sub carried — what it says it
    /// holds; `None` for a bare name ask.
    pub name_status: Option<PartBitmap>,
}

/// Wire facts observed by a script run, for test assertions.
#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    /// Largest single requested block (end - start).
    pub max_block: u64,
    /// How many `OP_STARTUPLOADREQ` frames arrived.
    pub start_upload_count: u32,
    /// The `start` of the first `OP_REQUESTPARTS` range seen.
    pub first_request_start: Option<u64>,
    /// The first file-request bundle that arrived, when one did (ADR-0054
    /// emit) — `None` against a downloader negotiating with the separate
    /// standalone packets.
    pub multipacket_request: Option<SeenMultiPacketRequest>,
    /// How many *standalone* probe-pair frames (`OP_REQUESTFILENAME 0x58` /
    /// `OP_SETREQFILEID 0x4F`) arrived — zero when the downloader folded its
    /// probe into a bundle instead.
    pub standalone_probe_asks: u32,
    /// Whether a null `OP_KAD_FWTCPCHECK_ACK` (`0xA8`, eMule protocol) arrived —
    /// the connect-back ack a Kad firewall-check dial-back delivers once the
    /// handshake completes (ADR-0058 responder). Its arrival is the whole proof
    /// that a self-checking peer's TCP port was reached.
    pub kad_fw_tcp_check_ack: bool,
    /// The 16-byte buddy-ID from an inbound `OP_CALLBACK` (`0x99`, eMule protocol)
    /// buddy relay, when one arrived (ADR-0061). Its arrival is the proof an
    /// open-node buddy relayed the Kad `0x52`→`0x99` callback over this buddy link,
    /// and the echoed buddy-ID being intact proves the relay body survived the wire.
    pub buddy_callback_buddy_id: Option<[u8; 16]>,
    /// How many `OP_CANCELTRANSFER` (`0x56`, ADR-0056) frames arrived — the
    /// downloader's "stop sending, I no longer want this transfer", which rmule
    /// emits when a download is cancelled or paused while it holds this
    /// uploader's slot. A normal completion releases the slot silently, so this
    /// stays zero there.
    pub cancel_transfer_count: u32,
}

/// A bound, not-yet-accepting fake peer. `spawn` consumes it with a script.
pub struct FakePeer {
    listener: TcpListener,
    addr: SocketAddrV4,
}

impl FakePeer {
    /// Bind `127.0.0.1:0`.
    pub async fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // The bound address is the literal that was asked for; only the port
        // was the OS's to choose.
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
        Self { listener, addr }
    }

    /// The bound loopback address, known before any connection is accepted —
    /// what a downloader under test is pointed at.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// This peer as a High-ID `PeerSource` (client id = its IPv4, LE).
    pub fn source(&self) -> PeerSource {
        PeerSource::new(
            ClientId::from_u32(u32::from_le_bytes(self.addr.ip().octets())),
            self.addr.port(),
        )
    }

    /// Accept one connection and run the script over it. The task ends at
    /// peer EOF (or earlier if the script closes), returning what it saw.
    pub fn spawn(self, script: PeerScript) -> JoinHandle<PeerStats> {
        tokio::spawn(async move {
            let (sock, _) = self.listener.accept().await.unwrap();
            run_script(sock, script).await
        })
    }

    /// Accept one connection and never speak: the dead-peer script whose
    /// eD2k hello hangs forever. Reads (and discards) until EOF.
    pub fn spawn_silent(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let (mut sock, _) = self.listener.accept().await.unwrap();
            let mut sink = [0u8; 1024];
            loop {
                match tokio::io::AsyncReadExt::read(&mut sock, &mut sink).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
    }
}

/// The three `OP_REQUESTPARTS` ranges: `[hash 16][s1 s2 s3][e1 e2 e3]`, u32 LE.
fn request_ranges(payload: &[u8]) -> [(u64, u64); 3] {
    let word =
        |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().expect("range word")) as u64;
    [
        (word(16), word(28)),
        (word(20), word(32)),
        (word(24), word(36)),
    ]
}

/// Compose the uploader's `OP_MULTIPACKETANSWER` for a received request
/// bundle: the file name and its part status — the hard-required subs a
/// downloader negotiates on — in the answer order. Source subs are served
/// out-of-band (`0x82`) and AICH is omitted with no complete hashset,
/// exactly aMule's `0x93` composition (ADR-0054).
fn multipacket_answer(script: &PeerScript, req: &MultiPacketRequest) -> MultiPacketAnswer {
    let mut items = Vec::new();
    for item in &req.items {
        match item {
            RequestItem::Name { .. } => {
                items.push(AnswerItem::Name(Ed2kText::from_utf8(
                    script.file_name.clone(),
                )));
            }
            RequestItem::SetReqId => items.push(AnswerItem::Status(uploader_part_status(
                script.bytes.len() as u64,
            ))),
            RequestItem::Sources | RequestItem::Sources2 { .. } | RequestItem::AichRoot => {}
        }
    }
    MultiPacketAnswer {
        file_hash: req.file_hash,
        items,
        unknown_sub: None,
    }
}

/// The uploader's advertised availability inside a bundled answer: every part
/// of the `file_size`-byte file it serves, at the count the downloader's
/// reader demands — any other count closes the session.
fn uploader_part_status(file_size: u64) -> PartBitmap {
    PartBitmap::all_present(rmule_primitives::ed2k_status_part_count(file_size))
}

/// The wire sub-opcode a decoded [`RequestItem`] arrived as, for the
/// [`SeenMultiPacketRequest`] record.
fn request_sub_opcode(item: &RequestItem) -> u8 {
    match item {
        RequestItem::Name { .. } => 0x58,
        RequestItem::SetReqId => 0x4F,
        RequestItem::Sources => 0x81,
        RequestItem::Sources2 { .. } => 0x83,
        RequestItem::AichRoot => 0x9E,
    }
}

async fn run_script(sock: tokio::net::TcpStream, script: PeerScript) -> PeerStats {
    let (mut rd, mut wr) = sock.into_split();
    let (wtx, mut wrx) = mpsc::channel::<Vec<u8>>(32);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = wrx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    let mut stats = PeerStats::default();
    let mut buf = Vec::new();
    let mut queue_pump_started = false;
    'conn: while let Some(packet) = next_packet(&mut rd, &mut buf).await {
        match packet.opcode() {
            0x01 => {
                if let Some(sx1) = script.legacy_mule_info {
                    let _ = wtx
                        .send(wire::legacy_hello_answer_bytes(
                            script.hello_user_hash,
                            &script.hello_nickname,
                        ))
                        .await;
                    let _ = wtx.send(wire::legacy_mule_info_bytes(sx1)).await;
                    continue;
                }
                let hello = match script.multipacket {
                    MultiPacketPolicy::AnswerBundle => wire::multipacket_hello_answer_bytes(
                        script.hello_user_hash,
                        &script.hello_nickname,
                    ),
                    MultiPacketPolicy::Unsupported => wire::hello_answer_bytes_with_sx1(
                        script.hello_user_hash,
                        &script.hello_nickname,
                        script.hello_source_exchange,
                    ),
                };
                let _ = wtx.send(hello).await;
            }
            // `OP_REQUESTFILENAME 0x58` asks for the name and is answered by
            // `OP_REQFILENAMEANSWER 0x59`; `OP_SETREQFILEID 0x4F` asks for
            // availability and is answered by `OP_FILESTATUS 0x50`. The pairing
            // is the one `rmule_peer::file_request` documents — a fake that
            // answers the other question lets an ordering bug pass.
            0x58 => {
                stats.standalone_probe_asks += 1;
                let _ = wtx
                    .send(wire::filename_answer_bytes(
                        script.file_hash,
                        &script.file_name,
                    ))
                    .await;
            }
            0x4F => {
                stats.standalone_probe_asks += 1;
                let _ = wtx
                    .send(wire::file_status_bytes(
                        script.file_hash,
                        script.bytes.len() as u64,
                    ))
                    .await;
            }
            0x51 => {
                let hashes: &[PartHash] = match &script.hash_set {
                    HashSetPolicy::ZeroPart => &[],
                    HashSetPolicy::Parts(hashes) => hashes,
                };
                let _ = wtx
                    .send(wire::hash_set_bytes(script.file_hash, hashes))
                    .await;
            }
            0x54 => {
                stats.start_upload_count += 1;
                match &script.slot {
                    SlotPolicy::Grant => {
                        let _ = wtx.send(wire::accept_upload_bytes()).await;
                    }
                    SlotPolicy::QueueThenGrant(ranks) => {
                        for &rank in ranks {
                            let _ = wtx.send(wire::queueranking_bytes(rank)).await;
                        }
                        let _ = wtx.send(wire::accept_upload_bytes()).await;
                    }
                    SlotPolicy::QueueThenSilence(ranks) => {
                        for &rank in ranks {
                            let _ = wtx.send(wire::queueranking_bytes(rank)).await;
                        }
                    }
                    SlotPolicy::QueueForever {
                        start_rank,
                        interval,
                    } => {
                        if !queue_pump_started {
                            queue_pump_started = true;
                            let pump_tx = wtx.clone();
                            let mut rank = *start_rank;
                            let interval = *interval;
                            tokio::spawn(async move {
                                loop {
                                    if pump_tx.send(wire::queueranking_bytes(rank)).await.is_err() {
                                        return;
                                    }
                                    rank = rank.saturating_sub(1).max(1);
                                    tokio::time::sleep(interval).await;
                                }
                            });
                        }
                    }
                }
            }
            0x47 => {
                let ranges = request_ranges(packet.payload());
                if stats.first_request_start.is_none() {
                    stats.first_request_start = Some(ranges[0].0);
                }
                match &script.serve {
                    ServePolicy::Blocks => {
                        for &(start, end) in ranges.iter().filter(|(s, e)| e > s) {
                            assert!(
                                end - start <= EMBLOCKSIZE,
                                "peer only serves <= EMBLOCKSIZE blocks, got {start}..{end}"
                            );
                            stats.max_block = stats.max_block.max(end - start);
                            let _ = wtx
                                .send(wire::sending_part_bytes(
                                    script.file_hash,
                                    start as u32,
                                    &script.bytes[start as usize..end as usize],
                                ))
                                .await;
                        }
                    }
                    ServePolicy::FirstBlockThenClose => {
                        let (start, _) = ranges[0];
                        let end = (start + EMBLOCKSIZE).min(script.bytes.len() as u64);
                        let _ = wtx
                            .send(wire::sending_part_bytes(
                                script.file_hash,
                                start as u32,
                                &script.bytes[start as usize..end as usize],
                            ))
                            .await;
                        // Give the writer a beat to flush, then close mid-part.
                        tokio::task::yield_now().await;
                        break 'conn;
                    }
                    ServePolicy::Nothing => {}
                }
            }
            0x92 | 0xA4 if packet.protocol() == PacketProtocol::Emule => {
                // Reverse harness: rmule folded its file request into a
                // bundle because this uploader advertised the capability.
                // Record the arrival (what asserts the live runner emits the bundle),
                // then fan it into the one composed 0x93 an aMule uploader
                // answers with.
                // This uploader advertises rmule's own `MiscOptions1`, and so
                // does its asker: both claim the same extended-requests level.
                let claim = MiscOptions1::rmule_advertised().extended_requests_version();
                let level = ExtendedRequests::negotiated(claim, claim);
                if let Ok(req) = MultiPacketRequest::decode_packet(&packet, level) {
                    if stats.multipacket_request.is_none() {
                        stats.multipacket_request = Some(SeenMultiPacketRequest {
                            opcode: packet.opcode(),
                            size8: req.file_size,
                            sub_opcodes: req.items.iter().map(request_sub_opcode).collect(),
                            name_status: req.items.iter().find_map(|item| match item {
                                RequestItem::Name { part_status } => part_status.clone(),
                                _ => None,
                            }),
                        });
                    }
                    if let MultiPacketPolicy::AnswerBundle = script.multipacket {
                        let _ = wtx
                            .send(multipacket_answer(&script, &req).encode_packet().encode())
                            .await;
                    }
                }
            }
            0xA8 if packet.protocol() == PacketProtocol::Emule => {
                // A Kad firewall-check dial-back's connect-back ack
                // (`OP_KAD_FWTCPCHECK_ACK`, ADR-0058 responder). Record the
                // arrival — a self-checking peer counts exactly this.
                stats.kad_fw_tcp_check_ack = true;
            }
            0x99 if packet.protocol() == PacketProtocol::Emule && packet.payload().len() >= 16 => {
                // An open-node buddy's `OP_CALLBACK` (`0x99`) relay of a Kad
                // `0x52` callback (ADR-0061). Record the echoed buddy-ID
                // (the body's leading 16 bytes) as proof the relay arrived intact.
                let mut buddy_id = [0u8; 16];
                buddy_id.copy_from_slice(&packet.payload()[..16]);
                stats.buddy_callback_buddy_id = Some(buddy_id);
            }
            0x56 => {
                // `OP_CANCELTRANSFER` (ADR-0056): the downloader is abandoning
                // this transfer (its download was cancelled/paused) and tells us
                // to stop before it releases the slot. Empty payload — its
                // arrival is the whole signal.
                stats.cancel_transfer_count += 1;
            }
            0x81 => {
                if let SourcesPolicy::AnswerPacked(sources) = &script.sources {
                    // Echo the requested hash (OP_REQUESTSOURCES payload is
                    // just `[file_hash 16]`) rather than `script.file_hash`,
                    // which names the shared-file flows instead.
                    let mut hash = [0u8; FileHash::BYTE_LEN];
                    hash.copy_from_slice(&packet.payload()[..FileHash::BYTE_LEN]);
                    let _ = wtx
                        .send(wire::packed_answer_sources_bytes(
                            FileHash::from_bytes(hash),
                            sources,
                        ))
                        .await;
                }
            }
            _ => {}
        }
    }
    // Writer drains any queued frames (channel close ends it after the drain).
    drop(wtx);
    let _ = writer.await;
    stats
}
