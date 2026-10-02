//! Deterministic in-process eD2k server (ADR-0040 Correctness Tier): models the
//! seams the Low-ID callback's interop bugs live in — a High-ID **Back-Connect
//! Probe** (the Lugdunum-captured `OP_HELLO` → `OP_HELLOANSWER` port check),
//! Low-ID assignment, and the callback relay across two client
//! sessions — plus an obfuscated-accept option (byte-0 discrimination into the
//! server-form **Obfuscated Handshake**, ADR-0042) for the connect-crypt seams.
//! Faithful to *behaviour*, not to wire bytes; it is not a re-implementation of
//! the real eserver (that is the Compatibility Tier's job) — the one deliberate
//! byte-level fidelity is the port-check hello, kept capture-shaped so rmule's
//! compact-tag decode stays exercised.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_ed2k::{
    CallbackRequest, FoundSources, GetSourcesRequest, IdChange, LoginRequest, Opcode, PeerCallback,
    SearchRequest, SearchResults, ServerTcpFlags,
};
use rmule_net::driver::CryptStream;
use rmule_net::ed2k::ServerObfuscationTransport;
use rmule_peer::HelloAnswer;
use rmule_primitives::{
    ClientId, FileHash, Ipv4Endpoint, KeywordQuery, Packet, PeerSource, PrimitiveError,
    SearchResult, ServerEndpoint, UserHash, is_plaintext_marker,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;

/// How long the back-connect probe waits — for the TCP connect, and again for
/// the `OP_HELLOANSWER` — before deeming a client unreachable. On loopback an
/// unbound port is refused and a live driver answers near-instantly, so this
/// only bounds the pathological case (the real Lugdunum allows ~10 s).
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// A stand-in routable id handed to reachable (High-ID) clients. Any value
/// `>= ClientId::LOW_ID_THRESHOLD` works; rmule never dials it for a callback.
const HIGH_ID: u32 = 0x0100_007F;

/// The user hash the port-check `OP_HELLO` carries — the value captured from
/// the bench Lugdunum eserver 17.15 check (back-connect probe pcap, 2026-07-27); note
/// the eMule marker bytes `hash[5] == 0x0E` / `hash[14] == 0x6F`.
const CHECK_HELLO_HASH: [u8; 16] = [
    0x8b, 0xd6, 0xf4, 0xda, 0xa3, 0x0e, 0xc8, 0x94, 0xeb, 0xa7, 0x4f, 0x83, 0x69, 0x3c, 0x6f, 0xb3,
];

#[derive(Default)]
struct Shared {
    /// Sequential Low-ID counter; assignments start at 1 (0 has no callback
    /// semantics — see `docs/reference/notes/low-id-callback.md`).
    next_low_id: u32,
    /// low id → a writer sink for that client's socket, so one client's handler
    /// can relay a frame onto another's connection (the callback relay).
    low_id_writers: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    /// Registered Low-ID sources, answered to any `OP_GETSOURCES`.
    sources: Vec<PeerSource>,
    /// Scripted mode (see [`FakeEd2kServer::start_scripted`]): skip the
    /// Back-Connect Probe (every client gets High-ID) and answer
    /// `OP_GETSOURCES` with this list instead of the Low-ID registry.
    scripted_sources: Option<Vec<PeerSource>>,
    /// Scripted `OP_SEARCHREQUEST` answer (empty result set by default).
    search_results: Vec<SearchResult>,
    /// Scripted delay between receiving `OP_LOGINREQUEST` and answering
    /// `OP_IDCHANGE` — the window a real Lugdunum spends on its Back-Connect
    /// Probe (the server dials the client's advertised port and
    /// waits for `OP_HELLOANSWER` before assigning an id, ~seconds live).
    /// Zero by default; set via [`FakeEd2kServer::set_login_delay`] to model
    /// a login still in flight when an activity command arrives.
    login_delay: Duration,
    /// The `SRV_TCPFLG_*` word every subsequent login's `OP_IDCHANGE` grants;
    /// `None` (the default) sends the bare id, which grants nothing.
    tcp_flags: Option<ServerTcpFlags>,
    /// Queries decoded from received `OP_SEARCHREQUEST` frames — the whole
    /// expression tree read back, not just the phrase — for test assertions on
    /// what rmule actually asked.
    search_queries: Vec<KeywordQuery>,
    /// Every id granted by an `IdChange`, in login order — the port-check
    /// verdict trail tests assert on.
    assigned_ids: Vec<ClientId>,
    /// Bumped to `assigned_ids.len()` on every grant, so a test can *await* a
    /// login rather than poll for one: a serve start returns at the bind and
    /// no longer waits for its own login, so "the login reached
    /// the server" became an asynchronous fact.
    logins: watch::Sender<usize>,
    /// Bumped by [`FakeEd2kServer::hang_up_all`]: every logged-in client's
    /// session is ended by the server, the listener staying up.
    hang_ups: watch::Sender<u64>,
    /// While set ([`FakeEd2kServer::set_refusing`]), a login is closed before
    /// any id is granted — a server that accepts the socket and refuses.
    refusing: bool,
    /// While set ([`FakeEd2kServer::set_search_silent`]), a search request is
    /// recorded and never answered — a server still thinking when its session
    /// ends.
    search_silent: bool,
}

/// A running fake server. Drop aborts the accept loop.
pub struct FakeEd2kServer {
    local_addr: SocketAddrV4,
    accept: JoinHandle<()>,
    shared: Arc<Mutex<Shared>>,
}

impl Drop for FakeEd2kServer {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl FakeEd2kServer {
    /// Bind `127.0.0.1:0` and start accepting client sessions, with the
    /// Back-Connect Probe live and `OP_GETSOURCES` answered from the Low-ID
    /// registry (the callback seams, ADR-0040).
    pub async fn start() -> Self {
        Self::start_with(
            Shared {
                next_low_id: 1,
                ..Shared::default()
            },
            false,
        )
        .await
    }

    /// Scripted mode for download scenarios: every client is assigned High-ID
    /// without a probe, and `OP_GETSOURCES` answers exactly the scripted list
    /// (empty until [`Self::set_sources`]) — the seams a download test drives,
    /// nothing more.
    pub async fn start_scripted() -> Self {
        Self::start_with(
            Shared {
                next_low_id: 1,
                scripted_sources: Some(Vec::new()),
                ..Shared::default()
            },
            false,
        )
        .await
    }

    /// Scripted mode with obfuscated accept (the connect-crypt seams,
    /// ADR-0042): byte-0 discrimination decides per connection — a plaintext
    /// protocol marker is served as-is, anything else runs the server-form
    /// **Obfuscated Handshake** (768-bit DH + RC4) and is served over the
    /// decrypted stream.
    pub async fn start_obfuscated() -> Self {
        Self::start_with(
            Shared {
                next_low_id: 1,
                scripted_sources: Some(Vec::new()),
                ..Shared::default()
            },
            true,
        )
        .await
    }

    async fn start_with(shared: Shared, obfuscated_accept: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr =
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
        let shared = Arc::new(Mutex::new(shared));
        let accept_shared = shared.clone();
        let accept = tokio::spawn(async move {
            while let Ok((sock, peer)) = listener.accept().await {
                let SocketAddr::V4(peer) = peer else { continue };
                tokio::spawn(handle_client(
                    sock,
                    *peer.ip(),
                    obfuscated_accept,
                    accept_shared.clone(),
                ));
            }
        });
        Self {
            local_addr,
            accept,
            shared,
        }
    }

    /// The bound server address clients connect to.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    /// The same address as the endpoint a core logs in to.
    pub fn endpoint(&self) -> ServerEndpoint {
        ServerEndpoint::new(self.local_addr.ip().to_string(), self.local_addr.port())
            .expect("a loopback endpoint")
    }

    /// End every logged-in client's session from the server's side, as a
    /// server that restarts or drops its clients does; the listener stays up
    /// and later logins are served as before.
    pub async fn hang_up_all(&self) {
        self.shared
            .lock()
            .await
            .hang_ups
            .send_modify(|count| *count += 1);
    }

    /// Refuse (`true`) or serve (`false`) every later login: a refused one is
    /// closed before any id is granted.
    pub async fn set_refusing(&self, refusing: bool) {
        self.shared.lock().await.refusing = refusing;
    }

    /// Replace the scripted `OP_GETSOURCES` answer (scripted mode only).
    pub async fn set_sources(&self, sources: Vec<PeerSource>) {
        let mut state = self.shared.lock().await;
        assert!(
            state.scripted_sources.is_some(),
            "set_sources is a scripted-mode seam; start with start_scripted()"
        );
        state.scripted_sources = Some(sources);
    }

    /// Record every later `OP_SEARCHREQUEST` without answering it (`true`),
    /// or answer again (`false`).
    pub async fn set_search_silent(&self, silent: bool) {
        self.shared.lock().await.search_silent = silent;
    }

    /// Replace the scripted `OP_SEARCHREQUEST` answer.
    pub async fn set_search_results(&self, results: Vec<SearchResult>) {
        self.shared.lock().await.search_results = results;
    }

    /// Delay every subsequent login's `OP_IDCHANGE` by `delay` — the
    /// Back-Connect-Probe window a real Lugdunum spends before assigning an
    /// id. Commands arriving during the window sit in the server's read
    /// buffer, exactly as they would on a real socket.
    pub async fn set_login_delay(&self, delay: Duration) {
        self.shared.lock().await.login_delay = delay;
    }

    /// Grant `flags` in every subsequent login's `OP_IDCHANGE` (ADR-0047).
    pub async fn set_tcp_flags(&self, flags: Option<ServerTcpFlags>) {
        self.shared.lock().await.tcp_flags = flags;
    }

    /// Every `OP_SEARCHREQUEST` received so far, decoded back to the query it
    /// states — phrase *and* the typed constraints its expression tree carried,
    /// so a test can assert on what the client actually asked for and not just
    /// what it typed.
    pub async fn search_queries(&self) -> Vec<KeywordQuery> {
        self.shared.lock().await.search_queries.clone()
    }

    /// Just the phrases, for tests whose subject is routing rather than the
    /// constraint tree.
    pub async fn search_phrases(&self) -> Vec<String> {
        self.search_queries()
            .await
            .iter()
            .map(|query| query.phrase().to_display_string())
            .collect()
    }

    /// Every id granted so far, in login order — High for a client whose
    /// listener answered the port-check `OP_HELLO` during its login, Low
    /// otherwise.
    pub async fn assigned_ids(&self) -> Vec<ClientId> {
        self.shared.lock().await.assigned_ids.clone()
    }

    /// Park until at least `count` logins have been granted an id, then return
    /// the whole trail. The awaitable form of [`Self::assigned_ids`], for the
    /// callers that used to read it straight after a serve start — which
    /// returns at the bind now, with the login still in flight.
    pub async fn assigned_ids_after(&self, count: usize) -> Vec<ClientId> {
        loop {
            let (mut granted, ids) = {
                let state = self.shared.lock().await;
                (state.logins.subscribe(), state.assigned_ids.clone())
            };
            if ids.len() >= count {
                return ids;
            }
            // `subscribe` was taken under the same lock as the read above, so
            // it is marked as having seen exactly that trail: a grant that
            // lands from here on wakes this, and one that landed before it is
            // already in `ids`.
            if granted.changed().await.is_err() {
                return ids;
            }
        }
    }
}

/// The client-side counterpart of the port check, for tests that log in over a
/// raw socket rather than through the serve adapter: bind an ephemeral
/// loopback listener whose accepts answer the check `OP_HELLO` as `identity`.
/// Returns the bound port (to advertise in the login) and the listener task
/// (aborted on drop by the caller keeping the handle).
pub async fn spawn_check_answering_listener(
    identity: rmule_primitives::ClientIdentity,
) -> (u16, JoinHandle<()>) {
    let listener = rmule_net::peer::PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the check-answering listener");
    let port = listener.local_port();
    let ctx = rmule_peer::PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0),
        connected_server: None,
    };
    let task = tokio::spawn(async move {
        loop {
            let Ok(mut conn) = listener
                .accept(ctx.clone(), rmule_net::peer::ConnectOptions::default())
                .await
            else {
                continue;
            };
            tokio::spawn(async move { while conn.next_event().await.is_some() {} });
        }
    });
    (port, task)
}

/// The High-ID port-check leg: back-connect `advertised`, send
/// the check `OP_HELLO`, and await an `OP_HELLOANSWER` whose user hash matches
/// the login's — `true` only when the answer arrives within [`PROBE_TIMEOUT`].
/// A connect that is accepted but never answered is a failed check, exactly as
/// on the bench Lugdunum.
async fn port_check(peer_ip: Ipv4Addr, advertised: u16, login_hash: UserHash) -> bool {
    let connect = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect((peer_ip, advertised)));
    let Ok(Ok(mut sock)) = connect.await else {
        return false;
    };
    if sock
        .write_all(&check_hello_frame(advertised))
        .await
        .is_err()
    {
        return false;
    }
    let answer = tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut buf = Vec::new();
        while let Some(packet) = next_packet(&mut sock, &mut buf).await {
            if let Ok(answer) = HelloAnswer::decode_packet(&packet) {
                return Some(answer.body().user_hash);
            }
        }
        None
    });
    matches!(answer.await, Ok(Some(hash)) if hash == login_hash)
}

/// The port-check `OP_HELLO`, byte-shaped after the frame captured from the
/// bench Lugdunum 17.15 (back-connect probe pcap, 2026-07-27): compact-name tags with
/// the short-string type (`0x97` = STR7|0x80 carrying CT_NAME "eServer",
/// `0x89` = UINT8|0x80 carrying CT_VERSION 60), client id 0, the client's own
/// advertised port mirrored back, and `connected_server` 0.0.0.0:0. Built raw
/// so the compact short-string form stays pinned to the capture (rmule's tag
/// encoder would re-encode the name as a length-prefixed `TAGTYPE_STRING`).
fn check_hello_frame(advertised: u16) -> Vec<u8> {
    let mut payload = vec![0x10];
    payload.extend_from_slice(&CHECK_HELLO_HASH);
    payload.extend_from_slice(&0u32.to_le_bytes()); // client id 0
    payload.extend_from_slice(&advertised.to_le_bytes());
    payload.extend_from_slice(&2u32.to_le_bytes()); // tag count
    payload.push(0x97); // STR7 | compact-name flag
    payload.push(0x01); // CT_NAME
    payload.extend_from_slice(b"eServer");
    payload.push(0x89); // UINT8 | compact-name flag
    payload.push(0x11); // CT_VERSION
    payload.push(60);
    payload.extend_from_slice(&[0u8; 6]); // connected_server 0.0.0.0:0
    let mut frame = vec![0xE3];
    let len = u32::try_from(payload.len() + 1).expect("check hello fits u32");
    frame.extend_from_slice(&len.to_le_bytes());
    frame.push(0x01); // OP_HELLO
    frame.extend_from_slice(&payload);
    frame
}

/// Pull one decoded packet, buffering across reads and keeping any trailing
/// bytes for the next call (frames on a shared session can coalesce). Anything
/// that is not eD2k framing — e.g. an obfuscation opening reaching a
/// plaintext-only accept — closes the connection, as a real server would; the
/// `Requested` fallback path rides on that close.
async fn next_packet<R: AsyncRead + Unpin>(stream: &mut R, buf: &mut Vec<u8>) -> Option<Packet> {
    loop {
        match Packet::decode(buf) {
            Ok((packet, consumed)) => {
                buf.drain(..consumed);
                return Some(packet);
            }
            Err(PrimitiveError::TruncatedPacket { .. }) => {}
            Err(_) => return None,
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Byte-0 discrimination on accept, mirroring the peer listener (ADR-0042): a
/// known plaintext protocol marker is served as-is; anything else opens the
/// server-form Obfuscated Handshake, and the session is served over the
/// decrypted stream — the serving loop never knows crypt was underneath.
async fn handle_client(
    sock: TcpStream,
    peer_ip: Ipv4Addr,
    obfuscated_accept: bool,
    shared: Arc<Mutex<Shared>>,
) {
    if obfuscated_accept {
        let mut first = [0u8; 1];
        let Ok(peeked) = sock.peek(&mut first).await else {
            return;
        };
        if peeked == 1 && !is_plaintext_marker(first[0]) {
            let mut crypt = CryptStream::new(sock, ServerObfuscationTransport::server());
            if crypt.complete_handshake().await.is_err() {
                return;
            }
            serve_client(crypt, peer_ip, shared).await;
            return;
        }
    }
    serve_client(sock, peer_ip, shared).await;
}

async fn serve_client<S>(stream: S, peer_ip: Ipv4Addr, shared: Arc<Mutex<Shared>>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    // A writer task drains a sink so another client's handler can push a relayed
    // frame onto *this* connection (the callback relay).
    let (wtx, mut wrx) = mpsc::channel::<Vec<u8>>(16);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = wrx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    let mut buf = Vec::new();
    let Some(login_pkt) = next_packet(&mut rd, &mut buf).await else {
        writer.abort();
        return;
    };
    let Ok(login) = LoginRequest::decode_packet(&login_pkt) else {
        writer.abort();
        return;
    };
    // Assert the login shape (ADR-0047 evidence): the aMule 2.3.3 four —
    // CT_NAME, CT_VERSION, CT_SERVER_FLAGS, CT_EMULE_VERSION — exactly and in
    // order, no CT_PORT. After them, and only after them, the two adverts
    // later ADRs settled may ride, each at most once and in this order:
    // `CT_MOD_IP_V6` (`0xAE`, ADR-0087) and `CT_EMULE_UDPPORTS` (`0xF9`,
    // ADR-0091 — present whenever a client-UDP socket is bound, which is
    // every running core). Anything else is a violating client and is dropped
    // before IdChange, so any test driving a session through this server
    // fails loudly on its login wait.
    let tag_ids: Vec<Option<u8>> = login.tags().iter().map(|t| t.name().id()).collect();
    let canonical = [Some(0x01), Some(0x11), Some(0x20), Some(0xFB)];
    let adverts: &[Option<u8>] = tag_ids.get(canonical.len()..).unwrap_or(&[]);
    let adverts_ok = matches!(
        adverts,
        [] | [Some(0xAE)] | [Some(0xF9)] | [Some(0xAE), Some(0xF9)]
    );
    if !tag_ids.starts_with(&canonical) || !adverts_ok {
        writer.abort();
        return;
    }
    let advertised = login.tcp_port();
    if shared.lock().await.refusing {
        writer.abort();
        return;
    }

    // High-ID reachability Back-Connect Probe, per the captured Lugdunum 17.15
    // check: dial the client's advertised TCP port, send the
    // port-check `OP_HELLO`, and require an `OP_HELLOANSWER` carrying the
    // login's user hash within the window. An unanswered (merely accepted)
    // connect fails the check — the real server then warns "No answer from
    // your <port> port" and assigns Low-ID — so the client must be accepting
    // AND answering *during* its login. Scripted mode skips the probe: every
    // client is High-ID by construction.
    let (scripted, login_delay, tcp_flags) = {
        let state = shared.lock().await;
        (
            state.scripted_sources.is_some(),
            state.login_delay,
            state.tcp_flags,
        )
    };
    // The scripted probe window: a real Lugdunum answers
    // `OP_IDCHANGE` only after its Back-Connect Probe resolves, so a client
    // command sent "right after connect" can land while the login is still
    // unanswered. The sleep sits exactly where the probe does.
    if !login_delay.is_zero() {
        tokio::time::sleep(login_delay).await;
    }
    let reachable = scripted || port_check(peer_ip, advertised, login.user_hash()).await;

    let assigned = if reachable {
        ClientId::from_u32(HIGH_ID)
    } else {
        let mut state = shared.lock().await;
        let low = state.next_low_id;
        state.next_low_id += 1;
        state.low_id_writers.insert(low, wtx.clone());
        state
            .sources
            .push(PeerSource::new(ClientId::from_u32(low), advertised));
        ClientId::from_u32(low)
    };
    {
        // The grant and its signal under one lock, so a waiter that read the
        // trail cannot miss the bump that follows it.
        let mut state = shared.lock().await;
        state.assigned_ids.push(assigned);
        let granted = state.assigned_ids.len();
        let _ = state.logins.send(granted);
    }
    let id_change = IdChange {
        client_id: assigned,
        tcp_flags,
        standard_tcp_port: None,
        public_ip: None,
        obfuscation_tcp_port: None,
        trailing: Vec::new(),
    };
    let _ = wtx.send(id_change.encode_packet().encode()).await;

    // The requester endpoint a called-back peer dials: this client's source ip +
    // advertised port (what `OP_CALLBACKREQUESTED` carries to the source).
    let requester = Ipv4Endpoint::new(peer_ip, advertised);

    let mut hang_ups = shared.lock().await.hang_ups.subscribe();
    loop {
        let packet = tokio::select! {
            packet = next_packet(&mut rd, &mut buf) => packet,
            _ = hang_ups.changed() => None,
        };
        let Some(packet) = packet else { break };
        let opcode = packet.opcode();
        if opcode == Opcode::GetSources.as_u8() {
            let Ok(request) = GetSourcesRequest::decode_packet(&packet) else {
                continue;
            };
            let sources = {
                let state = shared.lock().await;
                state
                    .scripted_sources
                    .clone()
                    .unwrap_or_else(|| state.sources.clone())
            };
            if let Ok(found) = FoundSources::new(requested_hash(&request), sources) {
                let _ = wtx.send(found.encode_packet().encode()).await;
            }
        } else if opcode == Opcode::SearchRequest.as_u8() {
            let Ok(request) = SearchRequest::decode_packet(&packet) else {
                continue;
            };
            let results = {
                let mut state = shared.lock().await;
                state.search_queries.push(request.query().clone());
                if state.search_silent {
                    continue;
                }
                state.search_results.clone()
            };
            let _ = wtx
                .send(SearchResults::new(results).encode_packet().encode())
                .await;
        } else if opcode == Opcode::CallbackRequest.as_u8() {
            let Ok(request) = CallbackRequest::decode_packet(&packet) else {
                continue;
            };
            let sink = shared
                .lock()
                .await
                .low_id_writers
                .get(&request.low_id.as_u32())
                .cloned();
            if let Some(sink) = sink {
                let relayed = PeerCallback::new(requester).encode_packet().encode();
                let _ = sink.send(relayed).await;
            }
        }
    }
    writer.abort();
}

fn requested_hash(request: &GetSourcesRequest) -> FileHash {
    match request {
        GetSourcesRequest::Legacy { file_hash } => *file_hash,
        GetSourcesRequest::Normal { target } | GetSourcesRequest::Large { target } => {
            target.file_hash()
        }
    }
}
