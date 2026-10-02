//! Setup the legs of this binary share: the identity a core logs in with, the
//! links and endpoints a command carries, the event pump every leg waits on,
//! the two kinds of TCP port a leg asks for, and the port a Half-Bound
//! Pair leg holds on one family.
//!
//! Anything a second crate would want belongs in `rmule-testkit` instead —
//! `test_identity`, `file_link`, and the fakes already live there.

use rmule_core::{DurableStore, open_durable_store};
use std::net::SocketAddrV4;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rmule_core::{
    ClientUdpBind, Core, CoreConfig, CoreError, CoreEvent, DurableAppConfig,
    DurableSharedFileRegistry, KadEnableConfig, KadId, KadReachLevel, KadRuntimeFactory, KadSource,
    KadSourceChannel, ServeEvent,
};
use rmule_ed2k::{IdChange, LoginRequest};
use rmule_primitives::{
    Capabilities, ClientId, ClientIdentity, CryptStance, Ed2kFileLink, Ed2kText, FileHash,
    KeywordQuery, Packet, ServerEndpoint, SourceLookupTarget,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

mod dual_stack;
mod kad;
mod search_server;
mod session;
pub use dual_stack::{
    host_binds_ipv6, reserve_dual_stack_port, reserve_dual_stack_port_from, skip_without_ipv6,
};
pub use kad::StubKad;
pub use search_server::LoopbackSearchServer;
pub use session::{
    connect_and_settle, connect_server, connect_server_as, list_and_connect, list_server,
    search_result, start_search, start_search_confirmed,
};

// ---- who the core is -------------------------------------------------------

/// The identity a core logs in with: a `0x42` User Hash on the default eD2k
/// TCP port, protocol version 60.
pub fn identity() -> ClientIdentity {
    identity_with_port(4662)
}

/// The same identity advertising `port` instead — the
/// advertise-what-you-bind invariant a serve leg has to hold to earn a
/// High-ID (ADR-0040).
pub fn identity_with_port(port: u16) -> ClientIdentity {
    rmule_testkit::test_identity(0x42, "rmule-core", port)
}

// ---- the durable store ------------------------------------------------------

/// The app-config seam on the engine's in-memory backend — no file, no lock, and
/// the same single implementation a real run uses (ADR-0083).
pub fn memory_config_store() -> DurableAppConfig {
    DurableAppConfig::new(rmule_testkit::memory_store())
}

/// The store in data directory `dir`, on a real file. One process may hold
/// one open engine per file, so a leg that wants two handles on the same
/// state clones this `Arc` rather than opening twice; a leg that wants a
/// *restart* drops the first handle entirely before calling again.
pub fn open_store(dir: impl AsRef<Path>) -> Arc<DurableStore> {
    open_durable_store(dir.as_ref()).expect("store file opens")
}

/// The app-config seam on a real file.
pub fn file_config_store(dir: impl AsRef<Path>) -> DurableAppConfig {
    DurableAppConfig::new(open_store(dir))
}

// ---- what a command carries -------------------------------------------------

/// A link with no content behind it: `seed` fills the file hash, so the
/// download it names can be recorded and read back but never transferred.
/// A leg that moves bytes wants `rmule_testkit::file_link` instead, which
/// digests them.
pub fn stub_link(name: &str, size: u64, seed: u8) -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8(name),
        size,
        file_hash: FileHash::from_bytes([seed; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// A server on the eD2k default port that the leg records but never reaches —
/// what a durable row or a rejected command needs a server for.
pub fn stub_server(host: &str) -> ServerEndpoint {
    ServerEndpoint::new(host, 4661).expect("a well-formed stub endpoint")
}

/// The first `OP_GLOBSEARCHREQ` (`0x98`/`0x92`/`0x90`) that reaches `udp`
/// inside `window` — a server-UDP socket standing in for a listed server —
/// or `None`.
pub async fn sweep_datagram(udp: &tokio::net::UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buf = [0_u8; 2048];
    timeout(window, async {
        loop {
            let (len, _) = udp.recv_from(&mut buf).await.unwrap();
            if len > 1 && matches!(buf[1], 0x98 | 0x92 | 0x90) {
                return buf[..len].to_vec();
            }
        }
    })
    .await
    .ok()
}

/// A **mute server**: a loopback listener that completes the TCP handshake and
/// then answers nothing, holding every accepted socket open so the peer never
/// sees a FIN.
///
/// The one shape that tells a login deadline from a dial failure —
/// a refused port fails the *dial*, a dropped socket fails the *link*, and only
/// a server that is up and mute exercises the session's own
/// `login_deadline_elapsed`. A leg that uses it pairs it with a short
/// [`CoreConfig::server_login_timeout`](rmule_core::CoreConfig::server_login_timeout);
/// the returned guard closes the listener when it drops.
pub async fn mute_server() -> (ServerEndpoint, MuteServer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (
        ServerEndpoint::new("127.0.0.1", port).expect("a loopback endpoint"),
        MuteServer { accepting },
    )
}

/// The live half of [`mute_server`]: dropping it ends the accept task, which
/// closes the listener and every socket it is holding open.
pub struct MuteServer {
    accepting: tokio::task::JoinHandle<()>,
}

impl Drop for MuteServer {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

// ---- the durable store ------------------------------------------------------

/// The search a leg issues. The phrase is the leg's own, so a fake that
/// records queries can tell two searches apart.
pub fn search_query(phrase: &str) -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8(phrase)).expect("a non-empty phrase")
}

// ---- how a leg is configured ------------------------------------------------

/// A config for the search legs: the status-ping sweep parked an hour out so
/// it never interleaves, and a quiet window short enough to complete a search
/// inside a test.
pub fn search_config() -> CoreConfig {
    CoreConfig {
        status_ping_tick: Duration::from_secs(3600),
        search_quiet_timeout: Duration::from_millis(300),
        ..CoreConfig::default()
    }
}

/// Enabling Kad on loopback with an ephemeral UDP port and no bootstrap: the
/// node a leg drives itself rather than one that goes looking for contacts.
pub fn kad_enable_config() -> KadEnableConfig {
    KadEnableConfig {
        kad_id: KadId::from_bytes([0x0A; KadId::BYTE_LEN]),
        peer_credentials: identity().into(),
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_udp_key: 0,
        kad_capture_dir: None,
        kad_shutdown: None,
    }
}

/// A Kad runtime that never starts a node but *publishes a TCP verdict* — the
/// ADR-0058 fact the chooser's route 1 gate reads. `open` false is the honest
/// fresh-node default and makes a LowID peer off our server a LowID→LowID drop;
/// `open` true states a verdict a real node would have reached (ADR-0058's
/// injected TCP verdict).
pub struct VerdictOnlyKad {
    pub open: bool,
}

/// A Kad seam that is asked things and never answers.
pub struct NeverChannel;
impl KadSourceChannel for NeverChannel {
    async fn search_sources(&self, _target: SourceLookupTarget) {}
    async fn publish_source(&self, _target: SourceLookupTarget) {}
    async fn next_sources(&self) -> Option<(FileHash, Vec<KadSource>)> {
        std::future::pending().await
    }
}

impl KadRuntimeFactory for VerdictOnlyKad {
    type Channel = NeverChannel;

    fn kad_reach(&self) -> KadReachLevel {
        KadReachLevel::fixed(self.open)
    }

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _bind: ClientUdpBind,
    ) -> Result<NeverChannel, CoreError> {
        Ok(NeverChannel)
    }
}

// ---- waiting on the core ----------------------------------------------------

/// How long a leg waits for an event before calling it a failure.
///
/// This is a hang detector, not a pass criterion: every leg that reaches
/// `next_matching`/`next_expected` is already waiting on a real signal (an
/// event the core emits, itself driven by a short, per-test-configured delay
/// such as `search_quiet_timeout`), so a correct leg returns in well under a
/// second. The budget only has to be wide enough that CPU starvation from
/// oversubscription — several copies of this binary, or several legs of it,
/// competing for the same cores — never reads as a failure
/// (`search_completes_after_quiet_timeout` once blew a 5 s budget under 5x load
/// with no bug behind it). 60 s is generous on purpose; a genuine hang still
/// fails, just later.
const EVENT_BUDGET: Duration = Duration::from_secs(60);

/// Pump events until `pred` accepts one, or fail.
pub async fn next_matching(core: &mut Core, pred: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
    next_expected(core, "a matching core event", pred).await
}

/// [`next_matching`] naming what the leg is waiting for, so a timeout says
/// which step of the sequence never arrived.
pub async fn next_expected(
    core: &mut Core,
    waiting_for: &str,
    pred: impl Fn(&CoreEvent) -> bool,
) -> CoreEvent {
    timeout(EVENT_BUDGET, async {
        loop {
            let event = core
                .next_event()
                .await
                .expect("core event stream stayed open");
            if pred(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {waiting_for}"))
}

/// Pump events until the serve activity reports the listener it bound.
///
/// A `ServingFailed` before that is a serve start that *failed* — most often a
/// listener whose port was taken between the probe and the bind — and it fails
/// here, naming the cause, instead of presenting as a five-second timeout
/// A timeout indistinguishable from a deadlock costs a bisect to
/// tell apart, which is exactly what this class of flake used to cost.
///
/// `ServingStarted` is the *bind*, not the login: a leg that needs
/// the assigned client id waits on `CoreEvent::ServerConnection` as well.
pub async fn serving_started(core: &mut Core) -> SocketAddrV4 {
    let event = next_expected(core, "the serve activity's ServingStarted", |event| {
        matches!(
            event,
            CoreEvent::Serve(
                ServeEvent::ServingStarted { .. }
                    | ServeEvent::ServingFailed { .. }
                    | ServeEvent::ServingStopped { .. }
            )
        )
    })
    .await;
    match event {
        CoreEvent::Serve(ServeEvent::ServingStarted { listen_addr }) => listen_addr,
        CoreEvent::Serve(ServeEvent::ServingFailed { reason }) => {
            panic!("the serve activity never bound its listener: {reason:?}")
        }
        _ => panic!("the serve activity stopped instead of starting"),
    }
}

/// Log in to `server` advertising `advertised_port` and return the id it
/// assigns — the whole login, reduced to the one fact a probe leg asserts.
pub async fn login_and_read_id(server: SocketAddrV4, advertised_port: u16) -> ClientId {
    let mut sock = TcpStream::connect(server).await.unwrap();
    let login = LoginRequest::from_identity(
        &identity_with_port(advertised_port),
        &Capabilities::shipped(CryptStance::disabled()),
    );
    sock.write_all(&login.encode_packet().encode())
        .await
        .unwrap();

    let mut buf = Vec::new();
    loop {
        if let Ok((packet, consumed)) = Packet::decode(&buf) {
            buf.drain(..consumed);
            return IdChange::decode_packet(&packet)
                .expect("IdChange")
                .client_id;
        }
        let mut tmp = [0u8; 4096];
        let n = timeout(Duration::from_secs(2), sock.read(&mut tmp))
            .await
            .expect("IdChange within 2s")
            .expect("read ok");
        assert!(n > 0, "server closed before sending IdChange");
        buf.extend_from_slice(&tmp[..n]);
    }
}

// ---- ports -----------------------------------------------------------------
//
// The residual position: every caller here needs a *pre-known*
// port number, which is what still routes it through [`take_port`] instead of
// the cheaper, race-free alternative — bind `:0`, let the OS pick, and read
// the real port back from `local_addr()` (or, for a live core, from the
// `ServingStarted` event `serving_started` returns). That alternative is
// already how this binary gets a port everywhere the number itself does not
// matter (`direct_callback_route`'s `the_0x95_…` leg and every leg that binds
// its own Kad-UDP socket, for instance) — it is the default, and `take_port`
// is the fallback for the two shapes that cannot use it:
//
// - [`dead_port`] needs a number *nothing* is listening on, the opposite of
//   what a live `:0` bind gives you.
// - [`free_port`] needs the same number in two places at once inside one
//   command — `listen_addr` and the login identity's advertised
//   `tcp_port` (ADR-0040's advertise-what-you-bind invariant) — so it has to
//   be chosen before either is sent, not read back after a bind that has not
//   happened yet.
//
// Audited for oversubscription robustness: all nine call sites across the binary are one of those
// two shapes, so none converts.
//
// What is left is the gap `take_port` cannot close on its own: it proves a
// candidate is free *right now*, but the real bind (the test's own, for
// `free_port`; the peer that must find the port dead, for `dead_port`) lands
// later, and another copy of this binary can land in that gap. The
// pid-scattered offset (below) turns that from "every process contends on
// every allocation" (100% collision) into "two scattered walks
// cross paths by coincidence" — measured well under 1% per pair of
// concurrent copies. A machine-wide reservation (a lock file per taken port)
// would close the residual outright, but it leaks a stale reservation on a
// crash with nothing to clean it up, and the one tool that closes that gap —
// `flock`, held for the process's life — needs `unsafe`, which this workspace
// bans everywhere, tests included. Recorded rather than done: under 1% is a
// flake rate worth documenting, not worth an unsafe block for.

/// Login credentials whose TCP port is free: an operator connect binds the
/// listener on it (**Listen Before Login**, ADR-0086),
/// so a leg on the shared `identity()` port could answer a sibling leg's
/// server port check under the same user hash.
pub async fn connect_credentials() -> rmule_core::ClientCredentials {
    identity_with_port(free_port().await).into()
}

/// A port this leg will bind itself, and also has to name in the same breath
/// — the login identity a served port's advertised `tcp_port` must match
/// before either is sent (ADR-0040). See the module-level position above for
/// why this cannot be a `:0` bind read back afterward.
pub async fn free_port() -> u16 {
    take_port().await
}

/// A port nothing listens on, so a connect to it is refused — what an
/// unreachable advertised port or a dead peer endpoint is made of. See the
/// module-level position above for why this cannot be a live `:0` bind.
pub async fn dead_port() -> u16 {
    take_port().await
}

/// The band ports are taken from: one no kernel hands out for `bind(":0")`
/// (macOS starts its ephemeral range at 49152, Linux at 32768), so a port a
/// leg is about to bind — or is asserting nothing listens on — is invisible to
/// every `:0` bind the others make.
const PORT_BAND: std::ops::Range<u16> = 20_000..30_000;

/// Ports are never handed out twice in this process, and this process walks the
/// band from its own offset.
///
/// Both halves matter. All legs run in one
/// binary in parallel, so the cursor is what keeps a sibling leg off a port —
/// the probe bind below only proves the number is free *right now*, and the
/// gap between that proof and the leg's real bind is wide enough to lose. But
/// several copies of this binary also run at once — two worktrees, a CI job
/// beside a laptop — and a cursor that always started at the bottom of the band
/// made them walk it in lockstep, contending on *every* allocation: one copy
/// probed a port, the other probed and bound it first, and the loser's listener
/// failed to bind at all. Starting each process somewhere else in the band
/// makes two runs share a number only by coincidence rather than by
/// construction.
async fn take_port() -> u16 {
    loop {
        let candidate = next_band_port();
        if TcpListener::bind(("127.0.0.1", candidate)).await.is_ok() {
            return candidate;
        }
    }
}

/// The next number off this process's cursor through [`PORT_BAND`] — never
/// the same one twice until the band wraps. Shared by [`take_port`] and
/// [`reserve_dual_stack_port`], so neither hands a sibling leg the other's
/// port.
fn next_band_port() -> u16 {
    static CURSOR: std::sync::LazyLock<Mutex<u16>> =
        std::sync::LazyLock::new(|| Mutex::new(band_offset()));

    let mut cursor = CURSOR.lock().expect("port cursor is never poisoned");
    let candidate = *cursor;
    *cursor = if candidate + 1 >= PORT_BAND.end {
        PORT_BAND.start
    } else {
        candidate + 1
    };
    candidate
}

/// Where this process starts walking the band: its pid, scattered (pids are
/// handed out in sequence, so two runs started seconds apart would otherwise
/// land side by side).
fn band_offset() -> u16 {
    let span = u64::from(PORT_BAND.end - PORT_BAND.start);
    let scattered = u64::from(std::process::id()).wrapping_mul(2_654_435_761) % span;
    PORT_BAND.start + u16::try_from(scattered).expect("an offset inside the band")
}

/// A durable Shared File Registry on a fresh in-memory store — the shape a
/// front-end wires, on the engine's isolation backend instead of a file.
pub fn durable_shared_file_registry() -> DurableSharedFileRegistry {
    DurableSharedFileRegistry::new(rmule_testkit::memory_store())
}

// ---- a called-back source --------------------------------------------------

/// Play a called-back Low-ID source on `conn` — the connection it dialed to us
/// — for up to ten seconds: answer the requester's probes as the owner of
/// `file_bytes` under `file_name`, grant the slot, and stream every range
/// asked for. Returns when the requester hangs up or the ten seconds run out.
pub async fn serve_called_back(
    conn: &mut rmule_net::peer::Connection,
    file_name: &str,
    file_bytes: &[u8],
) {
    use rmule_peer::{PartBitmap, PeerCommand, PeerEvent};
    let _ = timeout(Duration::from_secs(10), async {
        while let Some(event) = conn.next_event().await {
            match event {
                PeerEvent::FileRequested { file_hash, .. } => {
                    conn.send(PeerCommand::AnswerFileName {
                        file_hash,
                        file_name: Ed2kText::from_utf8(file_name),
                    })
                    .await
                    .unwrap();
                }
                PeerEvent::FileBundleRequested {
                    file_hash, asks, ..
                } => {
                    for ask in asks {
                        let command = match ask {
                            rmule_peer::BundledAsk::Name { .. } => PeerCommand::AnswerFileName {
                                file_hash,
                                file_name: Ed2kText::from_utf8(file_name),
                            },
                            rmule_peer::BundledAsk::SetReqId => PeerCommand::AnswerFileStatus {
                                file_hash,
                                bitmap: PartBitmap::decode(
                                    rmule_primitives::part_count(file_bytes.len() as u64),
                                    &[0xFF],
                                )
                                .unwrap(),
                            },
                            _ => continue,
                        };
                        conn.send(command).await.unwrap();
                    }
                }
                PeerEvent::FileIdSet { file_hash } => {
                    let bitmap = PartBitmap::decode(
                        rmule_primitives::part_count(file_bytes.len() as u64),
                        &[0xFF],
                    )
                    .unwrap();
                    conn.send(PeerCommand::AnswerFileStatus { file_hash, bitmap })
                        .await
                        .unwrap();
                }
                PeerEvent::HashSetRequested { file_hash } => {
                    conn.send(PeerCommand::AnswerHashSet {
                        file_hash,
                        part_hashes: Vec::new(),
                    })
                    .await
                    .unwrap();
                }
                PeerEvent::SlotRequested { file_hash } => {
                    conn.send(PeerCommand::GrantSlot { file_hash })
                        .await
                        .unwrap();
                }
                PeerEvent::PartsRequested { file_hash, ranges } => {
                    for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
                        conn.send(PeerCommand::SendBlock {
                            file_hash,
                            start,
                            end,
                            bytes: file_bytes[start as usize..end as usize].to_vec(),
                        })
                        .await
                        .unwrap();
                    }
                }
                PeerEvent::Disconnected { .. } => break,
                _ => {}
            }
        }
    })
    .await;
}

/// A file of `size` bytes on disk: a row must name a readable file to be
/// offered (ADR-0106, "The registry against the disk").
pub fn sized_file(size: u64) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(size).unwrap();
    file
}
