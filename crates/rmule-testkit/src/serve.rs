//! Scenario wiring for real-counterparty tests: a serve runtime over a real
//! `PeerListener` (no eD2k login) and a spawned, sharing, serving core — the
//! happy-path half of the both-fakes policy (ADR-0040).

use std::net::{Ipv4Addr, SocketAddrV4};

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreError, DownloadFailure, PeerTransferService, PeerWorker,
    ServeCommand, ServeConnection, ServeInput, ServeOutput, ServeRuntimeService,
    SourceLookupOutcome, SourceLookupService,
};
use rmule_ed2k::OfferedFile;
use rmule_net::peer::{ConnectOptions, Connection, PeerListener};
use rmule_peer::{PeerEvent, PeerHandshakeContext};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kText, PeerEndpoint, PeerSource, SourceLookupTarget,
    UserHash,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};

/// A `SourceLookupService` for serve-only cores: pends forever.
#[derive(Clone)]
pub struct PendingSourceLookup;

impl SourceLookupService for PendingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        std::future::pending().await
    }
}

/// A `PeerTransferService` for serve-only cores: refuses every worker.
pub struct RefusingPeerTransfer;

impl PeerTransferService for RefusingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        _peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        Err(DownloadFailure::NoUsableSources)
    }
}

/// A `ClientIdentity` for tests: `seed` fills the user hash, `name` the nick.
pub fn test_identity(seed: u8, name: &str, tcp_port: u16) -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([seed; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8(name),
        tcp_port,
        60,
    )
}

/// A `PeerHandshakeContext` for tests, High-ID, no connected server.
pub fn test_handshake_ctx(seed: u8, name: &str) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: test_identity(seed, name, 4662),
        client_id: ClientId::from_u32(0x0100_007F),
        ed2k_client_id: ClientId::from_u32(0x0100_007F),
        public_ip: None,
        connected_server: None,
    }
}

/// A serve runtime that binds a real `PeerListener` (no eD2k login), so a
/// `ServeTask` drives real accepted connections. Announce is a no-op. The
/// oneshot from [`Self::new`] yields the bound address.
pub struct LoopbackServeRuntime {
    listener: Option<PeerListener>,
    ctx: PeerHandshakeContext,
    bound_tx: Option<oneshot::Sender<SocketAddrV4>>,
}

impl LoopbackServeRuntime {
    /// Build the runtime and the receiver that yields the listener's bound
    /// address. The port is picked by the kernel, so the address is only known
    /// once [`ServeRuntimeService::start`] has run — await the receiver before
    /// dialing.
    pub fn new(ctx: PeerHandshakeContext) -> (Self, oneshot::Receiver<SocketAddrV4>) {
        let (bound_tx, bound_rx) = oneshot::channel();
        (
            Self {
                listener: None,
                ctx,
                bound_tx: Some(bound_tx),
            },
            bound_rx,
        )
    }
}

impl ServeRuntimeService for LoopbackServeRuntime {
    async fn start(
        &mut self,
        // Loopback serving cores run without SUI; a test that needs an
        // SUI-capable counterparty drives the production runtime instead.
        _identity: rmule_primitives::ClientIdentity,
        listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        let listener = PeerListener::bind(listen_addr)
            .await
            .map_err(|e| CoreError::Repository(e.to_string()))?;
        let bound = SocketAddrV4::new(*listen_addr.ip(), listener.local_port());
        if let Some(tx) = self.bound_tx.take() {
            let _ = tx.send(bound);
        }
        self.listener = Some(listener);
        Ok(bound)
    }

    async fn accept(&mut self) -> Option<ServeConnection> {
        let listener = self.listener.as_ref()?;
        let conn = listener
            .accept(self.ctx.clone(), ConnectOptions::default())
            .await
            .ok()?;
        let peer = conn.peer_endpoint();
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (evt_tx, evt_rx) = mpsc::channel(16);
        tokio::spawn(bridge(conn, cmd_rx, evt_tx));
        Some(ServeConnection::new(peer, cmd_tx, evt_rx))
    }

    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<rmule_core::AnnounceOutcome, CoreError> {
        Ok(rmule_core::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }

    /// Drop the listener with the activity that held it, so a restarted serve
    /// over this runtime binds rather than meeting its own dead port.
    async fn release(&mut self) {
        self.listener = None;
    }
}

// Bridge one accepted connection to the serve task in the session's own
// vocabulary, as production does: `Server` requests and `Connection` facts up,
// `Server` commands down.
async fn bridge(
    mut conn: Connection,
    mut cmd_rx: mpsc::Receiver<ServeOutput>,
    evt_tx: mpsc::Sender<ServeInput>,
) {
    loop {
        tokio::select! {
            command = cmd_rx.recv() => {
                let Some(command) = command else { break };
                if conn.send(command.into()).await.is_err() {
                    break;
                }
            }
            event = conn.next_event() => {
                let input = match event {
                    None => ServeInput::closed_here(),
                    Some(PeerEvent::Server(request)) => ServeInput::Server(request),
                    Some(PeerEvent::Connection(fact)) => ServeInput::Connection(fact),
                    Some(PeerEvent::Requester(_) | PeerEvent::Side(_) | PeerEvent::Notice(_)) => {
                        continue;
                    }
                };
                let done = input.is_disconnect();
                let _ = evt_tx.send(input).await;
                if done {
                    break;
                }
            }
        }
    }
    let _ = conn.shutdown().await;
}

/// A real serving core counterparty: shares `bytes` from a temp file and
/// serves it over a real loopback listener through the production `ServeTask`
/// (via [`LoopbackServeRuntime`], which skips the eD2k login — a serving
/// counterparty needs no server session of its own).
pub struct ServingCore {
    core: Core,
    bound: SocketAddrV4,
    _dir: tempfile::TempDir,
}

impl ServingCore {
    /// Spawn a core that shares `bytes` (as `file_name`) and serves it.
    /// Returns once the file is shared and the listener is bound.
    pub async fn spawn(identity_seed: u8, file_name: &str, bytes: &[u8]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        tokio::fs::write(&path, bytes).await.unwrap();

        let ctx = test_handshake_ctx(identity_seed, "rmule-testkit-serving-core");
        let (runtime, bound_rx) = LoopbackServeRuntime::new(ctx.clone());
        let mut core = Core::builder(CoreConfig::default(), crate::memory_store())
            .settings(rmule_core::CoreSettings::default())
            .user_hash(ctx.identity.user_hash())
            .source_lookup(PendingSourceLookup)
            .peer_transfer(RefusingPeerTransfer)
            .serve_runtime(runtime)
            .build();
        let shared = crate::share_directory(&mut core, dir.path()).await;
        assert_eq!(shared.len(), 1, "serving core shared its one file");
        core.send(CoreCommand::Serve(ServeCommand::StartServing {
            listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        }))
        .await
        .unwrap();

        let bound = timeout(Duration::from_secs(5), bound_rx)
            .await
            .expect("serving core bound within 5s")
            .expect("bound sender not dropped");

        Self {
            core,
            bound,
            _dir: dir,
        }
    }

    /// The bound listener address peers dial.
    pub fn bound(&self) -> SocketAddrV4 {
        self.bound
    }

    /// This serving core as a High-ID `PeerSource`.
    pub fn source(&self) -> PeerSource {
        PeerSource::new(
            ClientId::from_u32(u32::from_le_bytes(self.bound.ip().octets())),
            self.bound.port(),
        )
    }

    /// Keep the core (and its serve task) alive for the scenario's lifetime;
    /// drop to shut down. Exposed for event-draining if a test needs it.
    pub fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}
