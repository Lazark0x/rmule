//! The **HTTP-bootstrap cold-start** runner (ADR-0065 + ADR-0067): the
//! production caller of the core Join Sequence. One process that fetches
//! `nodes.dat` over HTTP, then drives [`run_join_sequence`] against a live
//! [`Core`] — the sequencer performs the first-run `server.met` fetch through
//! the injected [`ReqwestFetcher`], persists the acquired list, and dispatches
//! the **defaults-ON parallel joins** (`AddServer` per row + `EnableKad`)
//! exactly as amuled's `ConnectToED2K` / `ConnectToKad` posture does. This is
//! what makes flow H executable end to end *through the shipped
//! policy path* rather than a hand-rolled orchestration beside it.
//!
//! Deterministic doctrine (ADR-0045): the bootstrap pipelines
//! ([`fetch_nodes_dat`] and the sequencer-internal `fetch_server_met`) and the
//! core Join Sequence stay sans-I/O / injected-seam; this composition root
//! wires the real tokio runtime, the [`ReqwestFetcher`] (the bootstrap crate's
//! only I/O corner — rustls, redirect/size/timeout caps), and the live `Core`
//! (whose Kad runtime owns the real UDP socket and walks the ADR-0067
//! Bootstrap Dial List). That is the exact "pipelines stay pure, wire real
//! time/IO at the edge" split the other `rmule-tools` live commands use.
//!
//! Stages, each asserted (a failure bails with the stage that broke):
//!
//! 1. **nodes.dat fetch** — bounded GET → try-normal-then-v3-fallback dispatch
//!    → contacts (a v1/v2 file) or bootstrap-dial candidates (a v3 file), both
//!    becoming the front-end-supplied Kad seeds (`KadEnableConfig::bootstrap`).
//!    The seed acquisition stays runner-side by design: ADR-0067's deliberate
//!    asymmetry gives the Join Sequence a `server.met` first-run hook only.
//! 2. **Join Sequence** — [`run_join_sequence`] on a fresh
//!    [`DurableAppConfig`] on the engine's in-memory backend (a genuine cold
//!    start by construction): the
//!    first-run hook fetches `server.met` over live HTTP, persists the
//!    reconciled endpoints, and dispatches both joins into the live `Core`.
//! 3. **eD2k verification** — dial the join outcome's acquired server and
//!    observe `LoginAccepted` (the counterparty accepting the login the
//!    sequence made possible).
//! 4. **Kad verification** — poll the core's diagnostics barrier until the Kad
//!    runtime reports aMule's `HasHadContact` (`kad.contact_responded`): the
//!    node dialed the fetched seeds off the ADR-0067 dial list and a
//!    counterparty datagram came back.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_bootstrap::{BootstrapConfig, NodesDatInstall, ReqwestFetcher, fetch_nodes_dat};
use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreConfig, CoreEvent, DurableAppConfig, FirstRunFetch,
    JoinConfig, KadEnableConfig, KadId, open_durable_store_in_memory, run_join_sequence,
};
use rmule_ed2k::Ed2kEvent;
use rmule_kad::BootstrapDialList;
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{ClientIdentity, Ed2kText, ServerEndpoint, UserHash};

use crate::operand::parse_user_hash;

/// How often the runner re-polls the diagnostics barrier for the Kad
/// `HasHadContact` fact while the node walks the ADR-0067 dial list.
const CONTACT_POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Args)]
pub(crate) struct BootstrapFetchArgs {
    /// HTTP(S) URL of the `server.met` the Join Sequence's first-run hook
    /// fetches (rmule's `server.met` decoder parses it).
    #[arg(long)]
    server_met_url: String,
    /// HTTP(S) URL of the `nodes.dat` to fetch (rmule's `nodes.dat` readers parse it).
    #[arg(long)]
    nodes_dat_url: String,
    /// The one UDP bind — Kad, client-UDP and NAT-T share it (ADR-0057).
    /// Only the port is read (`0` binds ephemeral); the address has nowhere
    /// to go, since the unified socket takes no literal-address bind.
    #[arg(long, default_value = "0.0.0.0:0")]
    kad_bind: String,
    /// rmule's Kad node ID as 32 hex chars.
    #[arg(long, default_value = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")]
    kad_id: String,
    /// Local user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local eD2k TCP port advertised in the login / Kad headers.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// CT_VERSION value.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Local nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// Output directory for the server capture tap and the run summary.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Server login timeout, seconds.
    #[arg(long, default_value_t = 15)]
    login_timeout: u64,
    /// Max seconds to wait for the Kad node to reach contact via the fetched
    /// nodes before failing the run.
    #[arg(long, default_value_t = 60)]
    max_seconds: u64,
    /// Suppress the eD2k half of the join (`JoinConfig { connect_ed2k: false }`,
    /// the ADR-0067 per-network front-end override). Per the sequencer's own
    /// gating this also skips the first-run `server.met` fetch — no point
    /// acquiring servers a disabled eD2k side will never reach — so the run
    /// exercises the nodes.dat leg against a Kad-only bench.
    #[arg(long)]
    skip_ed2k: bool,
}

pub(crate) async fn run(args: BootstrapFetchArgs) -> Result<()> {
    let user_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let kad_id = KadId::from_bytes(parse_user_hash(&args.kad_id)?);
    let kad_bind: SocketAddr = args
        .kad_bind
        .parse()
        .with_context(|| format!("parse --kad-bind {}", args.kad_bind))?;
    let SocketAddr::V4(kad_bind) = kad_bind else {
        bail!("--kad-bind must be an IPv4 address, got {kad_bind}");
    };
    if let Some(dir) = &args.out {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    // The one reqwest seam (ADR-0065 hardening caps) serves both the runner's
    // nodes.dat fetch and the sequencer's injected first-run server.met fetch.
    let config = BootstrapConfig {
        server_met_url: args.server_met_url.clone(),
        ..BootstrapConfig::default()
    };
    let fetcher = ReqwestFetcher::from_config(&config)
        .map_err(|error| anyhow::anyhow!("build reqwest bootstrap fetcher: {error}"))?;

    // Stage 1: nodes.dat fetch. The parsed contacts/candidates become the
    // front-end-supplied Kad bootstrap seeds.
    let mut dial_list = BootstrapDialList::new();
    let nodes_install = fetch_nodes_dat(
        &fetcher,
        &args.nodes_dat_url,
        config.max_nodes_dat_bytes,
        kad_id,
        &mut dial_list,
    )
    .await
    .with_context(|| format!("fetch nodes.dat from {}", args.nodes_dat_url))?;
    let seeds = kad_seeds(&nodes_install);
    if seeds.is_empty() {
        bail!(
            "fetched nodes.dat yielded no dialable Kad contact — flow H needs the golden to carry \
             at least one contact/candidate"
        );
    }
    println!(
        "bootstrap-fetch nodes_dat url={} kind={} dialable={}",
        args.nodes_dat_url,
        nodes_install_kind(&nodes_install),
        seeds.len()
    );

    // Stage 2: the ADR-0067 Join Sequence against a live Core. A fresh
    // in-memory store makes every run a genuine cold start; the sequencer's
    // first-run hook therefore fetches server.met, persists it, and dispatches
    // the defaults-ON parallel joins (eD2k list + EnableKad with the fetched
    // seeds, which the node's s2 dial loop walks).
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let kad_enable = KadEnableConfig {
        kad_id,
        peer_credentials: identity.clone().into(),
        bootstrap: seeds.clone(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_udp_key: DurableAppConfig::new(open_durable_store_in_memory()?).ensure_kad_udp_key()?,
        kad_capture_dir: None,
        kad_shutdown: None,
    };
    let store = DurableAppConfig::new(open_durable_store_in_memory()?);
    let join = JoinConfig {
        connect_ed2k: !args.skip_ed2k,
        ..JoinConfig::default()
    };
    let mut core = Core::builder(
        CoreConfig {
            // The one UDP bind — Kad, client-UDP and NAT-T share it
            // (ADR-0057); `--kad-bind`'s IP has nowhere to go (no literal-address
            // bind on the unified socket), only its port does, as
            // `kad_handoff.rs` already wires it.
            udp_port: kad_bind.port(),
            ..CoreConfig::default()
        },
        open_durable_store_in_memory()?,
    )
    .user_hash(user_hash)
    .build();
    let outcome = run_join_sequence(&store, &fetcher, &config, &join, kad_enable, &core)
        .await
        .map_err(|error| anyhow::anyhow!("run the core join sequence: {error}"))?;
    let first_run = match &outcome.first_run {
        FirstRunFetch::Installed { added } => format!("installed added={added}"),
        FirstRunFetch::Skipped => "skipped".to_owned(),
        FirstRunFetch::Failed(error) => format!("failed error={error}"),
    };
    println!(
        "bootstrap-fetch join_sequence first_run={first_run} servers={} kad_seed={:?}",
        outcome.servers.len(),
        outcome.kad_seed
    );

    // Stage 3: eD2k verification — the acquired server accepts our login.
    let server_endpoint = if join.connect_ed2k {
        let Some(server) = outcome.servers.first() else {
            bail!(
                "join sequence acquired no usable server endpoint \
                 (first_run={first_run}); flow H needs the golden to name at least one server"
            );
        };
        connect_and_login(&args, server, &identity).await?;
        Some(server.clone())
    } else {
        println!("bootstrap-fetch ed2k_skipped (--skip-ed2k)");
        None
    };

    // Stage 4: Kad verification — the node reaches contact off the fetched
    // seeds (aMule's `HasHadContact`, surfaced through the diagnostics
    // barrier; only a received counterparty datagram can flip it).
    let joined = wait_for_kad_contact(&mut core, Duration::from_secs(args.max_seconds)).await?;
    core.shutdown().await;

    if let Some(dir) = &args.out {
        let server_line = server_endpoint.map_or_else(
            || "server_endpoint = skipped\n".to_owned(),
            |server| format!("server_endpoint = {}:{}\n", server.host(), server.port()),
        );
        let report = format!(
            "server_met_url = {}\njoin_first_run = {first_run}\n{server_line}nodes_dat_url = {}\n\
             dialable_contacts = {}\nkad_joined = {joined}\n",
            args.server_met_url,
            args.nodes_dat_url,
            seeds.len(),
        );
        let path = dir.join("bootstrap-fetch-summary.txt");
        std::fs::write(&path, report).with_context(|| format!("write {}", path.display()))?;
    }

    if joined {
        println!("bootstrap-fetch result=joined joined=true");
        Ok(())
    } else {
        bail!(
            "kad node did not reach contact within {} s after seeding the fetched contacts (no \
             HasHadContact)",
            args.max_seconds
        );
    }
}

/// The fetched nodes.dat as ADR-0067 bootstrap-dial seeds: a normal-reader
/// (v1/v2) file's contacts, or a v3 file's bootstrap-dial candidates — both
/// enter the node's one Bootstrap Dial List through
/// [`KadEnableConfig::bootstrap`], exactly where a file-loaded candidate would.
fn kad_seeds(install: &NodesDatInstall) -> Vec<SocketAddrV4> {
    let endpoints: Vec<_> = match install {
        NodesDatInstall::Contacts(contacts) => {
            contacts.iter().map(|contact| contact.endpoint()).collect()
        }
        NodesDatInstall::BootstrapCandidates(candidates) => {
            candidates.iter().map(|node| node.endpoint()).collect()
        }
    };
    endpoints
        .into_iter()
        .map(|endpoint| SocketAddrV4::new(endpoint.ip(), endpoint.udp_port()))
        .collect()
}

const fn nodes_install_kind(install: &NodesDatInstall) -> &'static str {
    match install {
        NodesDatInstall::Contacts(_) => "contacts",
        NodesDatInstall::BootstrapCandidates(_) => "v3-bootstrap-candidates",
    }
}

/// Dial the acquired server and drive its session until `LoginAccepted`.
async fn connect_and_login(
    args: &BootstrapFetchArgs,
    server: &ServerEndpoint,
    identity: &ClientIdentity,
) -> Result<()> {
    let options = ConnectOptions {
        capture_dir: args.out.as_ref().map(|dir| dir.join("server")),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        login_timeout: Duration::from_secs(args.login_timeout),
        obfuscation: None,
        advertised_ipv6: None,
        udp_ports: None,
    };
    let mut server_conn =
        Connection::connect_with_options(server.clone(), identity.clone(), options)
            .await
            .with_context(|| format!("dial acquired server {}:{}", server.host(), server.port()))?;
    while let Some(event) = server_conn.next_event().await {
        match event {
            Ed2kEvent::LoginAccepted { client_id, .. } => {
                println!(
                    "bootstrap-fetch server_login server={}:{} client_id={}",
                    server.host(),
                    server.port(),
                    client_id.as_u32()
                );
                let _ = server_conn.shutdown().await;
                return Ok(());
            }
            Ed2kEvent::Disconnected { reason } => {
                bail!("acquired server session ended before LoginAccepted: {reason:?}");
            }
            _ => {}
        }
    }
    bail!("acquired server session ended before LoginAccepted")
}

/// Poll the core's diagnostics barrier until the Kad runtime reports aMule's
/// `HasHadContact` (`kad.contact_responded`). Returns `true` on contact,
/// `false` on the deadline. A rejected join command fails the run — a dead Kad
/// start would otherwise poll to the deadline for a node that never bound.
async fn wait_for_kad_contact(core: &mut Core, window: Duration) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        core.send(CoreCommand::DumpDiagnostics)
            .await
            .context("ask the core for a diagnostics snapshot")?;
        // Drain to the snapshot barrier: the core answers FIFO, so a rejection
        // of the join necessarily precedes it.
        loop {
            let event = tokio::select! {
                () = tokio::time::sleep_until(deadline) => return Ok(false),
                event = core.next_event() => event,
            };
            match event {
                Some(CoreEvent::DiagnosticsSnapshot { snapshot }) => {
                    let contact = snapshot.kad.is_some_and(|kad| kad.contact_responded);
                    println!("bootstrap-fetch kad_contact_responded={contact}");
                    if contact {
                        return Ok(true);
                    }
                    break;
                }
                Some(CoreEvent::CommandRejected { reason }) => {
                    bail!("core rejected a join command: {reason:?}");
                }
                Some(event) => println!("bootstrap-fetch core_event={event}"),
                None => bail!("core event stream ended before the Kad join settled"),
            }
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(false),
            () = tokio::time::sleep(CONTACT_POLL) => {}
        }
    }
}
