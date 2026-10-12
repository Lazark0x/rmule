//! `rmule-tools natt server-punch` — the NAT-T `natt-server-punch-*` driver
//! (ADR-0091's second Rendezvous coordinator): log a real `Core` in to an
//! eD2k server from behind a **NAT Gateway**, and ask that server to introduce
//! it to another Low-ID peer.
//!
//! Both ends of this exchange are rmule, so every row it writes is
//! **`rmule-only`** (ADR-0045's 2026-09-16 amendment): the *server's* `0x60`
//! and `0x61` are counterparty bytes and the punch and the Tunnel between the
//! two peers are not. What the driver reports is therefore scored *exercised*,
//! against a proven NAT — never *captured*.
//!
//! # Why the driver is a whole `Core`
//!
//! The `0xF9` login tag, the 60 s `0x9F` keepalive, the `0x60` request and the
//! `0x61` that arms the front are one another's preconditions — the server
//! refuses to introduce a client that sent no `0xF9`, and the keepalive is what
//! keeps the observed port fresh for 600 s. A driver that framed those by hand
//! would be proving its own framing. So the leg runs the shipped orchestration
//! and drives it through `CoreCommand::ReachPeer`, the same command an operator
//! sends.
//!
//! # The two-phase rendezvous with the harness
//!
//! Each peer's Low ID is assigned by the server at login, so neither peer can
//! be told the other's id before both have one. The driver therefore
//! **publishes** its own identity the moment its session reads `Connected`, and
//! then waits for the harness to drop a **target file** naming the other
//! peer's id and user hash. That file is a **Readiness Gate**, not a sleep: the
//! run ends with a documented absence if it never appears.
//!
//! `Connected` is what the driver waits on, never `ServingStarted`: serving is
//! a bind and the login is its own fact, so a driver gated on the bind could
//! send `0x60` before the session that must carry it exists.

mod prediction;

use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::run_log::Level;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, NattConfig, OwnMapping, PeerReach,
    ServeCommand as CoreServeCommand, open_durable_store_in_memory,
};
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, ServerEndpoint, UserHash};

use crate::driver_row::Row;
use crate::operand::parse_user_hash;

/// How often the driver looks for the harness's target file. The gate is a
/// poll because the file is written by another process on a shared mount and
/// there is no event to wait on; the deadline is what bounds it.
const TARGET_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Args)]
pub(crate) struct NattServerPunchArgs {
    /// The eD2k server to log in to, `host:port`.
    #[arg(long)]
    server: String,
    /// The serve listener. Behind a NAT gateway that forwards no TCP this is
    /// what earns the Low ID the whole row depends on.
    #[arg(long, default_value = "0.0.0.0:4662")]
    listen: SocketAddrV4,
    /// The one UDP bind — Kad, client-UDP and NAT-T share it (ADR-0057). The
    /// `0x9F` keepalive leaves it and the punch lands on it, so it is pinned
    /// rather than ephemeral: the gateway's mapping is what the server
    /// observes.
    #[arg(long, default_value_t = 4672)]
    udp_port: u16,
    /// A file to share, so the serve activity has one. The punch needs no
    /// transfer; the share is what makes the node a credentialed serving node,
    /// which is when its identity is published.
    #[arg(long)]
    share: PathBuf,
    /// Our nickname.
    #[arg(long, default_value = "rmule-natt")]
    nickname: String,
    /// Our user hash as hex (32 chars) — the key the other peer's `0x61`
    /// introduction and the front's ledger both name us by.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Where to publish our own identity for the harness to read once the
    /// session is up.
    #[arg(long)]
    identity_out: PathBuf,
    /// The file the harness writes naming the *other* peer: `id=<u32>` and
    /// `user_hash=<hex>`, one per line.
    #[arg(long)]
    target_file: PathBuf,
    /// Seconds to wait for the login before giving up.
    #[arg(long, default_value_t = 60)]
    login_timeout: u64,
    /// Seconds to wait for the target file.
    #[arg(long, default_value_t = 120)]
    target_timeout: u64,
    /// Seconds to run after the reach command — the window a punch, a dial and
    /// a Tunnel have to happen in.
    #[arg(long, default_value_t = 60)]
    window: u64,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
    /// Port prediction: the knob, the Kad observers that tell the node
    /// its own mapping, and the gate that waits for them.
    #[command(flatten)]
    prediction: prediction::PredictionArgs,
}

/// What the run measured about rmule's own NAT-T surface.
#[derive(Debug, Default)]
struct PunchRow {
    client_id: u32,
    low_id: bool,
    connected: bool,
    login_failure: String,
    target_seen: bool,
    target_id: u32,
    routed: String,
    punches: u64,
    server_requests_emitted: u64,
    refusals: u64,
    last_refusal: String,
    dials: u64,
    last_attempt_dials: String,
    tunnels_dialed: u64,
    tunnels_accepted: u64,
    last_transport: String,
    unexpected_holepunches: u64,
    kad_enabled: bool,
    /// The **Own Mapping** the publish gate read, before the `0x60` went out —
    /// the reading the port-prediction claim scores.
    own_mapping: Option<OwnMapping>,
    /// The Own Mapping the end-of-window snapshot read, kept beside the gate's
    /// reading rather than over it.
    own_mapping_final: Option<OwnMapping>,
    prediction_attempts: u64,
    prediction_probes: u64,
    prediction_hits: u64,
    /// Whether the end-of-window diagnostics snapshot arrived. Every counter
    /// above that only it fills is written `-1` when it did not: a zero there
    /// would be a count nobody took.
    snapshot_read: bool,
}

/// Log in, be introduced, and record what the node's own NAT-T surface did.
///
/// # Errors
/// If an operand will not parse or the core cannot be started. A server that
/// refuses to introduce, or a punch that never lands, is a **row** — that is
/// the measurement the negative flows exist to take.
pub(crate) async fn run_server_punch(args: NattServerPunchArgs) -> Result<()> {
    args.prediction.validate()?;
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let our_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let kad_id = prediction::kad_id(&args.prediction)?;

    let builder = Core::builder(
        CoreConfig {
            natt: NattConfig {
                port_prediction: args.prediction.port_prediction.into(),
            },
            ..CoreConfig::default()
        },
        open_durable_store_in_memory()?,
    )
    .settings(rmule_core::CoreSettings {
        nickname: args.nickname.clone(),
        tcp_port: args.listen.port(),
        udp_port: args.udp_port,
        ..rmule_core::CoreSettings::default()
    })
    .user_hash(our_hash);
    let mut core = match kad_id {
        Some(kad_id) => builder.kad_id(kad_id),
        None => builder,
    }
    .build();
    let _share =
        crate::share::share_files(&mut core, std::slice::from_ref(&args.share), |_| {}).await?;
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    crate::node::connect(&core, &server).await?;

    let mut row = PunchRow {
        // Kad starts beside the login rather than after it, so the Extern
        // Port Round is already counting observers while the server answers.
        kad_enabled: prediction::enable_kad(&mut core, &args.prediction).await?,
        ..PunchRow::default()
    };
    // The login is its own fact: `ServingStarted` is a bind, and a `0x60` needs
    // the session the bind does not imply.
    match await_login(&mut core, Duration::from_secs(args.login_timeout)).await? {
        Login::Connected(id) => {
            row.connected = true;
            row.client_id = id.as_u32();
            row.low_id = !id.is_high_id();
        }
        Login::Failed(reason) => {
            row.login_failure = reason;
            return write(&args.out, &row);
        }
    }
    if row.kad_enabled {
        row.own_mapping = Some(prediction::await_own_mapping(&mut core, &args.prediction).await?);
        println!(
            "rmule-natt-own-mapping {}",
            prediction::mapping_name(row.own_mapping.unwrap_or(OwnMapping::Unknown))
        );
    }
    publish_identity(&args.identity_out, row.client_id, &args.user_hash)?;
    println!(
        "rmule-natt-punch-ready id={} low_id={} hash={}",
        row.client_id, row.low_id, args.user_hash
    );

    // The responder is told nothing — that is what makes the single `0x60` on
    // the server's tap attributable to the requester. It still runs its window
    // and still reports its own counters, because *accepting* a tunnel is its
    // half of the row and a driver that exited here would report that half as a
    // zero nobody measured.
    match await_target(
        &mut core,
        &args.target_file,
        Duration::from_secs(args.target_timeout),
    )
    .await?
    {
        Some(target) => {
            row.target_seen = true;
            row.target_id = target.id;
            core.send(CoreCommand::ReachPeer(reach(&target))).await?;
            println!("rmule-natt-punch-reach id={}", target.id);
        }
        None => {
            row.routed = "no-target-file (responder)".to_owned();
            println!("rmule-natt-punch-responder: no target named, holding the window open");
        }
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.window);
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            event = core.next_event() => event,
        };
        let Some(event) = event else { break };
        println!("{}", event.record().render(Level::Full));
        if let CoreEvent::PeerReachRouted { route, .. } = &event {
            row.routed = crate::natt::route_code(route).to_owned();
        }
    }

    // The diagnostics snapshot is rmule's own account of its NAT-T surface —
    // `rmule-only`, scored exercised rather than captured. The counterparty
    // bytes this row is read beside are the *server's* `0x60`/`0x61`, counted
    // off the flow's tap.
    core.send(CoreCommand::DumpDiagnostics).await?;
    if let Some(snapshot) = await_snapshot(&mut core, Duration::from_secs(10)).await? {
        row.snapshot_read = true;
        row.punches = snapshot.session.natt_server_punches_total;
        row.server_requests_emitted = snapshot.session.natt_server_requests_emitted_total;
        row.refusals = snapshot.session.natt_server_refusals_total;
        row.last_refusal = snapshot
            .session
            .natt_server_last_refusal
            .map(|reason| format!("{reason:?}"))
            .unwrap_or_default();
        row.dials = snapshot.session.natt_dials_total;
        row.last_attempt_dials = snapshot
            .session
            .natt_last_attempt_dials
            .map(|dials| dials.to_string())
            .unwrap_or_default();
        row.tunnels_dialed = snapshot.session.natt_tunnels_dialed_total;
        row.tunnels_accepted = snapshot.session.natt_tunnels_accepted_total;
        row.last_transport = snapshot
            .session
            .natt_last_tunnel_transport
            .map(|transport| format!("{transport:?}"))
            .unwrap_or_default();
        row.unexpected_holepunches = snapshot.session.natt_unexpected_holepunches_total;
        row.prediction_attempts = snapshot.session.natt_prediction_attempts_total;
        row.prediction_probes = snapshot.session.natt_prediction_probes_total;
        row.prediction_hits = snapshot.session.natt_prediction_hits_total;
        row.own_mapping_final = snapshot.natt_own_mapping;
    }
    write(&args.out, &row)
}

/// The other peer, as the harness named it.
struct Target {
    id: u32,
    user_hash: UserHash,
}

/// How the login came out.
enum Login {
    Connected(ClientId),
    Failed(String),
}

/// The `PeerReach` the server coordinator's rung needs: a Low-ID peer on our
/// own server, named by the hash a `0x61` and the front's ledger both key on.
///
/// No address is fabricated. A Low-ID candidate has none, so `tcp` carries the
/// unspecified address with the peer's port — the selector reads `tcp` only for
/// a High-ID direct dial, and a made-up address would sit where a diagnostic
/// reads a peer (ADR-0091).
fn reach(target: &Target) -> PeerReach {
    PeerReach {
        id: ClientId::from_u32(target.id),
        tcp: PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0)),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: true,
        buddy: None,
        ipv6: None,
        // What the server coordinator does NOT need: a harness run settled that the
        // server holds the target's own `0xF9` and answers `TargetNoUdp` when
        // it has none, so this flag is left false and the route is still the
        // server's.
        supports_natt: false,
        user_hash: Some(target.user_hash),
    }
}

/// Wait for the session's own `Connected`, or the failure that ends the run.
async fn await_login(core: &mut Core, budget: Duration) -> Result<Login> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                return Ok(Login::Failed(format!("no session within {budget:?}")));
            }
            event = core.next_event() => event,
        };
        let Some(event) = event else {
            return Ok(Login::Failed("the core event stream ended".to_owned()));
        };
        println!("{}", event.record().render(Level::Full));
        match event {
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Connected {
                client_id,
                ..
            }) => return Ok(Login::Connected(client_id)),
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::ConnectFailed {
                reason,
                ..
            }) => return Ok(Login::Failed(format!("{reason:?}"))),
            _ => {}
        }
    }
}

/// Poll for the harness's target file while keeping the core's events drained —
/// a core whose event channel fills stalls the session the `0x9F` keepalive
/// rides.
async fn await_target(core: &mut Core, path: &Path, budget: Duration) -> Result<Option<Target>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(target) = read_target(path)? {
            return Ok(Some(target));
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            () = tokio::time::sleep(TARGET_POLL) => {}
            event = core.next_event() => {
                let Some(event) = event else { return Ok(None) };
                println!("{}", event.record().render(Level::Full));
            }
        }
    }
}

/// Read a target file, or `None` while it is absent. A half-written file reads
/// as absent rather than as a malformed target: the harness writes it in one
/// `write`, and anything short of both fields is a file still arriving.
fn read_target(path: &Path) -> Result<Option<Target>> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
            .map(str::trim)
    };
    let (Some(id), Some(hash)) = (field("id"), field("user_hash")) else {
        return Ok(None);
    };
    let id: u32 = id
        .parse()
        .with_context(|| format!("parse target id {id}"))?;
    Ok(Some(Target {
        id,
        user_hash: UserHash::from_bytes(parse_user_hash(hash)?),
    }))
}

/// Ask for and read back one diagnostics snapshot.
async fn await_snapshot(
    core: &mut Core,
    budget: Duration,
) -> Result<Option<rmule_core::diagnostics::DiagnosticsSnapshot>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            event = core.next_event() => event,
        };
        let Some(event) = event else { return Ok(None) };
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            return Ok(Some(snapshot));
        }
    }
}

/// Publish our own identity for the harness, in the same `key=value` shape the
/// target file uses.
fn publish_identity(path: &Path, id: u32, user_hash: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, format!("id={id}\nuser_hash={user_hash}\n"))
        .with_context(|| format!("write {}", path.display()))
}

fn write(path: &Path, row: &PunchRow) -> Result<()> {
    crate::driver_row::write_row(path, render(row))
}

/// The row as the harness reads it.
fn render(row: &PunchRow) -> Row {
    println!(
        "natt-server-punch connected={} low_id={} routed={} punches={} dials={} tunnels={}/{}",
        row.connected,
        row.low_id,
        row.routed,
        row.punches,
        row.dials,
        row.tunnels_dialed,
        row.tunnels_accepted
    );
    let mut out = Row::new(
        "rmule-tools natt server-punch — one rmule peer being introduced to another\n\
         by an eD2k server (ADR-0091's second coordinator). Every value here is rmule's\n\
         own account and is scored `rmule-only`: the counterparty bytes this row is read\n\
         beside are the SERVER's 0x60/0x61, counted off the flow's tap.",
    );
    // A counter only the snapshot fills, or `-1` when no snapshot arrived.
    let counted = |value: u64| if row.snapshot_read { as_i64(value) } else { -1 };
    out.bool("connected", row.connected)
        .int("client_id", i64::from(row.client_id))
        .bool("low_id", row.low_id)
        .str("login_failure", &row.login_failure)
        .bool("target_seen", row.target_seen)
        .int("target_id", i64::from(row.target_id))
        .str("routed", &row.routed)
        .bool("snapshot_read", row.snapshot_read)
        .int("server_punches", counted(row.punches))
        .int(
            "server_requests_emitted",
            counted(row.server_requests_emitted),
        )
        .int("server_refusals", counted(row.refusals))
        .str("last_refusal", &row.last_refusal)
        .int("dials", counted(row.dials))
        .str("last_attempt_dials", &row.last_attempt_dials)
        .int("tunnels_dialed", counted(row.tunnels_dialed))
        .int("tunnels_accepted", counted(row.tunnels_accepted))
        .str("last_tunnel_transport", &row.last_transport)
        .int(
            "unexpected_holepunches",
            counted(row.unexpected_holepunches),
        )
        .bool("kad_enabled", row.kad_enabled)
        .str(
            "own_mapping",
            row.own_mapping.map_or("", prediction::mapping_name),
        )
        .str(
            "own_mapping_final",
            row.own_mapping_final.map_or("", prediction::mapping_name),
        )
        .int("prediction_attempts", counted(row.prediction_attempts))
        .int("prediction_probes", counted(row.prediction_probes))
        .int("prediction_hits", counted(row.prediction_hits));
    out
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{PunchRow, render};

    /// A missed end-of-window snapshot used to leave every counter at its
    /// default `0`, which the harness read as a measured zero feeding the
    /// symmetric negatives. They are `-1` now, beside `snapshot_read = false`.
    #[test]
    fn a_missed_snapshot_writes_no_measured_zero() {
        let text = render(&PunchRow::default()).finish();
        assert!(text.contains("snapshot_read = false"), "{text}");
        for key in [
            "tunnels_dialed",
            "tunnels_accepted",
            "dials",
            "server_punches",
        ] {
            assert!(text.contains(&format!("{key} = -1")), "{key}: {text}");
        }
        let read = PunchRow {
            snapshot_read: true,
            ..PunchRow::default()
        };
        assert!(render(&read).finish().contains("tunnels_dialed = 0"));
    }

    /// The gate's Own Mapping and the final snapshot's are two fields: the
    /// final one no longer overwrites the reading the publish was gated on.
    #[test]
    fn the_gate_reading_survives_the_final_snapshot() {
        use rmule_core::OwnMapping;
        let row = PunchRow {
            own_mapping: Some(OwnMapping::Unknown),
            own_mapping_final: Some(OwnMapping::EndpointDependent),
            snapshot_read: true,
            ..PunchRow::default()
        };
        let text = render(&row).finish();
        assert!(text.contains("own_mapping = \"unknown\""), "{text}");
        assert!(
            text.contains("own_mapping_final = \"endpoint-dependent\""),
            "{text}"
        );
    }
}
