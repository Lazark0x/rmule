//! `rmule-tools natt tunnel-transfer` — the NAT-T `natt-tunnel-transfer`
//! driver (ADR-0092): **a file crosses a punched path**, behind cone NATs, with
//! an eD2k server as the only coordinator.
//!
//! This is the rung ADR-0091 exists for, end to end. Two Low-ID rmule nodes,
//! neither dialable; one of them wants a file the other shares; rung 1 of the
//! ADR-0061 tree used to drop the pair outright. Now the download arms a 12 s
//! `CALLBACK_SILENCE_FALLBACK` beside the callback it asked for, the reach arm
//! picks the **server coordinator**, the `0x61` introduction arms both fronts,
//! both burst, the requester dials, a uTP **Tunnel** rises, the download
//! *claims* it by the target's User Hash, and the part bytes ride it.
//!
//! # Why the source record is an operand
//!
//! The one fact rung 1 needs about a Low-ID candidate — its **User Hash** — has
//! exactly two live channels (ADR-0091's reading): the obfuscation-aware
//! `OP_FOUNDSOURCES_OBFU` (`0x44`) and a source-exchange answer of version ≥ 2.
//! **No eD2k server this repo can pin emits either** (the project's parity verdict
//! found that "no crypt-capable eD2k server exists to serve them"), and a source-exchange
//! answer needs a third node already downloading. Without the hash the fallback
//! still fires and a Tunnel still rises — it is simply *unclaimable*, so it goes
//! down the serve road and no download adopts it.
//!
//! So the harness supplies the record its server cannot, through the shipped
//! [`SourceLookupService`] seam: one Low-ID [`SourceSighting`] carrying the
//! target's id and hash. That is **Stimulus** of the same standing as
//! `ed2k serve start --direct-callback` (it *declares* two facts a source row
//! would otherwise carry, and nothing else), it is declared in the row as
//! `source_injected`, and everything downstream of it — the candidate record,
//! both deadlines, the selector, the punch, the Tunnel, the claim, the hello
//! that confirms it, the slot and the part transfer — is the shipped path.
//! Both ends are rmule, so the whole row is **`rmule-only`** and is scored
//! *exercised* against a proven NAT, never captured.

use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use rmule_core::run_log::Level;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, DownloadEvent, DownloadFailure,
    ServeCommand as CoreServeCommand, SourceLookupOutcome, SourceLookupService,
    open_durable_store_in_memory,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kLink, Ed2kText, PeerSource, ServerEndpoint, SourceLookupTarget,
    SourceSighting, UserHash,
};

use crate::driver_row::Row;
use crate::operand::parse_user_hash;

/// How often the driver looks for the harness's source file — the same poll
/// the punch driver's target gate uses, and for the same reason: the file is
/// written by another process on a shared mount and there is no event to wait
/// on.
const SOURCE_POLL: Duration = Duration::from_millis(500);

/// Which half of the transfer this process is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum TransferRole {
    /// Shares the file and waits to be punched. It asks for nothing, which is
    /// what makes every `0x60` on the server's tap the requester's.
    Target,
    /// Downloads the file. The rendezvous requester, so it dials (ADR-0091's
    /// rule: the side that asked dials).
    Requester,
}

#[derive(Debug, Args)]
pub(crate) struct NattTunnelTransferArgs {
    /// Which half of the transfer to be.
    #[arg(long, value_enum)]
    role: TransferRole,
    /// The eD2k server to log in to, `host:port`.
    #[arg(long)]
    server: String,
    /// The serve listener. Behind a gateway that forwards no TCP this is what
    /// earns the Low ID the whole row depends on — for *both* roles: a
    /// requester that were High-ID would be called back over TCP and never
    /// reach the NAT-T rung.
    #[arg(long, default_value = "0.0.0.0:4662")]
    listen: SocketAddrV4,
    /// The one UDP bind — Kad, client-UDP and NAT-T share it (ADR-0057).
    #[arg(long, default_value_t = 4672)]
    udp_port: u16,
    /// The file to share (`--role target`).
    #[arg(long)]
    share: Option<PathBuf>,
    /// The ed2k link to fetch (`--role requester`).
    #[arg(long)]
    file: Option<String>,
    /// Where the fetched bytes land (`--role requester`).
    #[arg(long)]
    download_out: Option<PathBuf>,
    /// The file the harness writes naming the *target*: `id=<u32>` and
    /// `user_hash=<hex>`, one per line (`--role requester`). A **Readiness
    /// Gate**, not a sleep: a run whose file never arrives ends with a
    /// documented absence.
    #[arg(long)]
    source_file: Option<PathBuf>,
    /// Our nickname.
    #[arg(long, default_value = "rmule-natt")]
    nickname: String,
    /// Our user hash as hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Where to publish our own identity for the harness once the session is up.
    #[arg(long)]
    identity_out: PathBuf,
    /// Seconds to wait for the login before giving up.
    #[arg(long, default_value_t = 60)]
    login_timeout: u64,
    /// Seconds to wait for the source file.
    #[arg(long, default_value_t = 60)]
    source_timeout: u64,
    /// Seconds to run after the download starts — the window the callback's
    /// silence, the 12 s fallback, the punch, the dial, the adoption and the
    /// transfer all have to happen in.
    #[arg(long, default_value_t = 180)]
    window: u64,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
}

/// What the run measured.
#[derive(Debug, Default)]
struct TransferRow {
    role: &'static str,
    client_id: u32,
    low_id: bool,
    connected: bool,
    login_failure: String,
    source_seen: bool,
    source_id: u32,
    source_injected: bool,
    download_started: bool,
    download_completed: bool,
    download_failure: String,
    output_bytes: u64,
    output_ed2k_hash: String,
    routed: String,
    punches: u64,
    refusals: u64,
    last_refusal: String,
    dials: u64,
    last_attempt_dials: String,
    tunnels_dialed: u64,
    tunnels_accepted: u64,
    last_transport: String,
    download_fallbacks: u64,
    download_fallbacks_unclaimable: u64,
    download_adoptions: u64,
    download_adoptions_no_coordinator: u64,
    download_adoptions_refused: u64,
    download_claims_retired: u64,
    unexpected_holepunches: u64,
    /// Whether the diagnostics snapshot arrived. Every counter only it fills
    /// is written `-1` when it did not: a zero there is a count nobody took.
    snapshot_read: bool,
}

/// The **Harness Source Record**: the one Low-ID candidate the bench's server
/// cannot describe, handed to the download through the shipped seam.
///
/// A shared cell rather than a value, because neither half of the record exists
/// when the `Core` is built: *our* Low ID is the server's to assign at login,
/// and the target's is a file the harness drops once both peers have one. The
/// driver fills the cell before it issues `StartDownload`, so the first lookup
/// already sees it — and every later one sees the same record, because a source
/// that vanished between lookups would retire the candidate for a reason the
/// bench invented.
#[derive(Clone, Default)]
struct InjectedSource(std::sync::Arc<std::sync::Mutex<Option<Injected>>>);

/// One filled **Harness Source Record**.
#[derive(Clone, Copy)]
struct Injected {
    client_id: ClientId,
    source: SourceSighting,
}

impl InjectedSource {
    fn fill(&self, client_id: ClientId, source: SourceSighting) {
        *self
            .0
            .lock()
            .expect("the injected source cell is not poisoned") =
            Some(Injected { client_id, source });
    }
}

impl SourceLookupService for InjectedSource {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        // An empty cell is a lookup the driver has not armed yet, and the only
        // honest answer is "no sources" — never a fabricated one.
        let filled = *self
            .0
            .lock()
            .expect("the injected source cell is not poisoned");
        Ok(filled.map_or_else(
            || SourceLookupOutcome {
                client_id: ClientId::from_u32(0),
                sources: Vec::new(),
            },
            |injected| SourceLookupOutcome {
                client_id: injected.client_id,
                sources: vec![injected.source],
            },
        ))
    }
}

/// Run one half of the transfer and write its row.
///
/// # Errors
/// If an operand will not parse or the core cannot be started. A download that
/// does not finish is a **row**, never an error: the whole point of the flow is
/// that the reason is readable from the counters beside it.
pub(crate) async fn run_tunnel_transfer(args: NattTunnelTransferArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let our_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let identity = ClientIdentity::new(
        our_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.listen.port(),
        60,
    );
    let settings = CoreSettings {
        nickname: args.nickname.clone(),
        tcp_port: args.listen.port(),
        udp_port: args.udp_port,
        ..CoreSettings::default()
    };

    let mut row = TransferRow {
        role: match args.role {
            TransferRole::Target => "target",
            TransferRole::Requester => "requester",
        },
        ..TransferRow::default()
    };

    match args.role {
        TransferRole::Target => target(args, server, identity, settings, &mut row).await,
        TransferRole::Requester => requester(args, server, identity, settings, &mut row).await,
    }
}

/// The serving half: share the file, log in, publish the identity the harness
/// hands the requester, and hold the window open so *accepting* a tunnel is a
/// measurement rather than a zero nobody took.
async fn target(
    args: NattTunnelTransferArgs,
    server: ServerEndpoint,
    identity: ClientIdentity,
    settings: CoreSettings,
    row: &mut TransferRow,
) -> Result<()> {
    let share = args
        .share
        .clone()
        .context("--role target needs --share <file>")?;
    let mut core = Core::builder(CoreConfig::default(), open_durable_store_in_memory()?)
        .settings(settings)
        .user_hash(identity.user_hash())
        .build();
    let _share = crate::share::share_files(&mut core, &[share], |_| {}).await?;
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    crate::node::connect(&core, &server).await?;
    if !await_login(&mut core, Duration::from_secs(args.login_timeout), row).await? {
        return write(&args.out, row);
    }
    publish_identity(&args.identity_out, row.client_id, &args.user_hash)?;
    println!(
        "rmule-natt-transfer-ready role=target id={} low_id={} hash={}",
        row.client_id, row.low_id, args.user_hash
    );
    drain(&mut core, Duration::from_secs(args.window), row).await?;
    snapshot(&mut core, row).await?;
    write(&args.out, row)
}

/// The downloading half: log in (Low-ID, because the gateway forwards no TCP),
/// take the harness's source record, and start a real download of the link.
async fn requester(
    args: NattTunnelTransferArgs,
    server: ServerEndpoint,
    identity: ClientIdentity,
    settings: CoreSettings,
    row: &mut TransferRow,
) -> Result<()> {
    let link = args
        .file
        .clone()
        .context("--role requester needs --file <ed2k link>")?;
    let Ed2kLink::File(file) =
        Ed2kLink::parse(&link).with_context(|| format!("parse ed2k link {link}"))?
    else {
        anyhow::bail!("--file must be an ed2k *file* link, got {link}");
    };
    let output = args
        .download_out
        .clone()
        .context("--role requester needs --download-out <path>")?;
    let source_file = args
        .source_file
        .clone()
        .context("--role requester needs --source-file <path>")?;

    // One Core owns the whole run: the serve listener, the session, the NAT-T
    // front and the download. Two would give the server two observed ports to
    // key on and its `0x61` would name whichever keepalive landed last.
    let injected = InjectedSource::default();
    let settings = CoreSettings {
        download_dir: Some(crate::output::download_dir(std::slice::from_ref(&output))?),
        ..settings
    };
    let mut core = Core::builder(CoreConfig::default(), open_durable_store_in_memory()?)
        .settings(settings)
        .user_hash(identity.user_hash())
        .source_lookup(injected.clone())
        .build();
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    crate::node::connect(&core, &server).await?;
    // `StartServing` binds the listener the server's back-connect probe will
    // fail to reach, which is what earns the Low ID the whole row depends on.
    // The gate is the session's own `Connected`, never the bind (the
    // bind-is-not-login contract): a `0x60` needs the session the bind does not imply.
    if !await_login(&mut core, Duration::from_secs(args.login_timeout), row).await? {
        return write(&args.out, row);
    }
    publish_identity(&args.identity_out, row.client_id, &args.user_hash)?;
    println!(
        "rmule-natt-transfer-ready role=requester id={} low_id={} hash={}",
        row.client_id, row.low_id, args.user_hash
    );

    let target = match await_source(
        &mut core,
        &source_file,
        Duration::from_secs(args.source_timeout),
    )
    .await?
    {
        Some(target) => target,
        None => {
            row.routed = "no-source-file".to_owned();
            snapshot(&mut core, row).await?;
            return write(&args.out, row);
        }
    };
    row.source_seen = true;
    row.source_id = target.id;
    row.source_injected = true;
    injected.fill(
        ClientId::from_u32(row.client_id),
        SourceSighting::new(
            PeerSource::LowId {
                id: ClientId::from_u32(target.id),
                port: args.listen.port(),
            },
            Some(target.user_hash),
            None,
        ),
    );

    core.send(crate::output::start(file, Some(server), &output)?)
        .await?;
    row.download_started = true;
    println!("rmule-natt-transfer-download source_id={}", target.id);

    drain(&mut core, Duration::from_secs(args.window), row).await?;
    if row.download_completed {
        row.output_bytes = std::fs::metadata(&output)
            .map(|meta| meta.len())
            .unwrap_or(0);
        row.output_ed2k_hash = ed2k_hash(&output)?;
    }
    snapshot(&mut core, row).await?;
    write(&args.out, row)
}

/// The other half of the transfer, as the harness named it.
struct Target {
    id: u32,
    user_hash: UserHash,
}

/// Run the core's event loop for `budget`, recording what it said. Returns
/// early once the download terminates: the window bounds a *failure*, and a
/// completed transfer has nothing left to wait for.
async fn drain(core: &mut Core, budget: Duration, row: &mut TransferRow) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            event = core.next_event() => event,
        };
        let Some(event) = event else { break };
        println!("{}", event.record().render(Level::Full));
        match event {
            CoreEvent::PeerReachRouted { route, .. } => {
                row.routed = crate::natt::route_code(&route).to_owned()
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                row.download_completed = true;
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                row.download_failure = reason.to_string();
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => {
                row.download_failure = "cancelled".to_owned();
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Wait for the session's own `Connected`, recording the assigned id.
///
/// `ServingStarted` is a bind and the login is its own fact (the
/// bind-is-not-login contract), so nothing here reads the bind.
async fn await_login(core: &mut Core, budget: Duration, row: &mut TransferRow) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                row.login_failure = format!("no session within {budget:?}");
                return Ok(false);
            }
            event = core.next_event() => event,
        };
        let Some(event) = event else {
            row.login_failure = "the core event stream ended".to_owned();
            return Ok(false);
        };
        println!("{}", event.record().render(Level::Full));
        match event {
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Connected {
                client_id,
                ..
            }) => {
                row.connected = true;
                row.client_id = client_id.as_u32();
                row.low_id = !client_id.is_high_id();
                return Ok(true);
            }
            CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::ConnectFailed {
                reason,
                ..
            }) => {
                row.login_failure = format!("{reason:?}");
                return Ok(false);
            }
            _ => {}
        }
    }
}

/// Poll for the harness's source file while keeping the core's events drained.
async fn await_source(core: &mut Core, path: &Path, budget: Duration) -> Result<Option<Target>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(target) = read_target(path)? {
            return Ok(Some(target));
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            () = tokio::time::sleep(SOURCE_POLL) => {}
            event = core.next_event() => {
                let Some(event) = event else { return Ok(None) };
                println!("{}", event.record().render(Level::Full));
            }
        }
    }
}

/// Read the source file, or `None` while it is absent. Anything short of both
/// fields is a file still arriving, never a malformed target.
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
    Ok(Some(Target {
        id: id
            .parse()
            .with_context(|| format!("parse source id {id}"))?,
        user_hash: UserHash::from_bytes(parse_user_hash(hash)?),
    }))
}

/// Ask for and read back one diagnostics snapshot.
async fn snapshot(core: &mut Core, row: &mut TransferRow) -> Result<()> {
    core.send(CoreCommand::DumpDiagnostics).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let snapshot = loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            event = core.next_event() => event,
        };
        let Some(event) = event else { return Ok(()) };
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            break snapshot;
        }
    };
    row.snapshot_read = true;
    let session = &snapshot.session;
    row.punches = session.natt_server_punches_total;
    row.refusals = session.natt_server_refusals_total;
    row.last_refusal = session
        .natt_server_last_refusal
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_default();
    row.dials = session.natt_dials_total;
    row.last_attempt_dials = session
        .natt_last_attempt_dials
        .map(|dials| dials.to_string())
        .unwrap_or_default();
    row.tunnels_dialed = session.natt_tunnels_dialed_total;
    row.tunnels_accepted = session.natt_tunnels_accepted_total;
    row.last_transport = session
        .natt_last_tunnel_transport
        .map(|transport| format!("{transport:?}"))
        .unwrap_or_default();
    row.download_fallbacks = session.natt_download_fallbacks_total;
    row.download_fallbacks_unclaimable = session.natt_download_fallbacks_unclaimable_total;
    row.download_adoptions = session.natt_download_adoptions_total;
    row.download_adoptions_no_coordinator = session.natt_download_adoptions_no_coordinator_total;
    row.download_adoptions_refused = session.natt_download_adoptions_refused_total;
    row.download_claims_retired = session.natt_download_claims_retired_total;
    row.unexpected_holepunches = session.natt_unexpected_holepunches_total;
    Ok(())
}

/// Publish our own identity for the harness, in the `key=value` shape the
/// source file uses.
fn publish_identity(path: &Path, id: u32, user_hash: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, format!("id={id}\nuser_hash={user_hash}\n"))
        .with_context(|| format!("write {}", path.display()))
}

/// The fetched file's own **ED2K File Hash**, computed from the bytes on disk.
///
/// The claim of this flow is that the file arrived *byte-equal*, and the
/// cheapest statement of that which a reader can re-take by hand is the hash
/// the link already names.
fn ed2k_hash(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let summary = rmule_primitives::FileHashSummary::digest_reader(file)
        .with_context(|| format!("hash {}", path.display()))?;
    Ok(summary.file_hash().to_hex_upper())
}

fn write(path: &Path, row: &TransferRow) -> Result<()> {
    crate::driver_row::write_row(path, render(row))
}

/// The row as the harness reads it.
fn render(row: &TransferRow) -> Row {
    println!(
        "natt-tunnel-transfer role={} connected={} low_id={} completed={} tunnels={}/{} \
         fallbacks={} adoptions={}",
        row.role,
        row.connected,
        row.low_id,
        row.download_completed,
        row.tunnels_dialed,
        row.tunnels_accepted,
        row.download_fallbacks,
        row.download_adoptions,
    );
    let mut out = Row::new(
        "rmule-tools natt tunnel-transfer — a file crossing a punched path between two\n\
         Low-ID rmule nodes, coordinated by an eD2k server (ADR-0091 rung 1). Every value\n\
         here is rmule's own account and is scored `rmule-only`: the counterparty bytes\n\
         this row is read beside are the SERVER's 0x60/0x61, counted off the flow's tap.\n\
         `source_injected` declares the one operand the bench's server cannot deliver —\n\
         a Low-ID source's User Hash — supplied through the shipped source-lookup seam.",
    );
    // A counter only the snapshot fills, or `-1` when no snapshot arrived.
    let counted = |value: u64| if row.snapshot_read { as_i64(value) } else { -1 };
    out.str("role", row.role)
        .bool("snapshot_read", row.snapshot_read)
        .bool("connected", row.connected)
        .int("client_id", i64::from(row.client_id))
        .bool("low_id", row.low_id)
        .str("login_failure", &row.login_failure)
        .bool("source_seen", row.source_seen)
        .int("source_id", i64::from(row.source_id))
        // The same fact under the name every punch row states it by: the shared
        // NAT-T claims read one vocabulary off whichever driver wrote the row,
        // and a name only one driver writes reads back as a `-1` that looks
        // like a measurement.
        .int("target_id", i64::from(row.source_id))
        .bool("source_injected", row.source_injected)
        .bool("download_started", row.download_started)
        .bool("download_completed", row.download_completed)
        .str("download_failure", &row.download_failure)
        .int("output_bytes", as_i64(row.output_bytes))
        .str("output_ed2k_hash", &row.output_ed2k_hash)
        .str("routed", &row.routed)
        .int("server_punches", counted(row.punches))
        .int("server_refusals", counted(row.refusals))
        .str("last_refusal", &row.last_refusal)
        .int("dials", counted(row.dials))
        .str("last_attempt_dials", &row.last_attempt_dials)
        .int("tunnels_dialed", counted(row.tunnels_dialed))
        .int("tunnels_accepted", counted(row.tunnels_accepted))
        .str("last_tunnel_transport", &row.last_transport)
        .int("download_fallbacks", counted(row.download_fallbacks))
        .int(
            "download_fallbacks_unclaimable",
            counted(row.download_fallbacks_unclaimable),
        )
        .int("download_adoptions", counted(row.download_adoptions))
        .int(
            "download_adoptions_no_coordinator",
            counted(row.download_adoptions_no_coordinator),
        )
        .int(
            "download_adoptions_refused",
            counted(row.download_adoptions_refused),
        )
        .int(
            "download_claims_retired",
            counted(row.download_claims_retired),
        )
        .int(
            "unexpected_holepunches",
            counted(row.unexpected_holepunches),
        );
    out
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{TransferRow, render};

    /// A missed snapshot leaves no counter at a default `0` the harness would
    /// read as measured.
    #[test]
    fn a_missed_snapshot_writes_no_measured_zero() {
        let text = render(&TransferRow::default()).finish();
        assert!(text.contains("snapshot_read = false"), "{text}");
        for key in ["tunnels_dialed", "tunnels_accepted", "download_adoptions"] {
            assert!(text.contains(&format!("{key} = -1")), "{key}: {text}");
        }
    }
}
