//! Diagnostic durable-download orchestration commands (`ed2k download …`).
//! These drive the real [`rmule_core::Core`] and print each [`CoreEvent`] via
//! its co-located `Display` projection.

use rmule_core::DownloadRepository;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::KadEnableConfig;
use rmule_core::run_log::Level;
use rmule_core::{
    CoreCommand, CoreConfig, CoreEvent, DownloadCommand as CoreDownloadCommand, DownloadEvent,
    DownloadId, DownloadLifecycle, DurableDownloadRepository, ServeCommand as CoreServeCommand,
    open_durable_store,
};
use rmule_kad::KadId;
use rmule_primitives::{Ed2kLink, ServerEndpoint};

use crate::cli::DownloadIdentityArgs;
use crate::operand::{parse_hex16, parse_seeded_kad_contacts};
use crate::serve::PeerCryptPolicyArg;
use crate::serve::crypt_flip;
use endings::{Endings, Noted};

mod endings;

#[derive(Debug, Args)]
pub(crate) struct DownloadStartArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
    /// eD2k server endpoint as `host:port`.
    #[arg(long)]
    server: String,
    /// ED2K file link (`ed2k://|file|<name>|<size>|<hash>|...|/`); repeat
    /// for several downloads in the one core.
    #[arg(long, required = true)]
    file: Vec<String>,
    /// Output path for verified bytes, one per `--file`, in the same order.
    #[arg(long, required = true)]
    out: Vec<PathBuf>,
    /// Maximum concurrent High ID peer workers per download.
    #[arg(long)]
    peer_concurrency: Option<usize>,
    /// Also bind the inbound peer listener on `0.0.0.0:<tcp-port>` while
    /// downloading. This makes rmule reachable (High ID) and callback-capable
    /// (ADR-0039), so a discovered Low-ID source can be called back and adopted.
    /// No files are shared; the bound listener is the point.
    #[arg(long)]
    serve: bool,
    /// Optional overall deadline in seconds for a *bounded* run. When set and the
    /// download neither completes nor fails within the deadline, rmule prints a
    /// `deadline_reached` marker and exits 0 instead of blocking. This is the
    /// honest terminal for the Low-ID callback compatibility flow:
    /// the Lugdunum test eserver never surfaces a Low-ID peer as a source
    /// (ADR-0040), so a byte-completion cannot occur; the harness judges rmule's
    /// callback capability from its serve/reachability logs. Unset (default)
    /// leaves the *whole run* unbounded. This is distinct from — and layered
    /// on top of — `rmule-core`'s own default
    /// `CoreConfig::source_lookup_timeout`, which always bounds just the initial
    /// source lookup so a sourceless file's `download start` cannot hang forever
    /// even without this flag.
    #[arg(long)]
    max_seconds: Option<u64>,
    /// Also run Kad, so the download asks it for sources, seeded with this
    /// **Seeded Bootstrap** contact, `<kad-id-hex>@<ipv4>:<udp-port>`,
    /// repeatable. Needs `--serve`: the listener's port is the one Kad
    /// advertises, and its Family Pair bind is what gives the Dial Chooser an
    /// IPv6 of ours to dial from (ADR-0087).
    #[arg(long = "kad-contact", requires = "serve")]
    kad_contacts: Vec<String>,
    /// Our Kad ID as hex (32 chars); a fresh one when absent.
    #[arg(long, requires = "kad_contacts")]
    kad_id_hex: Option<String>,
    /// The one client-UDP port (reask, NAT-T and Kad share it, ADR-0057);
    /// `0` takes an ephemeral one.
    #[arg(long, default_value_t = 0)]
    udp_port: u16,
    /// Arm rmule's peer protocol-obfuscation policy for this run, as `ed2k
    /// serve start --peer-crypt` does — off unless passed. The download's own
    /// peer dials read it as they decide (ADR-0046).
    #[arg(long, value_enum)]
    peer_crypt: Option<PeerCryptPolicyArg>,
    /// Change the obfuscation policy mid-run, as `<secs>:<policy>` with the
    /// policy one of `off`, `supported`, `requested`, `required`; repeat for
    /// several. At each, the running core takes the policy up through its Core
    /// Settings handle, so a peer dialled after it runs under the new policy
    /// and a connection already negotiated keeps its own (ADR-0046), and a
    /// `rmule-obfuscation-flip after_secs=… policy=… at_unix_ms=…` line marks
    /// the moment. Seconds count from the login being asked for. `--peer-crypt` is the
    /// policy the run starts under.
    #[arg(long, value_parser = crypt_flip::parse)]
    peer_crypt_flip: Vec<crypt_flip::CryptFlip>,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

#[derive(Debug, Args)]
pub(crate) struct DownloadResumeArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
    /// Durable download id to resume.
    #[arg(long)]
    download_id: u64,
    /// Optional eD2k server endpoint override as `host:port`.
    #[arg(long)]
    server: Option<String>,
    /// Maximum concurrent High ID peer workers per download.
    #[arg(long)]
    peer_concurrency: Option<usize>,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

#[derive(Debug, Args)]
pub(crate) struct DownloadPauseArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
    /// Durable download id to mark paused.
    #[arg(long)]
    download_id: u64,
}

#[derive(Debug, Args)]
pub(crate) struct DownloadStatusArgs {
    /// Data directory holding the Durable Store (`rmule.redb`), created when
    /// absent.
    #[arg(long)]
    data_dir: PathBuf,
}

/// The Kad half of a Kad-sourced download: seeded, never bootstrapped, so the
/// source walk has its storer in hand from the first sweep.
fn kad_enable_config(args: &DownloadStartArgs) -> Result<KadEnableConfig> {
    Ok(KadEnableConfig {
        bootstrap: Vec::new(),
        contacts: parse_seeded_kad_contacts(&args.kad_contacts)?,
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    })
}

pub(crate) async fn start(args: DownloadStartArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    if args.file.len() != args.out.len() {
        anyhow::bail!(
            "{} --file links but {} --out paths: give one --out per --file",
            args.file.len(),
            args.out.len()
        );
    }
    let mut files = Vec::with_capacity(args.file.len());
    for text in &args.file {
        match Ed2kLink::parse(text).with_context(|| format!("parse ed2k link {text}"))? {
            Ed2kLink::File(file) => files.push(file),
            _ => anyhow::bail!("--file must be an ed2k file link, got {text}"),
        }
    }
    let store = open_store(&args.data_dir)?;
    let mut config = CoreConfig::default();
    if let Some(concurrency) = args.peer_concurrency {
        config.peer_concurrency_per_download = concurrency;
    }
    let settings = args.identity.settings(rmule_core::CoreSettings {
        udp_port: args.udp_port,
        obfuscation: args.peer_crypt.map(rmule_core::ObfuscationPolicy::from),
        download_dir: Some(crate::output::download_dir(&args.out)?),
        ..rmule_core::CoreSettings::default()
    });
    // One production core either way: with `--serve` it also
    // binds the inbound listener (earning High ID + Callback Capability,
    // ADR-0039) and shares the one Low-ID callback table so the accept-router
    // can adopt a called-back source. No files are shared — only the bound
    // listener matters. Without it the same wiring simply never serves.
    let builder = args.identity.core_builder(config, settings, store)?;
    // A pinned `--kad-id-hex` places the node; otherwise its store mints one.
    let mut core = match args.kad_id_hex.as_deref() {
        Some(hex) => builder.kad_id(KadId::from_bytes(parse_hex16("--kad-id-hex", hex)?)),
        None => builder,
    }
    .build();

    if args.serve {
        let listen = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.identity.tcp_port);
        core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
            listen_addr: listen,
        }))
        .await?;
        // Wait for the listener to bind before downloading so Callback Capability
        // is live when the first Low-ID source is considered. The bind is all
        // this waits for: the login is the connect below, a
        // separate fact on the session's own trail, and a server that never
        // answers must not hold a download up.
        loop {
            let Some(event) = core.next_event().await else {
                anyhow::bail!("serve event stream ended before ServingStarted");
            };
            println!("{}", event.record().render(Level::Full));
            match event {
                CoreEvent::Serve(rmule_core::ServeEvent::ServingStarted { .. }) => break,
                CoreEvent::Serve(rmule_core::ServeEvent::ServingFailed { reason }) => {
                    anyhow::bail!("the serve listener never bound: {reason:?}");
                }
                CoreEvent::Serve(rmule_core::ServeEvent::ServingStopped { .. }) => {
                    anyhow::bail!("serve stopped before it started");
                }
                _ => {}
            }
        }
    }
    if !args.kad_contacts.is_empty() {
        core.send(CoreCommand::EnableKad(kad_enable_config(&args)?))
            .await?;
    }

    // The operator's word, given on the command line (ADR-0095): the one
    // login, which binds the listener if `--serve` has not, then the download
    // rides it.
    let began = tokio::time::Instant::now();
    let mut crypt_flips = crypt_flip::CryptFlips::new(args.peer_crypt_flip.clone());
    crate::node::connect(&core, &server).await?;
    for (file, out) in files.into_iter().zip(&args.out) {
        core.send(crate::output::start(file, Some(server.clone()), out)?)
            .await?;
    }

    let deadline = args
        .max_seconds
        .map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));
    // Each download ends on its own; the run ends when every one has.
    let mut endings = Endings::new(args.out.len());
    let result = loop {
        // Bounded-run mode: the Low-ID callback compatibility flow
        // can never byte-complete against the Lugdunum eserver (it never surfaces
        // the Low-ID peer as a source, ADR-0040), so on the deadline print a
        // marker and end the run rather than block on an event that will not
        // arrive; it fails only when a download already failed. Callback
        // capability is judged from rmule's own serve/reachability logs, not
        // claimed here — the server-assigned HighID is only surfaced as an
        // event once the (blocked) source lookup returns. Unbounded runs keep
        // the plain await.
        // Resolved into a `Step` first: `next_event` borrows the core mutably
        // for the whole select, so a flip, which reads the core, runs after it.
        // One value per loop pass, so the size imbalance of the event arm is
        // intentional, as `CoreEvent` itself notes.
        #[allow(clippy::large_enum_variant)]
        enum Step {
            Deadline,
            Flip,
            Event(Option<CoreEvent>),
        }
        let step = tokio::select! {
            biased;
            () = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => Step::Deadline,
            () = async {
                match crypt_flips.next_at(began) {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => Step::Flip,
            event = core.next_event() => Step::Event(event),
        };
        let event = match step {
            Step::Deadline => {
                println!(
                    "download deadline_reached id={}",
                    endings.first().map_or(0, |id| id.as_u64()),
                );
                break endings.verdict();
            }
            Step::Flip => {
                crypt_flips.fire(&core)?;
                continue;
            }
            Step::Event(event) => event,
        };
        let Some(event) = event else {
            break Err(anyhow::anyhow!(
                "download event stream ended before completion for {:?}",
                endings.queued().collect::<Vec<_>>()
            ));
        };
        println!("{}", event.record().render(Level::Full));
        let CoreEvent::Download(event) = event else {
            continue;
        };
        match endings.observe(&event) {
            Noted::Nothing | Noted::EndedShort => {}
            Noted::Completed { id, position } => println!(
                "download finalized id={} path={}",
                id.as_u64(),
                position
                    .and_then(|index| args.out.get(index))
                    .map_or_else(|| "-".to_owned(), |path| path.display().to_string())
            ),
        }
        if endings.all_ended() {
            if args.serve {
                core.send(CoreCommand::Serve(CoreServeCommand::StopServing))
                    .await?;
            }
            break endings.verdict();
        }
    };

    let snapshot = core.diagnostics_snapshot();
    tracing::info!(
        downloads = snapshot.downloads.len(),
        "final diagnostics snapshot",
    );
    for (id, dd) in &snapshot.downloads {
        for (slot, entry) in &dd.workers {
            tracing::info!(
                download_id = id.as_u64(),
                worker_slot = slot.as_usize(),
                peer = ?entry.peer_endpoint(),
                phase = ?entry.phase(),
                phase_age_ms = entry.since().elapsed().as_millis() as u64,
                transition_count = entry.transition_count(),
                software = ?entry.software(),
                "worker final state",
            );
        }
    }

    result
}

pub(crate) async fn resume(args: DownloadResumeArgs) -> Result<()> {
    let server_override = args
        .server
        .as_deref()
        .map(ServerEndpoint::parse_host_port)
        .transpose()
        .with_context(|| format!("parse server override {:?}", args.server))?;
    let store = open_store(&args.data_dir)?;
    let download_id = DownloadId::from_u64(args.download_id);
    // The server this run connects to: the override, or the one the download
    // was recorded against as its source hint.
    let server = match &server_override {
        Some(server) => server.clone(),
        None => DurableDownloadRepository::new(std::sync::Arc::clone(&store))
            .load_download(download_id)
            .with_context(|| format!("load download {}", args.download_id))?
            .source_hint()
            .cloned()
            .context("the download records no server; name one with --server")?,
    };
    let mut config = CoreConfig::default();
    if let Some(concurrency) = args.peer_concurrency {
        config.peer_concurrency_per_download = concurrency;
    }
    let mut core = args
        .identity
        .core_builder(
            config,
            args.identity.settings(rmule_core::CoreSettings::default()),
            store,
        )?
        .build();
    // The operator's word, given on the command line (ADR-0095).
    crate::node::connect(&core, &server).await?;
    core.send(CoreCommand::Download(CoreDownloadCommand::ResumeDownload {
        download_id,
    }))
    .await?;

    while let Some(event) = core.next_event().await {
        println!("{}", event.record().render(Level::Full));
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => return Ok(()),
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => {
                anyhow::bail!("download cancelled")
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                anyhow::bail!("download failed: {reason}")
            }
            _ => {}
        }
    }

    anyhow::bail!("download event stream ended before resume completion")
}

/// The Durable Store under `data_dir`, named in the error when it will not
/// open — every subcommand here starts this way.
fn open_store(data_dir: &std::path::Path) -> Result<std::sync::Arc<rmule_core::DurableStore>> {
    open_durable_store(data_dir)
        .with_context(|| format!("open the Durable Store in {}", data_dir.display()))
}

pub(crate) fn pause(args: DownloadPauseArgs) -> Result<()> {
    let store = open_store(&args.data_dir)?;
    let repo = DurableDownloadRepository::new(store);
    let download_id = DownloadId::from_u64(args.download_id);
    repo.set_lifecycle(download_id, DownloadLifecycle::Paused)?;
    println!("download paused id={}", download_id.as_u64());
    Ok(())
}

pub(crate) fn status(args: DownloadStatusArgs) -> Result<()> {
    let store = open_store(&args.data_dir)?;
    let repo = DurableDownloadRepository::new(store);
    let records = repo.list_resumable()?;
    println!("# resumable downloads in {}", args.data_dir.display());
    if records.is_empty() {
        println!("# no resumable downloads");
        return Ok(());
    }
    for record in records {
        let parts = repo.verified_parts(record.id())?;
        let verified_bytes: u64 = parts.iter().map(|part| part.len).sum();
        println!(
            "download id={} state={:?} file_hash={} size={} verified_parts={} verified_bytes={} final_path={}",
            record.id().as_u64(),
            record.lifecycle(),
            record.file_hash().to_hex_upper(),
            record.file_size(),
            parts.len(),
            verified_bytes,
            record.paths().final_path().display()
        );
    }
    Ok(())
}
