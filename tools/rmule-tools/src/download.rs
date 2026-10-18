//! Diagnostic durable-download orchestration commands (`ed2k download …`).
//! These drive the real [`rmule_core::Core`] and print each [`CoreEvent`] via
//! its co-located `Display` projection.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::KadEnableConfig;
use rmule_core::{
    CoreCommand, CoreConfig, CoreEvent, ServeCommand as CoreServeCommand, open_durable_store,
};
use rmule_kad::KadId;
use rmule_primitives::{Ed2kLink, ServerEndpoint};

use crate::cli::DownloadIdentityArgs;
use crate::operand::{parse_hex16, parse_seeded_kad_contacts};
use crate::serve::PeerCryptPolicyArg;
use crate::serve::crypt_flip;
use endings::{Endings, Noted};
use served::{Gate, GateArgs, Gates, ServedArgs};

mod endings;
mod reopen;
mod served;
mod stored;

pub(crate) use reopen::{DownloadReopenArgs, reopen};
pub(crate) use stored::{
    DownloadPauseArgs, DownloadResumeArgs, DownloadStatusArgs, pause, resume, status,
};

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
    /// The **Dial Window** (ADR-0116): roads the downloads open per 5 s
    /// (`CoreConfig::peer_connections.dials_per_window`, default 20).
    #[arg(long)]
    dials_per_window: Option<u32>,
    /// The **Connection Ceiling** (ADR-0116): connections the downloads hold
    /// at once, asking and transferring
    /// (`CoreConfig::peer_connections.max_connections`, default 500).
    #[arg(long)]
    max_connections: Option<usize>,
    /// The **Streaming Window**'s width `N` in parts
    /// (`CoreConfig::streaming_window_parts`, ADR-0112); `0` for none.
    #[arg(long)]
    streaming_window: Option<u32>,
    /// Every this many milliseconds, print each download's positional part
    /// map (ADR-0079) off the diagnostics snapshot, one
    /// `download parts_tick id=… at_unix_ms=… parts=…` line with one letter
    /// per part: `V` verified, `I` in flight, `M` missing, and a
    /// `download sources_tick id=… at_unix_ms=… known=… asking=… queued=…
    /// transferring=…` line of its sources (ADR-0116). Unset prints none.
    #[arg(long)]
    report_parts_every_ms: Option<u64>,
    /// Also bind the inbound peer listener on `0.0.0.0:<tcp-port>` while
    /// downloading. This makes rmule reachable (High ID) and callback-capable
    /// (ADR-0039), so a discovered Low-ID source can be called back and adopted.
    /// Peers it accepts are answered for each download from its verified parts
    /// (ADR-0113); `--share` adds whole files beside them.
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
    served: ServedArgs,
    #[command(flatten)]
    gates: GateArgs,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
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
    let mut config = args.served.config(CoreConfig::default());
    if let Some(dials) = args.dials_per_window {
        config.peer_connections.dials_per_window = dials;
    }
    if let Some(connections) = args.max_connections {
        config.peer_connections.max_connections = connections;
    }
    if let Some(parts) = args.streaming_window {
        config.streaming_window_parts = parts;
    }
    let settings = args
        .served
        .settings(args.identity.settings(rmule_core::CoreSettings {
            udp_port: args.udp_port,
            obfuscation: args.peer_crypt.map(rmule_core::ObfuscationPolicy::from),
            download_dir: Some(crate::output::download_dir(&args.out)?),
            ..rmule_core::CoreSettings::default()
        }));
    // One production core either way: with `--serve` it also
    // binds the inbound listener (earning High ID + Callback Capability,
    // ADR-0039) and shares the one Low-ID callback table so the accept-router
    // can adopt a called-back source. Without it the same wiring simply never
    // serves.
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
            args.served.take(&core, &event).await?;
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
    let mut shared = args.served.share_at_start(&mut core).await?;
    let mut gates = Gates::new(&args.gates);
    let mut lingering = false;

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
    let mut parts_tick = args.report_parts_every_ms.map(|ms| {
        let mut ticker = tokio::time::interval(Duration::from_millis(ms.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    });
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
            PartsTick,
            Gates,
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
            () = async {
                match parts_tick.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending().await,
                }
            } => Step::PartsTick,
            () = gates.tick() => Step::Gates,
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
            Step::PartsTick => {
                print_parts_tick(&core);
                continue;
            }
            Step::Gates => match gates.look() {
                Gate::Shut => continue,
                Gate::Pause => {
                    let ids: Vec<u64> = endings.queued().collect();
                    served::pause_then_share(
                        &mut core,
                        &args.served,
                        &ids,
                        &args.gates.share_after_pause,
                        &mut shared,
                    )
                    .await?;
                    continue;
                }
                Gate::Stop => {
                    println!(
                        "download stop_gate id={} at_unix_ms={}",
                        endings.first().map_or(0, |id| id.as_u64()),
                        served::unix_ms()
                    );
                    break endings.verdict();
                }
            },
            Step::Event(event) => event,
        };
        let Some(event) = event else {
            break Err(anyhow::anyhow!(
                "download event stream ended before completion for {:?}",
                endings.queued().collect::<Vec<_>>()
            ));
        };
        args.served.take(&core, &event).await?;
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
        if endings.all_ended() && !lingering {
            // A peer mid-upload when the last download ended is served on,
            // from the final path, until the deadline.
            if args.served.linger && deadline.is_some() {
                lingering = true;
                println!("download all_ended lingering=yes");
                continue;
            }
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

/// One `download parts_tick` line per download row: the positional part map
/// (ADR-0079) as letters, stamped with the wall clock so a bench can lay it
/// beside a capture taken on the same host; and one `download sources_tick`
/// line beside it: the sources the run knows and its **Source Activity**
/// (ADR-0116).
fn print_parts_tick(core: &rmule_core::Core) {
    use rmule_core::diagnostics::PartState;
    let at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    for (id, row) in &core.diagnostics_snapshot().downloads {
        let parts: String = row
            .parts
            .iter()
            .map(|part| match part {
                PartState::Verified => 'V',
                PartState::InFlight => 'I',
                PartState::Missing => 'M',
            })
            .collect();
        println!(
            "download parts_tick id={} at_unix_ms={at_unix_ms} parts={parts}",
            id.as_u64()
        );
        let activity = row.source_activity;
        println!(
            "download sources_tick id={} at_unix_ms={at_unix_ms} known={} asking={} queued={} transferring={}",
            id.as_u64(),
            row.known_sources,
            activity.asking,
            activity.queued,
            activity.transferring,
        );
    }
}

/// The Durable Store under `data_dir`, named in the error when it will not
/// open — every subcommand here starts this way.
fn open_store(data_dir: &std::path::Path) -> Result<std::sync::Arc<rmule_core::DurableStore>> {
    open_durable_store(data_dir)
        .with_context(|| format!("open the Durable Store in {}", data_dir.display()))
}
