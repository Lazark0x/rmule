//! `rmule-cli` — the headless rmule client: a thin command router over
//! `rmule-core`. Each subcommand opens the one Durable Store in the data
//! directory (ADR-0083), issues one core command, and prints what the core
//! reports; a command that runs a core writes its records into the Run Log
//! (ADR-0075) beside the store, mirrored to stderr with `--verbose`.
//! The Kad node runner is the one long-lived command and lives in [`kad`].

#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmule_core::run_log::{self, Level, LevelHandle, RunLog, RunLogFailure};
use rmule_core::{
    AppConfigStore, Core, CoreBuilder, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent,
    CoreSettingsHandle, DirectoryRefusal, DownloadCommand, DownloadEvent, DownloadId,
    DurableAppConfig, DurableStore, ManagedServer, NameTaken, RuntimeKadFactory,
    RuntimePeerTransferService, RuntimeServeRuntimeService, RuntimeSourceLookupService, ScanEvent,
    ServerListStore, ServerPriority, Setting, SettingError, SettingRefusal, ShareGuards,
    open_durable_store,
};
use rmule_primitives::{Ed2kLink, SafeFileName, ServerEndpoint};
use rmule_words::download::{completed_line, hole_less_destination};
use rmule_words::reach::client_udp_bind_failed;

mod kad;

#[derive(Debug, Parser)]
#[command(name = "rmule-cli", about = "rmule headless client")]
struct Cli {
    /// Directory holding rmule's Durable Store (`rmule.redb`) and data files.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Also write the Run Log's records to stderr, as `rmule.log` holds them.
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the persisted client identity (generated once on first use).
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Manage the configured eD2k server list.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Manage preferences.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Download an ed2k file link to the configured download directory.
    Add { link: String },
    /// Kad DHT operations (ADR-0043).
    Kad {
        #[command(subcommand)]
        command: KadCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KadCommand {
    /// Join the public Kad network for a bounded window and observe node
    /// health (manual live smoke). The ONLY public-network path:
    /// unscored, never CI, and it writes no captured bytes to disk.
    Join {
        /// A public bootstrap contact `A.B.C.D:PORT`. Repeatable. This
        /// diagnostic reads no `nodes.dat`, so the operator supplies concrete
        /// endpoints.
        #[arg(long, required = true)]
        bootstrap: Vec<String>,
        /// How many seconds to stay joined and observing.
        #[arg(long, default_value_t = 1800)]
        duration: u64,
        /// Optionally fire one source lookup on this ed2k *file* link after the
        /// routing table warms, and print the projected Peer Source rows.
        #[arg(long)]
        search: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Show,
}

#[derive(Debug, Subcommand)]
enum ServerCommand {
    /// Add a server endpoint (`host:port`).
    Add { endpoint: String },
    /// List configured server endpoints.
    List,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Set the directory downloads are written to.
    SetDownloadDir { path: PathBuf },
    /// Show current preferences.
    Show,
}

/// Open the Run Log (ADR-0075) in `data_dir` at the level the shared *Full
/// run log* preference sets, and make it the process's subscriber, opened by
/// the run's `run_start` record. With `verbose` stderr also carries what the
/// `RMULE_LOG` filter admits, records and free-form lines alike; without it
/// stderr holds only the command's own lines. Answers the level the event
/// records are written at. A log that cannot be opened, or stops taking writes later, is said on
/// stderr once, and the run goes on without it.
fn install_run_log(
    data_dir: &std::path::Path,
    settings: &CoreSettingsHandle,
    verbose: bool,
) -> Result<LevelHandle> {
    let stored = settings.front_end_value(run_log::PREFERENCE_KEY)?;
    let opened = RunLog::open(data_dir, Level::from_preference(stored.as_deref())).map(|log| {
        if verbose {
            log.mirrored_to_stderr()
        } else {
            log
        }
    });
    let level = opened.as_ref().map(RunLog::level).unwrap_or_default();
    match opened.and_then(RunLog::install) {
        Ok(failures) => {
            // The run's boundary: a log many runs append to tells them apart
            // by the build that wrote each.
            run_log::write(
                &run_log::run_start(
                    env!("CARGO_PKG_VERSION"),
                    env!("RMULE_BUILD_COMMIT"),
                    env!("RMULE_BUILD_COMMITTED"),
                    matches!(env!("RMULE_BUILD_DIRTY").as_bytes(), b"1"),
                ),
                Level::Lean,
            );
            // The thread ends with the run when nothing failed.
            std::thread::spawn(move || {
                if let Ok(failure) = failures.recv() {
                    eprintln!("{}", no_run_log(failure));
                }
            });
        }
        Err(failure) => eprintln!("{}", no_run_log(failure)),
    }
    Ok(level)
}

/// What the operator is told when the Run Log is not, or no longer, written:
/// the TUI's sentence for the same code.
fn no_run_log(failure: RunLogFailure) -> String {
    rmule_words::app::no_run_log(failure).to_string()
}

/// The one store open of the process (ADR-0083): `data_dir/rmule.redb`,
/// created with its directory when absent. Every durable seam a command uses
/// is a view over this handle.
fn open_store(data_dir: &std::path::Path) -> Result<Arc<DurableStore>> {
    open_durable_store(data_dir).with_context(|| format!("open store in {}", data_dir.display()))
}

fn open_config_store(data_dir: &std::path::Path) -> Result<DurableAppConfig> {
    Ok(DurableAppConfig::new(open_store(data_dir)?))
}

/// Resolve the data directory by the rule `rmule` resolves it by, so both
/// open the same store: `--data-dir`, then the platform's variables.
fn resolve_data_dir(flag: Option<&std::path::Path>) -> anyhow::Result<PathBuf> {
    rmule_core::resolve_data_dir(flag, |name| std::env::var_os(name))
        .map(|dir| dir.path)
        .context("cannot determine data directory; pass --data-dir <PATH>")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = resolve_data_dir(cli.data_dir.as_deref())?;

    match cli.command {
        Command::Identity { command } => match command {
            IdentityCommand::Show => {
                let store = open_config_store(&data_dir)?;
                let id = store.ensure_identity()?;
                let hex: String = id
                    .user_hash()
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("user_hash {hex}");
                println!("nickname  {}", id.nickname().to_display_string());
                println!("tcp_port  {}", id.tcp_port());
            }
        },
        Command::Server { command } => match command {
            ServerCommand::Add { endpoint } => {
                let server = ServerEndpoint::parse_host_port(&endpoint)
                    .with_context(|| format!("parse server endpoint {endpoint}"))?;
                let store = open_config_store(&data_dir)?;
                let (host, port) = (server.host().to_owned(), server.port());
                store.merge_server(ManagedServer::listed(server))?;
                println!("added {host}:{port}");
            }
            ServerCommand::List => {
                let store = open_config_store(&data_dir)?;
                for server in store.servers()? {
                    // The whole managed row (ADR-0080), not just the endpoint:
                    // a name the list learned from server.met, the operator's
                    // priority and static pin, and the failure tally.
                    println!(
                        "{}:{} name=\"{}\" priority={} static={} failed={}",
                        server.endpoint.host(),
                        server.endpoint.port(),
                        server.name.to_display_string(),
                        priority_word(server.priority),
                        server.is_static,
                        server.fail_count,
                    );
                }
            }
        },
        // Core Settings on the store alone (ADR-0069): no core runs behind
        // these, so a change is persisted for the next start.
        Command::Config { command } => match command {
            ConfigCommand::SetDownloadDir { path } => {
                let dir = std::path::absolute(&path)
                    .with_context(|| format!("resolve {}", path.display()))?;
                // The guards the add's core scans it under refuse it here,
                // before it is stored.
                CoreSettingsHandle::open(open_store(&data_dir)?)
                    .share_guards(share_guards(&data_dir))
                    .set(Setting::DownloadDir {
                        dir: dir.clone(),
                        // No confirm is asked here: the first scan of the
                        // directory asks before it shares anything (ADR-0101).
                        share_confirmed: false,
                    })
                    .map_err(|error| match error {
                        SettingError::Refused(SettingRefusal::DownloadDirRefused(reason)) => {
                            anyhow::anyhow!(
                                "{} is not set as the download directory: everything under it is shared, and {}",
                                dir.display(),
                                refusal_clause(&reason)
                            )
                        }
                        other => other.into(),
                    })?;
                println!("download_dir {}", dir.display());
            }
            ConfigCommand::Show => {
                let settings = CoreSettingsHandle::open(open_store(&data_dir)?).read()?;
                match settings.download_dir {
                    Some(dir) => println!("download_dir {}", dir.display()),
                    None => println!("download_dir <unset>"),
                }
            }
        },
        Command::Add { link } => {
            run_add(&data_dir, &link, cli.verbose).await?;
        }
        Command::Kad { command } => match command {
            KadCommand::Join {
                bootstrap,
                duration,
                search,
            } => {
                let durable = open_store(&data_dir)?;
                let settings_handle = CoreSettingsHandle::open(Arc::clone(&durable));
                let settings = settings_handle.read()?;
                // The node's own tracing lands in the Run Log like any other
                // command's, from its first instant.
                install_run_log(&data_dir, &settings_handle, cli.verbose)?;
                let store = DurableAppConfig::new(durable);
                let bootstraps = bootstrap
                    .iter()
                    .map(|b| kad::parse_bootstrap(b))
                    .collect::<Result<Vec<_>>>()?;
                let target = search
                    .as_deref()
                    .map(kad::parse_search_target)
                    .transpose()?;
                kad::run_join(
                    &store,
                    &settings,
                    &bootstraps,
                    std::time::Duration::from_secs(duration),
                    target,
                )
                .await?;
            }
        },
    }
    Ok(())
}

async fn run_add(data_dir: &std::path::Path, link_str: &str, verbose: bool) -> Result<()> {
    let read = Ed2kLink::read(link_str).with_context(|| format!("parse ed2k link {link_str}"))?;
    if let Some(sentence) = skipped_sentence(&read.skipped_fields) {
        println!("{sentence}");
    }
    let file = match read.link {
        Ed2kLink::File(file) => file,
        _ => anyhow::bail!("link must be an ed2k *file* link"),
    };

    let durable = open_store(data_dir)?;
    let store = DurableAppConfig::new(Arc::clone(&durable));
    let settings_handle = CoreSettingsHandle::open(Arc::clone(&durable));
    // The per-install PCP nonce secret (ADR-0086): generate-once, so a restart
    // can renew and delete the mappings this install already holds.
    let port_map_secret = store.ensure_port_map_secret()?;
    // A link that names its own sources needs no server (ADR-0089): the run
    // starts from them, and a server only adds to them.
    let server = store
        .servers()?
        .into_iter()
        .next()
        .map(|listed| listed.endpoint);
    let link_sources = file.sources.peers().len() + file.ipv6_sources.len();
    match (&server, link_sources) {
        (None, 0) => anyhow::bail!(
            "no server configured and the link names no source; run `rmule-cli server add <host:port>`"
        ),
        (None, count) => println!(
            "no server configured; starting from the {count} source{} the link names",
            if count == 1 { "" } else { "s" }
        ),
        (Some(_), _) => {}
    }
    let name = SafeFileName::of_link(&file);

    // The Run Log first, so the core's own records from its first instant
    // are in it.
    let log_level = install_run_log(data_dir, &settings_handle, verbose)?;
    let mut core = add_core(data_dir, durable)
        // Port mapping (ADR-0086): a firewalled home node is the common rmule
        // deployment, and the backends are installed here rather than defaulted
        // inside core because talking to the operator's router is a deployment
        // decision — a test or a tool holds none and maps nothing. With the
        // operator's switch off, core starts no runtime and these are never
        // spoken to.
        .mapping_backends(rmule_core::live_mapping_backends(port_map_secret))
        .build();

    // The operator's word, given by running this command (ADR-0095,
    // "Connecting is the operator's act"): the one login — listener, mapping,
    // then the dial — and the download rides the session it makes. Both
    // present the Core Settings' nickname and port (ADR-0069).
    if let Some(server) = &server {
        core.send(CoreCommand::ConnectToServer {
            server: server.clone(),
        })
        .await?;
    }
    let serverless = server.is_none();
    // Core places the file in the download directory its settings name, or
    // refuses the start, so a fresh add never lands on a file it did not make.
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: server,
        name,
        if_taken: NameTaken::Refuse,
    }))
    .await?;

    let mut download_id: Option<DownloadId> = None;
    loop {
        let Some(event) = core.next_event().await else {
            anyhow::bail!("core event stream ended before the download completed");
        };
        run_log::write(&event.record(), log_level.get());
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => {
                download_id = Some(id);
                println!("queued id={}", id.as_u64());
            }
            CoreEvent::CommandRejected { reason } => {
                anyhow::bail!("{}", start_refused(&reason));
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted {
                download_id: id,
                final_path,
            }) => {
                println!("{}", completed_line(id, &final_path));
                return Ok(());
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                anyhow::bail!("download {} failed: {reason}", download_label(download_id));
            }
            // Core waits for a connection (ADR-0097); this one-shot run has
            // no operator to connect, so a wait would never end.
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) if serverless => {
                anyhow::bail!(
                    "download {} has no connection: none of the link's sources could be used, no server is configured and Kad is off",
                    download_label(download_id)
                );
            }
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) => {
                anyhow::bail!(
                    "download {} has no connection: the server did not answer and Kad is off",
                    download_label(download_id)
                );
            }
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => {
                anyhow::bail!("download {} cancelled", download_label(download_id));
            }
            // The run's disk holds no holes (ADR-0111): the download goes on,
            // and this edge is the only place the CLI hears of it.
            CoreEvent::Download(DownloadEvent::HoleLessDestination { directory, .. }) => {
                println!(
                    "{}",
                    hole_less_destination(&download_label(download_id), &directory)
                );
            }
            // The one client-UDP socket never bound at core start (ADR-0057):
            // non-fatal to this download (it runs over the
            // server-relayed and TCP-only paths), but reask, NAT-T and Kad
            // are off for the rest of the process, so it is worth a line
            // even though nothing here ever sends `EnableKad`.
            CoreEvent::ClientUdpBindFailed { port, kind } => {
                println!("{}", client_udp_bind_failed(port, kind));
            }
            // Half of the same story: the pair came up, but
            // without a family it selected, so some of what rides it is off
            // for the rest of the process. Worth a line for the same reason
            // the total failure is.
            CoreEvent::SocketBoundWithoutFamily { half_bound } => {
                println!("{half_bound}");
            }
            // The download still finishes there; only the sharing is off.
            CoreEvent::Scan(ScanEvent::DownloadDirectoryRefused { dir, reason }) => {
                println!(
                    "the download directory {} is not shared: {}; choose another with `rmule-cli config set-download-dir <path>`",
                    dir.display(),
                    refusal_clause(&reason)
                );
            }
            _ => {}
        }
    }
}

/// Why core refused to start the download.
fn start_refused(reason: &CoreCommandRejectReason) -> String {
    match reason {
        CoreCommandRejectReason::NoDownloadDir => {
            "no download directory configured; run `rmule-cli config set-download-dir <path>`"
                .to_owned()
        }
        CoreCommandRejectReason::DownloadDirRefused(guard) => format!(
            "download refused: everything under the download directory is shared, and {}; choose another with `rmule-cli config set-download-dir <path>`",
            refusal_clause(guard)
        ),
        CoreCommandRejectReason::DownloadPathConflict => {
            "download refused: a file of that name is already in the download directory".to_owned()
        }
        CoreCommandRejectReason::DuplicateDownload => {
            "download refused: this file is already being downloaded".to_owned()
        }
        CoreCommandRejectReason::DownloadStoreFailed => {
            "download refused: the download store failed (see the run log)".to_owned()
        }
        _ => "download refused (see the run log)".to_owned(),
    }
}

/// Why the share guards refuse the download directory, as a clause: the
/// TUI's, which says each refusal its own way.
fn refusal_clause(reason: &DirectoryRefusal) -> String {
    rmule_words::scan::download_dir_refusal(reason)
}

/// The core `add` runs, but for its router backends: the builder's default
/// adapter set (shared session, ban store, IP filter) over the one open store.
/// Every seam core needs — downloads, the registry a completed download
/// auto-shares into, and the managed server list `server add` writes
/// (ADR-0080/ADR-0083) — comes off that handle, and so do the operator's Core
/// Settings: the UDP port, the obfuscation policy, `Remember peers` and the
/// port-mapping switch the TUI's Settings tab wrote (ADR-0069). Overriding
/// `source_lookup`/`peer_transfer` here would hand the dial path unfiltered,
/// ban-less adapters; the defaults cost a download-only run nothing, since the
/// dialed-serve sink never holds a sender without a serve activity.
fn add_core(
    data_dir: &std::path::Path,
    durable: Arc<DurableStore>,
) -> CoreBuilder<
    RuntimeSourceLookupService,
    RuntimePeerTransferService,
    RuntimeServeRuntimeService,
    RuntimeKadFactory,
> {
    Core::builder(CoreConfig::default(), durable)
        // Credit-ring continuity: seed from and flush to
        // clients.met beside the other data files.
        .persist_credit_in(data_dir.to_path_buf())
        // IP filtering: `ipfilter.dat` + `ipfilter_static.dat`
        // load from the same data dir when present; absent files mean an
        // empty filter, exactly aMule's out-of-box posture.
        .ip_filter_dir(data_dir.to_path_buf())
        // The Shared Directory List's guards (ADR-0101): core scans the
        // download directory at attach, and never reads the environment.
        .share_guards(share_guards(data_dir))
}

/// The home and the data directory a shared directory may not be (ADR-0101),
/// named for core, which never reads the environment.
fn share_guards(data_dir: &std::path::Path) -> ShareGuards {
    ShareGuards {
        home: rmule_core::home_dir(|name| std::env::var_os(name)),
        data_dir: Some(data_dir.to_path_buf()),
    }
}

/// The download a one-shot run names in a refusal: its id once the core
/// queued it, nothing to name before.
fn download_label(download_id: Option<DownloadId>) -> String {
    download_id.map_or_else(
        || "(not yet queued)".to_owned(),
        |id| format!("id={}", id.as_u64()),
    )
}

/// The word `server list` prints for a server's priority.
/// The fields a link carried that no client reads, said once they were
/// skipped; `None` when there were none.
fn skipped_sentence(fields: &[String]) -> Option<String> {
    let quoted: Vec<String> = fields.iter().map(|name| format!("`{name}`")).collect();
    match quoted.as_slice() {
        [] => None,
        [one] => Some(format!(
            "ignored the field {one} the link carried, which no client reads"
        )),
        many => Some(format!(
            "ignored the fields {} the link carried, which no client reads",
            many.join(", ")
        )),
    }
}

fn priority_word(priority: ServerPriority) -> &'static str {
    match priority {
        ServerPriority::Normal => "Normal",
        ServerPriority::High => "High",
        ServerPriority::Low => "Low",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;

    use rmule_core::port_mapping::{MappingProtocol, PortMappingMode};
    use rmule_core::{
        CoreCommand, CoreSettingsHandle, MappingBackend, Setting, SocketRole, open_durable_store,
    };
    use rmule_testkit::{FakeGateways, ScriptedBackend};

    use super::add_core;

    /// What the TUI's Settings tab stored governs the core `add` builds from
    /// the same data directory: port mapping off talks to no router, and the
    /// client-UDP socket binds the operator's port rather than a default.
    #[tokio::test(flavor = "multi_thread")]
    async fn add_runs_its_core_under_the_operator_s_stored_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let durable = open_durable_store(dir.path()).expect("store");
        let port = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free UDP port")
            .port();
        let settings = CoreSettingsHandle::open(Arc::clone(&durable));
        settings
            .set(Setting::PortMapping(PortMappingMode::Off))
            .expect("mapping off");
        settings.set(Setting::UdpPort(port)).expect("the UDP port");

        let pcp = Arc::new(ScriptedBackend::available(MappingProtocol::Pcp));
        let core = add_core(dir.path(), durable)
            .gateway_source(FakeGateways::home_lan())
            .mapping_backends(vec![pcp.clone() as Arc<dyn MappingBackend>])
            .build();

        tokio::time::timeout(Duration::from_secs(5), async {
            while !core
                .diagnostics_snapshot()
                .addresses
                .iter()
                .any(|row| row.role == SocketRole::Udp)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the client-UDP socket bound");
        assert_eq!(
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
                .map(|_| ())
                .map_err(|error| error.kind()),
            Err(std::io::ErrorKind::AddrInUse),
            "the core holds the stored port"
        );

        core.send(CoreCommand::RecheckReachability)
            .await
            .expect("recheck accepted");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(core.diagnostics_snapshot().mappings.is_empty());
        assert!(pcp.asked().is_empty(), "no gateway was asked anything");
        core.shutdown().await;
    }
}
