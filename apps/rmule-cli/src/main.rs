//! `rmule-cli` — the headless rmule client: a thin command router over
//! `rmule-core`. Each subcommand opens the one Durable Store in the data
//! directory (ADR-0083), issues one core command, and prints what the core
//! reports; a command that runs a core writes its records into the Run Log
//! (ADR-0075) beside the store, mirrored to stderr with `--verbose`.
//! The Kad node runner is the one long-lived command and lives in [`kad`].

#![warn(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmule_core::run_log::{self, Level, LevelHandle, RunLog, RunLogFailure};
use rmule_core::{
    AppConfigStore, Core, CoreBuilder, CoreCommand, CoreConfig, CoreError, CoreEvent, CoreSettings,
    CoreSettingsHandle, DownloadCommand, DownloadEvent, DownloadId, DurableAppConfig, DurableStore,
    LongTask, ManagedServer, NameTaken, RuntimeKadFactory, RuntimePeerTransferService,
    RuntimeServeRuntimeService, RuntimeSourceLookupService, ScanEvent, ServerListStore,
    ServerPriority, Setting, SettingError, SettingRefusal, ShareGuards, StopRequest, VolumeStop,
    open_durable_store,
};
use rmule_primitives::{Ed2kLink, SafeFileName, ServerEndpoint};
use rmule_words::download::{
    LinkRefusal, completed_line, completing_line, download_failure_words, hole_less_destination,
    link_refused, source_wait_words, volume_stopped,
};
use rmule_words::reach::{client_udp_bind_failed, half_bound as half_bound_words};

/// Write one line to stdout through [`say_line`], the sink's one sanitiser.
macro_rules! say {
    ($($line:tt)*) => { $crate::say_line(format_args!($($line)*)) };
}

/// [`say!`] on stderr.
macro_rules! say_err {
    ($($line:tt)*) => { $crate::say_err_line(format_args!($($line)*)) };
}

mod kad;

/// The one stdout sink: a server's, a peer's or a link's words reach the
/// terminal as text. The crate denies a bare `println!`.
#[allow(clippy::print_stdout)]
fn say_line(line: fmt::Arguments<'_>) {
    println!("{}", rmule_words::plain(&line.to_string()));
}

/// The one stderr sink, as [`say_line`].
#[allow(clippy::print_stderr)]
fn say_err_line(line: fmt::Arguments<'_>) {
    eprintln!("{}", rmule_words::plain(&line.to_string()));
}

/// The build, as `--version` says it.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("RMULE_BUILD_COMMIT"),
    ")"
);

/// How a run ended short of done. Each is one exit code, which `--help` lists
/// and a script reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// The command line or the link could not be read.
    Unreadable = 2,
    /// The engine refused the download.
    Refused = 3,
    /// The download failed or was cancelled.
    Failed = 4,
    /// No server, no source or no connection.
    NoNetwork = 5,
    /// `--timeout` ran out.
    TimedOut = 6,
    /// A signal asked the run to stop.
    Stopped = 7,
}

/// An error that carries its exit code. Any other leaves as code 1.
#[derive(Debug)]
struct Ended {
    how: Ending,
    words: String,
}

impl fmt::Display for Ended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.words)
    }
}

impl std::error::Error for Ended {}

/// The run ends `how`, saying `words`.
fn ended(how: Ending, words: impl fmt::Display) -> anyhow::Error {
    Ended {
        how,
        words: words.to_string(),
    }
    .into()
}

/// The exit code of a run that failed.
fn exit_code(error: &anyhow::Error) -> u8 {
    error
        .downcast_ref::<Ended>()
        .map_or(1, |ended| ended.how as u8)
}

#[derive(Debug, Parser)]
#[command(
    name = "rmule-cli",
    about = "rmule headless client",
    version = VERSION,
    after_help = rmule_words::cli::EXIT_CODES
)]
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
    Add {
        /// The `ed2k://|file|…|/` link.
        link: String,
        /// Stop after this many seconds, leaving the part file for the next
        /// run. With none, `add` runs until the download ends.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Check the Kad network from this machine.
    Kad {
        #[command(subcommand)]
        command: KadCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KadCommand {
    /// Join the public Kad network for a while and report on the node. A
    /// diagnostic, not a way to run Kad; it saves nothing it hears.
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
    /// Set the directory new downloads keep their part files in, made when
    /// missing; downloads already started keep theirs.
    SetTempDir {
        #[arg(required_unless_present = "default")]
        path: Option<PathBuf>,
        /// Clear the one set: new downloads keep their part files in the
        /// default, `Temp` in the data directory.
        #[arg(long, conflicts_with = "path")]
        default: bool,
    },
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
    install_panic_hook(
        level.clone(),
        opened.is_ok().then(|| data_dir.join(run_log::FILE_NAME)),
    );
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
                    say_err!("{}", no_run_log(failure));
                }
            });
        }
        Err(failure) => say_err!("{}", no_run_log(failure)),
    }
    Ok(level)
}

/// A panic's record first (ADR-0118), then the place and the log in the
/// operator's words on stderr. Past the hook the task ends, or in a dist build
/// the process does.
fn install_panic_hook(level: LevelHandle, log: Option<std::path::PathBuf>) {
    std::panic::set_hook(Box::new(move |info| {
        run_log::panic_record(info, &level);
        let (file, line) = info
            .location()
            .map_or(("unknown", 0), |site| (site.file(), site.line()));
        say_err!("{}", rmule_words::app::fault_at(file, line, log.as_deref()));
    }));
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
    open_durable_store(data_dir).map_err(|error| match error {
        CoreError::StoreRefused { refusal, .. } => {
            anyhow::anyhow!(rmule_words::store::open_refusal(refusal, data_dir))
        }
        other => anyhow::Error::new(other).context(format!("open store in {}", data_dir.display())),
    })
}

fn open_config_store(data_dir: &std::path::Path) -> Result<DurableAppConfig> {
    Ok(DurableAppConfig::new(open_store(data_dir)?))
}

/// Resolve the data directory by the rule `rmule` resolves it by, so both
/// open the same store: `--data-dir`, then the platform's variables.
fn resolve_data_dir(flag: Option<&std::path::Path>) -> anyhow::Result<PathBuf> {
    rmule_core::resolve_data_dir(flag, |name| std::env::var_os(name))
        .map(|dir| dir.path)
        .with_context(|| rmule_words::app::NO_DATA_DIR.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    let _log_drained = run_log::DrainAtExit;
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        // An error can carry a link's or a directory's words, so it leaves
        // through the sink too rather than as `main`'s `Debug` return.
        Err(error) => {
            say_err!("rmule-cli: {error:#}");
            ExitCode::from(exit_code(&error))
        }
    }
}

async fn run() -> Result<()> {
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
                say!("user_hash {hex}");
                say!("nickname  {}", id.nickname().to_display_string());
                say!("tcp_port  {}", id.tcp_port());
            }
        },
        Command::Server { command } => match command {
            ServerCommand::Add { endpoint } => {
                let server = ServerEndpoint::parse_host_port(&endpoint).map_err(|_| {
                    ended(
                        Ending::Unreadable,
                        rmule_words::cli::unreadable_endpoint(&endpoint),
                    )
                })?;
                let store = open_config_store(&data_dir)?;
                let (host, port) = (server.host().to_owned(), server.port());
                store.merge_server(ManagedServer::listed(server))?;
                say!("{}", rmule_words::cli::server_added(&host, port));
            }
            ServerCommand::List => {
                let store = open_config_store(&data_dir)?;
                for server in store.servers()? {
                    // The whole managed row (ADR-0080), not just the endpoint:
                    // a name the list learned from server.met, the operator's
                    // priority and static pin, and the failure tally.
                    say!(
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
                            anyhow::anyhow!(rmule_words::scan::download_dir_not_set(&dir, &reason))
                        }
                        other => other.into(),
                    })?;
                say!("{}", rmule_words::scan::download_dir_line(Some(&dir)));
            }
            ConfigCommand::SetTempDir { path: None, .. } => {
                CoreSettingsHandle::open(open_store(&data_dir)?)
                    .share_guards(share_guards(&data_dir))
                    .set(Setting::TempDir(None))?;
                say!(
                    "{}",
                    rmule_words::scan::temp_dir_line(
                        &CoreSettings::default_temp_dir(&data_dir),
                        true
                    )
                );
            }
            ConfigCommand::SetTempDir {
                path: Some(path), ..
            } => {
                let dir = std::path::absolute(&path)
                    .with_context(|| format!("resolve {}", path.display()))?;
                // Judged against the download directory and every shared
                // directory the store lists, then made, before it is stored.
                CoreSettingsHandle::open(open_store(&data_dir)?)
                    .share_guards(share_guards(&data_dir))
                    .set(Setting::TempDir(Some(dir.clone())))
                    .map_err(|error| match error {
                        SettingError::Refused(SettingRefusal::TempDirRefused(reason)) => {
                            anyhow::anyhow!(rmule_words::scan::temp_dir_not_set(&dir, &reason))
                        }
                        other => other.into(),
                    })?;
                say!("{}", rmule_words::scan::temp_dir_line(&dir, false));
            }
            ConfigCommand::Show => {
                let settings = CoreSettingsHandle::open(open_store(&data_dir)?).read()?;
                say!(
                    "{}",
                    rmule_words::scan::download_dir_line(settings.download_dir.as_deref())
                );
                match &settings.temp_dir {
                    Some(dir) => say!("{}", rmule_words::scan::temp_dir_line(dir, false)),
                    None => say!(
                        "{}",
                        rmule_words::scan::temp_dir_line(
                            &CoreSettings::default_temp_dir(&data_dir),
                            true
                        )
                    ),
                }
            }
        },
        Command::Add { link, timeout } => {
            run_add(&data_dir, &link, timeout, cli.verbose).await?;
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

async fn run_add(
    data_dir: &std::path::Path,
    link_str: &str,
    timeout: Option<u64>,
    verbose: bool,
) -> Result<()> {
    let read = Ed2kLink::read(link_str)
        .map_err(|error| ended(Ending::Unreadable, link_refused(&LinkRefusal::of(&error))))?;
    if let Some(sentence) = rmule_words::cli::skipped_fields(&read.skipped_fields) {
        say!("{sentence}");
    }
    let file = match read.link {
        Ed2kLink::File(file) => file,
        _ => return Err(ended(Ending::Unreadable, rmule_words::cli::NOT_A_FILE_LINK)),
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
        (None, 0) => {
            return Err(ended(
                Ending::NoNetwork,
                rmule_words::cli::NO_SERVER_NO_SOURCE,
            ));
        }
        (None, count) => say!("{}", rmule_words::cli::starting_from_link(count)),
        (Some(_), _) => {}
    }
    let name = SafeFileName::of_link(&file);

    // The Run Log first, so the core's own records from its first instant
    // are in it.
    let log_level = install_run_log(data_dir, &settings_handle, verbose)?;
    let mut core = add_core(data_dir, durable)
        .run_log(log_level)
        // Port mapping (ADR-0086): a firewalled home node is the common rmule
        // deployment, and the backends are installed here rather than defaulted
        // inside core because talking to the operator's router is a deployment
        // decision — a test or a tool holds none and maps nothing. With the
        // operator's switch off, core starts no runtime and these are never
        // spoken to.
        .mapping_backends(rmule_core::live_mapping_backends(port_map_secret))
        .build();

    // The Quit runs on every way out — completion, a refusal, a bail — so the
    // credit checkpoint and `clients.met` are written before the process ends
    // (ADR-0093), and its steps reach the Run Log like any other record.
    let outcome = drive_add(&mut core, file, server, name, timeout).await;
    core.shutdown().await;
    outcome
}

/// Start the download on `core` and follow it to its end: `Ok` once it is
/// complete, an error naming why it is not. The caller quits the core.
async fn drive_add(
    core: &mut Core,
    file: rmule_primitives::Ed2kFileLink,
    server: Option<ServerEndpoint>,
    name: SafeFileName,
    timeout: Option<u64>,
) -> Result<()> {
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
    let mut stop = StopRequest::install().context("install the stop handlers")?;
    let size = file.size;
    let deadline = async {
        match timeout {
            Some(seconds) => tokio::time::sleep(std::time::Duration::from_secs(seconds)).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    // Core places the file in the download directory its settings name, or
    // refuses the start, so a fresh add never lands on a file it did not make.
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: server,
        name,
        if_taken: NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await?;

    let mut download_id: Option<DownloadId> = None;
    let mut parts_done = 0u64;
    let mut parts = None;
    let mut last_wait = None;
    loop {
        let event = tokio::select! {
            event = core.next_event() => event,
            // A stop signal leaves through the caller's Quit, as every other
            // way out does (ADR-0118).
            () = stop.recv() => {
                return Err(ended(Ending::Stopped, rmule_words::app::CLI_STOPPED));
            }
            () = &mut deadline => {
                let seconds = timeout.unwrap_or_default();
                return Err(ended(Ending::TimedOut, rmule_words::cli::timed_out(seconds)));
            }
        };
        let Some(event) = event else {
            anyhow::bail!("{}", rmule_words::cli::ENGINE_ENDED);
        };
        match event {
            // The tasks the actor left would hold the stream open past it.
            CoreEvent::TaskDied {
                task: task @ LongTask::Core,
            } => anyhow::bail!("{}", rmule_words::app::task_died(task)),
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => {
                download_id = Some(id);
                say!("{}", rmule_words::cli::queued(id.as_u64()));
            }
            CoreEvent::CommandRejected { reason } => {
                return Err(ended(
                    Ending::Refused,
                    rmule_words::app::cli_command_rejected(&reason),
                ));
            }
            // What a run that may take days has to show on the way: every
            // line on stderr, so stdout stays the results a script reads.
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total,
                usable_high_id,
                ..
            }) => {
                say_err!("{}", rmule_words::cli::sources_found(total, usable_high_id));
            }
            CoreEvent::Download(DownloadEvent::HashSetReceived { part_count, .. }) => {
                parts = Some(part_count);
            }
            CoreEvent::Download(DownloadEvent::PartVerified { .. }) => {
                parts_done += 1;
                say_err!(
                    "{}",
                    rmule_words::cli::part_verified(parts_done, parts, size)
                );
            }
            CoreEvent::Download(DownloadEvent::WaitingForSources { reason, .. })
                if last_wait != Some(reason) =>
            {
                last_wait = Some(reason);
                say_err!("{}", source_wait_words(reason));
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted {
                download_id: id,
                final_path,
            }) => {
                say!("{}", completed_line(id, &final_path));
                return Ok(());
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                return Err(ended(
                    Ending::Failed,
                    rmule_words::cli::download_failed(
                        &download_label(download_id),
                        &download_failure_words(&reason),
                    ),
                ));
            }
            // Core waits for a connection (ADR-0097); this one-shot run has
            // no operator to connect, so a wait would never end.
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) if serverless => {
                return Err(ended(
                    Ending::NoNetwork,
                    rmule_words::app::cli_no_connection(
                        &download_label(download_id),
                        rmule_words::app::NoConnection::NoSourceUsable,
                    ),
                ));
            }
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) => {
                return Err(ended(
                    Ending::NoNetwork,
                    rmule_words::app::cli_no_connection(
                        &download_label(download_id),
                        rmule_words::app::NoConnection::ServerSilent,
                    ),
                ));
            }
            CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) => {
                return Err(ended(
                    Ending::Failed,
                    rmule_words::cli::download_cancelled(&download_label(download_id)),
                ));
            }
            // Each step of the completion move that waits or copies, as it
            // begins (ADR-0115): a copy across disks or a held file can take
            // a while, and the one-shot run says why it has not ended.
            CoreEvent::Download(DownloadEvent::Completing { step, to, .. }) => {
                say!("{}", completing_line(step, &to));
            }
            // The run's disk holds no holes (ADR-0111): the download goes on,
            // and this edge is the only place the CLI hears of it.
            CoreEvent::Download(DownloadEvent::HoleLessDestination { directory, .. }) => {
                say!(
                    "{}",
                    hole_less_destination(&download_label(download_id), &directory)
                );
            }
            // The volume paused the download (ADR-0094). A stop for free
            // space resumes itself; any other waits for an operator this
            // one-shot run does not have.
            CoreEvent::Download(DownloadEvent::VolumeStopped {
                directory, stop, ..
            }) => {
                let line = volume_stopped(&download_label(download_id), &directory, stop);
                if !matches!(stop, VolumeStop::OutOfSpace { .. }) {
                    return Err(ended(Ending::Failed, line));
                }
                say!("{line}");
            }
            // The one client-UDP socket never bound at core start (ADR-0057):
            // non-fatal to this download (it runs over the
            // server-relayed and TCP-only paths), but reask, NAT-T and Kad
            // are off for the rest of the process, so it is worth a line
            // even though nothing here ever sends `EnableKad`.
            CoreEvent::ClientUdpBindFailed { port, kind } => {
                say!("{}", client_udp_bind_failed(port, kind));
            }
            // Half of the same story: the pair came up, but
            // without a family it selected, so some of what rides it is off
            // for the rest of the process. Worth a line for the same reason
            // the total failure is.
            CoreEvent::SocketBoundWithoutFamily { half_bound } => {
                say!("{}", half_bound_words(&half_bound));
            }
            // The download still finishes there; only the sharing is off.
            CoreEvent::Scan(ScanEvent::DownloadDirectoryRefused { dir, reason }) => {
                say!(
                    "{}",
                    rmule_words::app::cli_download_dir_not_shared(&dir, &reason)
                );
            }
            _ => {}
        }
    }
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
    // The Connection Ceiling under the open-descriptor limit, raised once
    // here, at start (ADR-0116); a lowered Ceiling is said once.
    let (peer_connections, lowered) = CoreConfig::default()
        .peer_connections
        .within_descriptors(rmule_os::descriptors::raise_descriptor_limit());
    if let Some(lowered) = lowered {
        say_err!("{}", rmule_words::download::ceiling_lowered(lowered));
    }
    let config = CoreConfig {
        peer_connections,
        ..CoreConfig::default()
    };
    Core::builder(config, durable)
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
        || rmule_words::cli::NOT_YET_QUEUED.to_owned(),
        |id| rmule_words::cli::download_label(id.as_u64()),
    )
}

/// The word `server list` prints for a server's priority.
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
