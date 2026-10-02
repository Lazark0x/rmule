//! `rmule-cli` — the headless rmule client: a thin command router over
//! `rmule-core`. Each subcommand opens the one Durable Store in the data
//! directory (ADR-0083), issues one core command, and prints what the core
//! reports;
//! the Kad node runner is the one long-lived command and lives in [`kad`].

#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmule_core::{
    AppConfigStore, ClientCredentials, Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadId, DurableAppConfig, DurableStore, ManagedServer, ServerListStore,
    ServerPriority, open_durable_store,
};
use rmule_primitives::{Ed2kLink, SafeFileName, ServerEndpoint};

mod kad;

#[derive(Debug, Parser)]
#[command(name = "rmule-cli", about = "rmule headless client")]
struct Cli {
    /// Directory holding rmule's Durable Store (`rmule.redb`) and data files.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
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

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("RMULE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
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
    init_tracing();
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
        Command::Config { command } => match command {
            ConfigCommand::SetDownloadDir { path } => {
                let store = open_config_store(&data_dir)?;
                store.set_download_dir(&path)?;
                println!("download_dir {}", path.display());
            }
            ConfigCommand::Show => {
                let store = open_config_store(&data_dir)?;
                match store.download_dir()? {
                    Some(dir) => println!("download_dir {}", dir.display()),
                    None => println!("download_dir <unset>"),
                }
            }
        },
        Command::Add { link } => {
            run_add(&data_dir, &link).await?;
        }
        Command::Kad { command } => match command {
            KadCommand::Join {
                bootstrap,
                duration,
                search,
            } => {
                let store = open_config_store(&data_dir)?;
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

async fn run_add(data_dir: &std::path::Path, link_str: &str) -> Result<()> {
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
    let identity = store.ensure_identity()?;
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
    let download_dir = store.download_dir()?.context(
        "no download directory configured; run `rmule-cli config set-download-dir <path>`",
    )?;
    let output_path = SafeFileName::of_link(&file).path_in(&download_dir);

    let config = CoreConfig::default();
    // The builder's default adapter set (shared session, ban store, IP
    // filter) over the one open store: every seam core needs — downloads, the
    // registry a completed download auto-shares into, and the managed server
    // list `server add` writes (ADR-0080/ADR-0083) — comes off that handle.
    // Overriding `source_lookup`/`peer_transfer` here would hand the dial path
    // unfiltered, ban-less adapters; the defaults cost a download-only run
    // nothing, since the dialed-serve sink never holds a sender without a
    // serve activity.
    let mut core = Core::builder(config, durable)
        // Credit-ring continuity: seed from and flush to
        // clients.met beside the other data files.
        .persist_credit_in(data_dir.to_path_buf())
        // IP filtering: `ipfilter.dat` + `ipfilter_static.dat`
        // load from the same data dir when present; absent files mean an
        // empty filter, exactly aMule's out-of-box posture.
        .ip_filter_dir(data_dir.to_path_buf())
        // Port mapping (ADR-0086): a firewalled home node is the common rmule
        // deployment, and the backends are installed here rather than defaulted
        // inside core because talking to the operator's router is a deployment
        // decision — a test or a tool holds none and maps nothing.
        .mapping_backends(rmule_core::live_mapping_backends(port_map_secret))
        .build();

    // The operator's word, given by running this command (ADR-0095,
    // "Connecting is the operator's act"): the one login — listener, mapping,
    // then the dial — and the download rides the session it makes.
    if let Some(server) = &server {
        core.send(CoreCommand::ConnectToServer {
            server: server.clone(),
            credentials: ClientCredentials::from(identity.clone()),
        })
        .await?;
    }
    let serverless = server.is_none();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: server,
        // No SUI key: the Core loaded it from `durable` at build.
        credentials: ClientCredentials::from(identity),
        output_path: output_path.clone(),
    }))
    .await?;

    let mut download_id: Option<DownloadId> = None;
    loop {
        let Some(event) = core.next_event().await else {
            anyhow::bail!("core event stream ended before the download completed");
        };
        match event {
            CoreEvent::Download(DownloadEvent::DownloadQueued {
                download_id: id, ..
            }) => {
                download_id = Some(id);
                println!("queued id={}", id.as_u64());
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { download_id: id }) => {
                println!(
                    "completed id={} path={}",
                    id.as_u64(),
                    output_path.display()
                );
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
            // The one client-UDP socket never bound at core start (ADR-0057):
            // non-fatal to this download (it runs over the
            // server-relayed and TCP-only paths), but reask, NAT-T and Kad
            // are off for the rest of the process, so it is worth a line
            // even though nothing here ever sends `EnableKad`.
            CoreEvent::ClientUdpBindFailed { port, kind } => {
                println!("{}", CoreEvent::client_udp_bind_failed_message(port, kind));
            }
            // Half of the same story: the pair came up, but
            // without a family it selected, so some of what rides it is off
            // for the rest of the process. Worth a line for the same reason
            // the total failure is.
            CoreEvent::SocketBoundWithoutFamily { half_bound } => {
                println!("{half_bound}");
            }
            other => {
                tracing::debug!(?other, "core event");
            }
        }
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
