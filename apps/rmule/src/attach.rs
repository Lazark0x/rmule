//! Standing the core up for one run (ADR-0069 data-dir layout, ADR-0083 one
//! `rmule.redb` per process): open the one Durable Store, mint-or-load the
//! identities, build the core over that store's seams with every adapter a run
//! needs, start the first-run `server.met` fetch when the list is empty, and
//! assemble what the app owes core once it is attached.
//!
//! `main` and the tests run this one path, so what a test proves of the core
//! it builds — the IP filter it loads, the list it fetches on a first run — is
//! what the app runs. The only things a test swaps are the ones that reach
//! past this host, through [`Deployment`].
//!
//! # The first-run fetch goes through the actor
//!
//! ADR-0065's first-run fetch is the second step of ADR-0067's Join Sequence,
//! and the app does not run that sequence whole: once core holds the
//! server-list store, its actor is the list's only writer (ADR-0080). So the
//! app takes the sequence's own gate, `should_auto_fetch_server_met`, and
//! sends the acquisition as the `UpdateServerList` command — the same
//! acquisition the sequence runs, on the actor, and what Networks' `U` sends.
//! The app has no switch that disables eD2k — connecting is the operator's
//! act (ADR-0095), and a listed server is what they connect to — so the gate
//! reads eD2k as on. The fetch dials no server, and it is one-shot like
//! amuled's: a failure waits for the operator.
//!
//! The server.met auto-update walk (ADR-0065), when the operator turned it
//! on, goes the same way as the `AutoUpdateServerList` command. Both share
//! the actor's one update slot, so when a first run is due too its mirror
//! goes in front of the walk's addresses and one walk runs.

use std::sync::Arc;

use rmule_bootstrap::{
    BootstrapConfig, FetchError, Fetcher, ReqwestFetcher, should_auto_fetch_server_met,
};
use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreConfig, DurableAppConfig, KadEnableConfig,
    MappingBackend, ServerListCommand, ServerListStore, open_durable_store,
};

use crate::args::DataDir;
use crate::config::{Preferences, SharedConfig};
use crate::connect::AtStart;
use crate::state::{AttachFailure, SessionConfig};

/// What attaching hands core from past this process: the HTTP fetch the
/// server-list update and the Kad seed acquisition share, the backends port
/// mapping talks to the router through, and the operator's home directory the
/// share guards refuse. Given rather than built inside, because talking to a
/// mirror or a router, and whose machine this is, are deployment facts: the
/// app takes [`Live`], a test a canned fetch, no backends and a scratch home.
pub trait Deployment {
    /// The fetch this deployment makes.
    type Fetcher: Fetcher + Clone + Send + Sync + 'static;

    /// The fetch, built from the mirror config the preferences name.
    ///
    /// # Errors
    ///
    /// When the HTTP client cannot be built.
    fn fetcher(&self, bootstrap: &BootstrapConfig) -> Result<Self::Fetcher, FetchError>;

    /// The Mapping Backends (ADR-0086), keyed by the install's PCP nonce
    /// secret. Empty maps nothing.
    fn mapping_backends(&self, port_map_secret: u32) -> Vec<Arc<dyn MappingBackend>>;

    /// The operator's home directory, which no shared directory may be
    /// (ADR-0101), or `None` when it cannot be named.
    fn home(&self) -> Option<std::path::PathBuf>;
}

/// The shipped app's deployment: `reqwest` for the mirrors, and PCP, NAT-PMP
/// and UPnP-IGD for the router.
#[derive(Clone, Copy, Debug, Default)]
pub struct Live;

impl Deployment for Live {
    type Fetcher = ReqwestFetcher;

    fn fetcher(&self, bootstrap: &BootstrapConfig) -> Result<ReqwestFetcher, FetchError> {
        ReqwestFetcher::from_config(bootstrap)
    }

    fn mapping_backends(&self, port_map_secret: u32) -> Vec<Arc<dyn MappingBackend>> {
        rmule_core::live_mapping_backends(port_map_secret)
    }

    fn home(&self) -> Option<std::path::PathBuf> {
        rmule_core::home_dir(|name| std::env::var_os(name))
    }
}

/// Everything attaching produced: the core itself, the session facts views
/// build real commands from, the config store the Settings tab edits, the Kad
/// join the app owes core, and what the start does about connecting.
pub struct Attachment<F> {
    /// The core, built and running, before any front-end command.
    pub core: Core,
    /// The session facts views build real commands from.
    pub session: SessionConfig,
    /// The config store the Settings tab edits.
    pub config: SharedConfig,
    /// The preferences as the store holds them at attach.
    pub preferences: Preferences,
    /// The Kad join, assembled here and run by the app later.
    pub kad: KadJoin<F>,
    /// What the start does about connecting (ADR-0095): nothing unless the
    /// operator turned connect at start on.
    pub at_start: AtStart,
    /// The Connection Ceiling the open-descriptor limit lowered at attach,
    /// for the operator to read why (ADR-0116).
    pub ceiling_lowered: Option<rmule_core::CeilingLowered>,
}

/// Everything the Kad join needs once the app arms it. Assembled during
/// attachment — its config and both mirror URLs are startup reads, so a later
/// Settings edit to either is restart-shaped and says so — but *run* only on
/// the first eD2k login or the operator's `K`, so a cold-start acquisition can
/// neither delay the first frame nor happen unattended.
pub struct KadJoin<F> {
    /// The Kad start config, seeds still unresolved.
    pub config: KadEnableConfig,
    /// The node's Kad ID, which the seeds are resolved about.
    pub own_id: rmule_core::KadId,
    /// The mirror config the seed acquisition reads.
    pub bootstrap: BootstrapConfig,
    /// The fetch the seed acquisition runs through.
    pub fetcher: F,
}

/// Trace why attaching failed, for the Run Log, and hand back the step.
fn attach_failed(failure: AttachFailure, error: &dyn std::fmt::Display) -> AttachFailure {
    tracing::warn!(
        step = crate::words::app::attach_failure_words(failure),
        %error,
        "the core could not be attached"
    );
    failure
}

/// Stand up the real core over the one Durable Store in `resolved` (the
/// rmule-cli wiring), and send it the first-run `server.met` fetch when the
/// list is empty and the preference allows it. Any failure returns the step
/// that failed, and what the store or the client said goes to the Run Log.
///
/// # Errors
///
/// The step that failed: no data directory, a store that would not open, an
/// identity or preference that could not be read, or an HTTP client that
/// could not be built.
pub async fn attach<D: Deployment>(
    resolved: Option<DataDir>,
    deployment: &D,
) -> Result<Attachment<D::Fetcher>, AttachFailure> {
    let resolved = resolved.ok_or(AttachFailure::NoDataDir)?;
    let data_dir = resolved.path.clone();
    // The one store open of the process: every durable seam below is a view
    // over this handle, and the engine's file lock makes a second app on the
    // same data dir fail here rather than race.
    let durable = open_durable_store(&data_dir)
        .map_err(|error| attach_failed(AttachFailure::OpenStore, &error))?;
    let store = DurableAppConfig::new(Arc::clone(&durable));

    // The per-install PCP nonce secret (ADR-0086): generate-once, so a restart
    // can renew and delete the mappings this install already holds.
    let port_map_secret = store
        .ensure_port_map_secret()
        .map_err(|error| attach_failed(AttachFailure::PortMapSecret, &error))?;
    // The default server activity commands name. An empty list is not fatal:
    // the Servers tab can add one or fetch a whole list, and only
    // search/download degrade until it does.
    let listed: Vec<_> = store
        .servers()
        .map_err(|error| attach_failed(AttachFailure::Servers, &error))?
        .into_iter()
        .map(|listed| listed.endpoint)
        .collect();
    let server = listed.first().cloned();
    // Everything the Settings tab shows, read once, before a core runs. From
    // here the store is *shared*: the builder opens its own seams on it and
    // the front end keeps a view — same handle, no lock (ADR-0083).
    let preferences = SharedConfig::open(Arc::clone(&durable))
        .load(Some(resolved))
        .map_err(|error| attach_failed(AttachFailure::Preferences, &error))?;

    // Core links no HTTP client of its own (ADR-0080): the fetch capability
    // for `UpdateServerList` is injected, and its absence would be refused
    // rather than silently ignored. This is the one place rmule supplies it.
    //
    // `auto_fetch_nodes_dat` is the app's one deliberate divergence from
    // aMule (ADR-0067 amendment): the library default is OFF because
    // aMule never fetches nodes.dat unattended, but aMule's three recovery
    // routes assume a Kad bootstrap-from-URL control this UI does not have
    // yet. Without the opt-in, a fresh install's Kad would stay stranded
    // until the user happened to open a peer session. It is a *preference*
    // rather than a hardcode — defaulting to the opt-in, and something an
    // operator can turn back off — as are both mirror URLs.
    let bootstrap = BootstrapConfig {
        auto_fetch_server_met: preferences.auto_fetch_server_met,
        auto_update_enabled: preferences.auto_update_server_met,
        auto_update_urls: preferences.server_met_auto_update_urls.clone(),
        auto_fetch_nodes_dat: preferences.auto_fetch_nodes_dat,
        server_met_url: preferences.server_met_url.clone(),
        nodes_dat_url: preferences.nodes_dat_url.clone(),
        ..BootstrapConfig::default()
    };
    let fetcher = deployment
        .fetcher(&bootstrap)
        .map_err(|error| attach_failed(AttachFailure::HttpClient, &error))?;

    // Core runs on the same open store this file opened: its download
    // repository, shared-file registry and managed server list are all seams
    // on that one handle, so the Servers tab and the core actor read one list
    // (ADR-0080: `AppConfigStore` is a `ServerListStore` supertrait; ADR-0083:
    // every seam method is `&self`, so nothing locks). The operator's Core
    // Settings — the UDP port, the obfuscation policy, `Remember peers`, the
    // port-mapping switch — come off that handle too (ADR-0069).
    // The Connection Ceiling under the open-descriptor limit, raised once
    // here, at start (ADR-0116).
    let (peer_connections, ceiling_lowered) = CoreConfig::default()
        .peer_connections
        .within_descriptors(rmule_os::descriptors::raise_descriptor_limit());
    let config = CoreConfig {
        peer_connections,
        ..CoreConfig::default()
    };
    let core = Core::builder(config, durable)
        .server_list_fetcher(fetcher.clone())
        // Credit-ring continuity: seed from and flush to clients.met beside
        // the other data files (ADR-0066).
        .persist_credit_in(data_dir.clone())
        // IP filtering, as `rmule-cli` loads it: `ipfilter.dat`, then
        // `ipfilter_static.dat` on top, from the data directory, at the
        // `CoreConfig` level and gates. Absent files are an empty filter —
        // aMule's out-of-box posture.
        .ip_filter_dir(data_dir.clone())
        // Port mapping (ADR-0086): the backends are the deployment's, because
        // talking to the operator's router is a deployment decision — a test
        // holds scripted ones or none. With the operator's switch off, core
        // starts no runtime and these are never spoken to.
        .mapping_backends(deployment.mapping_backends(port_map_secret))
        // The downloads Quit left running start again at attach (ADR-0094): core
        // decides which. Every login, hello and Kad dial presents the Core
        // Settings' nickname and port, and the Kad identity is the store's,
        // read by core itself (ADR-0069).
        .restore_at_attach()
        // The Shared Directory List's guards (ADR-0101), the download
        // directory's among them: core never reads the environment, so the
        // home and the data directory are named here.
        .share_guards(rmule_core::ShareGuards {
            home: deployment.home(),
            data_dir: Some(data_dir.clone()),
        })
        .build();

    // The Settings tab's door from here on is the running core's own, so a
    // live key is taken up at once (ADR-0069).
    let config = SharedConfig::new(core.settings(), store.clone());

    // ADR-0065's first-run fetch and auto-update walk, through the actor
    // (see the module docs).
    if let Some(acquisition) = list_acquisition_at_start(&bootstrap, listed.is_empty()) {
        // A core that cannot take its first command is gone; the bridge
        // reports the closed core, so the run still opens.
        if let Err(error) = core.send(CoreCommand::ServerList(acquisition)).await {
            tracing::warn!(%error, "the server list acquisition at start could not be sent");
        }
    }

    let session = SessionConfig {
        server,
        download_dir: preferences.download_dir.clone(),
    };
    let kad = KadJoin {
        config: crate::kad::enable_config(&data_dir),
        own_id: core.kad_id(),
        bootstrap,
        fetcher,
    };
    let at_start = crate::connect::at_start(
        preferences.connect_at_start,
        preferences.last_server.as_ref(),
        &listed,
    );

    Ok(Attachment {
        core,
        session,
        config,
        preferences,
        kad,
        at_start,
        ceiling_lowered,
    })
}

/// What the app sends core at start to grow the server list (ADR-0065): the
/// auto-update walk when its switch is on, with the first-run mirror in
/// front of its addresses when a first run is due too, so one acquisition
/// runs; else the first-run fetch alone when it is due; else nothing.
fn list_acquisition_at_start(
    bootstrap: &BootstrapConfig,
    list_empty: bool,
) -> Option<ServerListCommand> {
    let first_run = should_auto_fetch_server_met(true, list_empty, bootstrap.auto_fetch_server_met);
    if bootstrap.auto_update_enabled {
        let urls = first_run
            .then(|| bootstrap.server_met_url.clone())
            .into_iter()
            .chain(bootstrap.auto_update_urls.iter().cloned())
            .collect();
        return Some(ServerListCommand::AutoUpdateServerList { urls });
    }
    first_run.then(|| ServerListCommand::UpdateServerList {
        url: bootstrap.server_met_url.clone(),
    })
}
