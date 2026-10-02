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

use std::sync::Arc;

use rmule_bootstrap::{
    BootstrapConfig, FetchError, Fetcher, ReqwestFetcher, should_auto_fetch_server_met,
};
use rmule_core::port_mapping::{PortMappingConfig, PortMappingMode};
use rmule_core::{
    AppConfigStore, ClientCredentials, Core, CoreCommand, CoreConfig, DurableAppConfig,
    KadEnableConfig, MappingBackend, ServerListCommand, ServerListStore, open_durable_store,
};

use crate::args::DataDir;
use crate::config::{Preferences, SharedConfig};
use crate::connect::AtStart;
use crate::state::{AttachFailure, SessionConfig};

/// The two capabilities attaching hands core that reach past this host: the
/// HTTP fetch the server-list update and the Kad seed acquisition share, and
/// the backends port mapping talks to the router through. Given rather than
/// built inside, because talking to a mirror or a router is a deployment
/// decision: the app takes [`Live`], a test a canned fetch and no backends.
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
}

/// Everything the Kad join needs once the app arms it. Assembled during
/// attachment — its config and both mirror URLs are startup reads, so a later
/// Settings edit to either is restart-shaped and says so — but *run* only on
/// the first eD2k login or the operator's `K`, so a cold-start acquisition can
/// neither delay the first frame nor happen unattended.
pub struct KadJoin<F> {
    /// The Kad start config, seeds still unresolved.
    pub config: KadEnableConfig,
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

    let identity = store
        .ensure_identity()
        .map_err(|error| attach_failed(AttachFailure::Identity, &error))?;
    // The durable Kad node identity (ADR-0043): generate-once, so a restarted
    // node keeps its keyspace position and its advertised UDP port.
    let kad_identity = store
        .ensure_kad_identity()
        .map_err(|error| attach_failed(AttachFailure::KadIdentity, &error))?;
    // The per-install Kad UDP Key: generate-once, so the verify
    // keys the network learned for this node survive a restart.
    let kad_udp_key = store
        .ensure_kad_udp_key()
        .map_err(|error| attach_failed(AttachFailure::KadUdpKey, &error))?;
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
    // Everything the Settings tab edits, read once. From here the store
    // is *shared*: the builder gets a clone of the seam as the narrow
    // `ServerListStore` (ADR-0080) and the front-end keeps the whole
    // `AppConfigStore` — same handle, no lock (ADR-0083).
    let config = SharedConfig::new(store.clone());
    let preferences = config
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
    // every seam method is `&self`, so nothing locks).
    // The one UDP port the operator configured (ADR-0057): the reask surface,
    // the NAT-T frames and the Kad node all bind it, so it is core config and
    // no longer something `EnableKad` carries.
    let core = Core::builder(
        CoreConfig {
            udp_port: preferences.udp_port,
            // The one obfuscation policy (ADR-0046): peer TCP, peer UDP and
            // the Kad node's datagram crypt.
            peer_crypt: preferences.obfuscation.policy(),
            // The peers each download keeps for a restart (ADR-0109).
            remember_peers: preferences.remember_peers,
            // Whether the mapping runtime starts at all (ADR-0086). Core
            // starts it once, at build, so the switch holds until a restart.
            port_mapping: PortMappingConfig {
                mode: if preferences.port_mapping {
                    PortMappingMode::Auto
                } else {
                    PortMappingMode::Off
                },
                ..PortMappingConfig::default()
            },
            ..CoreConfig::default()
        },
        durable,
    )
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
    // decides which, and presents the same credentials a Resume would.
    .restore_credentials(ClientCredentials::from(identity.clone()))
    // The Shared Directory List's guards (ADR-0101): core never reads the
    // environment, so the home and the data directory are named here.
    .share_guards(rmule_core::ShareGuards {
        home: rmule_core::home_dir(|name| std::env::var_os(name)),
        data_dir: Some(data_dir.clone()),
    })
    .build();

    // ADR-0065's first-run fetch, through the actor (see the module docs).
    if should_auto_fetch_server_met(true, listed.is_empty(), bootstrap.auto_fetch_server_met) {
        let url = bootstrap.server_met_url.clone();
        let update = CoreCommand::ServerList(ServerListCommand::UpdateServerList { url });
        // A core that cannot take its first command is gone; the bridge
        // reports the closed core, so the run still opens.
        if let Err(error) = core.send(update).await {
            tracing::warn!(%error, "first-run server list fetch could not be sent");
        }
    }

    let session = SessionConfig {
        server,
        // No SUI key: the Core loaded it from `durable` at build.
        credentials: ClientCredentials::from(identity),
        download_dir: preferences.download_dir.clone(),
    };
    let kad_config =
        crate::kad::enable_config(&data_dir, kad_identity, kad_udp_key, &session.credentials);
    let kad = KadJoin {
        config: kad_config,
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
    })
}
