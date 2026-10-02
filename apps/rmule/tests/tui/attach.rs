//! The app's construction path, `rmule::attach`, over a scratch data
//! directory: the same core `main` builds, with the one swap a test needs — a
//! canned fetch and no router backends, so nothing here reaches past the host.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule::attach::{Attachment, Deployment, attach};
use rmule_bootstrap::{BootstrapConfig, FetchError, Fetcher};
use rmule_core::port_mapping::MappingProtocol;
use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreEvent, DataDir, DataDirSource, DurableAppConfig,
    LoginStep, ManagedServer, MappingBackend, Preference, ServerConnectFailure,
    ServerConnectionEvent, ServerListEvent, ServerListStore, open_durable_store,
};
use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};
use rmule_testkit::ScriptedBackend;

/// A fetch that answers from memory — `body`, or a timeout without one — and
/// records every URL asked of it.
#[derive(Clone, Default)]
struct CannedFetch {
    body: Option<Arc<Vec<u8>>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl CannedFetch {
    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

impl Fetcher for CannedFetch {
    fn get(
        &self,
        url: &str,
        _max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> + Send {
        self.asked.lock().expect("asked").push(url.to_owned());
        let answer = match &self.body {
            Some(body) => Ok(body.to_vec()),
            None => Err(FetchError::Timeout {
                url: url.to_owned(),
            }),
        };
        async move { answer }
    }
}

/// A `server.met` listing `servers`, untagged.
fn server_met(servers: &[(Ipv4Addr, u16)]) -> Vec<u8> {
    let mut bytes = vec![0xE0];
    bytes.extend_from_slice(&u32::try_from(servers.len()).expect("count").to_le_bytes());
    for (ip, port) in servers {
        bytes.extend_from_slice(&Ipv4Endpoint::new(*ip, *port).encode());
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes
}

/// The test deployment: the canned fetch, and scripted Mapping Backends or
/// none, so nothing speaks to a real mirror or router.
#[derive(Default)]
struct Scratch {
    fetch: CannedFetch,
    backends: Vec<Arc<dyn MappingBackend>>,
}

impl Deployment for Scratch {
    type Fetcher = CannedFetch;

    fn fetcher(&self, _bootstrap: &BootstrapConfig) -> Result<CannedFetch, FetchError> {
        Ok(self.fetch.clone())
    }

    fn mapping_backends(&self, _port_map_secret: u32) -> Vec<Arc<dyn MappingBackend>> {
        self.backends.clone()
    }
}

/// A scratch data directory whose store is seeded by `seed` and closed again
/// before the app opens it — the engine's file lock admits one opener.
fn data_dir(seed: impl FnOnce(&DurableAppConfig)) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DurableAppConfig::new(open_durable_store(dir.path()).expect("open the store"));
    // Ephemeral ports: the core binds its client UDP socket at start and its
    // eD2k listener before a login, and a fixed port would fight any other
    // client on this host.
    store.ensure_identity().expect("identity");
    store.ensure_kad_identity().expect("kad identity");
    store.set_tcp_port(0).expect("tcp port");
    store.set_udp_port(0).expect("udp port");
    seed(&store);
    dir
}

async fn attach_in(dir: &tempfile::TempDir, deployment: &Scratch) -> Attachment<CannedFetch> {
    let resolved = DataDir {
        path: dir.path().to_path_buf(),
        source: DataDirSource::Flag,
    };
    match attach(Some(resolved), deployment).await {
        Ok(attachment) => attachment,
        Err(failure) => panic!("the core did not attach: {failure:?}"),
    }
}

/// The core's server-list edges up to the answer to a `DumpDiagnostics` sent
/// now. Commands are taken in order, so every list edge the attach's own
/// commands caused at once is in what this returns.
async fn list_edges_so_far(core: &mut Core) -> Vec<ServerListEvent> {
    core.send(CoreCommand::DumpDiagnostics)
        .await
        .expect("the core takes the dump");
    let mut edges = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match core.next_event().await.expect("core alive") {
                CoreEvent::DiagnosticsSnapshot { .. } => return,
                CoreEvent::ServerList(edge) => edges.push(edge),
                _ => {}
            }
        }
    })
    .await
    .expect("the dump answers within 10s");
    edges
}

/// ADR-0065's first run: a fresh data directory has no servers, so attaching
/// fetches `server.met` from the default mirror once and lists what it holds
/// — through the fetch the deployment gave the core, without a key press.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_data_dir_fetches_its_server_list_once_at_attach() {
    let dir = data_dir(|_| {});
    let fetch = CannedFetch {
        body: Some(Arc::new(server_met(&[
            (Ipv4Addr::new(198, 51, 100, 7), 4661),
            (Ipv4Addr::new(198, 51, 100, 8), 4242),
        ]))),
        ..CannedFetch::default()
    };
    let deployment = Scratch {
        fetch: fetch.clone(),
        ..Scratch::default()
    };

    let Attachment { mut core, .. } = attach_in(&dir, &deployment).await;
    let updated = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match core.next_event().await.expect("core alive") {
                CoreEvent::ServerList(ServerListEvent::ServerListUpdated {
                    added, total, ..
                }) => {
                    return (added, total);
                }
                CoreEvent::ServerList(ServerListEvent::ServerListUpdateFailed { reason }) => {
                    panic!("the first-run fetch failed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the first-run fetch lands within 10s");

    assert_eq!(updated, (2, 2), "both rows listed, into the empty list");
    assert_eq!(
        fetch.asked(),
        [rmule_bootstrap::DEFAULT_SERVER_MET_URL],
        "one fetch, from the default mirror"
    );
}

/// The off switch: with `auto_fetch_server_met` off, a fresh data directory
/// starts with its empty list and nothing is fetched.
#[tokio::test(flavor = "multi_thread")]
async fn the_off_switch_keeps_a_first_run_from_fetching() {
    let dir = data_dir(|store| {
        store
            .set_preference(Preference::AutoFetchServerMet, "false")
            .expect("turn the fetch off");
    });
    let deployment = Scratch::default();

    let Attachment { mut core, .. } = attach_in(&dir, &deployment).await;

    assert_eq!(list_edges_so_far(&mut core).await, []);
    assert_eq!(deployment.fetch.asked(), Vec::<String>::new());
}

/// A listed server inside the range a scratch `ipfilter.dat` blocks.
fn filtered_server() -> ServerEndpoint {
    ServerEndpoint::new("198.51.100.7", 4661).expect("endpoint")
}

/// A scratch data directory listing [`filtered_server`] beside an
/// `ipfilter.dat` that blocks it, seeded further by `seed`.
fn filtered_data_dir(seed: impl FnOnce(&DurableAppConfig)) -> tempfile::TempDir {
    let dir = data_dir(|store| {
        store
            .merge_server(ManagedServer::listed(filtered_server()))
            .expect("list the server");
        seed(store);
    });
    std::fs::write(
        dir.path().join("ipfilter.dat"),
        b"198.51.100.0-198.51.100.255,0,test range\n",
    )
    .expect("write the filter");
    dir
}

/// Attach over `dir` and connect to [`filtered_server`]: the login steps the
/// core reported, then why the connect failed. The filter refuses before the
/// dial, so nothing leaves the host.
async fn connect_to_the_filtered_server(
    dir: &tempfile::TempDir,
    deployment: &Scratch,
) -> (Vec<LoginStep>, ServerConnectFailure) {
    let Attachment {
        mut core, session, ..
    } = attach_in(dir, deployment).await;
    core.send(CoreCommand::ConnectToServer {
        server: filtered_server(),
        credentials: session.credentials,
    })
    .await
    .expect("the core takes the connect");

    let mut steps = Vec::new();
    // The login mapping wait is bounded at 10 s when no gateway answers.
    let reason = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match core.next_event().await.expect("core alive") {
                CoreEvent::ServerLogin { step, .. } => steps.push(step),
                CoreEvent::ServerConnection(ServerConnectionEvent::ConnectFailed {
                    server,
                    reason,
                }) if server == filtered_server() => return reason,
                _ => {}
            }
        }
    })
    .await
    .expect("the connect ends within 30s");
    (steps, reason)
}

/// `rmule-cli` builds its core over `ipfilter.dat` in the data directory, and
/// so does the app: a listed server inside a blocked range is refused before
/// any dial, with the filter named as the reason.
#[tokio::test(flavor = "multi_thread")]
async fn the_app_core_refuses_a_server_its_ip_filter_blocks() {
    let dir = filtered_data_dir(|_| {});
    let (_, reason) = connect_to_the_filtered_server(&dir, &Scratch::default()).await;
    assert_eq!(reason, ServerConnectFailure::Filtered);
}

/// With mapping backends installed, does the login wait on the listener's
/// router mapping before it leaves — the mark of a running mapping runtime?
async fn login_waits_on_a_mapping(port_mapping: &str) -> bool {
    let dir = filtered_data_dir(|store| {
        store
            .set_preference(Preference::PortMapping, port_mapping)
            .expect("set port mapping");
    });
    let deployment = Scratch {
        backends: vec![Arc::new(ScriptedBackend::available(MappingProtocol::Pcp))],
        ..Scratch::default()
    };
    let (steps, _) = connect_to_the_filtered_server(&dir, &deployment).await;
    steps
        .iter()
        .any(|step| matches!(step, LoginStep::MappingWait { .. }))
}

/// The Settings switch reaches core: on (the default), the mapping runtime
/// runs and a login waits on the listener's mapping; off, core starts no
/// runtime, so nothing ever speaks to the router.
#[tokio::test(flavor = "multi_thread")]
async fn the_port_mapping_switch_starts_or_withholds_the_mapping_runtime() {
    assert!(login_waits_on_a_mapping("true").await, "on: mapped first");
    assert!(!login_waits_on_a_mapping("false").await, "off: no mapping");
}
