//! The app's construction path, `rmule::attach`, over a scratch data
//! directory: the same core `main` builds, with the one swap a test needs — a
//! canned fetch and no router backends, so nothing here reaches past the host.

use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule::attach::{Attachment, Deployment, attach};
use rmule::config::PrefEdit;
use rmule_bootstrap::{BootstrapConfig, FetchError, Fetcher};
use rmule_core::port_mapping::{MappingProtocol, PortMappingMode};
use rmule_core::{
    Core, CoreCommand, CoreEvent, CoreSettingsHandle, DataDir, DataDirSource, DirectoryRefusal,
    DirectoryRole, DirectoryState, DurableAppConfig, LoginStep, ManagedServer, MappingBackend,
    ScanEvent, ServerConnectFailure, ServerConnectionEvent, ServerListEvent, ServerListStore,
    Setting, TakesEffect, open_durable_store,
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

/// The test deployment: the canned fetch, scripted Mapping Backends or none,
/// and a scratch home or none, so nothing speaks to a real mirror or router
/// or names the operator's home.
#[derive(Default)]
struct Scratch {
    fetch: CannedFetch,
    backends: Vec<Arc<dyn MappingBackend>>,
    home: Option<PathBuf>,
}

impl Deployment for Scratch {
    type Fetcher = CannedFetch;

    fn fetcher(&self, _bootstrap: &BootstrapConfig) -> Result<CannedFetch, FetchError> {
        Ok(self.fetch.clone())
    }

    fn mapping_backends(&self, _port_map_secret: u32) -> Vec<Arc<dyn MappingBackend>> {
        self.backends.clone()
    }

    fn home(&self) -> Option<PathBuf> {
        self.home.clone()
    }
}

/// A scratch data directory whose store is seeded by `seed` — its server
/// rows, and Core Settings through the handle as an operator would — and
/// closed again before the app opens it: the engine's file lock admits one
/// opener.
fn data_dir(seed: impl FnOnce(&DurableAppConfig, &CoreSettingsHandle)) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let durable = open_durable_store(dir.path()).expect("open the store");
    let settings = CoreSettingsHandle::open(durable.clone());
    // The core binds its client UDP socket at start and its eD2k listener at
    // attach, and a fixed port would fight any other client on this host.
    rmule_testkit::scratch_ports(&settings);
    seed(&DurableAppConfig::new(durable), &settings);
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
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("core alive") {
                CoreEvent::DiagnosticsSnapshot { .. } => return,
                CoreEvent::ServerList(edge) => edges.push(edge),
                _ => {}
            }
        }
    })
    .await
    .expect("the dump answers");
    edges
}

/// ADR-0065's first run: a fresh data directory has no servers, so attaching
/// fetches `server.met` from the default mirror once and lists what it holds
/// — through the fetch the deployment gave the core, without a key press.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_data_dir_fetches_its_server_list_once_at_attach() {
    let dir = data_dir(|_, _| {});
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
    let updated = tokio::time::timeout(HANG_GUARD, async {
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
    .expect("the first-run fetch lands");

    assert_eq!(updated, (2, 2), "both rows listed, into the empty list");
    assert_eq!(
        fetch.asked(),
        [rmule_bootstrap::DEFAULT_SERVER_MET_URL],
        "one fetch, from the default mirror"
    );
}

/// The Settings tab edits through the attached core's own Core Settings
/// handle (ADR-0069): a live key is taken up at once, and a start-shaped one
/// is kept for the next start.
#[tokio::test(flavor = "multi_thread")]
async fn the_settings_tab_edits_through_the_attached_core() {
    let dir = data_dir(|_, _| {});
    let Attachment { core, config, .. } = attach_in(&dir, &Scratch::default()).await;
    let effect = |edit: PrefEdit| config.commit(&edit).expect("commit");
    assert_eq!(effect(PrefEdit::DeadServerRetries(5)), TakesEffect::Now);
    assert_eq!(effect(PrefEdit::UdpPort(4999)), TakesEffect::NextStart);
    core.shutdown().await;
    assert_eq!(
        config.load(None).expect("load").dead_server_retries,
        5,
        "and the store holds it"
    );
}

/// The off switch: with `auto_fetch_server_met` off, a fresh data directory
/// starts with its empty list and nothing is fetched.
#[tokio::test(flavor = "multi_thread")]
async fn the_off_switch_keeps_a_first_run_from_fetching() {
    let dir = data_dir(|_, settings| {
        settings
            .set(Setting::AutoFetchServerMet(false))
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
fn filtered_data_dir(seed: impl FnOnce(&CoreSettingsHandle)) -> tempfile::TempDir {
    let dir = data_dir(|store, settings| {
        store
            .merge_server(ManagedServer::listed(filtered_server()))
            .expect("list the server");
        seed(settings);
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
    let Attachment { mut core, .. } = attach_in(dir, deployment).await;
    core.send(CoreCommand::ConnectToServer {
        server: filtered_server(),
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
async fn login_waits_on_a_mapping(port_mapping: PortMappingMode) -> bool {
    let dir = filtered_data_dir(|settings| {
        settings
            .set(Setting::PortMapping(port_mapping))
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
    assert!(
        login_waits_on_a_mapping(PortMappingMode::Auto).await,
        "on: mapped first"
    );
    assert!(
        !login_waits_on_a_mapping(PortMappingMode::Off).await,
        "off: no mapping"
    );
}

/// The share guards hold for the download directory core scans at attach
/// (ADR-0101): one that is rmule's data directory, or the operator's home, is
/// refused — said, listed as refused, never scanned — though the operator's
/// share answer for it is on record.
#[tokio::test(flavor = "multi_thread")]
async fn attach_refuses_a_download_dir_that_is_the_data_dir_or_the_home() {
    let home = tempfile::tempdir().expect("home");
    for (in_home, reason) in [
        (false, DirectoryRefusal::DataDirectory),
        (true, DirectoryRefusal::HomeDirectory),
    ] {
        let dir = data_dir(|_, _| {});
        let download_dir = if in_home { home.path() } else { dir.path() }.to_path_buf();
        CoreSettingsHandle::open(open_durable_store(dir.path()).expect("reopen the store"))
            .set(Setting::DownloadDir {
                dir: download_dir.clone(),
                share_confirmed: true,
            })
            .expect("the download dir is stored");
        let deployment = Scratch {
            home: Some(home.path().to_path_buf()),
            ..Scratch::default()
        };
        let Attachment { mut core, .. } = attach_in(&dir, &deployment).await;

        let said = tokio::time::timeout(HANG_GUARD, async {
            loop {
                match core.next_event().await.expect("core alive") {
                    CoreEvent::Scan(ScanEvent::DownloadDirectoryRefused { dir, reason }) => {
                        return (dir, reason);
                    }
                    CoreEvent::Scan(other) => panic!("scanned before the guard: {other:?}"),
                    _ => {}
                }
            }
        })
        .await
        .expect("the refusal is said at attach");
        assert_eq!(said, (download_dir.clone(), reason.clone()));
        core.send(CoreCommand::DumpDiagnostics)
            .await
            .expect("the core takes the dump");
        let listed = tokio::time::timeout(HANG_GUARD, async {
            loop {
                match core.next_event().await.expect("core alive") {
                    CoreEvent::DiagnosticsSnapshot { snapshot } => {
                        return snapshot.shared_directories;
                    }
                    CoreEvent::Scan(other) => panic!("scanned after the refusal: {other:?}"),
                    _ => {}
                }
            }
        })
        .await
        .expect("the dump answers");
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].dir, download_dir);
        assert_eq!(listed[0].role, DirectoryRole::DownloadDirectory);
        assert_eq!(listed[0].state, DirectoryState::Refused(reason));
        core.shutdown().await;
    }
}
