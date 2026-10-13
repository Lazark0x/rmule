//! rmule run as a **client** inside the bench: the container that dials the
//! counterparty. Every builder returns a `DockerCommand` that mounts the
//! workspace, lands its artifacts in the run dir and — where a flow's window
//! cannot absorb a cold compile — reuses the persistent build caches, so a flow
//! composes rmule's participation without knowing the container layout.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, DockerCommand};

use super::{
    BenchStaging, CONTAINER_RUN_ROOT, HANDOFF_RUNNER_KAD_UDP_PORT, RMULE_SERVE_TCP_PORT,
    RmuleWorkspace, rmule_log_level,
};

/// Every **Registrant** container advertises this one TCP port; distinct
/// container IPs (not distinct ports) are what earn distinct High IDs.
pub const REGISTRANT_PORT_BASE: u16 = 14662;
/// Per-registrant announce budget. Must cover hashing the shared file while
/// every other registrant container hashes it too — the packed source answer
/// needs its sources present *simultaneously*, so a registrant lost to a
/// hashing race directly costs a source row.
pub const REGISTRANT_ANNOUNCE_TIMEOUT_SECS: u64 = 90;

/// One **Registrant**: a container holding a single fabricated High-ID identity
/// that offers the synthetic file's hash on the eserver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registrant<'a> {
    /// The container name.
    pub name: &'a str,
    /// Its static IP on the bench network — the identity the eserver assigns the
    /// High ID to.
    pub ip: &'a str,
    /// The eserver it registers with, `host:port`.
    pub server_endpoint: &'a str,
    /// The fabricated identity's index (`--index-base`).
    pub index: u16,
}

/// The run-dir file whose appearance starts a held download container's
/// `rmule-tools` ([`release_held_download`]).
pub(crate) const DOWNLOAD_START_GATE: &str = "download-start-gate";

/// Start the `rmule-tools` a held download container
/// ([`RmuleClientContainer::download_start_detached_command`]) is waiting
/// to run.
///
/// # Errors
/// If the gate file cannot be written.
pub fn release_held_download(layout: &RunLayout) -> Result<()> {
    let gate = layout.root().join(DOWNLOAD_START_GATE);
    std::fs::write(&gate, b"").with_context(|| format!("write {}", gate.display()))
}

/// The obfuscation knobs of a detached download (`ed2k download start
/// --peer-crypt` and `--peer-crypt-flip`): the policy it starts under and the
/// timed flips, each `<secs>:<policy>` counted from the download's login.
/// `DownloadCrypt::default()` passes neither, so the run is the plain one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownloadCrypt<'a> {
    /// The policy the download starts under; `None` leaves obfuscation off.
    pub peer_crypt: Option<&'a str>,
    /// The flips the downloading rmule applies mid-run.
    pub peer_crypt_flip: &'a [String],
}

/// The rust image plus mounted workspace an rmule client container runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmuleClientContainer {
    workspace: RmuleWorkspace,
}

impl RmuleClientContainer {
    /// Run `image` with `workspace_root` mounted as the repository.
    pub fn new(image: impl Into<OsString>, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace: RmuleWorkspace::new(image, workspace_root),
        }
    }

    /// Run `image` against the workspace this harness was built from.
    pub fn cargo_rmule_tools(image: impl Into<OsString>) -> Result<Self> {
        Ok(Self {
            workspace: RmuleWorkspace::from_manifest(image, "client")?,
        })
    }

    /// `rmule-tools ed2k download start` in the foreground (`--rm`): the caller
    /// blocks on the run and reads the download summary off stdout (the
    /// forward/reverse transfer and the Low-ID callback flows). `max_seconds`
    /// bounds the run: the Low-ID callback compatibility flow can never
    /// byte-complete against the Lugdunum eserver, which never surfaces the
    /// Low-ID peer as a source (ADR-0040), so it runs with an overall deadline
    /// after which rmule prints its callback-capability summary and exits 0;
    /// the forward/reverse flows leave it unbounded.
    ///
    /// Like every download container it runs the binary
    /// [`prebuild_command`](Self::prebuild_command) left in the
    /// host-persisted cache; the caller prebuilds first.
    ///
    /// # Errors
    /// If the cache directory cannot be created.
    pub fn download_start_command(
        &self,
        staging: BenchStaging<'_>,
        server_endpoint: &str,
        ed2k_link: &str,
        serve: bool,
        max_seconds: Option<u64>,
    ) -> Result<DockerCommand> {
        let mut container = self
            .download_start_body(
                staging.layout,
                server_endpoint,
                &[ed2k_link],
                serve,
                DownloadCrypt::default(),
                false,
            )?
            .remove_after_exit()
            .network(staging.network);
        if let Some(secs) = max_seconds {
            container = container.arg("--max-seconds").arg(secs.to_string());
        }
        Ok(staging.docker.run_container(container))
    }

    /// [`Self::download_start_command`], but **detached** under a stable `name`
    /// for a long-lived download that must outlive the call — the peer-UDP reask
    /// **EMIT** window (ADR-0057). One download per link, all in one core.
    /// rmule stays queued on an uploader whose slots are all held across the
    /// `FILEREASKTIME` cycle, emitting its own
    /// `OP_REASKFILEPING` (`0x90`) out the shared client-UDP socket. Always
    /// unbounded (no `--max-seconds`): a forever-queued download never
    /// self-terminates — it keeps its Remote-Queued Pool standing — so the harness
    /// taps rmule's netns for the window and removes the container at teardown.
    /// `serve` binds the inbound listener so the eserver's in-network dial-back
    /// makes rmule **High-ID**, the ADR-0057 gate that opens UDP-first reask (a
    /// Low-ID downloader falls back to the TCP full ask instead).
    ///
    /// The container is **held**: `rmule-tools` starts only once the flow
    /// calls [`release_held_download`] — after the tap on its namespace
    /// listens — so the tap holds rmule's login and its first dial, the
    /// plaintext a verdict reads keys off.
    ///
    /// # Errors
    /// If the cache directory cannot be created.
    pub fn download_start_detached_command(
        &self,
        staging: BenchStaging<'_>,
        name: &str,
        server_endpoint: &str,
        ed2k_links: &[&str],
        serve: bool,
        crypt: DownloadCrypt<'_>,
    ) -> Result<DockerCommand> {
        Ok(staging.docker.run_container(
            self.download_start_body(
                staging.layout,
                server_endpoint,
                ed2k_links,
                serve,
                crypt,
                true,
            )?
            .detach()
            .name(name)
            .network(staging.network),
        ))
    }

    /// The shared `ed2k download start …` body for both dispositions: the
    /// trace-level env and the fixed CLI flags, `--serve` last (the foreground
    /// caller may add `--max-seconds` after). The serve-side tracing knob
    /// reaches the downloading rmule too: in the Low-ID callback flow this one
    /// process both asks the server to relay (`OP_CALLBACKREQUEST 0x1C`) and
    /// serves the inbound dial-back, so `RMULE_SERVE_LOG=trace` surfaces the
    /// callback frame and the adopt.
    ///
    /// It executes the prebuilt binary, never a `cargo run` per container: a
    /// cold in-container build took minutes a flow's readiness budget had to
    /// absorb.
    fn download_start_body(
        &self,
        layout: &RunLayout,
        server_endpoint: &str,
        ed2k_links: &[&str],
        serve: bool,
        crypt: DownloadCrypt<'_>,
        held: bool,
    ) -> Result<crate::docker::RunContainer> {
        let binary = if held {
            self.workspace.prebuilt_held(
                layout,
                &format!("{CONTAINER_RUN_ROOT}/{DOWNLOAD_START_GATE}"),
            )?
        } else {
            self.workspace.prebuilt(layout)?
        };
        let mut container = binary
            .env("RMULE_LOG", rmule_log_level("info"))
            .arg("ed2k")
            .arg("download")
            .arg("start")
            .arg("--data-dir")
            .arg(format!("{CONTAINER_RUN_ROOT}/rmule"))
            .arg("--server")
            .arg(server_endpoint);
        // One download per link, in one core: the first lands in
        // `output.bin`, the n-th in `output-<n>.bin`.
        for (index, link) in ed2k_links.iter().enumerate() {
            let out = if index == 0 {
                "output.bin".to_owned()
            } else {
                format!("output-{}.bin", index + 1)
            };
            container = container
                .arg("--file")
                .arg(*link)
                .arg("--out")
                .arg(format!("{CONTAINER_RUN_ROOT}/rmule/{out}"));
        }
        let mut container = container
            .arg("--tcp-port")
            .arg(RMULE_SERVE_TCP_PORT.to_string());
        if let Some(policy) = crypt.peer_crypt {
            container = container.arg("--peer-crypt").arg(policy);
        }
        for flip in crypt.peer_crypt_flip {
            container = container.arg("--peer-crypt-flip").arg(flip);
        }
        // Serve while downloading so rmule is High-ID and callback-capable
        // (ADR-0039) — required to adopt a Low-ID source and (ADR-0057) to open
        // the UDP-first reask gate.
        Ok(if serve {
            container.arg("--serve")
        } else {
            container
        })
    }

    /// Run `rmule-tools ed2k server probe` inside the interop network,
    /// targeting the server by container name — docker DNS resolves it to the
    /// reachable container IP, so the probe's UDP offset sends (TCP+4/TCP+12)
    /// land on the server's own UDP ports with no host-NAT in the path. Run in
    /// the foreground so the caller captures the probe report from stdout.
    /// `--out` also drops a `probe/probe.txt` into the mounted run dir.
    pub fn probe_command(
        &self,
        staging: BenchStaging<'_>,
        server_endpoint: &str,
        udp_ports_advert: Option<u16>,
        advertise_ipv6: Option<std::net::Ipv6Addr>,
    ) -> DockerCommand {
        let mut run = self
            .workspace
            .cargo_run(staging.layout)
            .remove_after_exit()
            .network(staging.network)
            .arg("ed2k")
            .arg("server")
            .arg("probe")
            .arg(server_endpoint)
            .arg("--out")
            .arg(format!("{CONTAINER_RUN_ROOT}/probe"));
        if let Some(client_udp) = udp_ports_advert {
            run = run.arg("--udp-ports-advert").arg(client_udp.to_string());
        }
        if let Some(address) = advertise_ipv6 {
            run = run.arg("--advertise-ipv6").arg(address.to_string());
        }
        staging.docker.run_container(run)
    }

    /// The search-wire probe: a foreground `rmule-tools ed2k
    /// server search-wire` against `server_endpoint`, on static `ip`, writing
    /// its report and raw TCP capture to `out` under the run dir; `probe_args`
    /// are the probe's own flags (bursts, words, probes, requester posture).
    pub fn search_wire_command(
        &self,
        staging: BenchStaging<'_>,
        server_endpoint: &str,
        ip: &str,
        out: &str,
        probe_args: &[String],
    ) -> Result<DockerCommand> {
        let mut run = self
            .workspace
            .cached_cargo_run(staging.layout)?
            .remove_after_exit()
            .network(staging.network)
            .ip(ip)
            .env("RMULE_LOG", rmule_log_level("info"))
            .arg("ed2k")
            .arg("server")
            .arg("search-wire")
            .arg(server_endpoint)
            .arg("--out")
            .arg(format!("{CONTAINER_RUN_ROOT}/{out}"));
        for arg in probe_args {
            run = run.arg(arg);
        }
        Ok(staging.docker.run_container(run))
    }

    /// `rmule-tools ed2k search --query <query>` against `server_endpoint`, in
    /// the foreground so the caller reads the results off stdout.
    pub fn search_command(
        &self,
        staging: BenchStaging<'_>,
        server_endpoint: &str,
        query: &str,
    ) -> DockerCommand {
        staging.docker.run_container(
            self.workspace
                .cargo_run(staging.layout)
                .remove_after_exit()
                .network(staging.network)
                .arg("ed2k")
                .arg("search")
                .arg("--server")
                .arg(server_endpoint)
                .arg("--query")
                .arg(query)
                .arg("--tcp-port")
                .arg(RMULE_SERVE_TCP_PORT.to_string()),
        )
    }

    /// Run the ed2k→Kad handoff runner (ADR-0067): log in to
    /// `server_endpoint`, dial the Kad-running aMule at `peer_endpoint`, consume
    /// its `CT_EMULE_UDPPORTS`, and broker the Kad bootstrap from the same
    /// process until the node reaches contact. Runs in the interop network so the
    /// node's UDP socket reaches the aMule's Kad port directly. Foreground; the
    /// caller reads the `kad-handoff result=…` verdict off stdout.
    pub fn kad_handoff_command(
        &self,
        staging: BenchStaging<'_>,
        server_endpoint: &str,
        peer_endpoint: &str,
        max_seconds: u64,
    ) -> DockerCommand {
        staging.docker.run_container(
            self.workspace
                .cargo_run(staging.layout)
                .remove_after_exit()
                .network(staging.network)
                .arg("ed2k")
                .arg("kad-handoff")
                .arg("--server")
                .arg(server_endpoint)
                .arg("--peer")
                .arg(peer_endpoint)
                .arg("--kad-bind")
                .arg(format!("0.0.0.0:{HANDOFF_RUNNER_KAD_UDP_PORT}"))
                .arg("--out")
                .arg(format!("{CONTAINER_RUN_ROOT}/kad-handoff"))
                .arg("--max-seconds")
                .arg(max_seconds.to_string()),
        )
    }

    /// Mirror the `rmule-tools ed2k bootstrap-fetch` CLI: the production
    /// ADR-0067 Join Sequence caller — fetch `server.met` + `nodes.dat` over
    /// HTTP, join both networks through the live core, and verify each leg.
    /// `ip` pins the runner's static fake-public address so the aMule-netns
    /// pcap can name the join exchange. Rides the host-persisted build caches
    /// (see [`Self::prebuild_command`]) so a prebuilt runner starts in seconds
    /// rather than cold-compiling inside the flow window.
    pub fn bootstrap_fetch_command(
        &self,
        staging: BenchStaging<'_>,
        ip: &str,
        server_met_url: &str,
        nodes_dat_url: &str,
        max_seconds: u64,
    ) -> Result<DockerCommand> {
        Ok(staging.docker.run_container(
            self.workspace
                .cached_cargo_run(staging.layout)?
                .remove_after_exit()
                .network(staging.network)
                .ip(ip.to_owned())
                .arg("ed2k")
                .arg("bootstrap-fetch")
                .arg("--server-met-url")
                .arg(server_met_url)
                .arg("--nodes-dat-url")
                .arg(nodes_dat_url)
                .arg("--kad-bind")
                .arg(format!("0.0.0.0:{HANDOFF_RUNNER_KAD_UDP_PORT}"))
                .arg("--out")
                .arg(format!("{CONTAINER_RUN_ROOT}/bootstrap-fetch"))
                .arg("--max-seconds")
                .arg(max_seconds.to_string()),
        ))
    }

    /// A detached **Registrant** (ADR-0043): `rmule-tools ed2k
    /// register-sources` holding one fabricated identity on its own static IP,
    /// offering the synthetic file to its own `server_endpoint`. Rides the
    /// persisted build caches so N registrants pay one cold build between them.
    pub fn register_sources_command(
        &self,
        staging: BenchStaging<'_>,
        registrant: &Registrant<'_>,
    ) -> Result<DockerCommand> {
        Ok(staging.docker.run_container(
            self.workspace
                .cached_cargo_run(staging.layout)?
                .detach()
                .name(registrant.name)
                .network(staging.network)
                .ip(registrant.ip)
                .env("RMULE_LOG", rmule_log_level("info"))
                .arg("ed2k")
                .arg("register-sources")
                .arg("--file")
                .arg(format!("{CONTAINER_RUN_ROOT}/synthetic/shared.bin"))
                .arg("--server")
                .arg(registrant.server_endpoint)
                .arg("--count")
                .arg("1")
                .arg("--index-base")
                .arg(registrant.index.to_string())
                .arg("--port-base")
                .arg(REGISTRANT_PORT_BASE.to_string())
                .arg("--announce-timeout")
                .arg(REGISTRANT_ANNOUNCE_TIMEOUT_SECS.to_string()),
        ))
    }

    /// The source-exchange capture dial: a foreground `rmule-tools ed2k peer
    /// transfer capture` that dials `peer_endpoint`, asks for sources inside the
    /// `0xA4` bundle and holds the connection `max_seconds` for the answer,
    /// writing to `rmule/sx/` in the run dir. `sx_nibble` is the source-exchange
    /// version rmule advertises; `0` leaves the honest v1 advert.
    ///
    /// The ask must ride the bundle: aMule 2.3.3's *standalone*
    /// `OP_REQUESTSOURCES2` handler tests `size != 16` against its own 19-byte
    /// payload and drops the connection, while its multipacket sub-item handler
    /// answers normally.
    pub fn source_exchange_capture_command(
        &self,
        staging: BenchStaging<'_>,
        peer_endpoint: &str,
        ed2k_link: &str,
        sx_nibble: u8,
        max_seconds: u64,
    ) -> Result<DockerCommand> {
        let mut container = self
            .workspace
            .cached_cargo_run(staging.layout)?
            .remove_after_exit()
            .network(staging.network)
            .env("RMULE_LOG", rmule_log_level("info"))
            .arg("ed2k")
            .arg("peer")
            .arg("transfer")
            .arg("capture")
            .arg("--peer")
            .arg(peer_endpoint)
            .arg("--file")
            .arg(ed2k_link)
            .arg("--output-dir")
            .arg(format!("{CONTAINER_RUN_ROOT}/rmule/sx"))
            .arg("--mode")
            .arg("full")
            .arg("--request-sources")
            .arg("--multipacket")
            .arg("--max-seconds")
            .arg(max_seconds.to_string());
        if sx_nibble != 0 {
            container = container.arg("--sx-nibble").arg(sx_nibble.to_string());
        }
        Ok(staging.docker.run_container(container))
    }

    /// Compile `rmule-tools` into the host-persisted cache on the runtime's
    /// DEFAULT network, so a flow whose window cannot absorb a cold compile (or
    /// whose network has no egress) runs a warm build.
    pub fn prebuild_command(&self, docker: &Docker) -> Result<DockerCommand> {
        self.workspace.prebuild_command(docker)
    }
}
