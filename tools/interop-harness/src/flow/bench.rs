//! The interop bench: the Docker-level fabric every flow is staged on.
//!
//! Owns the container and network *names* a run derives from its run dir, the
//! guards that create and tear those down (`Bench` for the eD2k bench,
//! `KadResources` for the private Kad mesh), the passive **Capture Sidecar** a
//! flow attaches to a container, and the one checked way to run a
//! container-runtime command. Nothing here knows what any individual flow is
//! trying to prove.
//!
//! One rule holds for every guard: a container is owned for teardown from the
//! moment the runtime returns from starting it, on every path that escapes the
//! flow's closure — a leaked container is a bench that cannot be reused.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::artifacts::RunLayout;
use crate::bench_doctor::{BenchDoctor, DoctorReport};
use crate::docker::{Docker, DockerCommand, RunContainer};
use crate::flow::gate::{
    start_rmule_serve_with_login_retry, wait_for_amule_ready, wait_for_container_log,
};
use crate::flow::logs::{
    collect_amule_diagnostics, collect_amule_logs, collect_kad_logs, collect_rmule_logs,
    collect_server_logs,
};
use crate::flow::mesh::KAD_EC_PASSWORD;
use crate::readiness::wait_for_tcp_ready;
use crate::rmule::{BenchStaging, RmuleServeContainer, ServeKnobs};

/// aMule's peer TCP port inside its container (entrypoint `Port` default 4662).
pub(crate) const AMULE_PEER_TCP_PORT: u16 = 4662;

/// The eserver's TCP port inside its container: what an aMule is pointed at
/// (`ED2K_SERVER_PORT`) and what the bench publishes to the host.
pub(crate) const ED2K_SERVER_PORT: u16 = 4661;

/// Where a capture sidecar's host directory is mounted inside its container.
pub(crate) const CAPTURE_MOUNT: &str = "/capture";

/// A **Capture Sidecar**: a passive tcpdump attached to `target_container`'s
/// network namespace, writing `pcap_file` under `host_dir`. It never speaks, so
/// its pcap holds only genuine traffic between the real participants.
///
/// One snaplen for every flow (`-s 0`, whole packets): the peer-TCP wire rows
/// read opcodes at payload offsets and a promoted frame must be byte-complete,
/// and a divergent snaplen would make row counts across flows incomparable.
/// `-U` writes each packet unbuffered so a stopped sidecar leaves a complete
/// pcap; a named interface rather than `any`, because some runtimes
/// (colima/lima) do not deliver packets on the `any` pseudo-interface.
///
/// `--immediate-mode` is not a tuning knob either. Without it libpcap drains the
/// kernel's PF_PACKET ring on a **one-second** timer, so `-U` flushes only what
/// has already been handed up — and a flow whose exchange completes in under a
/// second (a `full-cone-pinned` gateway answers all five probe tests with no
/// timeouts) reads its pcap while every packet is still sitting in the ring.
/// The count then comes back zero, which is indistinguishable from a
/// **Documented Absence** and would be a fabricated row. Measured on
/// `natgw-selfproof`: the slow gateway legs counted 14/8 packets and the fast
/// ones 0/0 until immediate mode went in.
///
/// `interface` is what makes a **Per-Attachment Tap** possible: a multi-homed
/// container (a **NAT Gateway**) carries one interface per network, and the
/// same datagram before and after translation is only observable by tapping
/// both.
pub(crate) struct CaptureSidecar<'a> {
    /// The tcpdump image.
    pub(crate) image: &'a str,
    /// The sidecar's container name.
    pub(crate) name: &'a str,
    /// The container whose network namespace is tapped.
    pub(crate) target_container: &'a str,
    /// The interface inside that namespace — `eth0` for a single-homed
    /// container, `eth0`/`eth1` for the two sides of a gateway.
    pub(crate) interface: &'a str,
    /// The host directory the pcap lands in.
    pub(crate) host_dir: PathBuf,
    /// The pcap file name under `host_dir`.
    pub(crate) pcap_file: &'a str,
    /// The tcpdump filter expression.
    pub(crate) bpf: &'a str,
}

/// The tap's kernel capture buffer, in KiB (`tcpdump -B`).
///
/// libpcap's 2 MiB default, sliced into whole-snaplen frames at `-s 0`, holds
/// a handful of packets: a burst outruns it and the kernel drops the rest
/// before tcpdump reads them. Measured on colima, tcpdump's own count on a
/// receiver of back-to-back datagrams: the default dropped 132 of 194, 16 MiB
/// 48 of 394, 64 MiB none of 194. Search-wire's 40-datagram `0x98` burst lost
/// a third of its datagrams and most answers to the default.
pub(crate) const CAPTURE_BUFFER_KIB: &str = "65536";

/// The one interface a single-homed container's tap watches.
pub(crate) const DEFAULT_TAP_INTERFACE: &str = "eth0";

impl CaptureSidecar<'_> {
    /// The detached sidecar container.
    pub(crate) fn container(&self) -> RunContainer {
        RunContainer::new(self.image.to_owned())
            .detach()
            .name(self.name)
            .network(format!("container:{}", self.target_container))
            .cap_add("NET_RAW")
            .cap_add("NET_ADMIN")
            .volume(&self.host_dir, CAPTURE_MOUNT)
            .arg("tcpdump")
            .arg("-i")
            .arg(self.interface)
            .arg("--immediate-mode")
            .arg("-U")
            .arg("-s")
            .arg("0")
            .arg("-B")
            .arg(CAPTURE_BUFFER_KIB)
            .arg("-w")
            .arg(self.pcap_path())
            .arg("--")
            .arg(self.bpf)
    }

    /// The pcap's path inside the sidecar — what `tcpdump -r` reads there.
    pub(crate) fn pcap_path(&self) -> String {
        format!("{CAPTURE_MOUNT}/{}", self.pcap_file)
    }
}

/// Build an `amulecmd -P <pass> -c <command>` argv for `docker exec`.
pub(crate) fn amulecmd_command(command: &str) -> [OsString; 5] {
    [
        OsString::from("amulecmd"),
        OsString::from("-P"),
        OsString::from(KAD_EC_PASSWORD),
        OsString::from("-c"),
        OsString::from(command),
    ]
}

/// The container and network names a Kad mesh derives from its run dir.
pub(crate) struct KadMeshNames {
    pub(crate) network_name: String,
    pub(crate) publisher: String,
    pub(crate) requester: String,
    pub(crate) storer: String,
    pub(crate) capture: String,
    pub(crate) rmule: String,
    pub(crate) suffix: String,
}

impl KadMeshNames {
    pub(crate) fn from_layout(layout: &RunLayout) -> Result<Self> {
        let suffix = run_suffix(layout)?;
        Ok(Self {
            network_name: kad_network_name(&suffix),
            publisher: format!("rmule-interop-kad-publisher-{suffix}"),
            requester: format!("rmule-interop-kad-requester-{suffix}"),
            storer: format!("rmule-interop-kad-storer-{suffix}"),
            capture: format!("rmule-interop-kad-capture-{suffix}"),
            rmule: format!("rmule-interop-kad-rmule-{suffix}"),
            suffix,
        })
    }

    /// The mesh network's name derived from `layout` alone, for the callers that
    /// join a container to it without holding the full name set.
    pub(crate) fn network_for(layout: &RunLayout) -> String {
        match run_suffix(layout) {
            Ok(suffix) => kad_network_name(&suffix),
            Err(_) => "rmule-interop-kad".to_owned(),
        }
    }

    pub(crate) fn routing(&self, index: u32) -> String {
        format!("rmule-interop-kad-routing-{index}-{}", self.suffix)
    }
}

/// The mesh network's one spelling: the guard that removes it and the
/// containers joined to it must never derive it differently.
fn kad_network_name(suffix: &str) -> String {
    format!("rmule-interop-kad-{suffix}")
}

/// The run dir's own name — the suffix every container and network name
/// carries, so two runs never collide on the same runtime.
fn run_suffix(layout: &RunLayout) -> Result<String> {
    layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_owned())
        .ok_or_else(|| anyhow!("run directory has no utf-8 file name"))
}

/// What a guard owes teardown: the containers it owns in start order and the
/// network it created, if it created one. Both guards funnel here so the two
/// teardowns cannot drift.
struct OwnedResources<'a> {
    docker: &'a Docker,
    /// Print what would be removed instead of removing it (`--keep-containers`).
    keep: bool,
    /// Owned container names in start order.
    containers: Vec<String>,
    /// The networks this guard created, and therefore owes removal.
    networks: Vec<String>,
}

impl OwnedResources<'_> {
    /// Remove everything owned, newest container first and the network last —
    /// a runtime refuses to remove a network a container still sits on. Every
    /// removal is best-effort: teardown runs on the failure path too, and an
    /// error here must never displace the failure that got us here.
    fn tear_down(&self) {
        for container in self.containers.iter().rev() {
            if self.keep {
                println!("kept_container={container}");
                continue;
            }
            let _ = run_checked(
                self.docker.remove_container(container.clone()),
                "remove container",
            );
        }
        for network in self.networks.iter().rev() {
            if self.keep {
                println!("kept_network={network}");
                continue;
            }
            let _ = run_checked(
                self.docker.remove_network(network.clone()),
                "remove docker network",
            );
        }
    }
}

/// Run one best-effort log collection after a failure. A collection that itself
/// fails only warns: the failure that triggered the sweep is the one that must
/// surface.
fn collect_or_warn<T>(what: &str, collect: impl FnOnce() -> Result<T>) {
    if let Err(error) = collect() {
        eprintln!("warning: failed to collect {what} after failure: {error:#}");
    }
}

/// The guard over a private Kad mesh: every started node (by role), the
/// capture sidecar, and the network.
pub(crate) struct KadResources<'a> {
    docker: &'a Docker,
    keep_containers: bool,
    network_created: bool,
    started: Vec<(String, String)>,
    captures: Vec<String>,
}

impl<'a> KadResources<'a> {
    pub(crate) fn new(docker: &'a Docker, keep_containers: bool) -> Self {
        Self {
            docker,
            keep_containers,
            network_created: false,
            started: Vec::new(),
            captures: Vec::new(),
        }
    }

    /// Start a capture sidecar, own it for teardown, and record its container
    /// id under the run dir's docker directory as `id_file`.
    ///
    /// A flow may attach several: one netns only ever shows the traffic that
    /// crosses *it*, so a datagram a counterparty sends to a third node is
    /// invisible from the node the first tap watches.
    pub(crate) fn start_capture(
        &mut self,
        layout: &RunLayout,
        sidecar: &CaptureSidecar<'_>,
        id_file: &str,
    ) -> Result<()> {
        let capture_id = run_checked(
            self.docker.run_container(sidecar.container()),
            "run kad capture sidecar",
        )?;
        self.captures.push(sidecar.name.to_owned());
        write_id(
            &layout.docker_dir().join(id_file),
            fallback_id(&capture_id, sidecar.name),
        )
    }

    pub(crate) fn stop_capture(&mut self) {
        if self.keep_containers {
            return;
        }
        for capture in std::mem::take(&mut self.captures).into_iter().rev() {
            let _ = run_checked(
                self.docker.remove_container(capture),
                "remove kad capture sidecar",
            );
        }
    }

    /// Own a started mesh node for teardown, under the `role` that
    /// [`Self::stop_role`] and the failure-log sweep read it back by. Called
    /// from the moment the runtime returns from starting it, so no path out of
    /// the flow can leave the node unowned.
    pub(crate) fn track_started(&mut self, role: &str, container: impl Into<String>) {
        self.started.push((role.to_owned(), container.into()));
    }

    /// Mark the mesh network as this guard's to remove. Taken as soon as
    /// `network create` returns, so a failure between creation and the first
    /// node still tears the network down.
    pub(crate) fn own_network(&mut self) {
        self.network_created = true;
    }

    /// Remove the started containers with this role now (e.g. stop the hub
    /// before the rmule tap finalizes, so the tap's last frames are the last
    /// aMule datagrams).
    pub(crate) fn stop_role(&mut self, role: &str) {
        let mut index = 0;
        while index < self.started.len() {
            if self.started[index].0 == role {
                let (_, container) = self.started.remove(index);
                let _ = run_checked(
                    self.docker.remove_container(container),
                    "remove kad role container",
                );
            } else {
                index += 1;
            }
        }
    }

    /// Drain whatever each started node currently reports into the run dir.
    pub(crate) fn collect_failure_logs(&self, layout: &RunLayout) {
        for (role, container) in &self.started {
            collect_or_warn(&format!("kad {role} logs"), || {
                collect_kad_logs(self.docker, layout, role, container)
            });
        }
    }

    /// Tear the mesh down, or — under `--keep-containers` — print what was kept
    /// so the operator can inspect and remove it. The capture sidecar goes
    /// first: it is the last thing started, and a running tcpdump holds the
    /// namespace of the node it taps.
    pub(crate) fn cleanup_best_effort(&self, names: &KadMeshNames) {
        let mut containers: Vec<String> = Vec::new();
        containers.extend(self.started.iter().map(|(_, name)| name.clone()));
        containers.extend(self.captures.iter().cloned());
        OwnedResources {
            docker: self.docker,
            keep: self.keep_containers,
            containers,
            networks: self
                .network_created
                .then(|| names.network_name.clone())
                .into_iter()
                .collect(),
        }
        .tear_down();
    }
}

/// The container and network names an eD2k bench derives from its run dir.
pub(crate) struct BenchNames {
    pub(crate) network_name: String,
    pub(crate) server_container_name: String,
    pub(crate) amule_container_name: String,
    pub(crate) rmule_container_name: String,
}

impl BenchNames {
    pub(crate) fn from_layout(layout: &RunLayout) -> Result<Self> {
        let suffix = run_suffix(layout)?;
        Ok(Self {
            network_name: format!("rmule-interop-{suffix}"),
            server_container_name: format!("rmule-interop-server-{suffix}"),
            amule_container_name: format!("rmule-interop-amule-{suffix}"),
            rmule_container_name: format!("rmule-interop-rmule-{suffix}"),
        })
    }

    /// The eserver as an in-network endpoint: the container name (docker DNS
    /// resolves it) and the server port, so an in-network rmule's UDP offset
    /// sends land on the server with no host NAT in the path.
    pub(crate) fn server_endpoint(&self) -> String {
        format!("{}:{ED2K_SERVER_PORT}", self.server_container_name)
    }
}

/// The line the eserver image's entrypoint prints just before it starts the
/// server.
pub(crate) const ESERVER_ENTRYPOINT_LOG: &str = "starting Lugdunum eserver on tcp/";

/// The eserver as the bench stands it up: its image, the host port its
/// container port is published on (the readiness probe target), its extra
/// environment, and the readiness budget.
pub(crate) struct Eserver<'a> {
    pub(crate) image: &'a str,
    pub(crate) host_port: u16,
    pub(crate) env: &'a [String],
    pub(crate) timeout: Duration,
}

/// The **Bench** an eD2k flow is staged on: the private network, the three
/// named roles (eserver, aMule, rmule) plus any extra containers a flow tracks,
/// and the guard that tears them all down.
pub(crate) struct Bench {
    pub(crate) docker: Docker,
    pub(crate) names: BenchNames,
    keep_containers: bool,
    network_created: bool,
    server_started: bool,
    pub(crate) amule_started: bool,
    rmule_started: bool,
    /// Detached containers beyond the three roles, in start order.
    extra: Vec<String>,
    /// Networks beyond the bench's own, in creation order — a NAT topology
    /// needs a fake-public WAN and a masquerade-free LAN at once.
    extra_networks: Vec<String>,
}

impl Bench {
    pub(crate) fn new(
        container_runtime: &str,
        layout: &RunLayout,
        keep_containers: bool,
    ) -> Result<Self> {
        Ok(Self {
            docker: Docker::new(container_runtime),
            names: BenchNames::from_layout(layout)?,
            keep_containers,
            network_created: false,
            server_started: false,
            amule_started: false,
            rmule_started: false,
            extra: Vec::new(),
            extra_networks: Vec::new(),
        })
    }

    /// This bench as one rmule container's staging: its runtime, the run dir
    /// `layout`, and the bench network.
    pub(crate) fn staging<'a>(&'a self, layout: &'a RunLayout) -> BenchStaging<'a> {
        BenchStaging {
            docker: &self.docker,
            layout,
            network: &self.names.network_name,
        }
    }

    /// Create the bench network (with `subnet` when the flow assigns static
    /// addresses) and record its id under the run dir. Owned for teardown from
    /// the moment `network create` returns, so a failed id write still tears it
    /// down.
    pub(crate) fn create_network(
        &mut self,
        layout: &RunLayout,
        subnet: Option<&str>,
    ) -> Result<()> {
        fs::create_dir_all(layout.docker_dir()).with_context(|| {
            format!(
                "create docker artifact directory {}",
                layout.docker_dir().display()
            )
        })?;
        let name = self.names.network_name.clone();
        let command = match subnet {
            Some(subnet) => self.docker.create_network_with_subnet(name, subnet),
            None => self.docker.create_network(name),
        };
        let network_id = run_checked(command, "create docker network")?;
        self.network_created = true;
        write_id(
            &layout.network_id_file(),
            fallback_id(&network_id, &self.names.network_name),
        )
    }

    /// Start the eserver role container as given (already named and networked),
    /// own it for teardown and record its id. Ownership is taken before the
    /// runtime is invoked: a `run` refused after the container was created (a
    /// host port another run already publishes) leaves it behind as
    /// `Created`.
    pub(crate) fn start_server_container(
        &mut self,
        layout: &RunLayout,
        server: RunContainer,
    ) -> Result<()> {
        self.server_started = true;
        let id = run_checked(self.docker.run_container(server), "run server container")?;
        write_id(
            &layout.server_container_id_file(),
            fallback_id(&id, &self.names.server_container_name),
        )
    }

    /// Stand the eserver up on the bench: publish its port to the host, start
    /// it, wait for the host-side TCP readiness probe, and collect its logs.
    /// On a readiness timeout the timeout is the error and a failed log
    /// collection only warns, so the primary failure is never masked.
    pub(crate) fn start_eserver(
        &mut self,
        layout: &RunLayout,
        eserver: &Eserver<'_>,
    ) -> Result<()> {
        let server = RunContainer::new(eserver.image.to_owned())
            .detach()
            .name(self.names.server_container_name.clone())
            .network(self.names.network_name.clone())
            .publish(
                eserver.host_port.to_string(),
                format!("{ED2K_SERVER_PORT}/tcp"),
            )
            .env_assignments(eserver.env);
        self.start_server_container(layout, server)?;

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), eserver.host_port);
        let readiness = wait_for_tcp_ready(server_addr, eserver.timeout);
        let logs = collect_server_logs(&self.docker, layout, &self.names.server_container_name);
        if let Err(readiness_error) = readiness {
            if let Err(log_error) = logs {
                eprintln!(
                    "warning: failed to collect server logs after readiness failure: {log_error:#}"
                );
            }
            return Err(readiness_error);
        }
        logs
    }

    /// Stand the eserver up inside the bench network only, its port never
    /// published to the host, for a leg whose every client runs in the
    /// network. The clients' own logins are the readiness signal (an aMule
    /// sharer keeps reconnecting until the server listens), so this holds only
    /// until the container's entrypoint has run, then collects its logs.
    pub(crate) fn start_eserver_in_network(
        &mut self,
        layout: &RunLayout,
        image: &str,
        env: &[String],
        timeout: Duration,
    ) -> Result<()> {
        let server = RunContainer::new(image.to_owned())
            .detach()
            .name(self.names.server_container_name.clone())
            .network(self.names.network_name.clone())
            .env_assignments(env);
        self.start_server_container(layout, server)?;
        wait_for_container_log(
            &self.docker,
            &self.names.server_container_name,
            ESERVER_ENTRYPOINT_LOG,
            timeout,
        )?;
        collect_server_logs(&self.docker, layout, &self.names.server_container_name)
    }

    /// An aMule container joined to the bench and pointed at its eserver; the
    /// caller adds the role's own mounts and knobs.
    pub(crate) fn amule_container(&self, image: &str, name: &str) -> RunContainer {
        RunContainer::new(image.to_owned())
            .detach()
            .name(name)
            .network(self.names.network_name.clone())
            .env(
                "ED2K_SERVER_HOST",
                self.names.server_container_name.as_str(),
            )
            .env("ED2K_SERVER_PORT", ED2K_SERVER_PORT.to_string())
    }

    /// The aMule role container: [`Self::amule_container`] under the bench's
    /// aMule name.
    pub(crate) fn amule_role_container(&self, image: &str) -> RunContainer {
        self.amule_container(image, &self.names.amule_container_name)
    }

    /// Start the aMule role container, own it for teardown, record its id, and
    /// hold until its log carries `ready_log_pattern`. Ownership is taken
    /// before the runtime is invoked, as [`Self::start_server_container`]
    /// takes it.
    pub(crate) fn start_amule(
        &mut self,
        layout: &RunLayout,
        amule: RunContainer,
        ready_log_pattern: &str,
        timeout: Duration,
    ) -> Result<()> {
        self.amule_started = true;
        let id = run_checked(self.docker.run_container(amule), "run aMule container")?;
        write_id(
            &layout.amule_container_id_file(),
            fallback_id(&id, &self.names.amule_container_name),
        )?;
        wait_for_amule_ready(
            &self.docker,
            layout,
            &self.names.amule_container_name,
            timeout,
            ready_log_pattern,
        )
    }

    /// Start the rmule role container behind the eserver-login retry gate and
    /// own it for teardown. Ownership is taken *before* the first attempt, not
    /// after the gate passes: an exhausted retry has still left a container
    /// under the role's fixed name, and a container the bench does not own is
    /// never removed.
    pub(crate) fn start_rmule_serve(
        &mut self,
        layout: &RunLayout,
        serve_container: &RmuleServeContainer,
        knobs: ServeKnobs<'_>,
        timeout: Duration,
    ) -> Result<String> {
        self.rmule_started = true;
        start_rmule_serve_with_login_retry(
            self.staging(layout),
            serve_container,
            &self.names.rmule_container_name,
            &self.names.server_endpoint(),
            knobs,
            timeout,
        )
    }

    /// Start the rmule role container from an already-composed `command` and own
    /// it for teardown. Ownership is taken before the runtime is invoked, for
    /// the same reason [`Self::start_rmule_serve`] takes it early: a `run` that
    /// fails after the container exists still leaves one behind.
    pub(crate) fn start_rmule_container(
        &mut self,
        command: DockerCommand,
        phase: &str,
    ) -> Result<String> {
        self.rmule_started = true;
        run_checked(command, phase)
    }

    /// Create an extra network and own it for teardown. Ownership is taken
    /// *before* the runtime is invoked, for the same reason the role containers
    /// take it early: a `network create` that fails after the network exists
    /// still leaves one behind.
    ///
    /// # Errors
    /// If the runtime refuses the creation.
    pub(crate) fn create_extra_network(
        &mut self,
        name: &str,
        command: DockerCommand,
        phase: &str,
    ) -> Result<()> {
        self.extra_networks.push(name.to_owned());
        run_checked(command, phase).map(|_| ())
    }

    /// Remove one extra container now, before the rest of the teardown — a
    /// gateway leg that has written its proof must go before the next leg takes
    /// its addresses. Under `--keep-containers` it is left standing and
    /// reported, like every other teardown path, so an operator can inspect the
    /// leg that misbehaved.
    pub(crate) fn stop_extra(&mut self, name: &str) {
        if self.keep_containers {
            println!("kept_container={name}");
            return;
        }
        self.extra.retain(|container| container != name);
        let _ = run_checked(
            self.docker.remove_container(name.to_owned()),
            "remove extra container",
        );
    }

    /// Start an extra detached container under `name` and own it for teardown.
    pub(crate) fn start_extra(
        &mut self,
        name: &str,
        container: RunContainer,
        phase: &str,
    ) -> Result<()> {
        self.track(name);
        run_checked(self.docker.run_container(container), phase)?;
        Ok(())
    }

    /// Build `tag` from `context`; `role` names the image in the failure.
    pub(crate) fn build_image(&self, role: &str, tag: &str, context: &Path) -> Result<()> {
        run_checked(
            self.docker.build_image(tag, context),
            &format!("build {role} image"),
        )
        .map(|_| ())
    }

    /// The Bench Doctor, run first: build the one image it probes with (`role`
    /// names it in a failure; a 30 s Debian layer that caches) and examine the
    /// kernel with it. A flow builds nothing else until its `require` has
    /// passed, so a run the host cannot carry is written down as skipped in
    /// seconds instead of after every image has been built.
    ///
    /// # Errors
    /// If the doctor image fails to build or the probes cannot run.
    pub(crate) fn examine_doctor(
        &self,
        role: &str,
        image: &str,
        context: &Path,
        suffix: &str,
    ) -> Result<DoctorReport> {
        self.build_image(role, image, context)?;
        BenchDoctor::new(&self.docker, image, suffix)
            .examine()
            .context("run the bench doctor")
    }

    /// Build the `rmule-tools` driver image from the warm host-cached
    /// prebuild (see [`crate::flow::driver_image`]). `context` is the
    /// workspace root the prebuild compiles; `dockerfile` is the runtime
    /// recipe.
    pub(crate) fn build_rmule_tools_image(
        &self,
        tag: &str,
        dockerfile: &Path,
        context: &Path,
    ) -> Result<()> {
        crate::flow::driver_image::build(&self.docker, tag, dockerfile, context)
    }

    /// Own an extra detached container (a helper aMule, a sidecar, a
    /// registrant) for teardown: removed in reverse start order, before the
    /// three roles.
    pub(crate) fn track(&mut self, container: impl Into<String>) {
        self.extra.push(container.into());
    }

    /// Drain every started role's own logs (and the aMule diagnostics sweep)
    /// into the run dir after a failure.
    pub(crate) fn collect_failure_logs(&self, layout: &RunLayout) {
        if self.server_started {
            collect_or_warn("server logs", || {
                collect_server_logs(&self.docker, layout, &self.names.server_container_name)
            });
        }
        if self.amule_started {
            collect_or_warn("aMule logs", || {
                collect_amule_logs(&self.docker, layout, &self.names.amule_container_name)
            });
            collect_or_warn("aMule diagnostics", || {
                collect_amule_diagnostics(&self.docker, layout, &self.names.amule_container_name)
            });
        }
        if self.rmule_started {
            collect_or_warn("rmule logs", || {
                collect_rmule_logs(&self.docker, layout, &self.names.rmule_container_name)
            });
        }
    }

    /// Tear everything down, or — under `--keep-containers` — print what was
    /// kept so the operator can inspect and remove it. The extras go before the
    /// three roles: they are started last and a helper aMule still dialling a
    /// role holds it open.
    pub(crate) fn cleanup_best_effort(&self) {
        let mut containers = Vec::new();
        if self.server_started {
            containers.push(self.names.server_container_name.clone());
        }
        if self.rmule_started {
            containers.push(self.names.rmule_container_name.clone());
        }
        if self.amule_started {
            containers.push(self.names.amule_container_name.clone());
        }
        containers.extend(self.extra.iter().cloned());
        OwnedResources {
            docker: &self.docker,
            keep: self.keep_containers,
            containers,
            networks: self
                .network_created
                .then(|| self.names.network_name.clone())
                .into_iter()
                .chain(self.extra_networks.iter().cloned())
                .collect(),
        }
        .tear_down();
    }
}

/// Run a container-runtime command, failing with `phase` and the runtime's
/// stderr on a non-zero exit; the trimmed stdout otherwise.
pub(crate) fn run_checked(command: DockerCommand, phase: &str) -> Result<String> {
    let output = command
        .to_command()
        .output()
        .with_context(|| format!("{phase}: failed to spawn container runtime"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{phase}: container runtime exited unsuccessfully: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Record a container or network id under the run dir.
pub(crate) fn write_id(path: &Path, id: &str) -> Result<()> {
    fs::write(path, format!("{id}\n")).with_context(|| format!("write {}", path.display()))
}

/// The id the runtime printed, or the name it was started under when the
/// runtime printed nothing (a fake runtime, or a quiet one).
pub(crate) fn fallback_id<'a>(output: &'a str, fallback: &'a str) -> &'a str {
    if output.is_empty() { fallback } else { output }
}
