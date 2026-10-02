//! Composing the container-runtime argv a flow runs its **Bench** on. The
//! builders are pure — they produce a `DockerCommand` and never spawn — which is
//! what lets the suite assert the exact orchestration a flow performs against a
//! **Fake Docker**. The runtime program itself is a parameter, so a flow never
//! hard-codes `docker`.

use std::ffi::{OsStr, OsString};
use std::process::Command;

/// One container-runtime invocation: the program and its argv, pure until
/// `to_command` builds a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DockerCommand {
    program: OsString,
    args: Vec<OsString>,
}

impl DockerCommand {
    fn new(program: impl Into<OsString>, args: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
        }
    }

    /// The runtime program.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// The argv after the program.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The process to spawn.
    pub fn to_command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command
    }
}

/// The label every harness Dockerfile's non-final (`AS build`) stage carries.
/// A multi-stage build under the plain `docker build` — no BuildKit; colima's
/// engine defaults to the legacy builder — commits every stage as its own
/// image, and only the final stage gets `-t`: every earlier stage is dangling
/// the moment the build succeeds. [`Docker::prune_bench_stage_images`] sweeps
/// exactly the images carrying this label, so it never touches an unrelated
/// dangling image on the host.
pub const BENCH_STAGE_LABEL: &str = "org.rmule.bench.stage=1";

/// Whether a failed `docker build`'s combined output names one of the three
/// containerd content-store races the legacy (non-BuildKit) builder flakes
/// with on colima: a layer export whose content digest went missing, a
/// snapshot ingest rename that lost the race, or a commit that could no
/// longer find the snapshot it just made. Each is a
/// transient loser inside the image store, not a Dockerfile or compile
/// error, so a bare retry — same context, same cache — clears it; anything
/// else (a real compile failure, a missing file) is not retried.
pub fn is_retriable_build_export_failure(output: &str) -> bool {
    (output.contains("content digest") && output.contains("not found"))
        || output.contains("ingest rename")
        || (output.contains("snapshot") && output.contains("not found"))
}

/// The container runtime: every builder below composes `<runtime> ...` argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Docker {
    runtime: OsString,
}

impl Docker {
    /// Compose commands for `runtime` (`docker`, `podman`, or a fake).
    pub fn new(runtime: impl Into<OsString>) -> Self {
        Self {
            runtime: runtime.into(),
        }
    }

    /// `<runtime> --version`, the availability probe.
    pub fn version(&self) -> DockerCommand {
        self.command([OsString::from("--version")])
    }

    /// `docker build -t <tag> <context>`.
    pub fn build_image(
        &self,
        tag: impl Into<OsString>,
        context: impl Into<OsString>,
    ) -> DockerCommand {
        self.command(vec![
            OsString::from("build"),
            OsString::from("-t"),
            tag.into(),
            context.into(),
        ])
    }

    /// `docker build -f <dockerfile> -t <tag> <context>` — for images whose
    /// Dockerfile lives outside the build context root (e.g. the rmule-node
    /// image builds from the repo root to see the workspace sources).
    pub fn build_image_with_dockerfile(
        &self,
        tag: impl Into<OsString>,
        dockerfile: impl Into<OsString>,
        context: impl Into<OsString>,
    ) -> DockerCommand {
        self.command(vec![
            OsString::from("build"),
            OsString::from("-f"),
            dockerfile.into(),
            OsString::from("-t"),
            tag.into(),
            context.into(),
        ])
    }

    /// `docker image prune -f --filter label=<BENCH_STAGE_LABEL> --filter
    /// dangling=true` — removes the dangling build-stage images a harness
    /// `docker build` left behind, never an unlabeled image on
    /// the host: an image only matches when it is both labeled AND dangling.
    /// It does not tell one run's stages from another's. Under the legacy
    /// builder a concurrent build's finished `AS build` stage is dangling
    /// until its final stage has copied from it, and it is also that build's
    /// layer cache, so a sweep can race a build on a shared bench and evicts
    /// the cached compile layer (not verified live). `main` runs this after
    /// every subcommand, success or failure, as a best-effort sweep — its own
    /// failure never turns a passing flow red.
    pub fn prune_bench_stage_images(&self) -> DockerCommand {
        self.command(vec![
            OsString::from("image"),
            OsString::from("prune"),
            OsString::from("-f"),
            OsString::from("--filter"),
            OsString::from(format!("label={BENCH_STAGE_LABEL}")),
            OsString::from("--filter"),
            OsString::from("dangling=true"),
        ])
    }

    /// `docker network create <name>` on the runtime's default driver.
    pub fn create_network(&self, name: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("network"),
            OsString::from("create"),
            name.into(),
        ])
    }

    /// Create a user-defined bridge network with an explicit IPv4 subnet so
    /// containers can be assigned deterministic static addresses (`RunContainer::ip`).
    /// The private Kad mesh needs this: each node's bootstrap `nodes.dat` must
    /// name peer IPs that are known *before* the peers are started.
    pub fn create_network_with_subnet(
        &self,
        name: impl Into<OsString>,
        subnet: impl Into<OsString>,
    ) -> DockerCommand {
        self.command(vec![
            OsString::from("network"),
            OsString::from("create"),
            OsString::from("--subnet"),
            subnet.into(),
            name.into(),
        ])
    }

    /// Create an **internal** (`--internal`) bridge with an explicit subnet: an
    /// isolated segment with **no egress to the host or the internet**. This is
    /// the fake-public Kad swarm's network: `--internal` guarantees an isolated
    /// aMule Kad swarm never emits a datagram outward, and a documentation-range
    /// `--subnet` (`203.0.113.0/24`, RFC 5737) gives the containers non-RFC1918
    /// addresses that stock aMule's `IsGoodIPPort` admits at the routing-add
    /// gate — so the nodes route on their normal (non-LAN-mode) code paths.
    pub fn create_internal_network_with_subnet(
        &self,
        name: impl Into<OsString>,
        subnet: impl Into<OsString>,
    ) -> DockerCommand {
        self.create_internal_network(InternalNetwork::new(name).subnet_v4(subnet))
    }

    /// Create an `--internal` bridge from a full [`InternalNetwork`] — the
    /// dual-stack form of [`Self::create_internal_network_with_subnet`].
    ///
    /// A v6 subnet adds `--ipv6`, which is what gives the WAN its **Fake-Public
    /// v6 Plan** `/64`. `--internal` isolation applies to `ip6tables` exactly as
    /// it does to `iptables` (moby ships the `__ip6tables.golden` variants), so
    /// a dual-stack WAN is no less air-gapped than the v4-only one.
    pub fn create_internal_network(&self, network: InternalNetwork) -> DockerCommand {
        let mut args = vec![
            OsString::from("network"),
            OsString::from("create"),
            OsString::from("--internal"),
        ];
        if network.subnet_v6.is_some() {
            args.push(OsString::from("--ipv6"));
        }
        for subnet in [network.subnet_v4, network.subnet_v6].into_iter().flatten() {
            args.push(OsString::from("--subnet"));
            args.push(subnet);
        }
        args.push(network.name);
        self.command(args)
    }

    /// Create the **NAT Gateway**'s LAN side: an ordinary bridge with an
    /// explicit subnet and `enable_ip_masquerade=false`.
    ///
    /// Not `--internal`, and the difference is load-bearing: a gateway
    /// cannot bridge two `--internal` networks, because Docker's host-side
    /// `DOCKER-INTERNAL` chain drops every packet leaving the bridge whose
    /// destination is outside the bridge's own subnet — which is every
    /// translated hop. Masquerading is off so the LAN has no egress of its own:
    /// the client's only way out is its default route through the gateway, whose
    /// WAN side *is* `--internal`.
    pub fn create_lan_bridge(
        &self,
        name: impl Into<OsString>,
        subnet: impl Into<OsString>,
    ) -> DockerCommand {
        self.create_lan_bridge_dual(name, subnet, None::<OsString>)
    }

    /// The dual-stack form of [`Self::create_lan_bridge`]: the same
    /// masquerade-free bridge with a **Fake-Public v6 Plan** `/64` beside the
    /// RFC 1918 `/24`.
    ///
    /// A LAN v6 prefix is what an IPv6 pinhole flow needs and what the baseline flows had
    /// no use for: a PCP MAP over IPv6 is a firewall pinhole to *our own*
    /// address, so the client must hold a global-unicast-shaped v6 on the LAN
    /// and the gateway must be reachable at one in the same `/64` — a link-local
    /// next hop is exactly what `crab_nat` cannot source a request from.
    pub fn create_lan_bridge_dual(
        &self,
        name: impl Into<OsString>,
        subnet: impl Into<OsString>,
        subnet_v6: Option<impl Into<OsString>>,
    ) -> DockerCommand {
        let mut args = vec![OsString::from("network"), OsString::from("create")];
        if let Some(subnet_v6) = subnet_v6 {
            args.push(OsString::from("--ipv6"));
            args.push(OsString::from("--subnet"));
            args.push(subnet_v6.into());
        }
        args.push(OsString::from("--subnet"));
        args.push(subnet.into());
        args.push(OsString::from("-o"));
        args.push(OsString::from(
            "com.docker.network.bridge.enable_ip_masquerade=false",
        ));
        args.push(name.into());
        self.command(args)
    }

    /// `docker network connect [--ip <v4>] [--ip6 <v6>] <network> <container>` —
    /// the second and later attachments of a multi-homed container. `docker run`
    /// takes one `--network` with one `--ip`, so a **NAT Gateway** joins its WAN
    /// at `run` time and its LAN through this.
    pub fn connect_network(
        &self,
        network: impl Into<OsString>,
        container: impl Into<OsString>,
        ip: Option<OsString>,
        ip6: Option<OsString>,
    ) -> DockerCommand {
        let mut args = vec![OsString::from("network"), OsString::from("connect")];
        if let Some(ip) = ip {
            args.push(OsString::from("--ip"));
            args.push(ip);
        }
        if let Some(ip6) = ip6 {
            args.push(OsString::from("--ip6"));
            args.push(ip6);
        }
        args.push(network.into());
        args.push(container.into());
        self.command(args)
    }

    /// `docker inspect -f {{.State.Status}} <container>` — whether a container
    /// is still running.
    ///
    /// A flow that must *watch* a counterparty while a driver runs cannot block
    /// on `docker wait`: the whole point is to read the counterparty's own state
    /// at intervals, and `wait` returns only once there is nothing left to
    /// watch.
    pub fn inspect_state(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("inspect"),
            OsString::from("-f"),
            OsString::from("{{.State.Status}}"),
            container.into(),
        ])
    }

    /// `docker image inspect -f {{.Id}} <tag>` — whether an image is present
    /// locally at all. A flow whose counterparty image was never built records a
    /// **Documented Absence** naming that, rather than failing in a way that
    /// looks like the counterparty refused something.
    pub fn inspect_image(&self, tag: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("image"),
            OsString::from("inspect"),
            OsString::from("-f"),
            OsString::from("{{.Id}}"),
            tag.into(),
        ])
    }

    /// `docker image inspect -f '{{ index .Config.Labels "<key>" }}' <tag>` —
    /// one label off an image, which prints `<no value>` when it is unset.
    pub fn image_label(&self, tag: impl Into<OsString>, key: &str) -> DockerCommand {
        self.command(vec![
            OsString::from("image"),
            OsString::from("inspect"),
            OsString::from("-f"),
            OsString::from(format!("{{{{ index .Config.Labels \"{key}\" }}}}")),
            tag.into(),
        ])
    }

    /// `docker info --format <format>` — what **Bench Doctor** reads the daemon's
    /// own capability report out of.
    pub fn info(&self, format: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("info"),
            OsString::from("--format"),
            format.into(),
        ])
    }

    /// `docker run` with the container's options rendered in docker's argv order:
    /// lifecycle flags, name, network, ip, capabilities, workdir, ports, volumes,
    /// env, then the image and its command.
    pub fn run_container(&self, container: RunContainer) -> DockerCommand {
        let mut args = vec![OsString::from("run")];

        if container.detach {
            args.push(OsString::from("--detach"));
        }
        if container.remove_after_exit {
            args.push(OsString::from("--rm"));
        }
        if let Some(name) = container.name {
            args.push(OsString::from("--name"));
            args.push(name);
        }
        if let Some(network) = container.network {
            args.push(OsString::from("--network"));
            args.push(network);
        }
        if let Some(ip) = container.ip {
            args.push(OsString::from("--ip"));
            args.push(ip);
        }
        if let Some(ip6) = container.ip6 {
            args.push(OsString::from("--ip6"));
            args.push(ip6);
        }
        for capability in container.cap_add {
            args.push(OsString::from("--cap-add"));
            args.push(capability);
        }
        for sysctl in container.sysctls {
            args.push(OsString::from("--sysctl"));
            args.push(sysctl);
        }
        if let Some(workdir) = container.workdir {
            args.push(OsString::from("-w"));
            args.push(workdir);
        }
        if let Some(entrypoint) = container.entrypoint {
            args.push(OsString::from("--entrypoint"));
            args.push(entrypoint);
        }
        for port in container.ports {
            args.push(OsString::from("-p"));
            args.push(port);
        }
        for volume in container.volumes {
            args.push(OsString::from("-v"));
            args.push(volume);
        }
        for env in container.env {
            args.push(OsString::from("-e"));
            args.push(env);
        }

        args.push(container.image);
        args.extend(container.args);
        self.command(args)
    }

    /// `docker logs <container>`.
    pub fn logs(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![OsString::from("logs"), container.into()])
    }

    /// `docker inspect` printing the container's IP on its network.
    pub fn container_ip(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("inspect"),
            OsString::from("--format"),
            OsString::from("{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}"),
            container.into(),
        ])
    }

    /// `docker exec <container> <args...>`.
    pub fn exec(
        &self,
        container: impl Into<OsString>,
        args: impl IntoIterator<Item = OsString>,
    ) -> DockerCommand {
        let mut command_args = vec![OsString::from("exec"), container.into()];
        command_args.extend(args);
        self.command(command_args)
    }

    /// `docker wait <container>` — block until the container stops, printing
    /// its exit code. The golden flush waits on this after `amulecmd Shutdown`
    /// so amuled finishes its `write_safe` (temp-file + rename) of `server.met`
    /// / `nodes.dat` before the `docker cp` lifts them — without it the cp races
    /// the rename and grabs the pre-shutdown file (a 15-byte seed
    /// instead of aMule's ~237-byte 21-tag SaveServerMet output).
    pub fn wait(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![OsString::from("wait"), container.into()])
    }

    /// `docker cp <container>:<src> <dest>` — copy a file out of a container.
    /// The golden-author flush uses this to lift
    /// aMule's shutdown-flushed `server.met` / `nodes.dat` into the run dir.
    pub fn copy_from_container(
        &self,
        container: impl AsRef<OsStr>,
        container_path: impl AsRef<OsStr>,
        dest: impl Into<OsString>,
    ) -> DockerCommand {
        let mut source = container.as_ref().to_os_string();
        source.push(":");
        source.push(container_path.as_ref());
        self.command(vec![OsString::from("cp"), source, dest.into()])
    }

    /// `docker pause <container>` — freezes every process; the container
    /// keeps its address, so no later container on the network takes it.
    pub fn pause_container(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![OsString::from("pause"), container.into()])
    }

    /// `docker stop --time <timeout_secs> <container>` — SIGTERM, then
    /// SIGKILL only after `timeout_secs` — never `docker kill`'s immediate
    /// SIGKILL. A container's own process needs its SIGTERM
    /// handler to actually run (the Core-pumped stimulus's Kad node stop and
    /// ADR-0022 tap finalize) before the runtime gives up and force-kills it.
    pub fn stop_container(
        &self,
        container: impl Into<OsString>,
        timeout_secs: u64,
    ) -> DockerCommand {
        self.command(vec![
            OsString::from("stop"),
            OsString::from("--time"),
            OsString::from(timeout_secs.to_string()),
            container.into(),
        ])
    }

    /// `docker rm -f <container>`.
    pub fn remove_container(&self, container: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("rm"),
            OsString::from("-f"),
            container.into(),
        ])
    }

    /// `docker network rm <name>`.
    pub fn remove_network(&self, name: impl Into<OsString>) -> DockerCommand {
        self.command(vec![
            OsString::from("network"),
            OsString::from("rm"),
            name.into(),
        ])
    }

    fn command(&self, args: impl IntoIterator<Item = OsString>) -> DockerCommand {
        DockerCommand::new(self.runtime.clone(), args)
    }
}

/// An `--internal` bridge under construction: its name and the address families
/// it carries. At least one subnet is expected; a v6 subnet also turns `--ipv6`
/// on, since Docker will not allocate v6 addresses on a network without it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalNetwork {
    name: OsString,
    subnet_v4: Option<OsString>,
    subnet_v6: Option<OsString>,
}

impl InternalNetwork {
    /// The network named `name`, with no subnet yet.
    pub fn new(name: impl Into<OsString>) -> Self {
        Self {
            name: name.into(),
            subnet_v4: None,
            subnet_v6: None,
        }
    }

    /// The IPv4 `--subnet` (a fake-public `/24`).
    pub fn subnet_v4(mut self, subnet: impl Into<OsString>) -> Self {
        self.subnet_v4 = Some(subnet.into());
        self
    }

    /// The IPv6 `--subnet` (a **Fake-Public v6 Plan** `/64`), which also
    /// turns `--ipv6` on.
    pub fn subnet_v6(mut self, subnet: impl Into<OsString>) -> Self {
        self.subnet_v6 = Some(subnet.into());
        self
    }
}

/// A `docker run` under construction: the image, its options and its command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunContainer {
    image: OsString,
    name: Option<OsString>,
    detach: bool,
    remove_after_exit: bool,
    network: Option<OsString>,
    ip: Option<OsString>,
    ip6: Option<OsString>,
    sysctls: Vec<OsString>,
    cap_add: Vec<OsString>,
    entrypoint: Option<OsString>,
    workdir: Option<OsString>,
    ports: Vec<OsString>,
    volumes: Vec<OsString>,
    env: Vec<OsString>,
    args: Vec<OsString>,
}

impl RunContainer {
    /// Run `image` with no options yet.
    pub fn new(image: impl Into<OsString>) -> Self {
        Self {
            image: image.into(),
            name: None,
            detach: false,
            remove_after_exit: false,
            network: None,
            ip: None,
            ip6: None,
            sysctls: Vec::new(),
            cap_add: Vec::new(),
            entrypoint: None,
            workdir: None,
            ports: Vec::new(),
            volumes: Vec::new(),
            env: Vec::new(),
            args: Vec::new(),
        }
    }

    /// `--name`.
    pub fn name(mut self, name: impl Into<OsString>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// `--detach`.
    pub fn detach(mut self) -> Self {
        self.detach = true;
        self
    }

    /// `--rm`.
    pub fn remove_after_exit(mut self) -> Self {
        self.remove_after_exit = true;
        self
    }

    /// `--network` (a network name, or `container:<name>` to share a namespace).
    pub fn network(mut self, network: impl Into<OsString>) -> Self {
        self.network = Some(network.into());
        self
    }

    /// Assign a static IPv4 address on the container's user-defined network.
    /// Requires the network to have an explicit subnet (`create_network_with_subnet`).
    pub fn ip(mut self, ip: impl Into<OsString>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Assign a static IPv6 address on the container's user-defined network.
    /// Requires the network to carry a v6 subnet ([`InternalNetwork::subnet_v6`]).
    pub fn ip6(mut self, ip6: impl Into<OsString>) -> Self {
        self.ip6 = Some(ip6.into());
        self
    }

    /// `--sysctl KEY=VALUE`. Docker permits every namespaced `net.*` sysctl for
    /// a container with its own netns, which is how a **NAT Gateway** gets
    /// `net.ipv4.ip_forward=1` and the RFC 4787 REQ-5 conntrack UDP timeout
    /// without a privileged container.
    pub fn sysctl(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.sysctls
            .push(join_os_pair(key.as_ref(), value.as_ref(), "="));
        self
    }

    /// `--cap-add`.
    pub fn cap_add(mut self, capability: impl Into<OsString>) -> Self {
        self.cap_add.push(capability.into());
        self
    }

    /// `--entrypoint` — how a probe runs a plain shell in an image whose own
    /// entrypoint is a role script that would refuse to start without its
    /// configuration. **Bench Doctor** needs exactly this: it wants the
    /// gateway image's *toolchain*, not a gateway.
    pub fn entrypoint(mut self, entrypoint: impl Into<OsString>) -> Self {
        self.entrypoint = Some(entrypoint.into());
        self
    }

    /// `-w`.
    pub fn workdir(mut self, workdir: impl Into<OsString>) -> Self {
        self.workdir = Some(workdir.into());
        self
    }

    /// `-p host:container`.
    pub fn publish(mut self, host: impl AsRef<OsStr>, container: impl AsRef<OsStr>) -> Self {
        self.ports
            .push(join_os_pair(host.as_ref(), container.as_ref(), ":"));
        self
    }

    /// `-v host:container`.
    pub fn volume(mut self, host: impl AsRef<OsStr>, container: impl AsRef<OsStr>) -> Self {
        self.volumes
            .push(join_os_pair(host.as_ref(), container.as_ref(), ":"));
        self
    }

    /// `-e KEY=VALUE`.
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push(join_os_pair(key.as_ref(), value.as_ref(), "="));
        self
    }

    /// `-e` with a ready-made `KEY=VALUE`.
    pub fn env_assignment(mut self, assignment: impl Into<OsString>) -> Self {
        self.env.push(assignment.into());
        self
    }

    /// Every `KEY=VALUE` in `assignments`, in order — the `--amule-env` /
    /// `--server-env` passthrough.
    pub fn env_assignments<A: Into<OsString>>(
        mut self,
        assignments: impl IntoIterator<Item = A>,
    ) -> Self {
        self.env.extend(assignments.into_iter().map(Into::into));
        self
    }

    /// One argument of the container's command.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }
}

fn join_os_pair(left: &OsStr, right: &OsStr, separator: &str) -> OsString {
    let mut value = left.to_os_string();
    value.push(separator);
    value.push(right);
    value
}
