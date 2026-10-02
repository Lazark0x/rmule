//! rmule run as a **serving** node inside the bench: the container a
//! counterparty dials, downloads from, or — with `KadStimulusKnobs` — meets on
//! Kad. The knob types are the only sanctioned levers over that stimulus; they
//! shape rmule's own posture and never touch the counterparty.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Result;

use crate::docker::{Docker, DockerCommand};

use super::{
    BenchStaging, CONTAINER_RUN_ROOT, RMULE_SERVE_TCP_PORT, RmuleWorkspace,
    STIMULUS_CLOSED_SERVER_ENDPOINT, rmule_log_level,
};

/// The rust image plus mounted workspace an rmule serve container runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmuleServeContainer {
    workspace: RmuleWorkspace,
}

impl RmuleServeContainer {
    /// Run `image` with `workspace_root` mounted as the repository.
    pub fn new(image: impl Into<OsString>, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace: RmuleWorkspace::new(image, workspace_root),
        }
    }

    /// Run `image` against the workspace this harness was built from.
    pub fn cargo_rmule_tools(image: impl Into<OsString>) -> Result<Self> {
        Ok(Self {
            workspace: RmuleWorkspace::from_manifest(image, "serve")?,
        })
    }

    /// The plain `ed2k serve start`: [`Self::start_command_with_knobs`] under
    /// `ServeKnobs::default()`.
    pub fn start_command(
        &self,
        staging: BenchStaging<'_>,
        name: &str,
        server_endpoint: &str,
    ) -> DockerCommand {
        self.start_command_with_knobs(staging, name, server_endpoint, ServeKnobs::default())
    }

    /// A detached `ed2k serve start` sharing the synthetic file toward
    /// `server_endpoint` and listening on [`RMULE_SERVE_TCP_PORT`], under the
    /// flow's [`ServeKnobs`]. A default `ServeKnobs` passes no extra flag at
    /// all, so the serve tool's own defaults stand and the run stays
    /// byte-for-byte the plain one. The serve peer driver logs each PeerEvent
    /// at debug, so `RMULE_SERVE_LOG=debug` lets a reverse-download diagnosis
    /// watch the inbound handshake progress.
    pub fn start_command_with_knobs(
        &self,
        staging: BenchStaging<'_>,
        name: &str,
        server_endpoint: &str,
        knobs: ServeKnobs<'_>,
    ) -> DockerCommand {
        let mut container = self
            .workspace
            .cargo_run(staging.layout)
            .detach()
            .name(name)
            .network(staging.network)
            .env("RMULE_LOG", rmule_log_level("info"))
            .arg("ed2k")
            .arg("serve")
            .arg("start")
            .arg("--file")
            .arg(format!("{CONTAINER_RUN_ROOT}/synthetic/shared.bin"))
            .arg("--server")
            .arg(server_endpoint)
            .arg("--listen")
            .arg(format!("0.0.0.0:{RMULE_SERVE_TCP_PORT}"));
        if let Some(slots) = knobs.upload_slots {
            container = container.arg("--upload-slots").arg(slots.to_string());
        }
        if let Some(policy) = knobs.peer_crypt {
            container = container.arg("--peer-crypt").arg(policy);
        }
        if let Some(dir) = knobs.identity_dir {
            container = container.arg("--identity-dir").arg(dir);
        }
        staging.docker.run_container(container)
    }

    /// Run the **Core-Pumped Stimulus Node**: `ed2k serve start --kad …` on a
    /// static fake-public address, so the serve listener and the Kad node share
    /// one `Core` and one identity.
    ///
    /// `--server` deliberately names a closed local port. A Config-A Kad swarm
    /// has no eD2k server, and the serve activity treats a failed login as
    /// non-fatal (binding the listener is what serving means, ADR-0043) — a
    /// local refusal fails in milliseconds instead of hanging on an unroutable
    /// address, so the listener is up before the counterparty's first hello.
    ///
    /// The stimulus runs the **pre-built binary**, not `cargo run`, because a
    /// Config-A swarm is a Docker `internal` network with no DNS or egress.
    /// `rust-toolchain.toml` pins components the base image does not ship, so a
    /// `cargo` invocation there makes rustup try to fetch them and die on name
    /// resolution — [`prebuild_command`](Self::prebuild_command) does the compile
    /// on a networked run first, and this only executes what it produced.
    ///
    /// The buddy/relay dispositions (recruit accepted or refused, held-link
    /// attach, relay drop) are `tracing::debug` in rmule-core — rmule's own
    /// disposition trail beside the pcap's counterparty bytes — so the default
    /// log level opens them.
    pub fn stimulus_start_command(
        &self,
        staging: BenchStaging<'_>,
        name: &str,
        kad: KadStimulusKnobs<'_>,
    ) -> Result<DockerCommand> {
        let mut container = self
            .workspace
            .prebuilt(staging.layout)?
            .detach()
            .name(name)
            .network(staging.network)
            .ip(kad.static_ip)
            .env(
                "RMULE_LOG",
                rmule_log_level("info,rmule_core=debug,rmule_net::kad=debug"),
            )
            .arg("ed2k")
            .arg("serve")
            .arg("start")
            .arg("--file")
            .arg(format!("{CONTAINER_RUN_ROOT}/synthetic/shared.bin"))
            .arg("--server")
            .arg(STIMULUS_CLOSED_SERVER_ENDPOINT)
            .arg("--listen")
            .arg(format!("0.0.0.0:{RMULE_SERVE_TCP_PORT}"))
            .arg("--kad")
            .arg("--kad-id-hex")
            .arg(kad.kad_id_hex)
            .arg("--udp-port")
            .arg(kad.udp_port.to_string())
            .arg("--kad-bootstrap")
            .arg(kad.kad_bootstrap);
        if kad.assume_open {
            container = container.arg("--kad-assume-open");
        }
        if let Some(hash) = kad.user_hash_hex {
            container = container.arg("--user-hash").arg(hash);
        }
        if let Some(target) = kad.direct_callback {
            container = container
                .arg("--direct-callback")
                .arg(target)
                .arg("--direct-callback-every-secs")
                .arg(kad.direct_callback_every_secs.to_string());
        }
        if let Some(policy) = kad.peer_crypt {
            // The Core leg of Kad-UDP crypt: a policy here
            // arms `CoreConfig::peer_crypt`, which the Kad runtime's crypt
            // gate reads for BOTH the peer and Kad layers (ADR-0046 — one
            // setting), and prints `rmule-kad-crypt-armed verify_key_secret=…`
            // at start.
            container = container.arg("--peer-crypt").arg(policy);
        }
        if let Some(dir) = kad.kad_capture_dir {
            container = container.arg("--kad-capture-dir").arg(dir);
        }
        if kad.report_kad_verdicts_every_secs > 0 {
            container = container
                .arg("--report-kad-verdicts-every-secs")
                .arg(kad.report_kad_verdicts_every_secs.to_string());
        }
        Ok(staging.docker.run_container(container))
    }

    /// Compile `rmule-tools` for the container's platform into the host-persisted
    /// cache, on the runtime's DEFAULT network so cargo and rustup can reach the
    /// registry. Foreground and cached: a warm run returns in seconds.
    pub fn prebuild_command(&self, docker: &Docker) -> Result<DockerCommand> {
        self.workspace.prebuild_command(docker)
    }
}

/// The Kad half of a **Core-Pumped Stimulus Node** run: the
/// `ed2k serve start --kad …` knobs that put a Kad node inside the same `Core`
/// that owns the serve listener, so a counterparty reaches core-owned surfaces
/// (the held buddy link, the listener it dials back on) mid-exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KadStimulusKnobs<'a> {
    /// The static fake-public address the container binds (Config A).
    pub static_ip: &'a str,
    /// 32 hex digits pinning the Kad ID, so a counterparty's FindBuddy walk
    /// (which targets `~ownKadID`) converges on this node.
    pub kad_id_hex: &'a str,
    /// The one UDP listen port the container binds — peer reask, the NAT-T
    /// frames and Kad share it (ADR-0057).
    pub udp_port: u16,
    /// The counterparty's Kad endpoint to bootstrap from, `ip:port`.
    pub kad_bootstrap: &'a str,
    /// Pass `--kad-assume-open`: declare our own reachability open instead of
    /// waiting for self-checks that cannot converge in a two-node swarm.
    pub assume_open: bool,
    /// Pass `--direct-callback <ip:udp_port>` (flow N): drive the
    /// ADR-0061 route 2 emit at the firewalled counterparty's UDP port on a
    /// cadence. `None` leaves the stimulus byte-for-byte the flow-M one.
    pub direct_callback: Option<&'a str>,
    /// The `--direct-callback-every-secs` cadence. Ignored without a target.
    pub direct_callback_every_secs: u64,
    /// `--peer-crypt <policy>`: arms Kad-UDP crypt on the
    /// Core side, keyed on this run's minted seed. `None` leaves the stimulus
    /// byte-for-byte the plaintext one.
    pub peer_crypt: Option<&'a str>,
    /// `--kad-capture-dir <path>`: writes the node's per-frame
    /// tap — the same format `kad join-node --capture-dir` writes — so flow
    /// M's crypt verdict can decode the exchange frame-by-frame instead of
    /// trusting the process log alone. `None` (every caller but the
    /// `--kad-crypt` leg) writes no tap.
    pub kad_capture_dir: Option<&'a str>,
    /// `--user-hash <hex>`: the stimulus's User Hash. `None` keeps the tool's
    /// default, `0x42` sixteen times — a hash every four-byte word of which
    /// reads the same both ways, so it cannot tell a word-order bug in a
    /// `WriteUInt128`-framed hash field from a correct one. Flow R
    /// pins an asymmetric one.
    pub user_hash_hex: Option<&'a str>,
    /// `--report-kad-verdicts-every-secs`: the stimulus prints its own
    /// Kad self-check verdicts, `rmule-kad-verdicts tcp=… udp=…`, from its
    /// diagnostics whenever they change. `0` prints none.
    pub report_kad_verdicts_every_secs: u64,
}

/// The `ed2k serve start` overrides a flow applies. Every field defaults to
/// "leave the tool's default alone", so `ServeKnobs::default()` is the plain
/// serve command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServeKnobs<'a> {
    /// `--upload-slots`. `Some(1)` holds a second requester **queued** — the
    /// peer-UDP reask consume precondition.
    pub upload_slots: Option<usize>,
    /// `--peer-crypt <policy>`: arms rmule's peer obfuscation policy, which
    /// lights the peer hello's `MiscOptions2` crypt bits **and** the peer-UDP
    /// per-datagram layer. The counterparty's own gate reads that advert —
    /// aMule's `ShouldReceiveCryptUDPPackets()` refuses to obfuscate toward a
    /// peer whose hello did not claim `SupportsCryptLayer` — so the peer-UDP
    /// crypt capture needs this set on rmule *and*
    /// `AMULE_CRYPT_SUPPORTED`/`_REQUESTED` on the counterparty.
    pub peer_crypt: Option<&'a str>,
    /// `--identity-dir <DIR>` (container path): the SUI key for the serve
    /// body's User Hash lives in `<DIR>/<HASH>`, created on the first run and
    /// reused after, so the hash proves with one key across runs.
    pub identity_dir: Option<&'a str>,
}
