//! The wire-smoke flow: what the eserver advertises.
//!
//! Starts the plain eserver and drives an in-network rmule probe that reads the
//! server's advertised compression (`SRV_TCPFLG`) and UDP-obfuscation
//! (`SRV_UDPFLG`) capabilities. No aMule, no counterparty fixture — the probe
//! reports wire facts only, distilled into the run dir's summary as the two
//! bench decision inputs.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, Eserver};
use crate::rmule::RmuleClientContainer;

/// Options for the wire-smoke flow: start the plain eserver
/// and drive an in-network rmule probe that reads the server's advertised
/// compression (`SRV_TCPFLG`) and UDP-obfuscation (`SRV_UDPFLG`) capabilities.
/// No aMule, no counterparty fixture — the probe reports wire facts only.
pub struct BenchSmokeOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The eserver image.
    pub server_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on (the readiness probe target).
    pub server_host_port: u16,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The rust image + workspace rmule runs as a client in.
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Ride `CT_EMULE_UDPPORTS` (`0xF9`, ADR-0091) on the probe's login, naming
    /// this client-UDP port — the tag a running core sends on every login.
    pub udp_ports_advert: Option<u16>,
    /// Ride `CT_MOD_IP_V6` (`0xAE`) with its `SRVCAP_IPV6` bit, naming this
    /// address; beside `udp_ports_advert` the login carries six tags.
    pub advertise_ipv6: Option<std::net::Ipv6Addr>,
}

/// Start `rmule/interop-eserver:local` and probe its advertised capabilities
/// from an in-network rmule. Two decision inputs land in the run
/// dir's `bench-smoke-summary.toml` and print prominently: whether the server
/// advertises `SRV_TCPFLG_COMPRESSION` and whether it advertises /
/// answers UDP obfuscation (the crypt advert). The probe captures no
/// counterparty bytes.
pub fn run_bench_smoke(options: BenchSmokeOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
    }

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: options.server_env,
                timeout: Duration::from_secs(options.timeout_secs),
            },
        )?;

        let probe = options.rmule_client_container.probe_command(
            bench.staging(options.layout),
            &bench.names.server_endpoint(),
            crate::rmule::ProbeAsks {
                udp_ports_advert: options.udp_ports_advert,
                advertise_ipv6: options.advertise_ipv6,
                holepunch_target: None,
            },
        );
        fs::create_dir_all(options.layout.probe_dir()).with_context(|| {
            format!("create probe dir {}", options.layout.probe_dir().display())
        })?;
        let output = probe
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run bench-smoke probe container")?;
        fs::write(options.layout.probe_stdout_log(), &output.stdout)
            .with_context(|| format!("write {}", options.layout.probe_stdout_log().display()))?;
        fs::write(options.layout.probe_stderr_log(), &output.stderr)
            .with_context(|| format!("write {}", options.layout.probe_stderr_log().display()))?;
        if !output.status.success() {
            bail!(
                "bench-smoke probe exited unsuccessfully: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let summary = BenchSmokeSummary::from_probe_stdout(&stdout);
        fs::write(options.layout.bench_smoke_summary_file(), summary.to_toml()).with_context(
            || {
                format!(
                    "write {}",
                    options.layout.bench_smoke_summary_file().display()
                )
            },
        )?;
        summary.print();
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// The distilled bench-smoke verdict parsed from the probe's `key: value`
/// report. The two headline fields (`compression_advert`, `crypt_advert`) are
/// the decision inputs; the raw flag words are retained for the record.
pub(crate) struct BenchSmokeSummary {
    pub(crate) compression_advert: String,
    pub(crate) crypt_advert: String,
    pub(crate) tcp_flags: String,
    pub(crate) udp_flags: String,
    pub(crate) crypt_ping_answered: String,
    /// Whether the login the flag words were read from was accepted, and the
    /// `0xF9` word it carried (`none` for aMule 2.3.3's four-tag login).
    pub(crate) login_accepted: String,
    pub(crate) udp_ports_advert: String,
    /// The `CT_MOD_IP_V6` address the login carried (`none` without one),
    /// and how many tags it carried in all.
    pub(crate) advertised_ipv6: String,
    pub(crate) login_tags: String,
}

impl BenchSmokeSummary {
    pub(crate) fn from_probe_stdout(stdout: &str) -> Self {
        // The probe emits one of each headline line; take the last occurrence
        // so a re-emit never leaves a stale value. Missing lines default to a
        // conservative UNKNOWN rather than a fabricated verdict.
        let last = |key: &str| -> Option<String> {
            stdout
                .lines()
                .filter_map(|line| line.strip_prefix(key))
                .map(|value| value.trim().to_owned())
                .next_back()
        };
        let first_udp_flags = stdout
            .lines()
            .find_map(|line| line.split("udp_flags=0x").nth(1))
            .map(|rest| {
                let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
                format!("0x{hex}")
            })
            .unwrap_or_else(|| "none".to_owned());
        Self {
            compression_advert: last("compression_advert:").unwrap_or_else(|| "UNKNOWN".to_owned()),
            crypt_advert: last("crypt_advert:").unwrap_or_else(|| "UNKNOWN".to_owned()),
            tcp_flags: last("tcp_flags:").unwrap_or_else(|| "none".to_owned()),
            udp_flags: first_udp_flags,
            crypt_ping_answered: last("crypt_ping_answered:").unwrap_or_else(|| "false".to_owned()),
            login_accepted: last("login_accepted:")
                .map(|value| value.starts_with("true").to_string())
                .unwrap_or_else(|| "false".to_owned()),
            udp_ports_advert: last("udp_ports_advert:").unwrap_or_else(|| "none".to_owned()),
            advertised_ipv6: last("advertised_ipv6:").unwrap_or_else(|| "none".to_owned()),
            login_tags: last("login_tags:").unwrap_or_else(|| "UNKNOWN".to_owned()),
        }
    }

    pub(crate) fn to_toml(&self) -> String {
        format!(
            "scenario = \"bench-smoke\"\n\
             compression_advert = \"{}\"\n\
             crypt_advert = \"{}\"\n\
             crypt_ping_answered = \"{}\"\n\
             tcp_flags = \"{}\"\n\
             udp_flags = \"{}\"\n\
             login_accepted = \"{}\"\n\
             udp_ports_advert = \"{}\"\n\
             advertised_ipv6 = \"{}\"\n\
             login_tags = \"{}\"\n",
            self.compression_advert,
            self.crypt_advert,
            self.crypt_ping_answered,
            self.tcp_flags,
            self.udp_flags,
            self.login_accepted,
            self.udp_ports_advert,
            self.advertised_ipv6,
            self.login_tags,
        )
    }

    pub(crate) fn print(&self) {
        // The two decision inputs, printed prominently so they surface in the
        // flow's stdout as well as the run-dir summary.
        println!(
            "bench-smoke: compression_advert={} (SRV_TCPFLG={})",
            self.compression_advert, self.tcp_flags
        );
        println!(
            "bench-smoke: crypt_advert={} (SRV_UDPFLG={}, crypt_ping_answered={})",
            self.crypt_advert, self.udp_flags, self.crypt_ping_answered
        );
        println!(
            "bench-smoke: login_accepted={} (udp_ports_advert={}, advertised_ipv6={}, \
             login_tags={})",
            self.login_accepted, self.udp_ports_advert, self.advertised_ipv6, self.login_tags
        );
    }
}

#[cfg(test)]
mod tests {
    use super::BenchSmokeSummary;

    /// The six-tag login reads back as the probe stated it — its address and
    /// its tag count beside the answer — and a bare login as aMule 2.3.3's
    /// four with no address.
    #[test]
    fn the_summary_names_what_the_login_carried_beside_its_answer() {
        let six = BenchSmokeSummary::from_probe_stdout(
            "udp_ports_advert: 0x00001240\nadvertised_ipv6: 2001:db8::9\nlogin_tags: 6\n\
             login_accepted: true client_id=16777343\n",
        );
        assert_eq!(
            (
                six.login_accepted.as_str(),
                six.advertised_ipv6.as_str(),
                six.login_tags.as_str()
            ),
            ("true", "2001:db8::9", "6")
        );
        let bare = BenchSmokeSummary::from_probe_stdout("login_tags: 4\nlogin_accepted: false\n");
        assert_eq!(
            (
                bare.login_accepted.as_str(),
                bare.advertised_ipv6.as_str(),
                bare.udp_ports_advert.as_str(),
                bare.login_tags.as_str()
            ),
            ("false", "none", "none", "4")
        );
    }
}
