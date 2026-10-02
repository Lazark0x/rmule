//! **Bench Doctor**: the capability gate every NAT or IPv6 flow runs before it
//! stands anything up.
//!
//! The flows below this gate assert things about a kernel — that nftables can
//! hold a dynamic set, that a container's conntrack UDP timeout can be raised
//! past RFC 4787 REQ-5's two minutes, that bridge netfiltering is on so
//! `--internal` actually isolates, that the daemon will build an IPv6 bridge.
//! None of that is portable, and all of it fails *quietly*: a missing dynamic
//! set makes a "restricted" gateway silently behave like a port-restricted one,
//! and a flow that then reported `PASS` would have fabricated its NAT type.
//!
//! So the doctor measures first and every answer is a [`Capability`] with the
//! command that produced it. A flow asks for the capabilities it needs; a
//! missing one yields a [`SkipReason`] the flow writes into its verdict as a
//! documented skip. There is no path here that turns an unmeasured capability
//! into a pass.

use std::collections::BTreeMap;
use std::ffi::OsString;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::docker::{Docker, InternalNetwork, RunContainer};

/// One measured capability: whether it is there, and what said so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capability {
    /// The capability's name, as a flow asks for it.
    pub name: String,
    /// Whether the probe found it.
    pub available: bool,
    /// The probe's own output — the reason, readable in the run dir.
    pub detail: String,
}

/// Why a flow did not run. Written into the flow's verdict verbatim, so the
/// run dir records an honest skip rather than an absent file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SkipReason {
    /// The capabilities that were asked for and not found.
    pub missing: Vec<String>,
    /// One sentence naming what is missing and what it would have proved.
    pub reason: String,
}

/// `nft` runs, a NAT chain installs, and a dynamic set with a timeout holds —
/// the `restricted` gateway's Address-Dependent Filtering depends on the set.
pub const CAP_NFTABLES: &str = "nftables";
/// `conntrack -L` runs in the container — half the **NAT Type Proof**.
pub const CAP_CONNTRACK: &str = "conntrack";
/// The container's `nf_conntrack_udp_timeout` took the raised value; the 30 s
/// default closes the punch window inside RFC 4787 REQ-5's two-minute floor.
pub const CAP_CONNTRACK_UDP_TIMEOUT: &str = "conntrack-udp-timeout";
/// Bridge netfiltering is on, so `--internal` isolation actually bites.
pub const CAP_BR_NETFILTER: &str = "br_netfilter";
/// The daemon builds an `--ipv6` bridge and allocates on it.
pub const CAP_DAEMON_IPV6: &str = "daemon-ipv6";
/// The kernel carries an `ip6` NAT chain — the v6 firewall analogue the v6
/// flows filter with.
pub const CAP_IP6TABLES: &str = "ip6tables";

/// The conntrack UDP timeout the gateway asks for: RFC 4787 REQ-5 forbids a UDP
/// mapping timer under two minutes, and the Linux default of 30 s violates it
/// by 4×. 180 s is the value the `natgw` image and this probe both request.
pub const CONNTRACK_UDP_TIMEOUT_SECS: u32 = 180;

/// The full capability report — what the doctor measured, in name order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    /// Every capability probed.
    pub capabilities: Vec<Capability>,
}

impl DoctorReport {
    /// Whether `name` was measured present.
    pub fn has(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.name == name && capability.available)
    }

    /// `Ok(())` when every capability in `required` is present, otherwise the
    /// [`SkipReason`] the flow writes into its verdict. `what_it_would_prove`
    /// completes the sentence "…, so `<flow>` could not prove …".
    ///
    /// # Errors
    /// Never — the `Result` shape is the caller's, so a gate reads as
    /// `doctor.require(...)?` at the top of a flow.
    pub fn require(
        &self,
        required: &[&str],
        what_it_would_prove: &str,
    ) -> std::result::Result<(), SkipReason> {
        let missing: Vec<String> = required
            .iter()
            .filter(|name| !self.has(name))
            .map(|name| (*name).to_owned())
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let details: Vec<String> = self
            .capabilities
            .iter()
            .filter(|capability| missing.contains(&capability.name))
            .map(|capability| format!("{}: {}", capability.name, capability.detail))
            .collect();
        Err(SkipReason {
            reason: format!(
                "bench-doctor found {} missing on this runtime ({}), so {what_it_would_prove} \
                 could not be measured; the flow skipped rather than reporting an unproven pass",
                missing.join(", "),
                details.join("; ")
            ),
            missing,
        })
    }
}

/// The gate itself: a container runtime, and the `natgw` image whose toolchain
/// (`nft`, `conntrack`) the in-container probes run from.
pub struct BenchDoctor<'a> {
    docker: &'a Docker,
    /// The `natgw` image tag — it already carries nftables and conntrack, so the
    /// doctor measures the same toolchain the gateway will use rather than a
    /// lookalike.
    natgw_image: &'a str,
    /// A run-unique suffix for the throwaway network the IPv6 probe builds.
    suffix: &'a str,
}

impl<'a> BenchDoctor<'a> {
    /// A doctor that probes with `natgw_image` and names its throwaway network
    /// after `suffix`.
    pub fn new(docker: &'a Docker, natgw_image: &'a str, suffix: &'a str) -> Self {
        Self {
            docker,
            natgw_image,
            suffix,
        }
    }

    /// Measure everything, once. Probe failures are *results*, not errors: a
    /// runtime that refuses the container is a missing capability, which is
    /// exactly what the report is for. The only hard error is a runtime that
    /// cannot be spawned at all.
    ///
    /// # Errors
    /// If the container runtime binary cannot be executed.
    pub fn examine(&self) -> Result<DoctorReport> {
        let mut probed = self.probe_in_container()?;
        let (available, detail) = self.probe_daemon_ipv6();
        probed.insert(CAP_DAEMON_IPV6.to_owned(), (available, detail));

        let mut capabilities: Vec<Capability> = probed
            .into_iter()
            .map(|(name, (available, detail))| Capability {
                name,
                available,
                detail,
            })
            .collect();
        capabilities.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(DoctorReport { capabilities })
    }

    /// Everything one throwaway `natgw` container can answer for itself.
    fn probe_in_container(&self) -> Result<BTreeMap<String, (bool, String)>> {
        let script = format!(
            "set -u; \
             nft add table ip doctor >/dev/null 2>&1 \
               && nft add set ip doctor seen '{{ type ipv4_addr ; flags dynamic,timeout ; \
                  timeout 1m ; size 64 ; }}' >/dev/null 2>&1 \
               && nft add chain ip doctor post '{{ type nat hook postrouting priority srcnat ; }}' \
                  >/dev/null 2>&1 \
               && echo '{CAP_NFTABLES}=yes nft-dynamic-set-and-nat-chain-installed' \
               || echo \"{CAP_NFTABLES}=no $(nft --version 2>&1 | head -1)\"; \
             conntrack -L >/dev/null 2>&1 \
               && echo '{CAP_CONNTRACK}=yes conntrack -L returned' \
               || echo \"{CAP_CONNTRACK}=no $(conntrack -L 2>&1 | head -1)\"; \
             timeout=$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null \
                       || echo unreadable); \
             [ \"$timeout\" = '{CONNTRACK_UDP_TIMEOUT_SECS}' ] \
               && echo \"{CAP_CONNTRACK_UDP_TIMEOUT}=yes nf_conntrack_udp_timeout=$timeout\" \
               || echo \"{CAP_CONNTRACK_UDP_TIMEOUT}=no nf_conntrack_udp_timeout=$timeout \
(--sysctl did not take)\"; \
             bridge=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null \
                      || echo unreadable); \
             [ \"$bridge\" = '1' ] \
               && echo \"{CAP_BR_NETFILTER}=yes bridge-nf-call-iptables=$bridge\" \
               || echo \"{CAP_BR_NETFILTER}=no bridge-nf-call-iptables=$bridge\"; \
             nft add table ip6 doctor6 >/dev/null 2>&1 \
               && nft add chain ip6 doctor6 post '{{ type nat hook postrouting priority srcnat ; }}' \
                  >/dev/null 2>&1 \
               && echo '{CAP_IP6TABLES}=yes ip6 nat chain installed' \
               || echo '{CAP_IP6TABLES}=no ip6 nat chain refused'"
        );
        let container = RunContainer::new(self.natgw_image.to_owned())
            .remove_after_exit()
            .cap_add("NET_ADMIN")
            .sysctl(
                "net.netfilter.nf_conntrack_udp_timeout",
                CONNTRACK_UDP_TIMEOUT_SECS.to_string(),
            )
            // The natgw image's own entrypoint is a gateway role script that
            // refuses to start without a LAN client; the doctor wants its
            // toolchain, not a gateway.
            .entrypoint("sh")
            .arg("-c")
            .arg(script);

        let output = self
            .docker
            .run_container(container)
            .to_command()
            .output()
            .context("bench-doctor: failed to spawn the container runtime")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut measured = BTreeMap::new();
        for name in [
            CAP_NFTABLES,
            CAP_CONNTRACK,
            CAP_CONNTRACK_UDP_TIMEOUT,
            CAP_BR_NETFILTER,
            CAP_IP6TABLES,
        ] {
            let line = stdout
                .lines()
                .find_map(|line| line.trim().strip_prefix(&format!("{name}=")));
            let entry = match line {
                Some(line) => match line.strip_prefix("yes ") {
                    Some(detail) => (true, detail.trim().to_owned()),
                    None => (false, line.trim_start_matches("no ").trim().to_owned()),
                },
                None => (
                    false,
                    format!(
                        "probe container produced no `{name}=` line (exit {}): {}",
                        output.status,
                        stderr.trim()
                    ),
                ),
            };
            measured.insert(name.to_owned(), entry);
        }
        Ok(measured)
    }

    /// The one capability no container can answer for: whether the *daemon*
    /// will build an IPv6 bridge. Measured by building one from the **Fake-Public
    /// v6 Plan**'s own block and removing it again — `docker info` stopped
    /// reporting a usable IPv6 field, so a trial is the only honest read.
    ///
    /// The trial names no IPv4 subnet, so the daemon picks one from its own
    /// pool instead of colliding with a flow's fake-public `/24` on a shared
    /// bench. A `/64` another probe holds is not a missing capability: the
    /// next candidate is tried, and only an all-overlap run says so.
    fn probe_daemon_ipv6(&self) -> (bool, String) {
        let name = format!("rmule-bench-doctor-v6-{}", self.suffix);
        let mut overlaps = Vec::new();
        for subnet in daemon_probe_subnets(self.suffix) {
            let create = self
                .docker
                .create_internal_network(InternalNetwork::new(name.clone()).subnet_v6(&subnet));
            match create.to_command().output() {
                Ok(output) if output.status.success() => {
                    let _ = self
                        .docker
                        .remove_network(OsString::from(name))
                        .to_command()
                        .output();
                    return (
                        true,
                        format!("network create --internal --ipv6 accepted {subnet}"),
                    );
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                    if !is_overlap(&stderr) {
                        return (
                            false,
                            format!("network create --internal --ipv6 failed: {stderr}"),
                        );
                    }
                    overlaps.push(subnet);
                }
                Err(error) => {
                    return (
                        false,
                        format!("network create could not be spawned: {error}"),
                    );
                }
            }
        }
        (
            false,
            format!(
                "not measured: every candidate /64 overlapped a network already on this \
                 daemon ({})",
                overlaps.join(", ")
            ),
        )
    }
}

/// The `/64`s the daemon-IPv6 trial may take, in the order tried: sixteen
/// out of the plan's top corner (`3fff:ed2:fff0::`–`3fff:ed2:ffff::`), none
/// of which a flow's plan index reaches, rotated by the run suffix so two
/// doctors on one daemon start apart.
fn daemon_probe_subnets(suffix: &str) -> Vec<String> {
    let start = suffix.bytes().fold(0usize, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(usize::from(byte))
    });
    (0..16)
        .map(|offset| format!("3fff:ed2:fff{:x}::/64", (start + offset) % 16))
        .collect()
}

/// Whether a `network create` failed only because the subnet is taken.
fn is_overlap(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("overlap")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trial used to create `203.0.113.0/24`, the plan's first WAN, so a
    /// running flow made it read "no daemon IPv6". It now names no IPv4 subnet
    /// and walks sixteen `/64`s no plan index reaches.
    #[test]
    fn the_daemon_ipv6_trial_stays_off_the_plan() {
        let subnets = daemon_probe_subnets("123");
        assert_eq!(subnets.len(), 16);
        let mut sorted = subnets.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 16, "every candidate is tried once");
        assert!(
            subnets
                .iter()
                .all(|subnet| subnet.starts_with("3fff:ed2:fff"))
        );
        assert_ne!(
            daemon_probe_subnets("123")[0],
            daemon_probe_subnets("124")[0]
        );
        assert!(is_overlap(
            "Error response from daemon: Pool overlaps with other one on this address space"
        ));
        assert!(!is_overlap(
            "Error response from daemon: IPv6 is not enabled"
        ));
    }

    fn report(entries: &[(&str, bool)]) -> DoctorReport {
        DoctorReport {
            capabilities: entries
                .iter()
                .map(|(name, available)| Capability {
                    name: (*name).to_owned(),
                    available: *available,
                    detail: "probed".to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_complete_report_lets_the_flow_run() {
        let report = report(&[(CAP_NFTABLES, true), (CAP_CONNTRACK, true)]);
        assert!(
            report
                .require(&[CAP_NFTABLES, CAP_CONNTRACK], "the NAT Type Proof")
                .is_ok()
        );
    }

    #[test]
    fn a_missing_capability_skips_and_names_itself_and_the_probe_detail() {
        let report = report(&[(CAP_NFTABLES, true), (CAP_CONNTRACK, false)]);
        let skip = report
            .require(&[CAP_NFTABLES, CAP_CONNTRACK], "the NAT Type Proof")
            .unwrap_err();
        assert_eq!(skip.missing, vec![CAP_CONNTRACK.to_owned()]);
        assert!(skip.reason.contains(CAP_CONNTRACK), "{}", skip.reason);
        assert!(skip.reason.contains("probed"), "{}", skip.reason);
        assert!(
            skip.reason.contains("the NAT Type Proof"),
            "{}",
            skip.reason
        );
    }

    #[test]
    fn an_unprobed_capability_counts_as_missing_not_as_present() {
        // The whole point of the gate: silence is never a pass.
        let report = report(&[(CAP_NFTABLES, true)]);
        let skip = report
            .require(&[CAP_NFTABLES, CAP_DAEMON_IPV6], "the v6 prefix acceptance")
            .unwrap_err();
        assert_eq!(skip.missing, vec![CAP_DAEMON_IPV6.to_owned()]);
    }
}
