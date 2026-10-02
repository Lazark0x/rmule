//! The requester's **firewall-check client** for the firewalled aMule, and the
//! gate that holds flow M's ed2k link until aMule has deleted it.
//!
//! Every `KadFirewalled2Req` the requester sends `.2` makes `.2` dial the
//! requester's TCP port and say `OP_HELLO`, so for a while the requester holds
//! a client carrying `.2`'s user hash. aMule 2.3.3 (kno `4e8f2b3c`, "Release 2.3.3") deletes it once its socket
//! sits idle for `CONNECTION_TIMEOUT` (40 s: `CClientTCPSocket::CheckTimeOut`,
//! `ClientTCPSocket.cpp:201-233` → `Disconnect("Timeout")` →
//! `CUpDownClient::Disconnected` → `Safe_Delete`, `ClientTCPSocket.cpp:258-275`),
//! logged `--- Deleted client … Reason was Timeout` (`BaseClient.cpp:1385`) —
//! 44–45 s after the check in runs `1790185890`, `1790190646` and
//! `1790208592`. While it lives, a Kad type-3 source under the same hash is
//! not a new client: `CheckAndAddSource` hands it to `AttachToAlreadyKnown`
//! (`DownloadQueue.cpp:672`), whose `FindMatchingClient` falls through a
//! Low-ID source's empty IP and server to the user-hash match
//! (`ClientList.cpp:334-342`), so the source rides the connected client, the
//! requester dials `.2:4662` directly and never walks to the buddy.
//!
//! The gate reads the requester's own log, in order: the client is released
//! once a deletion naming `.2` follows both the last check sent to `.2` and
//! the last connection accepted from it. A deletion of a client that never
//! read `OP_HELLO` does not count — it has no user name (`Client Unknown on
//! IP:Port`, `BaseClient.cpp:2313-2314`) and so no user hash to match.
//!
//! The gate cannot stop a check sent after it opens: aMule checks again on
//! any Kad hello while fewer than four `KadFirewalledRes` have come back
//! (`KademliaUDPListener.cpp:566-567`, `634-635`; `Prefs.h:67`). Every
//! archived run sent `.2` one check, two minutes before the link.

use std::fs;
use std::time::{Duration, Instant};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::logs::collect_amule_logfile;

/// How long the link waits for the firewall-check client's deletion before it
/// goes in anyway: a check's dial-back plus the 40 s `CONNECTION_TIMEOUT`
/// deletion landed within 45 s of the check in every archived run, so twice
/// that bounds a check still pending when the gate starts.
const RELEASE_DEADLINE_SECS: u64 = 90;
/// How often the requester's log is re-read while the gate holds.
const POLL_TICK: Duration = Duration::from_secs(2);

/// What the requester's log says about its firewall-check client for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirewallCheckClient {
    /// No check sent to the host and no connection accepted from it.
    NeverChecked,
    /// A check is pending or its client is still held.
    Held,
    /// Deleted after the host's last check and its last connection.
    Deleted,
}

impl FirewallCheckClient {
    /// Read the requester's aMule log for the client `ip` left behind.
    pub(crate) fn read(log: &str, ip: &str) -> Self {
        let check = format!("KadFirewalled2Req to {ip}:");
        let accepted = format!("Accepted connection from {ip}");
        let deleted = format!(" on IP:Port {ip}:");
        let (mut last_hold, mut last_release) = (None, None);
        for (index, line) in log.lines().enumerate() {
            if line.contains(&check) || line.trim_end().ends_with(&accepted) {
                last_hold = Some(index);
            } else if line.contains("--- Deleted client ")
                && line.contains(&deleted)
                && !line.contains("\"Client Unknown on IP:Port ")
            {
                last_release = Some(index);
            }
        }
        match (last_hold, last_release) {
            (None, _) => Self::NeverChecked,
            (Some(hold), Some(release)) if release > hold => Self::Deleted,
            _ => Self::Held,
        }
    }
}

/// How the gate before the link ended.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReleaseGate {
    /// The client's state when the link went in.
    pub(crate) client: FirewallCheckClient,
    /// How long the gate held the link.
    pub(crate) waited_secs: u64,
}

impl ReleaseGate {
    /// Hold until the requester's log shows no firewall-check client for
    /// `firewalled_ip`, or [`RELEASE_DEADLINE_SECS`] pass — then the link
    /// goes in anyway and [`Self::verdict_toml`] names the risk.
    pub(crate) fn hold(
        docker: &Docker,
        layout: &RunLayout,
        container: &str,
        firewalled_ip: &str,
    ) -> Self {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(RELEASE_DEADLINE_SECS);
        let log_path = layout
            .kad_node_logs_dir("requester")
            .join("amule-logfile.log");
        loop {
            collect_amule_logfile(docker, layout, "requester", container);
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            let client = FirewallCheckClient::read(&log, firewalled_ip);
            if client != FirewallCheckClient::Held || Instant::now() >= deadline {
                return Self {
                    client,
                    waited_secs: started.elapsed().as_secs(),
                };
            }
            std::thread::sleep(POLL_TICK.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// The gate's lines for `kad-amule-requester-verdict.toml`. A gate that
    /// timed out is a named degrade, not a claim: the run can still pass, and
    /// the note says why it might have taken the direct road instead.
    pub(crate) fn verdict_toml(&self) -> String {
        let state = match self.client {
            FirewallCheckClient::NeverChecked => "never-checked",
            FirewallCheckClient::Deleted => "deleted",
            FirewallCheckClient::Held => "degraded",
        };
        let mut out = format!(
            "firewall_check_client_gate = \"{state}\"\nfirewall_check_client_gate_secs = {}\n",
            self.waited_secs
        );
        if self.client == FirewallCheckClient::Held {
            out.push_str(&format!(
                "# degraded: the link went in after {RELEASE_DEADLINE_SECS} s with a firewall-check \
                 client for the firewalled aMule still held; its Kad source could attach to it \
                 (AttachToAlreadyKnown) and dial it directly instead of walking to the buddy.\n"
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::FirewallCheckClient;

    const FIREWALLED: &str = "203.0.113.2";

    /// `kad-core-buddy --amule-requester`, run `1790185890`
    /// (bench run 1790185890, `logs/kad/requester/amule-logfile.log`
    /// lines 340–349, 542, 854, 870): the check at 17:58:55, `.2`'s dial-back
    /// and hello the same second, its deletion 44 s later, then a check to the
    /// stimulus and the link.
    const RUN_1790185890: [&str; 10] = [
        ".2026-09-23 17:58:55: KademliaUDPListener.cpp(443): Kademlia Routing: Not adding firewalled client to routing table (203.0.113.2)",
        ".2026-09-23 17:58:55: KademliaUDPListener.cpp(170): Client Kademlia UDP: KadFirewalled2Req to 203.0.113.2:4674",
        " 2026-09-23 17:58:55: ExternalConn.cpp(412): New external connection accepted",
        ".2026-09-23 17:58:55: ClientTCPSocket.cpp(190): ED2k Client: Accepted connection from 203.0.113.2",
        ".2026-09-23 17:58:55: KademliaUDPListener.cpp(319): Client Kademlia UDP: KadFirewalledRes from 203.0.113.2:4674",
        ".2026-09-23 17:58:55: ClientTCPSocket.cpp(348): Remote Client Protocol: Remote Client: OP_HELLO from 203.0.113.2",
        ".2026-09-23 17:59:39: BaseClient.cpp(1385): ED2k Client: --- Deleted client D:13 U:8 \"Client http://www.aMule.org on IP:Port 203.0.113.2:4662 using aMule v2.3.3 \"; Reason was Timeout",
        ".2026-09-23 18:00:54: KademliaUDPListener.cpp(170): Client Kademlia UDP: KadFirewalled2Req to 203.0.113.3:4679",
        ".2026-09-23 18:00:54: KademliaUDPListener.cpp(319): Client Kademlia UDP: KadFirewalledRes from 203.0.113.3:4679",
        "!2026-09-23 18:00:55: ExternalConn.cpp(1378): ExternalConn: adding link 'ed2k://|file|shared.bin|4194304|009D91607B0D86D64FAFF631E02ED864|/'.",
    ];

    fn read(lines: &[&str]) -> FirewallCheckClient {
        FirewallCheckClient::read(&lines.join("\n"), FIREWALLED)
    }

    #[test]
    fn run_1790185890s_client_is_held_from_its_dial_back_until_its_timeout_deletion() {
        assert_eq!(read(&RUN_1790185890[..6]), FirewallCheckClient::Held);
        assert_eq!(read(&RUN_1790185890[..7]), FirewallCheckClient::Deleted);
        // The stimulus's check after the deletion holds nothing for `.2`, so
        // the link went in with `.2`'s client already gone.
        assert_eq!(read(&RUN_1790185890), FirewallCheckClient::Deleted);
    }

    /// `kad-core-buddy --amule-requester --omit-buddy-endpoint`, run
    /// `1790190646` (`1790190646/.../requester/amule-logfile.log`
    /// lines 337–339, 344): `.2`'s hello names it before any check, then the
    /// check goes out a second before `.2` dials back.
    #[test]
    fn run_1790190646s_check_holds_before_the_dial_back_lands() {
        let lines = [
            ".2026-09-23 19:20:22: KademliaUDPListener.cpp(251): Client Kademlia UDP: Kad2HelloRes from 203.0.113.2:4674",
            ".2026-09-23 19:20:22: KademliaUDPListener.cpp(443): Kademlia Routing: Not adding firewalled client to routing table (203.0.113.2)",
            ".2026-09-23 19:20:22: KademliaUDPListener.cpp(170): Client Kademlia UDP: KadFirewalled2Req to 203.0.113.2:4674",
            ".2026-09-23 19:20:23: KademliaUDPListener.cpp(319): Client Kademlia UDP: KadFirewalledRes from 203.0.113.2:4674",
        ];
        assert_eq!(read(&lines[..2]), FirewallCheckClient::NeverChecked);
        assert_eq!(read(&lines), FirewallCheckClient::Held);
    }

    /// A client that never read `OP_HELLO` has no user hash, so its deletion
    /// releases nothing — the line is run `1790185890`'s line 270 (the
    /// requester's failed dial of `.4`) with `.2` in `.4`'s place.
    #[test]
    fn an_unidentified_clients_deletion_does_not_release_the_hello_d_one() {
        let unidentified = ".2026-09-23 17:58:39: BaseClient.cpp(1385): ED2k Client: --- Deleted client D:13 U:8 \"Client Unknown on IP:Port 203.0.113.2:4662 using Unknown Unknown \"; Reason was OnError: Unknown client (IP:203.0.113.2) caused an error: 111. Disconnecting client!";
        let mut lines = RUN_1790185890[..6].to_vec();
        lines.push(unidentified);
        assert_eq!(read(&lines), FirewallCheckClient::Held);
    }
}
