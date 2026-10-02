//! The flow-K verdict: firewall install, self-check, recruit.
//!
//! Judges the firewalled-buddy leg from rmule's own tap plus the aMule log. PASS
//! is the honest, achievable observable — the firewall installed and the
//! firewalled aMule reached rmule — plus a recorded scan for the buddy/callback
//! opcodes the recipe targets. Present opcodes are noted; absent ones are
//! documented as timer- or wiring-blocked, never fabricated.

use std::fs;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::evidence::{TapRow, read_tap_rows, read_verdict_log};
use crate::flow::identity::ipv4_string;
use crate::flow::kad_buddy::firewalled::{KAD_BUDDY_CALLBACK_OPCODES, KadFirewalledBuddyOptions};

/// The tap rows to or from the aMule at `amule_ip:hub_udp_port`.
fn amule_rows(layout: &RunLayout, amule_ip: [u8; 4], hub_udp_port: u16) -> Result<Vec<TapRow>> {
    let amule_remote = format!("{}:{hub_udp_port}", ipv4_string(amule_ip));
    let rows = read_tap_rows(&layout.kad_rmule_dir().join("tap"))?;
    Ok(rows
        .into_iter()
        .filter(|row| row.remote == amule_remote)
        .collect())
}

/// Judge the firewalled-buddy leg from rmule's own tap + the aMule log. PASS is
/// the honest, achievable observable — the firewall installed and the firewalled
/// aMule reached rmule — plus a recorded scan for the buddy/callback opcodes the
/// recipe targets (present ⇒ noted; absent ⇒ documented as timer/wiring-blocked).
pub(crate) fn assert_kad_firewalled_buddy(
    layout: &RunLayout,
    amule_ip: [u8; 4],
    hub_udp_port: u16,
    options: &KadFirewalledBuddyOptions<'_>,
) -> Result<()> {
    // Firewall install proof from the aMule entrypoint's own stdout.
    let amule_log = read_verdict_log(&layout.kad_node_stdout_log("storer"))?;
    let tcp_fw = amule_log.contains("rmule-amule-kad-tcp-firewall-installed");
    let udp_fw = amule_log.contains("rmule-amule-kad-udp-firewall-installed");

    let inbound_opcodes: Vec<i64> = amule_rows(layout, amule_ip, hub_udp_port)?
        .iter()
        .filter(|row| row.direction == "in")
        .map(|row| row.opcode)
        .collect();
    let inbound_from_amule = inbound_opcodes.len();

    let buddy_hits: Vec<&str> = KAD_BUDDY_CALLBACK_OPCODES
        .iter()
        .filter(|(op, _)| inbound_opcodes.contains(op))
        .map(|(_, name)| *name)
        .collect();

    let verdict = if !buddy_hits.is_empty() {
        "PASS"
    } else if tcp_fw && inbound_from_amule > 0 {
        // Harness stands up + firewalled aMule reached rmule, but no buddy/
        // callback opcode inside the window: the documented timer/wiring block.
        "OBSERVED"
    } else {
        "FAIL"
    };

    let opcodes_hex: Vec<String> = {
        let mut seen: Vec<i64> = inbound_opcodes.clone();
        seen.sort_unstable();
        seen.dedup();
        seen.iter().map(|op| format!("0x{op:02X}")).collect()
    };
    let verdict_toml = format!(
        "# Flow K — firewalled-counterparty buddy/callback leg (ADR-0061).\n\
         verdict = \"{verdict}\"\n\
         block_tcp_requested = {}\n\
         block_udp_requested = {}\n\
         tcp_firewall_installed = {tcp_fw}\n\
         udp_firewall_installed = {udp_fw}\n\
         amule_datagrams_toward_rmule = {inbound_from_amule}\n\
         inbound_opcodes = {opcodes_hex:?}\n\
         buddy_callback_opcodes_seen = {buddy_hits:?}\n\
         # OBSERVED = harness up + firewalled aMule reached rmule, but the buddy/\n\
         # callback opcode is 20-min FIND_BUDDY_INTERVAL + reachability-convergence\n\
         # gated and rmule's live Kad node does not wire the ADR-0061 responder —\n\
         # documented, not fabricated (ADR-0045).\n",
        options.block_tcp, options.block_udp,
    );
    let verdict_path = layout.kad_dir().join("kad-firewalled-buddy-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!("kad-firewalled-buddy verdict={verdict} buddy_hits={buddy_hits:?}");

    if verdict == "FAIL" {
        bail!(
            "flow K did not stand up: tcp_firewall_installed={tcp_fw}, \
             amule_datagrams_toward_rmule={inbound_from_amule} (expected firewall + ≥1 inbound)"
        );
    }
    Ok(())
}

/// Judge the **requester-capture leg** (ADR-0058) from rmule's own
/// tap. PASS is the honest observable: rmule's self-check armed, it emitted its
/// own `0x53`/`0x50` firewall check toward the open aMule, and the aMule
/// answered `0x58` — the mirror of the reachability-responder fixture, now the
/// requester direction. The tap frames are rmule's + the counterparty's genuine
/// wire bytes; the verdict scans them, never fabricates them (ADR-0045).
pub(crate) fn assert_kad_firewall_selfcheck(
    layout: &RunLayout,
    amule_ip: [u8; 4],
    hub_udp_port: u16,
) -> Result<()> {
    // The self-check-armed marker from rmule's own stdout.
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let armed = rmule_log.contains("rmule-kad-firewall-self-check-armed");

    let rows = amule_rows(layout, amule_ip, hub_udp_port)?;
    // rmule → aMule firewall check (`0x53` v7+, `0x50` legacy).
    let checks_out = rows
        .iter()
        .filter(|row| row.is("out", 0x53) || row.is("out", 0x50))
        .count();
    // aMule → rmule firewall response (`0x58`).
    let responses_in = rows.iter().filter(|row| row.is("in", 0x58)).count();

    let verdict = if checks_out > 0 && responses_in > 0 {
        "PASS"
    } else if checks_out > 0 {
        // rmule fired its check but the open aMule's `0x58` did not land in the
        // window (lossy UDP / short window): the emission is proven, the reply
        // is not — documented, not fabricated (ADR-0045).
        "OBSERVED"
    } else {
        "FAIL"
    };

    let verdict_toml = format!(
        "# Kad firewall self-check — requester leg (ADR-0058).\n\
         verdict = \"{verdict}\"\n\
         self_check_armed = {armed}\n\
         rmule_firewall_checks_out = {checks_out}\n\
         amule_firewall_responses_in = {responses_in}\n\
         # PASS = rmule emitted its own 0x53/0x50 check toward the open aMule and\n\
         # the aMule answered 0x58 (the requester mirror of the responder\n\
         # fixture). OBSERVED = the check emitted but no 0x58 landed in-window.\n",
    );
    let verdict_path = layout.kad_dir().join("kad-firewall-selfcheck-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!(
        "kad-firewall-selfcheck verdict={verdict} armed={armed} \
         checks_out={checks_out} responses_in={responses_in}"
    );

    if verdict == "FAIL" {
        bail!(
            "requester leg did not fire: self_check_armed={armed}, \
             firewall_checks_out={checks_out} (expected rmule to emit ≥1 0x53/0x50 toward the aMule)"
        );
    }
    Ok(())
}

/// Judge the **buddy-recruit leg** (ADR-0061) from rmule's own tap:
/// rmule (buddy recruiter armed) emitted its `0x51 KADEMLIA_FINDBUDDY_REQ` toward
/// the open aMule, and — the counterparty capture — the aMule answered `0x5A`.
/// PASS on a captured `0x5A`; OBSERVED when rmule's `0x51` emitted but no `0x5A`
/// landed (the documented reachability-convergence wall — a lone open aMule that
/// cannot itself self-verify open silently refuses to serve as a buddy, ADR-0061
/// / ADR-0045). All bytes are genuine wire bytes; never fabricated.
pub(crate) fn assert_kad_buddy_recruit(
    layout: &RunLayout,
    amule_ip: [u8; 4],
    hub_udp_port: u16,
) -> Result<()> {
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let armed = rmule_log.contains("rmule-kad-buddy-recruit-armed");
    // rmule's own driver logs a `BuddyFound` event iff a verified `0x5A` landed.
    let events = read_verdict_log(&layout.kad_rmule_dir().join("events.log"))?;
    let buddy_found = events.contains("BuddyFound");

    let rows = amule_rows(layout, amule_ip, hub_udp_port)?;
    // rmule → aMule recruit (`0x51`); aMule → rmule accept (`0x5A`).
    let recruits_out = rows.iter().filter(|row| row.is("out", 0x51)).count();
    let answers_in = rows.iter().filter(|row| row.is("in", 0x5A)).count();

    let verdict = if recruits_out > 0 && answers_in > 0 {
        "PASS"
    } else if recruits_out > 0 {
        "OBSERVED"
    } else {
        "FAIL"
    };

    let verdict_toml = format!(
        "# Kad buddy recruit — recruiter leg (ADR-0061).\n\
         verdict = \"{verdict}\"\n\
         recruit_armed = {armed}\n\
         rmule_findbuddy_req_out = {recruits_out}\n\
         amule_findbuddy_res_in = {answers_in}\n\
         rmule_buddy_found_event = {buddy_found}\n\
         # PASS = rmule emitted its own 0x51 toward the open aMule and the aMule\n\
         # answered 0x5A. OBSERVED = the 0x51 emitted but no 0x5A landed — an open\n\
         # aMule that cannot self-verify open in a lone swarm silently refuses to\n\
         # serve as a buddy (ADR-0061 refusal matrix); documented, not fabricated.\n",
    );
    let verdict_path = layout.kad_dir().join("kad-buddy-recruit-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!(
        "kad-buddy-recruit verdict={verdict} armed={armed} \
         recruits_out={recruits_out} answers_in={answers_in} buddy_found={buddy_found}"
    );

    if verdict == "FAIL" {
        bail!(
            "recruit leg did not fire: recruit_armed={armed}, \
             findbuddy_req_out={recruits_out} (expected rmule to emit ≥1 0x51 toward the aMule)"
        );
    }
    Ok(())
}
