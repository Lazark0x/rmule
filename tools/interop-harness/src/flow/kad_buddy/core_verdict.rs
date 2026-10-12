//! The flow-M verdict, judged from the pcap rows plus both sides' logs.
//!
//! PASS is the flow's headline: the counterparty's own `0x51` reached the
//! Core-pumped node **and** its `0x5A` answer went back — the recruit a
//! Kad-UDP-only stimulus could never complete. The peer-TCP rows are recorded
//! beside it, because they are what the Core pump newly makes reachable at all.
//! OBSERVED covers the honest partial: the topology stood up and the
//! counterparty talked to us, but its buddy search did not fire in-window.
//! Nothing is ever fabricated (ADR-0045); an absent row is written as an
//! absence.

use std::fs;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::evidence::read_verdict_log;
use crate::flow::identity::ipv4_string;
use crate::flow::kad_buddy::BuddyWireRow;
use crate::flow::kad_buddy::core::{
    KAD_CORE_BUDDY_AMULE_KAD_ID, KAD_CORE_BUDDY_RMULE_KAD_ID, KadCoreBuddyOptions,
};
use crate::flow::kad_buddy::core_tap::{TapReadout, read_core_tap};
use crate::flow::kad_buddy::verify_keys::KAD_UDP_KEY_SEED;

/// Judge flow M from the pcap rows plus both sides' logs.
///
/// PASS is the flow's headline: the counterparty's own `0x51` reached the
/// Core-pumped node **and** its `0x5A` answer went back — the recruit the
/// Kad-UDP-only stimulus could never complete. The peer-TCP rows are recorded
/// beside it, because they are what the Core pump newly makes reachable at all.
/// OBSERVED covers the honest partial: the topology stood up and the counterparty
/// talked to us, but its buddy search did not fire in-window. Nothing is ever
/// fabricated (ADR-0045); an absent row is written as an absence.
pub(crate) fn assert_kad_core_buddy(
    layout: &RunLayout,
    rows: &[(&'static BuddyWireRow, u64)],
    options: &KadCoreBuddyOptions<'_>,
    publish_body: Option<&[u8]>,
    near_file_kad_id_hex: Option<&str>,
    amule_ip: [u8; 4],
    hub_udp_port: u16,
) -> Result<()> {
    let count = |key: &str| -> u64 {
        rows.iter()
            .find(|(row, _)| row.key == key)
            .map_or(0, |(_, count)| *count)
    };

    let amule_log = read_verdict_log(&layout.kad_node_stdout_log("storer"))?;
    let tcp_fw = amule_log.contains("rmule-amule-kad-tcp-firewall-installed");
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let rmule_err = read_verdict_log(&layout.kad_node_stderr_log("rmule"))?;
    let rmule_trail = format!("{rmule_log}{rmule_err}");
    let serving = rmule_trail.contains("serve.serving_started");
    let posture_declared = rmule_trail.contains("kad stimulus posture");
    // rmule's own disposition trail: which branch of the ADR-0061 recruit gate
    // ran. The refusal reason is the finding when the answer never goes out.
    let recruit_accepted = rmule_trail.contains("accepted recruit, answering 0x5A");
    let recruit_refused = rmule_trail.contains("silently refused FINDBUDDY_REQ");
    let link_attached = rmule_trail.contains("buddy link attached");
    // The Kad-UDP crypt leg: the marker `serve start --kad --peer-crypt`
    // prints once crypt arms, the same one `kad join-node --kad-crypt` prints.
    // It carries no seed: the flow passed `KAD_UDP_KEY_SEED` in.
    let kad_crypt_armed = rmule_trail.contains("rmule-kad-crypt-armed");
    // A hostile or malformed datagram is never a panic — `rmule_kad::wire`
    // emits this diagnostic and the node carries on. The Core's kad runtime
    // adapter surfaces `KadEvent::Diagnostic(UndecodableEnvelope)` as a
    // `tracing::warn!` naming the reason, so this count is real:
    // it substring-matches the same text the warn line and the session
    // counter's doc both use.
    let undecodable_envelope_count = rmule_trail.matches("UndecodableEnvelope").count();
    // Once Kad-UDP crypt is armed, aMule's outgoing datagrams toward rmule are
    // fully-obfuscated envelopes (ADR-0046): the wire-row filters below
    // all key on the plain `0xE4` protocol byte at a fixed offset, which a
    // keyed envelope simply does not carry, so `kad_in` (and every opcode row)
    // reads zero whether or not the exchange is actually happening. rmule's
    // own decode trail is the substitute liveness signal — these lines only
    // fire out of a message the crypt gate already opened and decoded, so
    // their presence is itself proof the keyed exchange reached the node.
    let rmule_kad_crypt_decode_activity = kad_crypt_decode_activity(&rmule_trail);

    // The crypt leg's own per-frame proof: when the Core wrote
    // its own tap (`--kad-capture-dir`, wired only under `--kad-crypt`), its
    // frames decode under this exchange's two keys — the
    // `assert_kad_verify_keys`-style byte-level check flow K runs, here
    // generalized to flow M's own Kad IDs. `Absent` while no tap was written
    // (an older run, or `--kad-crypt` unset). `Unfinalized` is the common
    // case today: this function runs before the stimulus container is torn
    // down, and the tap format only finalizes on the Kad node's own clean
    // shutdown (ADR-0022) — real bytes, not yet decodable, not a failure.
    let tap = options
        .kad_crypt
        .then(|| -> Result<TapReadout> {
            let our_key_for_amule =
                rmule_kad::udp_verify_key(KAD_UDP_KEY_SEED, std::net::Ipv4Addr::from(amule_ip));
            let inbound_keys = rmule_primitives::ClientDecryptKeys {
                kad_id: Some(&KAD_CORE_BUDDY_RMULE_KAD_ID),
                receiver_verify_key: Some(our_key_for_amule),
                sender: rmule_primitives::DatagramSenderAddress::V4(amule_ip),
                ..Default::default()
            };
            let outbound_keys = rmule_primitives::ClientDecryptKeys {
                kad_id: Some(&KAD_CORE_BUDDY_AMULE_KAD_ID),
                ..Default::default()
            };
            let remote = format!("{}:{hub_udp_port}", ipv4_string(amule_ip));
            read_core_tap(
                &layout.kad_rmule_dir().join("tap"),
                &remote,
                &inbound_keys,
                &outbound_keys,
            )
        })
        .transpose()?
        .unwrap_or(TapReadout::Absent);

    let recruit_in = count("amule_findbuddy_req_0x51_rmule_tap");
    let answer_out = count("rmule_findbuddy_res_0x5a_rmule_tap");
    let kad_in = count("amule_kad_datagrams_in_rmule_tap");
    let buddy_syn = count("amule_buddy_tcp_syn_rmule_tap");
    let buddy_ping = count("amule_buddyping_0x9f_rmule_tap");
    // The publish leaves toward whichever contact is closest to the FILE key,
    // which under `--publish-source` is the placed near-file member and not
    // rmule — so the counterparty's own tap is the row that can see it, and
    // the rmule-netns row stays a true (and separately interesting) zero.
    let publish_out = count("amule_publish_source_req_0x44_rmule_tap")
        .max(count("amule_publish_source_req_0x44_storer_tap"));

    // Liveness is "the counterparty sent us Kad datagrams at all", not any one
    // opcode: seeded straight into aMule's routing ZONE, rmule is already a
    // known contact, so aMule queries it (`0x21`) without ever helloing it — and
    // `FirewalledCheck` only fires out of `Process2Hello{Request,Response}`, so a
    // `0x53` is not a precondition of anything here.
    let verdict = if recruit_in > 0 && answer_out > 0 {
        "PASS"
    } else if tcp_fw
        && serving
        && (kad_in > 0 || (options.kad_crypt && rmule_kad_crypt_decode_activity))
    {
        "OBSERVED"
    } else {
        "FAIL"
    };

    let mut verdict_toml =
        String::from("# Flow M — Core-Pumped Stimulus Node buddy/relay leg (ADR-0061).\n");
    verdict_toml.push_str(&format!("verdict = \"{verdict}\"\n"));
    verdict_toml.push_str(&format!("helper_count = {}\n", options.helper_count));
    verdict_toml.push_str(&format!("block_udp_requested = {}\n", options.block_udp));
    // Helpers force the UDP block, so the requested flag alone would misstate
    // what ran; record both.
    verdict_toml.push_str(&format!(
        "block_udp_effective = {}\n",
        options.block_udp_effective()
    ));
    verdict_toml.push_str(&format!(
        "assume_open_requested = {}\n",
        options.assume_open
    ));
    verdict_toml.push_str(&format!("amule_tcp_firewall_installed = {tcp_fw}\n"));
    verdict_toml.push_str(&format!("rmule_serving_started = {serving}\n"));
    verdict_toml.push_str(&format!(
        "rmule_stimulus_posture_declared = {posture_declared}\n"
    ));
    verdict_toml.push_str(&format!("rmule_recruit_accepted = {recruit_accepted}\n"));
    verdict_toml.push_str(&format!("rmule_recruit_refused = {recruit_refused}\n"));
    verdict_toml.push_str(&format!("rmule_buddy_link_attached = {link_attached}\n"));
    verdict_toml.push_str(&format!("kad_crypt_requested = {}\n", options.kad_crypt));
    verdict_toml.push_str(&format!("rmule_kad_crypt_armed = {kad_crypt_armed}\n"));
    // The live changes the stimulus marked (`--peer-crypt-flip`): the tap's
    // frames before each ran under the old arming, those after under the new
    // (ADR-0046). Listed only when flips were asked for.
    if !options.peer_crypt_flip.is_empty() {
        verdict_toml.push_str(&format!(
            "rmule_obfuscation_flips = {}\n",
            crate::flow::evidence::toml_strings(&crate::flow::evidence::obfuscation_flips(
                &rmule_trail
            ))
        ));
    }
    verdict_toml.push_str(&format!("rmule_kad_udp_key_seed = {KAD_UDP_KEY_SEED}\n"));
    verdict_toml.push_str(&format!(
        "rmule_undecodable_envelope_count = {undecodable_envelope_count}\n"
    ));
    verdict_toml.push_str(&format!(
        "rmule_kad_crypt_decode_activity = {rmule_kad_crypt_decode_activity}\n"
    ));
    // The tap's own per-frame proof, under `--kad-crypt` only
    // (the only leg that ever wires `--kad-capture-dir`): a status line, so a
    // reader can tell "recording but not yet finalized" from "decoded" —
    // never a zero standing in for an absence (ADR-0045).
    if options.kad_crypt {
        match tap {
            TapReadout::Absent => verdict_toml.push_str("kad_tap_status = \"absent\"\n"),
            TapReadout::Unfinalized { bytes } => {
                verdict_toml.push_str("kad_tap_status = \"unfinalized\"\n");
                verdict_toml.push_str(&format!("kad_tap_unfinalized_bytes = {bytes}\n"));
            }
            TapReadout::Finalized(counts) => {
                verdict_toml.push_str("kad_tap_status = \"finalized\"\n");
                verdict_toml.push_str(&format!("kad_tap_frames_total = {}\n", counts.total));
                verdict_toml.push_str(&format!(
                    "kad_tap_frames_decoded_in = {}\n",
                    counts.decoded_in
                ));
                verdict_toml.push_str(&format!(
                    "kad_tap_frames_decoded_out = {}\n",
                    counts.decoded_out
                ));
            }
        }
    }
    verdict_toml.push_str(&format!(
        "publish_source_requested = {}\n",
        options.publish_source
    ));
    // The publish's fifth gate is topological: record where the one contact
    // inside `SEARCHTOLERANCE` of the file key was placed, so a zero row can be
    // read against it.
    verdict_toml.push_str(&format!(
        "near_file_member_kad_id = \"{}\"\n",
        near_file_kad_id_hex.unwrap_or("")
    ));
    // The body is the fixture; its length is what the verdict can state without
    // re-encoding a single byte of it.
    verdict_toml.push_str(&format!(
        "amule_publish_source_body_bytes = {}\n",
        publish_body.map_or(0, <[u8]>::len)
    ));
    verdict_toml.push_str(
        "\n# Wire rows: every key names its tap. `_rmule_tap` = counted off the\n\
         # rmule-netns pcap; `_storer_tap` = counted off the counterparty's own\n\
         # netns (tools/interop-harness/CONTEXT.md, Capture Sidecar).\n",
    );
    for (row, count) in rows {
        verdict_toml.push_str(&format!("{} = {count} # {}\n", row.key, row.label));
    }
    verdict_toml.push_str(
        "\n# PASS = the counterparty's own 0x51 reached the Core-pumped node AND its\n\
         # 0x5A went back — the recruit a Kad-UDP-only stimulus can never complete.\n\
         # OBSERVED = the topology stood up and the firewalled aMule talked to us,\n\
         # but its BuddySearch did not fire in-window: the search needs\n\
         # BOTH verdicts firewalled (Kademlia.cpp:109 arms the flag at +5 min,\n\
         # UDPFirewallTester.cpp:60 times the UDP verdict out at +6 min from the\n\
         # first inbound datagram), and the flag is consume-once. The 0x52/0x94\n\
         # relay rows need a THIRD party asking us to relay toward the firewalled\n\
         # node; this two-node topology drives none, so a zero there is a\n\
         # documented absence, not a failure. Never fabricated (ADR-0045).\n",
    );
    let verdict_path = layout.kad_dir().join("kad-core-buddy-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!(
        "kad-core-buddy verdict={verdict} 0x51_in={recruit_in} 0x5A_out={answer_out} \
         buddy_tcp_syn={buddy_syn} buddyping={buddy_ping} link_attached={link_attached} \
         0x44_out={publish_out} body_bytes={}",
        publish_body.map_or(0, <[u8]>::len)
    );

    if verdict == "FAIL" {
        bail!(
            "flow M did not stand up: amule_tcp_firewall_installed={tcp_fw}, \
             rmule_serving_started={serving}, amule_kad_datagrams_in_rmule_tap={kad_in} \
             (expected the firewall installed, the serve listener bound, and the \
             counterparty reaching us)"
        );
    }
    // The crypt leg's own acceptance, layered on top: the
    // Core must have armed and minted a seed, its own decode trail must show
    // it actually opened a keyed datagram from the counterparty (the
    // verify-keys-shaped "both ways" claim), and no envelope it could not
    // open under the keys the two sides agreed — the log-line count above,
    // real since `KadEvent::Diagnostic` was wired to a session
    // counter. Where the Core's own tap exists, its per-frame decode is a
    // second, byte-level reading of the same claim. Never weakened — a real
    // mismatch (a wrong sync word, a stale key) would surface here as a
    // missing decode line or a nonzero count, and that is the finding, not a
    // harness bug to paper over.
    if options.kad_crypt {
        if !kad_crypt_armed {
            bail!(
                "--kad-crypt requested but rmule never printed `rmule-kad-crypt-armed`: \
                 the Core's --peer-crypt requested did not arm Kad-UDP crypt"
            );
        }
        if !rmule_kad_crypt_decode_activity {
            bail!(
                "--kad-crypt requested and armed, but rmule's own log shows no trace of \
                 decoding a counterparty datagram (no dial-back, flood-guard, recruit-accept \
                 or buddy-link line): the keyed exchange never reached the node"
            );
        }
        if undecodable_envelope_count > 0 {
            bail!(
                "--kad-crypt requested but rmule's log shows {undecodable_envelope_count} \
                 UndecodableEnvelope diagnostic(s): the keyed exchange did not open cleanly"
            );
        }
        // Only a *finalized* tap can convict: `Unfinalized` means the tap
        // never reached ADR-0022's rename-on-clean-shutdown before this read
        // (the stimulus container is still running), which is a harness
        // timing gap, not a decode failure — bailing on it would fabricate a
        // finding the bytes never supported.
        if let TapReadout::Finalized(counts) = tap
            && counts.total > 0
            && counts.decoded_in == 0
            && counts.decoded_out == 0
        {
            bail!(
                "--kad-crypt requested and the Core's own tap captured {} datagram(s) \
                 to/from aMule, but none decoded under the negotiated verify keys",
                counts.total
            );
        }
    }
    Ok(())
}

/// Whether rmule's own trail shows a Kad message the crypt gate opened and
/// decoded: the firewall dial-back, an accepted recruit, or the buddy link it
/// attached. A peer-TCP flood-ban line is not one — it fires on the peer TCP
/// surface, where no Kad-UDP crypt applies.
fn kad_crypt_decode_activity(rmule_trail: &str) -> bool {
    rmule_trail.contains("kad firewall dial-back")
        || rmule_trail.contains("accepted recruit, answering 0x5A")
        || rmule_trail.contains("buddy link attached")
}

#[cfg(test)]
mod tests {
    use super::kad_crypt_decode_activity;

    /// The peer-TCP flood-ban line used to count as Kad-crypt decode proof,
    /// so a crypt leg whose Kad exchange never reached the node could read
    /// `OBSERVED` on a TCP event.
    #[test]
    fn a_peer_tcp_ban_is_not_kad_crypt_decode_activity() {
        assert!(!kad_crypt_decode_activity(
            "flood offender banned at the peer-TCP surface"
        ));
        assert!(kad_crypt_decode_activity(
            "accepted recruit, answering 0x5A"
        ));
        assert!(kad_crypt_decode_activity("buddy link attached"));
    }
}
