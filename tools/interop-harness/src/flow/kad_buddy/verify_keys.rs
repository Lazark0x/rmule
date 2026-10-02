//! The verify-key / `0x22` three-way leg (ADR-0064).
//!
//! The capture target is aMule's own `KADEMLIA2_HELLO_RES_ACK`, whose emit
//! condition is narrow: aMule must have sent the `HELLO_REQ`, rmule's
//! `HELLO_RES` must set the misc-options ACK-request bit, and rmule must have
//! supplied a sender key. The verdict reads rmule's tap for the whole exchange,
//! decrypting with rmule's own derivations, and promotes the counterparty
//! datagram itself as the evidence.

use std::fs;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::evidence::{
    KAD2_HELLO_REQ, KAD2_HELLO_RES, KAD2_HELLO_RES_ACK, KadFrameFacts, kad_frame_facts,
    read_tap_frames, read_verdict_log,
};
use crate::flow::identity::ipv4_string;
use crate::flow::kad_buddy::firewalled::{KAD_FW_AMULE_KAD_ID, KAD_FW_RMULE_KAD_ID};

/// The private verify-key derivation secret this run's rmule node minted, read
/// from the marker it prints when `--kad-crypt` arms. Without it a counterparty
/// datagram encrypted under a key rmule handed out cannot be opened at all.
pub(crate) fn parse_verify_key_secret(log: &str) -> Option<u32> {
    log.lines()
        .filter_map(|line| line.split("verify_key_secret=").nth(1))
        .find_map(|value| value.split_whitespace().next()?.parse().ok())
}

/// Judge the **verify-key / `0x22` three-way leg** (ADR-0064).
///
/// The capture target is aMule's own `KADEMLIA2_HELLO_RES_ACK`. Its emit
/// condition (`Process2HelloResponse`, `KademliaUDPListener.cpp#L603`) is narrow:
/// aMule must have sent the `HELLO_REQ`, rmule's `HELLO_RES` must set the
/// misc-options ACK-request bit, and rmule must have supplied a **sender key** —
/// with an empty one aMule logs "Remote client demands ACK, but didn't send any
/// sender key!" and stays silent. The verdict therefore reads rmule's tap for
/// the whole exchange, decrypting with rmule's own derivations, and promotes the
/// counterparty datagram itself as the evidence (ADR-0045: never fabricated).
pub(crate) fn assert_kad_verify_keys(
    layout: &RunLayout,
    amule_ip: [u8; 4],
    hub_udp_port: u16,
    rmule_ip: [u8; 4],
) -> Result<()> {
    let rmule_log = read_verdict_log(&layout.kad_node_stdout_log("rmule"))?;
    let secret = parse_verify_key_secret(&rmule_log).context(
        "rmule never printed `rmule-kad-crypt-armed ... verify_key_secret=`: the crypt + \
         verify-key arming did not take, so no sender key could reach aMule",
    )?;
    // The key rmule hands aMule — and therefore the key aMule encrypts its `0x22`
    // answer under (`SendPacket(..., senderKey, NULL)` takes the receiver-key
    // family, `EncryptSendClient` `kadRecvKeyUsed`).
    let our_key_for_amule = rmule_kad::udp_verify_key(secret, std::net::Ipv4Addr::from(amule_ip));

    let frames = read_tap_frames(&layout.kad_rmule_dir().join("tap"))?;
    let amule_remote = format!("{}:{hub_udp_port}", ipv4_string(amule_ip));

    // Inbound: rmule's own Kad ID (aMule keys hellos to it) plus rmule's verify
    // key for aMule's IP (aMule keys the ACK to that). Outbound: aMule's pinned
    // Kad ID — the family rmule uses toward a known contact.
    let inbound_keys = rmule_primitives::ClientDecryptKeys {
        kad_id: Some(&KAD_FW_RMULE_KAD_ID),
        receiver_verify_key: Some(our_key_for_amule),
        sender: rmule_primitives::DatagramSenderAddress::V4(amule_ip),
        ..Default::default()
    };
    let outbound_keys = rmule_primitives::ClientDecryptKeys {
        kad_id: Some(&KAD_FW_AMULE_KAD_ID),
        ..Default::default()
    };

    let mut inbound_opcodes: Vec<u8> = Vec::new();
    let mut outbound_opcodes: Vec<u8> = Vec::new();
    let mut rmule_acks_out = 0usize;
    let mut amule_ack: Option<(Vec<u8>, KadFrameFacts)> = None;
    for frame in &frames {
        if frame.remote != amule_remote {
            continue;
        }
        let inbound = frame.direction == "in";
        let keys = if inbound {
            &inbound_keys
        } else {
            &outbound_keys
        };
        let Some(facts) = kad_frame_facts(&frame.bytes, keys) else {
            continue;
        };
        if inbound {
            inbound_opcodes.push(facts.opcode);
            if facts.opcode == KAD2_HELLO_RES_ACK && amule_ack.is_none() {
                amule_ack = Some((frame.bytes.clone(), facts));
            }
        } else {
            outbound_opcodes.push(facts.opcode);
            if facts.opcode == KAD2_HELLO_RES_ACK {
                rmule_acks_out += 1;
            }
        }
    }

    // The capture-bearing direction: aMule as hello INITIATOR, rmule answering.
    let hellos_in = inbound_opcodes
        .iter()
        .filter(|&&op| op == KAD2_HELLO_REQ)
        .count();
    let hello_res_out = outbound_opcodes
        .iter()
        .filter(|&&op| op == KAD2_HELLO_RES)
        .count();
    // The mirror pair, which drives whether aMule ever *consumes* an rmule `0x22`.
    let hellos_out = outbound_opcodes
        .iter()
        .filter(|&&op| op == KAD2_HELLO_REQ)
        .count();
    let hello_res_in = inbound_opcodes
        .iter()
        .filter(|&&op| op == KAD2_HELLO_RES)
        .count();
    let datagrams_out = outbound_opcodes.len();

    // Decode the counterparty ACK and promote its raw datagram.
    let mut promoted = String::from("none");
    let mut ack_detail = String::new();
    if let Some((raw, facts)) = &amule_ack {
        let path = layout.kad_dir().join("hello-res-ack-0x22.bin");
        fs::write(&path, raw).with_context(|| format!("write {}", path.display()))?;
        promoted = path.display().to_string();

        // `<selfID16><tagcount1>` — aMule writes its own Kad ID and no tags.
        let id_matches = facts.payload.get(2..18) == Some(&KAD_FW_AMULE_KAD_ID[..]);
        let tag_count = facts.payload.get(18).copied();
        // The crypt marker is judged MASKED: aMule draws the high bits at random,
        // so only `& 0x03` (the key-family index) is a protocol fact. Family 2 is
        // the receiver-key family — aMule answered under the key rmule handed it.
        let marker = facts.marker.unwrap_or(0);
        ack_detail = format!(
            "ack_wire = \"{}\"\n\
             ack_len = {}\n\
             ack_marker_masked = {}\n\
             ack_marker_literal = \"0x{marker:02X}\"\n\
             ack_self_id_matches_amule = {id_matches}\n\
             ack_tag_count = {tag_count:?}\n\
             ack_receiver_verify_key = \"{:?}\"\n\
             ack_sender_verify_key = \"{:?}\"\n\
             rmule_key_handed_to_amule = {our_key_for_amule}\n",
            raw.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            raw.len(),
            marker & 0x03,
            facts.receiver_verify_key,
            facts.sender_verify_key,
        );
    }

    let verdict = if amule_ack.is_some() {
        "PASS"
    } else if !inbound_opcodes.is_empty() {
        // The counterparty reached rmule but never emitted the ACK. That is a
        // real finding, not a harness failure — the opcode columns below say
        // which half of the emit condition stayed shut. Recorded, never forced.
        "OBSERVED"
    } else {
        "FAIL"
    };

    let verdict_toml = format!(
        "# Kad UDP verify keys — the 0x22 three-way leg (ADR-0064).\n\
         verdict = \"{verdict}\"\n\
         rmule_verify_key_secret = {secret}\n\
         rmule_public_ip_argument = \"{}\"\n\
         amule_hello_req_in = {hellos_in}\n\
         rmule_hello_res_out = {hello_res_out}\n\
         rmule_hello_req_out = {hellos_out}\n\
         amule_hello_res_in = {hello_res_in}\n\
         rmule_datagrams_out = {datagrams_out}\n\
         amule_hello_res_ack_in = {}\n\
         rmule_hello_res_ack_out = {rmule_acks_out}\n\
         inbound_opcodes = {:?}\n\
         outbound_opcodes = {:?}\n\
         promoted_frame = \"{promoted}\"\n\
         {ack_detail}\
         # PASS = aMule emitted its own 0x22 toward rmule (the capture target).\n\
         # OBSERVED = aMule reached rmule but never emitted the ACK. Its\n\
         # Process2HelloResponse needs ALL of: aMule sent the HELLO_REQ\n\
         # (amule_hello_req_in > 0), rmule answered HELLO_RES with the\n\
         # ACK-request misc bit, and rmule supplied a sender key — an empty one\n\
         # makes aMule log and drop. Recorded, never fabricated (ADR-0045).\n",
        ipv4_string(rmule_ip),
        usize::from(amule_ack.is_some()),
        inbound_opcodes
            .iter()
            .map(|op| format!("0x{op:02X}"))
            .collect::<Vec<_>>(),
        outbound_opcodes
            .iter()
            .map(|op| format!("0x{op:02X}"))
            .collect::<Vec<_>>(),
    );
    let verdict_path = layout.kad_dir().join("kad-verify-keys-verdict.toml");
    fs::write(&verdict_path, &verdict_toml)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!(
        "kad-verify-keys verdict={verdict} amule_0x22_in={} rmule_0x22_out={rmule_acks_out} \
         hello_req_in={hellos_in} hello_res_out={hello_res_out}",
        usize::from(amule_ack.is_some())
    );

    if verdict == "FAIL" {
        bail!(
            "verify-key leg saw no counterparty datagram at all from {amule_remote}: the \
             topology never came up (rmule must be a routing-zone contact of the aMule)"
        );
    }
    Ok(())
}
