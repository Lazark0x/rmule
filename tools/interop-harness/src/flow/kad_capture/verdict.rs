//! The source and keyword capture verdicts, judged from rmule's datagram tap.
//!
//! Only aMule-emitted datagrams can acceptance a row (Kad Stimulus Node
//! doctrine, ADR-0045): the storer's `0x4B` publish ack and its genuine `0x3B`
//! source answer for the source leg, the `0x4B`/`0x3B` answers to rmule's
//! `0x43`/`0x33` for the keyword leg. Accepted frames are written out verbatim
//! for fixture promotion; an absent frame is recorded as an absence.

use std::fs;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::evidence::{
    KAD2_PUBLISH_KEY_REQ, KAD2_PUBLISH_RES, KAD2_PUBLISH_SOURCE_REQ, KAD2_SEARCH_KEY_REQ,
    KAD2_SEARCH_RES, KAD2_SEARCH_SOURCE_REQ, TapRow, read_capture_frame, read_tap_rows,
};
use crate::flow::identity::{ParseHex16, hex_lower, ipv4_string};

/// Judge the source capture from rmule's datagram tap, using only
/// aMule-emitted datagrams (Kad Stimulus Node doctrine). The acceptance
/// moments are aMule's `0x4B` publish ack and its genuine `0x3B` source answer.
/// On success, the `0x3B` datagram bytes are written to
/// `kad-source-result-0x3b.bin` for fixture promotion, and the verdict records
/// the IP-substitution finding. `storer_ip` keys the tap frames to the aMule
/// storer, so both the RFC1918 (LAN-mode) and fake-public (Config A) topologies
/// share this judge.
pub(crate) fn assert_kad_source_capture(
    layout: &RunLayout,
    storer_ip: [u8; 4],
    storer_udp_port: u16,
    user_hash_hex: &str,
    storer_kad_id: [u8; 16],
) -> Result<()> {
    let tap_dir = layout.kad_rmule_dir().join("tap");
    let rows = read_tap_rows(&tap_dir)?;
    let storer_remote = format!("{}:{storer_udp_port}", ipv4_string(storer_ip));
    let storer_frames: Vec<&TapRow> = rows
        .iter()
        .filter(|row| row.remote == storer_remote)
        .collect();

    let rmule_published = storer_frames
        .iter()
        .any(|row| row.is("out", KAD2_PUBLISH_SOURCE_REQ));
    let amule_acked_publish = storer_frames
        .iter()
        .any(|row| row.is("in", KAD2_PUBLISH_RES));
    let rmule_searched = storer_frames
        .iter()
        .any(|row| row.is("out", KAD2_SEARCH_SOURCE_REQ));
    // The evidence datagram: aMule's genuine 0x3B source answer.
    let source_result_seq = storer_frames
        .iter()
        .find(|row| row.is("in", KAD2_SEARCH_RES))
        .map(|row| row.seq);

    let verdict_pass =
        rmule_published && amule_acked_publish && rmule_searched && source_result_seq.is_some();

    // Extract + persist the 0x3B bytes for promotion, and decode the source-row
    // facts the verdict records.
    let mut source_id_hex = String::new();
    let mut source_ip_present = false;
    if let Some(seq) = source_result_seq {
        let bytes = read_capture_frame(&tap_dir.join("datagrams.bin"), seq)
            .with_context(|| format!("read 0x3B frame {seq} from datagrams.bin"))?;
        let out = layout.kad_dir().join("kad-source-result-0x3b.bin");
        fs::write(&out, &bytes).with_context(|| format!("write {}", out.display()))?;
        println!(
            "captured 0x3B written to {} ({} bytes)",
            out.display(),
            bytes.len()
        );
        // The 0x3B payload after the [0xE4][0x3B] header: [senderKadID 16]
        // [keyID 16][count u16] then per-source [sourceID 16][taglist]. Peek the
        // first source ID for the SourceIdMeaning cross-check, and note whether
        // aMule authored a SOURCEIP tag (0x03) in the taglist.
        if bytes.len() >= 2 + 16 + 16 + 2 + 16 {
            let source_id = &bytes[2 + 16 + 16 + 2..2 + 16 + 16 + 2 + 16];
            source_id_hex = hex_lower(source_id);
            source_ip_present = bytes[2 + 16 + 16 + 2 + 16..].contains(&0x03);
        }
    }

    // SourceIdMeaning: the stored source ID should equal the publisher User Hash
    // word-swapped per 32-bit word (same transform as the Kad key).
    let expected_source_id = user_hash_hex
        .parse_hex16()
        .map(|h| hex_lower(&crate::kad_seed::storer_kad_id_for_file_hash(h)))
        .unwrap_or_default();

    let mut report = String::new();
    report.push_str("# kad-source-capture verdict (ADR-0043)\n\n");
    report.push_str(&format!("storer = \"{storer_remote}\"\n"));
    report.push_str(&format!(
        "storer_kad_id = \"{}\"\n",
        hex_lower(&storer_kad_id)
    ));
    report.push_str(&format!("frames_total = {}\n", rows.len()));
    report.push_str(&format!("rmule_sent_publish_0x44 = {rmule_published}\n"));
    report.push_str(&format!(
        "amule_acked_publish_0x4b = {amule_acked_publish}\n"
    ));
    report.push_str(&format!("rmule_sent_search_0x34 = {rmule_searched}\n"));
    report.push_str(&format!(
        "amule_answered_search_0x3b = {}\n",
        source_result_seq.is_some()
    ));
    report.push_str(&format!("captured_source_id = \"{source_id_hex}\"\n"));
    report.push_str(&format!(
        "expected_source_id_wordswap = \"{expected_source_id}\"\n"
    ));
    report.push_str(&format!(
        "source_id_matches_user_hash_wordswap = {}\n",
        !source_id_hex.is_empty() && source_id_hex == expected_source_id
    ));
    // IP-substitution finding: the publisher sends no SOURCEIP; any SOURCEIP tag
    // in aMule's answer is aMule-authored from its observed sender.
    report.push_str(&format!(
        "amule_authored_source_ip_tag = {source_ip_present}\n"
    ));
    report.push_str(&format!(
        "verdict = \"{}\"\n",
        if verdict_pass { "PASS" } else { "FAIL" }
    ));
    let verdict_path = layout.kad_dir().join("kad-source-capture-verdict.txt");
    fs::write(&verdict_path, &report)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!("{report}");
    println!("verdict written to {}", verdict_path.display());

    if !verdict_pass {
        bail!(
            "kad-source-capture acceptance not met: published={rmule_published} \
             acked={amule_acked_publish} searched={rmule_searched} \
             answered={} (see {})",
            source_result_seq.is_some(),
            verdict_path.display()
        );
    }
    Ok(())
}

/// The ADR-0062 KEYWORD capture verdict: rmule's own datagram tap
/// is scanned for the two undriven legs — rmule's `0x43` publish + aMule's `0x4B`
/// ack (publisher leg), and rmule's `0x33` search + aMule's `0x3B` answer
/// (requester leg). aMule's answers are the counterparty evidence (rmule's own
/// bytes are never evidence, ADR-0045); each is written out for promotion.
pub(crate) fn assert_kad_keyword_capture(
    layout: &RunLayout,
    storer_ip: [u8; 4],
    storer_udp_port: u16,
) -> Result<()> {
    let tap_dir = layout.kad_rmule_dir().join("tap");
    let rows = read_tap_rows(&tap_dir)?;
    let storer_remote = format!("{}:{storer_udp_port}", ipv4_string(storer_ip));
    let storer_frames: Vec<&TapRow> = rows
        .iter()
        .filter(|row| row.remote == storer_remote)
        .collect();

    let rmule_published = storer_frames
        .iter()
        .any(|row| row.is("out", KAD2_PUBLISH_KEY_REQ));
    let publish_res_seq = storer_frames
        .iter()
        .find(|row| row.is("in", KAD2_PUBLISH_RES))
        .map(|row| row.seq);
    let rmule_searched = storer_frames
        .iter()
        .any(|row| row.is("out", KAD2_SEARCH_KEY_REQ));
    let search_res_seq = storer_frames
        .iter()
        .find(|row| row.is("in", KAD2_SEARCH_RES))
        .map(|row| row.seq);

    // Promote aMule's counterparty answers. The `0x4B` ack proves aMule ACCEPTED
    // rmule's keyword publish (publisher leg); the `0x3B` proves the search-back
    // finds rmule's file (requester leg).
    let bin = tap_dir.join("datagrams.bin");
    let mut wrote = Vec::new();
    if let Some(seq) = publish_res_seq {
        let bytes =
            read_capture_frame(&bin, seq).with_context(|| format!("read 0x4B frame {seq}"))?;
        let out = layout.kad_dir().join("kad-keyword-publish-res-0x4b.bin");
        fs::write(&out, &bytes).with_context(|| format!("write {}", out.display()))?;
        wrote.push(format!("{} ({} bytes)", out.display(), bytes.len()));
    }
    if let Some(seq) = search_res_seq {
        let bytes =
            read_capture_frame(&bin, seq).with_context(|| format!("read 0x3B frame {seq}"))?;
        let out = layout.kad_dir().join("kad-keyword-search-res-0x3b.bin");
        fs::write(&out, &bytes).with_context(|| format!("write {}", out.display()))?;
        wrote.push(format!("{} ({} bytes)", out.display(), bytes.len()));
    }

    let verdict_pass =
        rmule_published && publish_res_seq.is_some() && rmule_searched && search_res_seq.is_some();
    let mut report = String::new();
    report.push_str("# kad-keyword-capture verdict (ADR-0062)\n\n");
    report.push_str(&format!("storer = \"{storer_remote}\"\n"));
    report.push_str(&format!("frames_total = {}\n", rows.len()));
    report.push_str(&format!("rmule_sent_publish_0x43 = {rmule_published}\n"));
    report.push_str(&format!(
        "amule_acked_publish_0x4b = {}\n",
        publish_res_seq.is_some()
    ));
    report.push_str(&format!("rmule_sent_search_0x33 = {rmule_searched}\n"));
    report.push_str(&format!(
        "amule_answered_search_0x3b = {}\n",
        search_res_seq.is_some()
    ));
    for path in &wrote {
        report.push_str(&format!("promoted = \"{path}\"\n"));
    }
    report.push_str(&format!(
        "verdict = \"{}\"\n",
        if verdict_pass { "PASS" } else { "FAIL" }
    ));
    let verdict_path = layout.kad_dir().join("kad-keyword-capture-verdict.txt");
    fs::write(&verdict_path, &report)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!("{report}");
    println!("verdict written to {}", verdict_path.display());

    if !verdict_pass {
        bail!(
            "kad-keyword-capture acceptance not met: published={rmule_published} \
             acked={} searched={rmule_searched} answered={} (see {})",
            publish_res_seq.is_some(),
            search_res_seq.is_some(),
            verdict_path.display()
        );
    }
    Ok(())
}
