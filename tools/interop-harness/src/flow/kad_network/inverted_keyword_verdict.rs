//! The flow-J verdict, judged from rmule's own tap plus its events log.
//!
//! Kad Stimulus Node doctrine: aMule's bytes are the evidence, rmule's are not.
//! The two ADR-0062 recipes are judged independently — recipe 4 (the aMule's
//! inbound `0x33` search paired with a `KeywordSearchServed` event, which only
//! fires after a clean decode) is the required half the flow's PASS hinges on,
//! while recipe 2 (the `0x43` publish) is best-effort because aMule only emits
//! it once its autonomous publisher's TCP-open gate opens.

use std::fs;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::evidence::{
    KAD2_PUBLISH_KEY_REQ, KAD2_SEARCH_KEY_REQ, TapRow, read_capture_frame, read_tap_rows,
    read_verdict_log,
};
use crate::flow::identity::{hex_lower, ipv4_string};

/// Judge the inversion from rmule's own tap + events log (Kad Stimulus Node
/// doctrine: aMule's bytes are the evidence, rmule's are not).
///
/// The two recipes are judged independently:
///
/// - **Recipe 4 (search, `0x33`)** — the required, reliably-triggerable half: an
///   inbound `KADEMLIA2_SEARCH_KEY_REQ` from the aMule publisher AND a
///   `KeywordSearchServed` event (which is only emitted after a clean
///   `decode_search_key_req`, so its presence proves rmule parsed the request,
///   restrictive tree and all). The flow's PASS hinges on this.
/// - **Recipe 2 (publish, `0x43`)** — best-effort: an inbound
///   `KADEMLIA2_PUBLISH_KEY_REQ` AND a `KeywordPublishServed` event. aMule only
///   emits it once its autonomous publisher's TCP-open gate opens (helpers), so
///   a miss is recorded, not a failure.
pub(crate) fn assert_kad_inverted_keyword(
    layout: &RunLayout,
    publisher_ip: [u8; 4],
    publisher_udp_port: u16,
    keyword: &str,
    storer_kad_id: [u8; 16],
    publisher_connected: bool,
    results_view: &str,
) -> Result<()> {
    let tap_dir = layout.kad_rmule_dir().join("tap");
    let rows = read_tap_rows(&tap_dir)?;
    let publisher_remote = format!("{}:{publisher_udp_port}", ipv4_string(publisher_ip));
    let publisher_frames: Vec<&TapRow> = rows
        .iter()
        .filter(|row| row.remote == publisher_remote)
        .collect();

    let search_req_seq = publisher_frames
        .iter()
        .find(|row| row.is("in", KAD2_SEARCH_KEY_REQ))
        .map(|row| row.seq);
    let publish_req_seq = publisher_frames
        .iter()
        .find(|row| row.is("in", KAD2_PUBLISH_KEY_REQ))
        .map(|row| row.seq);

    // rmule's own event log — the consume proof. `Keyword*Served` events are
    // emitted only after a clean `decode_*_key_req` + serve (node.rs), so their
    // presence is the "rmule parsed aMule's real bytes and answered" fact. A
    // decode/store failure surfaces instead as "aMule sent 0x33 but rmule did
    // not serve" — the two per-recipe facts below make that visible.
    let events = read_verdict_log(&layout.kad_rmule_dir().join("events.log"))?;
    let keyword_search_served = events.contains("KeywordSearchServed");
    let keyword_publish_served = events.contains("KeywordPublishServed");

    // Extract the counterparty request bytes for promotion (raw datagrams). A
    // search-key-req's `startpos` u16 (at offset 2 + 16) carries aMule's
    // restrictive-tree flag in its top bit (ADR-0062): a plain query clears it
    // (baseline vector), a multi-word query sets it (the tree vector recipe 4
    // names). Promote the first of each so both are reproducible from the run.
    let mut plain_search: Option<Vec<u8>> = None;
    let mut tree_search: Option<Vec<u8>> = None;
    for row in publisher_frames
        .iter()
        .filter(|row| row.is("in", KAD2_SEARCH_KEY_REQ))
    {
        let seq = row.seq;
        let bytes = read_capture_frame(&tap_dir.join("datagrams.bin"), seq)
            .with_context(|| format!("read 0x33 frame {seq} from datagrams.bin"))?;
        let restrictive = bytes.get(2 + 16 + 1).is_some_and(|hi| hi & 0x80 != 0);
        if restrictive {
            tree_search.get_or_insert(bytes);
        } else {
            plain_search.get_or_insert(bytes);
        }
    }
    for (bytes, file) in [
        (&plain_search, "keyword-search-req-0x33.bin"),
        (&tree_search, "keyword-search-req-tree-0x33.bin"),
    ] {
        if let Some(bytes) = bytes {
            let out = layout.kad_dir().join(file);
            fs::write(&out, bytes).with_context(|| format!("write {}", out.display()))?;
            println!(
                "captured aMule 0x33 search-key-req written to {} ({} bytes)",
                out.display(),
                bytes.len()
            );
        }
    }
    if let Some(seq) = publish_req_seq {
        let bytes = read_capture_frame(&tap_dir.join("datagrams.bin"), seq)
            .with_context(|| format!("read 0x43 frame {seq} from datagrams.bin"))?;
        let out = layout.kad_dir().join("keyword-publish-req-0x43.bin");
        fs::write(&out, &bytes).with_context(|| format!("write {}", out.display()))?;
        println!(
            "captured aMule 0x43 publish-key-req written to {} ({} bytes)",
            out.display(),
            bytes.len()
        );
    }

    let search_captured = search_req_seq.is_some() && keyword_search_served;
    let publish_captured = publish_req_seq.is_some() && keyword_publish_served;
    // aMule showing the searched file in its own Results view means it parsed
    // rmule's 0x3B answer — the round-trip bonus (only possible when the store
    // is populated, i.e. after a publish).
    let amule_rendered_result = results_view
        .to_lowercase()
        .contains(&keyword.to_lowercase());

    let inbound_opcodes: Vec<String> = publisher_frames
        .iter()
        .filter(|row| row.direction == "in")
        .map(|row| format!("0x{:02x}", row.opcode))
        .collect();

    let mut report = String::new();
    report.push_str("# kad-inverted-keyword verdict (ADR-0062 recipes 2+4)\n\n");
    report.push_str(&format!("publisher = \"{publisher_remote}\"\n"));
    report.push_str(&format!("keyword = \"{keyword}\"\n"));
    report.push_str(&format!(
        "storer_kad_id = \"{}\"\n",
        hex_lower(&storer_kad_id)
    ));
    report.push_str(&format!(
        "publisher_kad_connected = {publisher_connected}\n"
    ));
    report.push_str(&format!("frames_total = {}\n", rows.len()));
    report.push_str(&format!("amule_to_rmule_opcodes = {inbound_opcodes:?}\n"));
    report.push_str("\n# Recipe 4 — aMule searches, rmule serves (0x33).\n");
    report.push_str(&format!(
        "amule_sent_search_key_req_0x33 = {}\n",
        search_req_seq.is_some()
    ));
    report.push_str(&format!(
        "rmule_served_keyword_search = {keyword_search_served}\n"
    ));
    report.push_str(&format!("search_captured = {search_captured}\n"));
    report.push_str("\n# Recipe 2 — aMule publishes, rmule stores (0x43).\n");
    report.push_str(&format!(
        "amule_sent_publish_key_req_0x43 = {}\n",
        publish_req_seq.is_some()
    ));
    report.push_str(&format!(
        "rmule_served_keyword_publish = {keyword_publish_served}\n"
    ));
    report.push_str(&format!("publish_captured = {publish_captured}\n"));
    report.push_str(&format!(
        "amule_rendered_result_roundtrip = {amule_rendered_result}\n"
    ));
    report.push_str(&format!(
        "verdict = \"{}\"\n",
        if search_captured { "PASS" } else { "FAIL" }
    ));
    let verdict_path = layout.kad_dir().join("kad-inverted-keyword-verdict.txt");
    fs::write(&verdict_path, &report)
        .with_context(|| format!("write {}", verdict_path.display()))?;
    println!("{report}");
    println!("verdict written to {}", verdict_path.display());

    if !search_captured {
        bail!(
            "kad-inverted-keyword: no genuine aMule 0x33 search reached rmule's store \
             (search_req={}, served={keyword_search_served}). The inversion did not exercise \
             the serve side; diagnostics retained (see {}).",
            search_req_seq.is_some(),
            verdict_path.display()
        );
    }
    Ok(())
}
