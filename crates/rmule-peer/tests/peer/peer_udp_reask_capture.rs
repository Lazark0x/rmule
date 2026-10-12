//! Peer-UDP source-reask capture (genuine stock aMule 2.3.3, interop flow L `peer-udp-reask`
//! consume leg, run `1785122114`). The
//! `0x90` is aMule's own inbound reask (counterparty); the `0x91` is rmule's
//! egress answer, captured on the same tcpdump on rmule's netns — the ADR-0057
//! reply-matrix proof. Each frame is re-decoded through the public codec to
//! prove the shapes; provenance + the anomaly root-cause note live alongside in
//! `meta.toml`. Counterparty and own bytes only — nothing here is fabricated.

use crate::fixture::{FILE_HASH, load};
use rmule_peer::{ReaskAck, ReaskFilePing};
use rmule_primitives::FileHash;

const FIXTURE_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-peer-udp-reask-20260727/";

/// aMule's inbound `OP_REASKFILEPING`: a UDP v>3 form (part status + complete
/// source count) for the exact file rmule shares — a correct, on-file reask from
/// a queued waiter. Decodes to the captured shape and re-encodes byte-exact.
#[test]
fn amule_reask_ping_is_a_v4_on_file_ping_and_roundtrips() {
    let bytes = load(FIXTURE_DIR, "reask_ping_0x90.bin");
    // The sender advertised UDP version 4, so both the part status and the
    // complete-source count ride (aMule `UDPReaskForDownload`).
    let ping = ReaskFilePing::decode_udp(&bytes, 4).expect("0x90 decodes as a v4 reask ping");

    assert_eq!(ping.file_hash, FileHash::from_bytes(FILE_HASH));
    let part_status = ping
        .part_status
        .as_ref()
        .expect("a v4 reask ping carries the part status");
    assert_eq!(
        part_status.part_count(),
        5,
        "the 40 MiB file spans 5 ED2K parts",
    );
    assert_eq!(ping.complete_sources, Some(1));

    // Byte-exact re-encode: our codec reproduces aMule's own datagram.
    assert_eq!(ping.encode_udp(), bytes);
}

/// rmule's egress `OP_REASKACK`, captured 2.4 ms after the inbound ping —
/// **capture-corrected**: this run exercised the dial-back-grant reask path,
/// which at capture time hardcoded the grantee's UDP version to 0 and emitted
/// a rank-only ack. That form is unparseable at the v4 aMule that pinged (it
/// keys the `0x91` parse on the responder's advertised version, reads the rank
/// as a `WritePartStatus` count, and drops the datagram) — so the capture
/// proves the emit *left* rmule, not that the counterparty accepted it. The
/// defect is fixed (the granted slot now carries the waiter's promoted UDP
/// version; `rmule-core` `serve::state` tests pin the corrected v4 egress);
/// these bytes stay as the provenance-true record of what was on the wire.
#[test]
fn rmule_reask_ack_egress_was_the_pre_correction_rank_only_form() {
    let bytes = load(FIXTURE_DIR, "reask_ack_0x91.bin");
    assert_eq!(
        bytes,
        [0xC5, 0x91, 0x01, 0x00],
        "OP_EMULEPROT OP_REASKACK, rank 1 LE"
    );
    // The captured shape is the rank-only (pre-UDPv4) form. Under the v4
    // version rmule actually advertised, this exact datagram fails to parse —
    // the interop defect the capture exposed, asserted here so the correction
    // stays honest about what was observed.
    let ack = ReaskAck::decode_udp(&bytes, 3).expect("rank-only shape decodes under v3");
    assert_eq!(ack.part_status, None);
    assert_eq!(ack.rank, 1);
    assert_eq!(ack.encode_udp(), bytes);
    assert!(
        ReaskAck::decode_udp(&bytes, 4).is_err(),
        "a v4 counterparty cannot parse the captured rank-only ack — the fixed \
         emit carries part status (see serve::state's promoted-grant test)"
    );
}
