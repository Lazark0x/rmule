//! What flow M reads off the wire: the rows it counts on rmule's tap and on
//! the counterparty's own netns, and the `0x44` body it lifts beside the pcap.

use std::fs;

use anyhow::{Context, Result};

use crate::docker::Docker;
use crate::flow::kad_buddy::BuddyWireRow;
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT, WireFilter};

/// The wire rows flow M harvests. The Kad-UDP rows read the opcode byte straight
/// after the `0xE4` protocol byte; the peer-TCP rows count eD2k frames walked
/// out of the link's reassembled streams, since a frame need not open its
/// segment.
pub(crate) const KAD_CORE_BUDDY_WIRE_ROWS: &[BuddyWireRow] = &[
    BuddyWireRow {
        key: "amule_findbuddy_req_0x51_rmule_tap",
        label: "KADEMLIA_FINDBUDDY_REQ",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xe4 and udp[9] = 0x51",
        ),
    },
    BuddyWireRow {
        key: "rmule_findbuddy_res_0x5a_rmule_tap",
        label: "KADEMLIA_FINDBUDDY_RES",
        filter: WireFilter::packets_static(
            "udp and dst host {a} and udp[8] = 0xe4 and udp[9] = 0x5a",
        ),
    },
    BuddyWireRow {
        key: "amule_firewalled2_req_0x53_rmule_tap",
        label: "KADEMLIA_FIREWALLED2_REQ",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xe4 and udp[9] = 0x53",
        ),
    },
    BuddyWireRow {
        key: "amule_callback_req_0x52_rmule_tap",
        label: "KADEMLIA_CALLBACK_REQ",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xe4 and udp[9] = 0x52",
        ),
    },
    BuddyWireRow {
        key: "amule_kad_datagrams_in_rmule_tap",
        label: "any Kad datagram from the counterparty (liveness)",
        filter: WireFilter::packets_static("udp and src host {a} and udp[8] = 0xe4"),
    },
    BuddyWireRow {
        key: "amule_buddy_tcp_syn_rmule_tap",
        label: "buddy TCP dial to the serve listener",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst port {p} and tcp[tcpflags] & tcp-syn != 0",
        ),
    },
    BuddyWireRow {
        key: "amule_hello_0xe3_0x01_rmule_tap",
        label: "OP_HELLO on the buddy link",
        filter: WireFilter::ed2k_static("src host {a}", &[OP_EDONKEYPROT], 0x01),
    },
    BuddyWireRow {
        key: "amule_buddyping_0x9f_rmule_tap",
        label: "OP_BUDDYPING",
        filter: WireFilter::ed2k_static("src host {a}", &[OP_EMULEPROT], 0x9f),
    },
    BuddyWireRow {
        key: "rmule_buddypong_0xa0_rmule_tap",
        label: "OP_BUDDYPONG",
        filter: WireFilter::ed2k_static("dst host {a}", &[OP_EMULEPROT], 0xa0),
    },
    BuddyWireRow {
        key: "rmule_callback_0x99_rmule_tap",
        label: "OP_CALLBACK relayed on the held link",
        filter: WireFilter::ed2k_static("dst host {a}", &[OP_EMULEPROT], 0x99),
    },
    BuddyWireRow {
        key: "rmule_reaskcallbacktcp_0x9a_rmule_tap",
        label: "OP_REASKCALLBACKTCP relayed on the held link",
        filter: WireFilter::ed2k_static("dst host {a}", &[OP_EMULEPROT], 0x9a),
    },
    // The source publish itself. Zero unless `--publish-source`
    // gave the counterparty something to share, and zero even then until its
    // buddy link attaches — `CSharedFileList::Publish` gates the firewalled
    // branch on `GetBuddyStatus() == Connected`.
    BuddyWireRow {
        key: "amule_publish_source_req_0x44_rmule_tap",
        label: "KADEMLIA2_PUBLISH_SOURCE_REQ",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xe4 and udp[9] = 0x44",
        ),
    },
    BuddyWireRow {
        key: "rmule_publish_res_0x4b_rmule_tap",
        label: "KADEMLIA2_PUBLISH_RES",
        filter: WireFilter::packets_static(
            "udp and dst host {a} and udp[8] = 0xe4 and udp[9] = 0x4b",
        ),
    },
];

/// The publish rows, counted a second time off the **counterparty's own**
/// netns. The rmule tap can only ever see a `0x44` addressed to rmule, and
/// under `--publish-source` the publish is addressed to whichever contact sits
/// closest to the *file* key — the placed near-file member. Counting from
/// aMule's own interface makes the row independent of who the recipient was.
pub(crate) const KAD_CORE_BUDDY_STORER_ROWS: &[BuddyWireRow] = &[
    BuddyWireRow {
        key: "amule_publish_source_req_0x44_storer_tap",
        label: "KADEMLIA2_PUBLISH_SOURCE_REQ, off the counterparty's own netns",
        filter: WireFilter::packets_static(
            "udp and src host {a} and udp[8] = 0xe4 and udp[9] = 0x44",
        ),
    },
    BuddyWireRow {
        key: "publish_res_0x4b_storer_tap",
        label: "KADEMLIA2_PUBLISH_RES back to the counterparty, off its own netns",
        filter: WireFilter::packets_static(
            "udp and dst host {a} and udp[8] = 0xe4 and udp[9] = 0x4b",
        ),
    },
];

/// Where the captured `0x44` body lands, beside the pcap that carried it.
pub(crate) const PUBLISH_SOURCE_BODY: &str = "amule-publish-source-req-0x44";

/// Lift the first `0x44` the counterparty sent into a `.bin` beside the pcap,
/// and return its bytes so the verdict can describe what was captured.
///
/// The extraction is the pcap's, start to finish: tcpdump selects the datagram
/// with the same filter the wire row counted with, and the body is read out of
/// the one-packet capture it writes. Nothing is reconstructed from a decode.
pub(crate) fn lift_publish_body(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    amule_ip: &str,
    capture_host_dir: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    let filter = format!("udp and src host {amule_ip} and udp[8] = 0xe4 and udp[9] = 0x44");
    let subset = format!("{PUBLISH_SOURCE_BODY}.pcap");
    crate::flow::evidence::write_pcap_first_match(
        docker,
        capture_container,
        pcap,
        &filter,
        &subset,
    )?;
    let subset_path = capture_host_dir.join(&subset);
    let body = crate::flow::pcap::first_udp_payload(&subset_path)?;
    if let Some(bytes) = &body {
        let body_path = capture_host_dir.join(format!("{PUBLISH_SOURCE_BODY}.bin"));
        fs::write(&body_path, bytes).with_context(|| format!("write {}", body_path.display()))?;
        println!(
            "kad-core-buddy: captured a {} byte KADEMLIA2_PUBLISH_SOURCE_REQ body -> {}",
            bytes.len(),
            body_path.display()
        );
    } else {
        println!("kad-core-buddy: no KADEMLIA2_PUBLISH_SOURCE_REQ in the capture");
    }
    Ok(body)
}
