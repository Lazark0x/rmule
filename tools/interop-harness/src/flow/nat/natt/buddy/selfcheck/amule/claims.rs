//! The `natt-udp-selfcheck-amule` verdict's claims, settled from aMule's
//! own account — its debug logfile and `amulecmd status` — and the wire rows
//! counted off the gateway's and the storer's taps.

use super::evidence::StoredPublish;
use super::{
    CONNECT_OPTIONS_DIRECT_UDP_CALLBACK, PUBLISH_CLAIM, SOURCE_TYPE_DIRECT_UDP_CALLBACK,
    UDP_OPEN_LINE,
};
use crate::flow::nat::claims::{Claim, Evidence, gateways_probed_as_claimed};
use crate::flow::nat::natt::verdict::WireRow;

/// aMule's own account of the run, read off its debug logfile and status.
pub(super) struct AmuleFacts {
    verdict_line: Option<String>,
    udp_open: bool,
    fw_packets: Vec<String>,
    extern_port: Option<String>,
    buddy_searches: usize,
    store_file_searches: usize,
    status_kad: Option<String>,
}

impl AmuleFacts {
    pub(super) fn read(log: &str, status: &str, verdict_line: Option<String>) -> Self {
        let count = |needle: &str| log.lines().filter(|line| line.contains(needle)).count();
        let first = |needle: &str| {
            log.lines()
                .find(|line| line.contains(needle))
                .map(|line| line.trim().to_owned())
        };
        Self {
            udp_open: log.lines().any(|line| line.contains(UDP_OPEN_LINE)),
            verdict_line,
            fw_packets: log
                .lines()
                .filter(|line| line.contains("Received UDP FirewallCheck"))
                .map(|line| line.trim().to_owned())
                .collect(),
            extern_port: first("Set external Kad port to"),
            buddy_searches: count("Starting BuddySearch"),
            store_file_searches: count("Search request type: StoreFile"),
            status_kad: status
                .lines()
                .find(|line| line.contains("Kad:"))
                .map(|line| line.trim().to_owned()),
        }
    }
}

fn wire_count(wire: &[WireRow], name: &str) -> u64 {
    wire.iter()
        .find(|row| row.name == name)
        .map_or(0, |row| row.packets)
}

pub(super) fn claims(
    proof: &crate::nat::NatTypeProof,
    facts: &AmuleFacts,
    answered: &[bool],
    wire: &[WireRow],
    publish: Option<&StoredPublish>,
    gateway_wan: &str,
) -> Vec<Claim> {
    let asked = wire_count(wire, "amule-fwcheckudpreq-0xa7-out");
    let type6 = publish.is_some_and(|row| {
        row.source_type == Some(SOURCE_TYPE_DIRECT_UDP_CALLBACK)
            && row
                .connect_options
                .is_some_and(|byte| byte & CONNECT_OPTIONS_DIRECT_UDP_CALLBACK != 0)
    });
    let publish_claim = PUBLISH_CLAIM;
    let publish_row = if type6 || publish.is_some() {
        let row = publish.expect("checked above");
        Claim::about(
            publish_claim,
            type6,
            Evidence::Captured,
            format!(
                "the storer's netns holds a {}-byte 0x44 from {gateway_wan}: TAG_SOURCETYPE = \
                 {:?}, TAG_ENCRYPTION = {:?}, TAG_SOURCEUPORT = {:?}; bytes {}",
                row.bytes.len(),
                row.source_type,
                row.connect_options,
                row.source_udp_port,
                crate::flow::identity::hex_lower(&row.bytes),
            ),
        )
    } else if facts.udp_open && facts.buddy_searches == 0 && facts.store_file_searches == 0 {
        Claim::blocked(
            publish_claim,
            format!(
                "no 0x44 from {gateway_wan} at the storer ({} aMule datagrams reached it). \
                 aMule read UDP open and TCP firewalled ({:?}) and never published: a \
                 firewalled 2.3.3 publishes only while it holds a buddy \
                 (SharedFileList.cpp:773, `!IsFirewalled || GetBuddyStatus() == Connected`; \
                 KnownFile.cpp:1308-1318 PublishSrc), it searches for one only while BOTH \
                 verdicts read firewalled (ClientList.cpp:687), and it drops a High-ID buddy \
                 the moment they do not (ClientList.cpp:706-712). `Starting BuddySearch` \
                 x{}, `Search request type: StoreFile` x{}",
                wire_count(wire, "amule-kad-datagrams-at-storer"),
                facts.status_kad,
                facts.buddy_searches,
                facts.store_file_searches,
            ),
        )
    } else {
        Claim::about(
            publish_claim,
            false,
            Evidence::Captured,
            format!(
                "no 0x44 from {gateway_wan} at the storer; UDP open = {}, `Starting \
                 BuddySearch` x{}, `Search request type: StoreFile` x{}",
                facts.udp_open, facts.buddy_searches, facts.store_file_searches
            ),
        )
    };
    vec![
        Claim::about(
            "the-lan-reached-the-wan-on-the-pinned-port",
            proof.pinned_port_reachable && proof.pinned_port != 0,
            Evidence::RmuleOnly,
            format!(
                "{gateway_wan}: the Pinned-Port Sink at port {} {}; RFC 4787 axes observed \
                 {}/{} against a {} claim (agrees = {})",
                proof.pinned_port,
                if proof.pinned_port_reachable {
                    "was reached"
                } else {
                    "was never reached"
                },
                proof.observed_mapping,
                proof.observed_filtering,
                proof.nat_type.knob(),
                proof.agrees,
            ),
        ),
        gateways_probed_as_claimed([(gateway_wan, proof)]),
        Claim::about(
            "amule-asked-a-fresh-helper-with-0xa7",
            asked > 0,
            Evidence::Captured,
            format!(
                "WAN tap: {asked} OP_FWCHECKUDPREQ (0xC5 0xA7) from {gateway_wan}; aMule's \
                 extern port: {:?}",
                facts.extern_port
            ),
        ),
        Claim::about(
            "a-fresh-helper-answered-0x62-to-the-gateway",
            answered.iter().any(|answered| *answered),
            Evidence::RmuleOnly,
            format!(
                "helpers that logged an unbiased 0x62 toward {gateway_wan}: {answered:?}; WAN \
                 tap: {} datagrams from them to its Kad port, {} of them plaintext 0x62",
                wire_count(wire, "helper-udp-to-amule-kad-port"),
                wire_count(wire, "helper-0x62-plain-to-amule"),
            ),
        ),
        Claim::about(
            "the-amule-udp-verdict-read-open",
            facts.udp_open,
            Evidence::Captured,
            format!(
                "aMule's own verdict line: {:?}; its 0x62 receipts: {:?}",
                facts.verdict_line, facts.fw_packets
            ),
        ),
        publish_row,
    ]
}

/// The keyed-`0x62` row, on a crypt-armed run: the helper's `0x62` left keyed on
/// the verify key aMule's `0xA7` carried, and aMule — which drops what it
/// cannot decrypt — read its UDP verdict open off it.
pub(super) fn keyed_answer(facts: &AmuleFacts, wire: &[WireRow], answer: Option<&[u8]>) -> Claim {
    let plain = wire_count(wire, "helper-0x62-plain-to-amule");
    let keyed = answer.is_some_and(|bytes| bytes.first() != Some(&0xE4));
    Claim::about(
        "amule-accepted-the-helpers-keyed-0x62",
        keyed && plain == 0 && facts.udp_open,
        Evidence::Captured,
        format!(
            "the first helper datagram to aMule's Kad port: {}; plaintext 0x62 on the WAN: \
             {plain}; aMule's verdict: {:?}",
            answer.map_or_else(
                || "none".to_owned(),
                |bytes| format!(
                    "{} bytes, {}",
                    bytes.len(),
                    crate::flow::identity::hex_lower(bytes)
                ),
            ),
            facts.verdict_line,
        ),
    )
}
