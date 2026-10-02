//! What the `natt-udp-selfcheck-amule` flow reads back: aMule's own logfile
//! and status over `docker exec`, the wire rows its claims cite off the
//! gateway's and the storer's taps, and the counterparty datagrams lifted byte
//! for byte out of those pcaps.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::{
    AMULE_EC_PASSWORD, AMULE_LOGFILE, PUBLISH_BODY, UDP_VERDICT_LINES, UDP_VERDICT_TIMEOUT_SECS,
};
use crate::flow::bench::{Bench, CAPTURE_MOUNT, run_checked};
use crate::flow::evidence::write_pcap_first_match;
use crate::flow::nat::NAT_CLIENT_UDP_PORT;
use crate::flow::nat::natt::verdict::WireRow;
use crate::flow::taps::PerAttachmentTaps;
use crate::flow::wire_filter::{OP_EMULEPROT, WireFilter, capture_ed2k_frames};

/// aMule's debug logfile as it stands, or empty when it cannot be read.
pub(super) fn amule_logfile(bench: &Bench, container: &str) -> String {
    run_checked(
        bench.docker.exec(
            container.to_owned(),
            [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from(format!("cat {AMULE_LOGFILE} 2>/dev/null || true")),
            ],
        ),
        "read aMule's logfile",
    )
    .unwrap_or_default()
}

/// `amulecmd status`: aMule's own statement of its Kad state.
pub(super) fn amule_status(bench: &Bench, container: &str) -> String {
    run_checked(
        bench.docker.exec(
            container.to_owned(),
            [
                OsString::from("amulecmd"),
                OsString::from("-P"),
                OsString::from(AMULE_EC_PASSWORD),
                OsString::from("-c"),
                OsString::from("status"),
            ],
        ),
        "ask aMule its status",
    )
    .unwrap_or_else(|error| format!("amulecmd status failed: {error:#}"))
}

/// Wait for aMule's first UDP verdict line; `None` when the budget runs out
/// first.
pub(super) fn wait_for_udp_verdict(bench: &Bench, container: &str) -> Option<String> {
    wait_for_log_line(
        bench,
        container,
        &UDP_VERDICT_LINES,
        Duration::from_secs(UDP_VERDICT_TIMEOUT_SECS),
    )
}

/// Wait for the first line of aMule's logfile carrying any of `needles`,
/// reading it every few seconds; `None` when `budget` runs out first.
pub(super) fn wait_for_log_line(
    bench: &Bench,
    container: &str,
    needles: &[&str],
    budget: Duration,
) -> Option<String> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let log = amule_logfile(bench, container);
        if let Some(line) = log
            .lines()
            .find(|line| needles.iter().any(|needle| line.contains(needle)))
        {
            return Some(line.trim().to_owned());
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    None
}

/// aMule's `OP_FWCHECKUDPREQ` on the gateway's WAN: `0xC5`/`0xA7` frames on
/// the peer-TCP links leaving the gateway.
pub(super) fn fwcheck_filter(gateway_wan: &str) -> WireFilter {
    WireFilter::ed2k(format!("src host {gateway_wan}"), &[OP_EMULEPROT], 0xa7)
}

/// Count the rows the claims cite off the two taps' own pcaps.
pub(super) fn count_wire(
    bench: &Bench,
    gateway: &PerAttachmentTaps,
    storer: &PerAttachmentTaps,
    gateway_wan: &str,
    helpers: &[&str],
) -> Result<Vec<WireRow>> {
    let from_helpers = helpers
        .iter()
        .map(|ip| format!("src host {ip}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let requests = [
        (
            gateway,
            "amule-fwcheckudpreq-0xa7-out",
            fwcheck_filter(gateway_wan),
        ),
        (
            gateway,
            "helper-udp-to-amule-kad-port",
            format!(
                "udp and dst host {gateway_wan} and dst port {NAT_CLIENT_UDP_PORT} and ({from_helpers})"
            )
            .into(),
        ),
        (
            gateway,
            "helper-0x62-plain-to-amule",
            format!(
                "udp and dst host {gateway_wan} and dst port {NAT_CLIENT_UDP_PORT} and \
                 ({from_helpers}) and udp[8:2] = 0xe462"
            )
            .into(),
        ),
        (
            storer,
            "amule-publish-source-req-0x44-at-storer",
            format!("udp and src host {gateway_wan} and udp[8] = 0xe4 and udp[9] = 0x44")
            .into(),
        ),
        (
            storer,
            "amule-kad-datagrams-at-storer",
            format!("udp and src host {gateway_wan}")
            .into(),
        ),
    ];
    requests
        .into_iter()
        .map(|(taps, name, bpf)| {
            let packets = taps
                .rows(&bench.docker, &bpf)?
                .into_iter()
                .find(|row| row.attachment == "wan")
                .map_or(0, |row| row.packets);
            Ok(WireRow {
                name: name.to_owned(),
                bpf: bpf.to_string(),
                packets,
            })
        })
        .collect()
}

/// The first `OP_FWCHECKUDPREQ` frame aMule sent through the gateway, as a
/// hex line for the leg directory; empty when none was sent.
pub(super) fn fwcheck_frame_text(
    bench: &Bench,
    sidecar: &str,
    gateway_wan: &str,
) -> Result<String> {
    let frames = capture_ed2k_frames(
        &bench.docker,
        sidecar,
        &format!("{CAPTURE_MOUNT}/tap-wan.pcap"),
        &fwcheck_filter(gateway_wan),
    )?;
    Ok(frames.first().map_or_else(String::new, |frame| {
        let hex: String = frame
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!(
            "{:.6} {} > {} ({} bytes): {hex}\n",
            frame.at,
            frame.source,
            frame.destination,
            frame.bytes.len()
        )
    }))
}

/// What the storer's tap says aMule published: the first `0x44` from the
/// gateway, lifted byte for byte into a `.bin` beside the pcap, and decoded.
pub(super) struct StoredPublish {
    pub(super) bytes: Vec<u8>,
    pub(super) source_type: Option<u8>,
    pub(super) connect_options: Option<u8>,
    pub(super) source_udp_port: Option<u16>,
}

pub(super) fn lift_publish(
    bench: &Bench,
    prefix: &str,
    tap_dir: &Path,
    gateway_wan: &str,
) -> Result<Option<StoredPublish>> {
    let subset = format!("{PUBLISH_BODY}.pcap");
    write_pcap_first_match(
        &bench.docker,
        &format!("{prefix}-wan"),
        &format!("{CAPTURE_MOUNT}/tap-wan.pcap"),
        &format!("udp and src host {gateway_wan} and udp[8] = 0xe4 and udp[9] = 0x44"),
        &subset,
    )?;
    let Some(bytes) = crate::flow::pcap::first_udp_payload(&tap_dir.join(&subset))? else {
        return Ok(None);
    };
    fs::write(tap_dir.join(format!("{PUBLISH_BODY}.bin")), &bytes)?;
    let decoded = match rmule_kad::decode_exact(&bytes) {
        Ok(rmule_kad::KadDecoded::Plain(envelope) | rmule_kad::KadDecoded::Packed(envelope)) => {
            rmule_kad::Kad2Message::decode(&envelope).ok()
        }
        _ => None,
    };
    let source = match decoded {
        Some(rmule_kad::Kad2Message::PublishSourceReq { source, .. }) => Some(source),
        _ => None,
    };
    Ok(Some(StoredPublish {
        source_type: source.as_ref().and_then(|s| s.source_type),
        connect_options: source.as_ref().and_then(|s| s.encryption),
        source_udp_port: source.as_ref().and_then(|s| s.udp_port_tag),
        bytes,
    }))
}

/// The first datagram a helper sent to aMule's Kad port — its `0x62`, the
/// exchange's opening datagram toward that port — lifted into
/// `helper-answer-0x62.bin` beside the gateway's pcaps. Keyed when the helper
/// was crypt-armed and the `0xA7` carried a verify key.
pub(super) fn lift_helper_answer(
    bench: &Bench,
    gateway_tap_prefix: &str,
    dir: &Path,
    gateway_wan: &str,
    helpers: &[&str],
) -> Result<Option<Vec<u8>>> {
    let from_helpers = helpers
        .iter()
        .map(|ip| format!("src host {ip}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let subset = "helper-answer-0x62.pcap";
    write_pcap_first_match(
        &bench.docker,
        &format!("{gateway_tap_prefix}-wan"),
        &format!("{CAPTURE_MOUNT}/tap-wan.pcap"),
        &format!(
            "udp and dst host {gateway_wan} and dst port {NAT_CLIENT_UDP_PORT} and ({from_helpers})"
        ),
        subset,
    )?;
    let body = crate::flow::pcap::first_udp_payload(&dir.join(subset))?;
    if let Some(bytes) = &body {
        fs::write(dir.join("helper-answer-0x62.bin"), bytes)?;
    }
    Ok(body)
}
