//! `kad-core-buddy --shared-files <n>`: rmule shares many small files in a
//! small stock mesh, so its publish walks all lean on the same few contacts.
//! Its Kad Send Gate has to keep `KADEMLIA2_REQ` (`0x21`) under what a stock
//! node takes from one address, 10 a minute (`PacketTracking.cpp:128-130`);
//! past that the node logs `Request flood detected` under
//! `logKadPacketTracking` (`PacketTracking.cpp:215,222`) and drops the packets.
//!
//! The stock node's own logfile decides, on the debug image with
//! `AMULE_KAD_VERBOSE=1`. The tap's count sits beside it and says the walks
//! ran at all.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::flow::pcap::udp4_datagrams;
use crate::rmule::CONTAINER_RUN_ROOT;

/// A staged file's size, plus its index so no two share a hash.
const FILE_BYTES: usize = 1024;
/// `logKadPacketTracking`'s drop and ban lines for the opcode.
const FLOOD_LINES: [&str; 2] = [
    "Request flood detected for opcode 0x21",
    "Massive request flood detected for opcode 0x21",
];
/// The line the category writes as it sweeps its table: without one the
/// logfile cannot speak for the rule (`PacketTracking.cpp:256`).
const CATEGORY_ON: &str = "Cleaned up Kad Incoming Requests Tracklist";
/// Kad's protocol byte and `KADEMLIA2_REQ`.
const REQ_HEAD: [u8; 2] = [0xE4, 0x21];
/// A stock node's allowance a minute, `PacketTracking.cpp:130`.
const REQ_PER_MINUTE: usize = 10;
const MINUTE_SECS: f64 = 60.0;

fn name(index: usize) -> String {
    format!("extra-{index:03}.bin")
}

/// Stage `count` small files beside the Synthetic File.
///
/// # Errors
/// If a file cannot be written.
pub(crate) fn stage(layout: &RunLayout, count: usize) -> Result<()> {
    let dir = layout.synthetic_dir();
    for index in 0..count {
        let fill = u8::try_from(index % 251).unwrap_or(0);
        let path = dir.join(name(index));
        fs::write(&path, vec![fill; FILE_BYTES + index])
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

/// The staged files as the stimulus container sees them.
pub(crate) fn container_paths(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{CONTAINER_RUN_ROOT}/synthetic/{}", name(index)))
        .collect()
}

/// The most `0x21` one address took from rmule in any sixty seconds, per
/// address, from sorted send times.
fn peak_per_minute(sends: &BTreeMap<Ipv4Addr, Vec<f64>>) -> BTreeMap<Ipv4Addr, usize> {
    sends
        .iter()
        .map(|(to, times)| {
            let peak = times
                .iter()
                .enumerate()
                .map(|(index, start)| {
                    times[index..]
                        .iter()
                        .take_while(|at| **at - *start < MINUTE_SECS)
                        .count()
                })
                .max()
                .unwrap_or(0);
            (*to, peak)
        })
        .collect()
}

/// Every stock node's flood lines and whether its category ran, from the
/// logfiles under `logs`.
fn node_lines(logs: &Path) -> Result<Vec<(String, usize, bool)>> {
    let mut nodes = Vec::new();
    for entry in fs::read_dir(logs).with_context(|| format!("read {}", logs.display()))? {
        let dir = entry?.path();
        let Ok(text) = fs::read_to_string(dir.join("amule-logfile.log")) else {
            continue;
        };
        let floods = FLOOD_LINES.iter().map(|line| text.matches(line).count());
        nodes.push((
            dir.file_name()
                .map_or_else(String::new, |role| role.to_string_lossy().into_owned()),
            floods.sum(),
            text.contains(CATEGORY_ON),
        ));
    }
    nodes.sort();
    Ok(nodes)
}

/// Write `kad-shared-files-verdict.toml`.
///
/// # Errors
/// If the tap or a log directory cannot be read, or the verdict written.
pub(crate) fn write(layout: &RunLayout, pcap: &Path, rmule: Ipv4Addr, count: usize) -> Result<()> {
    let mut sends: BTreeMap<Ipv4Addr, Vec<f64>> = BTreeMap::new();
    for datagram in udp4_datagrams(pcap)? {
        if *datagram.source.ip() == rmule && datagram.payload.starts_with(&REQ_HEAD) {
            sends
                .entry(*datagram.destination.ip())
                .or_default()
                .push(datagram.at);
        }
    }
    for times in sends.values_mut() {
        times.sort_by(f64::total_cmp);
    }
    let peaks = peak_per_minute(&sends);
    let logs = layout
        .kad_node_logs_dir("storer")
        .parent()
        .map(Path::to_path_buf)
        .context("the node logs' parent")?;
    let nodes = node_lines(&logs)?;
    let floods: usize = nodes.iter().map(|(_, lines, _)| lines).sum();
    let spoke = nodes.iter().any(|(_, _, on)| *on);
    let peak = peaks.values().copied().max().unwrap_or(0);
    let sent: usize = sends.values().map(Vec::len).sum();
    let pass = floods == 0 && spoke && sent > 0 && peak <= REQ_PER_MINUTE;
    let mut out = format!(
        "scenario = \"kad-core-buddy-shared-files\"\nverdict = \"{}\"\nshared_files = {count}\n\
         req_0x21_sent = {sent}\npeak_0x21_per_minute_to_one_address = {peak}\n\
         flood_lines_0x21 = {floods}\ntracking_category_on = {spoke}\n",
        if pass { "PASS" } else { "FAIL" },
    );
    for (role, lines, on) in &nodes {
        writeln!(out, "# {role}: flood lines {lines}, category on {on}")?;
    }
    for (to, peak) in &peaks {
        writeln!(out, "# {to}: peak {peak} a minute")?;
    }
    let path = layout.kad_dir().join("kad-shared-files-verdict.toml");
    fs::write(&path, &out).with_context(|| format!("write {}", path.display()))?;
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst inside one minute counts whole; spread sends do not stack.
    #[test]
    fn the_peak_reads_the_busiest_sixty_seconds() {
        let to: Ipv4Addr = "203.0.113.2".parse().unwrap();
        let burst: Vec<f64> = (0..12).map(|i| f64::from(i) * 2.0).collect();
        let spread: Vec<f64> = (0..12).map(|i| f64::from(i) * 7.0).collect();
        assert_eq!(peak_per_minute(&BTreeMap::from([(to, burst)]))[&to], 12);
        assert_eq!(peak_per_minute(&BTreeMap::from([(to, spread)]))[&to], 9);
    }
}
