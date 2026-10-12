//! The Kad buddy / callback family (ADR-0061).
//!
//! Every flow here stands a firewalled stock aMule on the fake-public /24 and
//! watches what it does about its own unreachability — recruit a buddy, answer a
//! direct callback, or hand out verify keys. The shared piece is the wire-row
//! harvest: a named opcode plus the [`WireFilter`] that finds it in the capture
//! sidecar's pcap, counted per row so a verdict can be written from absences as honestly
//! as from hits.

use anyhow::Result;

use crate::docker::Docker;
use crate::flow::evidence::count_pcap_rows;
use crate::flow::wire_filter::WireFilter;
use crate::rmule::RMULE_SERVE_TCP_PORT;

pub(crate) mod amule_requester;
pub(crate) mod callback;
pub(crate) mod callback_walk;
pub(crate) mod core;
pub(crate) mod core_options;
pub(crate) mod core_swarm;
pub(crate) mod core_tap;
pub(crate) mod core_verdict;
pub(crate) mod core_wire;
pub(crate) mod dialed_link;
pub(crate) mod direct_callback;
pub(crate) mod firewalled;
pub(crate) mod firewalled_verdict;
pub(crate) mod id_only_row;
pub(crate) mod requester_datagrams;
pub(crate) mod required_check;
pub(crate) mod third_party;
pub(crate) mod verify_keys;

pub use self::core::{KadCoreBuddyOptions, run_kad_core_buddy};
pub use self::dialed_link::{DialedLinkVerdict, KadDialedLinkOptions, run_kad_dialed_link};
pub use self::direct_callback::{KadDirectCallbackOptions, run_kad_direct_callback};
pub use self::firewalled::{KadFirewalledBuddyOptions, run_kad_firewalled_buddy};
pub use self::required_check::{
    KadRequiredCheckOptions, RequiredCheckVerdict, run_kad_required_check,
};

/// One opcode the flow-M verdict counts off the pcap, with the BPF that finds it.
pub(crate) struct BuddyWireRow {
    /// The capture row's name in the verdict file.
    pub(crate) key: &'static str,
    /// Human label (the aMule/eMule opcode name).
    pub(crate) label: &'static str,
    /// What the row selects; `{a}` in its BPF is substituted with the aMule's
    /// IP and `{p}` with [`RMULE_SERVE_TCP_PORT`], the port a counterparty
    /// dials rmule on.
    pub(crate) filter: WireFilter,
}

/// Count each `rows` filter against `pcap`, inside the capture container (the
/// only place tcpdump and the file are both present). `{a}` in a filter is
/// substituted with the counterparty's IP and `{p}` with the serve port; `flow`
/// prefixes the progress lines.
pub(crate) fn harvest_wire_rows(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    rows: &'static [BuddyWireRow],
    amule_ip: &str,
    flow: &str,
) -> Result<Vec<(&'static BuddyWireRow, u64)>> {
    let mut counted_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let filter = row.filter.map_bpf(|bpf| {
            bpf.replace("{a}", amule_ip)
                .replace("{p}", &RMULE_SERVE_TCP_PORT.to_string())
        });
        let count = count_pcap_rows(docker, capture_container, pcap, filter)?;
        println!("{flow} row {} ({}) = {count}", row.key, row.label);
        counted_rows.push((row, count));
    }
    Ok(counted_rows)
}
