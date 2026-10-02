//! The one address plan the legacy leg's stimulus argv, its **Source Sinks**,
//! its wire rows and its verdict all read.
//!
//! Every record the stimulus emits names an address and a port; the dial that
//! lands on one of them is the counterparty naming, in its own SYN, the record
//! it decoded. Those three uses must not drift, so the plan is declared once
//! here and never spelled at a call site.
//!
//! The addresses are the **Fake-Public** RFC 5737 plan (`fake_public.rs`): aMule
//! 2.3.3's `IsGoodIP` does not classify `203.0.113.0/24` as LAN or reserved, so
//! a source at one of them is admitted on the node's ordinary, non-LAN-mode
//! paths. The sentinel addresses come from RFC 9637's `3fff::/20` documentation
//! block, the same **Fake-Public v6 Plan** `ipv6-net-accept` measures.

use std::fmt::Write as _;

/// The bench `/24`: the first fake-public prefix.
pub(crate) const BENCH_SUBNET: &str = "203.0.113.0/24";

/// The stimulus's own address on it (`.1` is the bridge gateway).
pub(crate) const STIMULUS_IP: &str = "203.0.113.2";

/// The eD2k server face the stimulus binds, and the aMule dials.
pub(crate) const STIMULUS_TCP_PORT: u16 = 4661;

/// Its server-UDP face (the eD2k `TCP + 4` convention).
pub(crate) const STIMULUS_UDP_PORT: u16 = 4665;

/// Where the packed datagram is pushed: aMule's own **server-UDP** socket,
/// which is its peer TCP port **+ 3** — not its configured `UDPPort`. Measured,
/// not assumed: a run's `amule-listeners.log` shows the daemon holding
/// `00000000:1239` (4665) and `00000000:1240` (4672), and aMule's own status
/// ping to the stimulus leaves from 4665. A push at 4672 lands on the
/// client-UDP socket and is never seen by the source-list reader.
pub(crate) const AMULE_SERVER_UDP_PORT: u16 = 4665;

/// One scripted source record: the endpoint a correct reader decodes out of it.
pub(crate) struct Record {
    /// What the flow calls this record in a verdict row.
    pub(crate) label: &'static str,
    /// The address half — an IPv4 dotted quad, or an IPv6 address for a
    /// **Sentinel Source** (whose record id is `0xFFFFFFFF` and whose address
    /// rides the list's tail).
    pub(crate) host: &'static str,
    /// The TCP port half.
    pub(crate) port: u16,
    /// Whether this record is a Sentinel Source.
    pub(crate) sentinel: bool,
}

impl Record {
    /// The `ip:port` spelling `rmule-tools ed2k sentinel-stimulus` parses — an
    /// IPv6 record is bracketed, which is exactly how the tool tells a Sentinel
    /// Source from a plain one.
    pub(crate) fn spec(&self) -> String {
        if self.sentinel {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The **Source Sink** endpoint a dial at this record lands on. `None` for
    /// a Sentinel Source: a legacy reader unpacks its `0xFFFFFFFF` id as
    /// `255.255.255.255`, which no sink can hold — that dial is observable on
    /// the pcap only.
    pub(crate) fn sink_endpoint(&self) -> Option<String> {
        (!self.sentinel).then(|| format!("{}:{}", self.host, self.port))
    }
}

/// The `OP_FOUNDSOURCES` list the TCP leg emits: a plain record, a **Sentinel
/// Source**, and a plain record *after* it. The third record is the whole
/// point — a reader that walked the sentinel's sixteen tail bytes inline would
/// decode it at the wrong offset and dial something else.
pub(crate) const TCP_RECORDS: [Record; 3] = [
    Record {
        label: "before_sentinel",
        host: "203.0.113.50",
        port: 5001,
        sentinel: false,
    },
    Record {
        label: "sentinel",
        host: "3fff:abcd:1::2",
        port: 5002,
        sentinel: true,
    },
    Record {
        label: "after_sentinel",
        host: "203.0.113.60",
        port: 5003,
        sentinel: false,
    },
];

/// The first body of the packed `OP_GLOBFOUNDSOURCES` datagram: a plain record
/// and a **Sentinel Source**, so the datagram's sixteen tail bytes land exactly
/// where the next packed packet's `[0xE3][0x9B]` header begins.
pub(crate) const PACKED_FIRST_RECORDS: [Record; 2] = [
    Record {
        label: "packed_first",
        host: "203.0.113.70",
        port: 5004,
        sentinel: false,
    },
    Record {
        label: "packed_sentinel",
        host: "3fff:abcd:1::3",
        port: 5005,
        sentinel: true,
    },
];

/// The second body of that datagram, for a second file. Whether the
/// counterparty dials this one is the packed form's legacy-safety answer: it
/// can only do so by reading *past* the first body's sentinel tail.
pub(crate) const PACKED_SECOND_RECORDS: [Record; 1] = [Record {
    label: "packed_second",
    host: "203.0.113.80",
    port: 5006,
    sentinel: false,
}];

/// The **control** datagram's two bodies: the same two-packet shape with **no**
/// Sentinel Source and therefore no tail. It is what makes the sentinel-bearing
/// datagram's result attributable — a counterparty that reads this datagram's
/// second body but not the other's names the tail as the difference, and one
/// that reads neither never reads a second packed packet at all, which
/// exonerates the sentinel.
pub(crate) const CONTROL_FIRST_RECORDS: [Record; 1] = [Record {
    label: "control_first",
    host: "203.0.113.90",
    port: 5007,
    sentinel: false,
}];

/// The control datagram's second body.
pub(crate) const CONTROL_SECOND_RECORDS: [Record; 1] = [Record {
    label: "control_second",
    host: "203.0.113.100",
    port: 5008,
    sentinel: false,
}];

/// Every record the plan emits, in emission order.
pub(crate) fn all_records() -> impl Iterator<Item = &'static Record> {
    TCP_RECORDS
        .iter()
        .chain(PACKED_FIRST_RECORDS.iter())
        .chain(PACKED_SECOND_RECORDS.iter())
        .chain(CONTROL_FIRST_RECORDS.iter())
        .chain(CONTROL_SECOND_RECORDS.iter())
}

/// The distinct sink ports the stimulus holds open.
pub(crate) fn sink_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = all_records()
        .filter(|record| !record.sentinel)
        .map(|record| record.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The `ip addr add` CIDRs the stimulus container holds so a dial at a decoded
/// record reaches a real listener. Without them the dial dies at ARP and the
/// counterparty's read would leave no SYN on the wire at all.
pub(crate) fn sink_address_cidrs() -> String {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = String::new();
    for record in all_records().filter(|record| !record.sentinel) {
        if seen.contains(&record.host) {
            continue;
        }
        seen.push(record.host);
        if !out.is_empty() {
            out.push(' ');
        }
        let _ = write!(out, "{}/24", record.host);
    }
    out
}

/// One `<file-hash-hex>=<record>[,…]` spec for the stimulus CLI.
pub(crate) fn list_spec(file_hash_hex: &str, records: &[Record]) -> String {
    let specs: Vec<String> = records.iter().map(Record::spec).collect();
    format!("{file_hash_hex}={}", specs.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sentinel_record_is_bracketed_and_holds_no_sink() {
        let sentinel = &TCP_RECORDS[1];
        assert_eq!(sentinel.spec(), "[3fff:abcd:1::2]:5002");
        assert_eq!(sentinel.sink_endpoint(), None);
        let plain = &TCP_RECORDS[2];
        assert_eq!(plain.spec(), "203.0.113.60:5003");
        assert_eq!(plain.sink_endpoint().as_deref(), Some("203.0.113.60:5003"));
    }

    #[test]
    fn every_plain_record_gets_a_sink_port_and_an_address_to_hold() {
        assert_eq!(sink_ports(), vec![5001, 5003, 5004, 5006, 5007, 5008]);
        assert_eq!(
            sink_address_cidrs(),
            "203.0.113.50/24 203.0.113.60/24 203.0.113.70/24 203.0.113.80/24 \
             203.0.113.90/24 203.0.113.100/24"
        );
    }

    #[test]
    fn a_list_spec_keeps_record_order() {
        assert_eq!(
            list_spec(&"51".repeat(16), &TCP_RECORDS),
            format!(
                "{}=203.0.113.50:5001,[3fff:abcd:1::2]:5002,203.0.113.60:5003",
                "51".repeat(16)
            )
        );
    }
}
