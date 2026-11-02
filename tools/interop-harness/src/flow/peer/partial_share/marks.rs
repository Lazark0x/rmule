//! rmule's own trail of the run, read from the `rmule-tools` stdout: each
//! event line its `--stamp-events` stamped with the wall clock, each
//! positional part map its `--report-parts-every-ms` printed, and the lines
//! the tool writes at a gate, a reopen and an offer after one.
//!
//! A line is a name (one token or more) then `key=value` fields, a value in
//! double quotes when it holds a space. Times are seconds since the epoch,
//! the clock the tap stamps its records with: both run on the one host.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

/// One line of rmule's trail.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Mark {
    /// The tokens before the first field, space-joined: `serve.partial_offered`,
    /// `download parts_tick`.
    pub(crate) name: String,
    /// The line's fields.
    pub(crate) fields: BTreeMap<String, String>,
    /// Its `at_unix_ms` in seconds, when it carries one.
    pub(crate) at: Option<f64>,
    /// The leg it belongs to: `1` until rmule's reopen, `2` from it.
    pub(crate) leg: u8,
}

impl Mark {
    /// The field `key`.
    pub(crate) fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// The IPv4 address its `peer` field names.
    pub(crate) fn peer(&self) -> Option<Ipv4Addr> {
        let peer = self.field("peer")?;
        peer.parse::<SocketAddrV4>()
            .map(|address| *address.ip())
            .or_else(|_| peer.parse::<Ipv4Addr>())
            .ok()
    }

    /// The parts a `download parts_tick` line shows verified.
    pub(crate) fn verified(&self) -> Option<BTreeSet<u32>> {
        let parts = self.field("parts")?;
        Some(
            (0u32..)
                .zip(parts.chars())
                .filter(|(_, letter)| *letter == 'V')
                .map(|(index, _)| index)
                .collect(),
        )
    }
}

/// The name of the line that opens rmule's second leg.
pub(crate) const REOPENED: &str = "download reopened";

/// Every line of `stdout` that has a name, legs assigned.
pub(crate) fn parse(stdout: &str) -> Vec<Mark> {
    let mut leg = 1;
    stdout
        .lines()
        .filter_map(|line| {
            let mark = parse_line(line, leg)?;
            if mark.name == REOPENED {
                leg = 2;
                return Some(Mark { leg, ..mark });
            }
            Some(mark)
        })
        .collect()
}

fn parse_line(line: &str, leg: u8) -> Option<Mark> {
    let mut name = Vec::new();
    let mut fields = BTreeMap::new();
    for token in tokens(line) {
        match token.split_once('=') {
            Some((key, value)) if !key.is_empty() => {
                fields.insert(key.to_owned(), value.to_owned());
            }
            _ if fields.is_empty() => name.push(token),
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }
    let at = fields
        .get("at_unix_ms")
        .and_then(|ms| ms.parse::<u64>().ok())
        .map(|ms| ms as f64 / 1000.0);
    Some(Mark {
        name: name.join(" "),
        fields,
        at,
        leg,
    })
}

/// A line's space-separated tokens, a double-quoted run (with its
/// backslash escapes) kept whole and unquoted.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '\\' if quoted => {
                if let Some(next) = chars.next() {
                    token.push(next);
                }
            }
            ' ' if !quoted => {
                if !token.is_empty() {
                    out.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(c),
        }
    }
    if !token.is_empty() {
        out.push(token);
    }
    out
}

/// What rmule's trail says about one run, queried by the verdict and by the
/// live waits.
pub(crate) struct Trail {
    pub(crate) marks: Vec<Mark>,
}

impl Trail {
    /// The trail in `stdout`.
    pub(crate) fn new(stdout: &str) -> Self {
        Self {
            marks: parse(stdout),
        }
    }

    /// Every stamped mark named `name`, in order.
    pub(crate) fn named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Mark> + 'a {
        self.marks.iter().filter(move |mark| mark.name == name)
    }

    /// When the first mark named `name` was stamped.
    pub(crate) fn first_at(&self, name: &str) -> Option<f64> {
        self.named(name).find_map(|mark| mark.at)
    }

    /// When the first mark named `name` about `peer` was stamped.
    pub(crate) fn first_at_for(&self, name: &str, peer: Ipv4Addr) -> Option<f64> {
        self.named(name)
            .filter(|mark| mark.peer() == Some(peer))
            .find_map(|mark| mark.at)
    }

    /// The parts verified by the first part map printed at or after `at` in
    /// `leg`: rmule reads a part only once it is verified, so a block sent at
    /// `at` must lie in parts this map shows verified. `None` when no map
    /// follows.
    pub(crate) fn verified_after(&self, at: f64, leg: u8) -> Option<BTreeSet<u32>> {
        self.named("download parts_tick")
            .filter(|mark| mark.leg == leg)
            .find(|mark| mark.at.is_some_and(|tick| tick >= at))
            .and_then(Mark::verified)
    }

    /// The parts verified by the last part map printed at or before `at` in
    /// `leg`: what rmule held for certain by then.
    pub(crate) fn verified_before(&self, at: f64, leg: u8) -> Option<BTreeSet<u32>> {
        self.named("download parts_tick")
            .filter(|mark| mark.leg == leg)
            .take_while(|mark| mark.at.is_some_and(|tick| tick <= at))
            .last()
            .and_then(Mark::verified)
    }

    /// When the first part map with a part verified was printed in `leg`.
    pub(crate) fn first_verified_at(&self, leg: u8) -> Option<f64> {
        self.named("download parts_tick")
            .filter(|mark| mark.leg == leg)
            .find(|mark| mark.verified().is_some_and(|parts| !parts.is_empty()))
            .and_then(|mark| mark.at)
    }

    /// The last part map printed, in either leg.
    pub(crate) fn last_parts(&self) -> Option<&Mark> {
        self.named("download parts_tick").last()
    }
}

#[cfg(test)]
mod tests {
    use super::{Trail, parse};

    /// A stamped record keeps its quoted path whole, a part map reads its
    /// letters, and the reopen line starts leg two.
    #[test]
    fn the_trail_reads_records_maps_and_legs() {
        let stdout = "\
scan.finished dir=\"/w/a b/incoming\" trusted=1 hashed=0 at_unix_ms=1000500
download parts_tick id=1 at_unix_ms=1001000 parts=VMMVMM
download finalized id=1 path=/w/x
download reopened downloads=1 verified_bytes=19456000 at_unix_ms=1002000
serve.upload_slot_granted peer=172.19.0.7:4662 file_hash=AB at_unix_ms=1003000
";
        let marks = parse(stdout);
        assert_eq!(marks[0].field("dir"), Some("/w/a b/incoming"));
        assert_eq!(marks[0].at, Some(1000.5));
        assert_eq!(marks[1].verified(), Some([0, 3].into()));
        assert_eq!(marks[2].at, None);
        assert_eq!((marks[3].leg, marks[4].leg), (2, 2));
        assert_eq!(marks[2].leg, 1);
        let trail = Trail::new(stdout);
        assert_eq!(
            trail.first_at_for("serve.upload_slot_granted", "172.19.0.7".parse().unwrap()),
            Some(1003.0)
        );
        assert_eq!(trail.verified_after(1000.9, 1), Some([0, 3].into()));
        assert_eq!(trail.verified_after(1001.1, 1), None);
    }
}
