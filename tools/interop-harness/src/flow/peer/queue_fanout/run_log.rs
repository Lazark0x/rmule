//! rmule's stdout as the asking-and-transferring flows read it (ADR-0116):
//! its `download.*` event records, stamped with `at_unix_ms` under
//! `--stamp-events`, and its `download sources_tick` lines, each a
//! `key=value` field list after its name.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};

/// One line: its name and its fields.
#[derive(Debug)]
struct Record {
    name: String,
    fields: HashMap<String, String>,
}

impl Record {
    /// A record line, or `None` for a line that is not one. A tick line's
    /// name is its two leading words (`download sources_tick`).
    fn parse(line: &str) -> Option<Self> {
        let mut words = line.split_whitespace().peekable();
        let first = words.next()?;
        let name = if first == "download" {
            format!("download {}", words.next()?)
        } else {
            first.to_owned()
        };
        let fields = words
            .filter_map(|word| word.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        Some(Self { name, fields })
    }

    fn at(&self) -> Option<f64> {
        Some(self.fields.get("at_unix_ms")?.parse::<f64>().ok()? / 1000.0)
    }

    fn count(&self, key: &str) -> Option<u64> {
        self.fields.get(key)?.parse().ok()
    }
}

/// The records of one rmule run, in print order.
#[derive(Debug)]
pub(crate) struct RunLog {
    records: Vec<Record>,
}

/// The most sources a run held in each activity at once, over its
/// `download sources_tick` lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ActivityPeaks {
    /// The most asking at once.
    pub(crate) asking: u64,
    /// The most queued with no connection at once.
    pub(crate) queued: u64,
    /// The most transferring at once.
    pub(crate) transferring: u64,
}

impl RunLog {
    /// Read `run_dir`'s `rmule/stdout.log`.
    pub(crate) fn read(run_dir: &Path) -> Result<Self> {
        let path = run_dir.join("rmule").join("stdout.log");
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(Self::parse(&text))
    }

    /// The records in `text`.
    pub(crate) fn parse(text: &str) -> Self {
        Self {
            records: text.lines().filter_map(Record::parse).collect(),
        }
    }

    fn naming<'a>(&'a self, name: &'a str, peer: SocketAddr) -> impl Iterator<Item = &'a Record> {
        let peer = peer.to_string();
        self.records
            .iter()
            .filter(move |record| record.name == name && record.fields.get("peer") == Some(&peer))
    }

    /// Whether a record `name` names `peer`, with `field` when given.
    pub(crate) fn names(&self, name: &str, peer: SocketAddr, field: Option<(&str, &str)>) -> bool {
        self.naming(name, peer).any(|record| {
            field.is_none_or(|(key, value)| {
                record.fields.get(key).map(String::as_str) == Some(value)
            })
        })
    }

    /// When the first record `name` naming `peer` was printed.
    pub(crate) fn first_naming_at(&self, name: &str, peer: SocketAddr) -> Option<f64> {
        self.naming(name, peer).find_map(Record::at)
    }

    /// The ranks `peer` was given, in order (`download.peer_queued`).
    pub(crate) fn ranks(&self, peer: SocketAddr) -> Vec<u64> {
        self.naming("download.peer_queued", peer)
            .filter_map(|record| record.count("rank"))
            .collect()
    }

    /// When the first record `name` was printed.
    pub(crate) fn first_at(&self, name: &str) -> Option<f64> {
        self.records
            .iter()
            .filter(|record| record.name == name)
            .find_map(Record::at)
    }

    /// The most sources each activity held at once.
    pub(crate) fn activity_peaks(&self) -> ActivityPeaks {
        self.records
            .iter()
            .filter(|record| record.name == "download sources_tick")
            .fold(ActivityPeaks::default(), |peaks, record| ActivityPeaks {
                asking: peaks.asking.max(record.count("asking").unwrap_or(0)),
                queued: peaks.queued.max(record.count("queued").unwrap_or(0)),
                transferring: peaks
                    .transferring
                    .max(record.count("transferring").unwrap_or(0)),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record is read for its own peer and field; a tick is read by its
    /// two-word name.
    #[test]
    fn records_and_ticks_are_read_by_name_peer_and_field() {
        let log = RunLog::parse(
            "download.peer_retired id=1 peer=172.18.0.6:4662 reason=queued at_unix_ms=2000\n\
             download.peer_retired id=1 peer=172.18.0.7:4662 reason=no_free_part\n\
             download sources_tick id=1 at_unix_ms=1000 known=4 asking=3 queued=0 transferring=1\n\
             download sources_tick id=1 at_unix_ms=2000 known=4 asking=1 queued=2 transferring=1\n",
        );
        let six: SocketAddr = "172.18.0.6:4662".parse().unwrap();
        let seven: SocketAddr = "172.18.0.7:4662".parse().unwrap();
        assert!(log.names("download.peer_retired", six, Some(("reason", "queued"))));
        assert!(!log.names("download.peer_retired", seven, Some(("reason", "queued"))));
        assert_eq!(log.first_naming_at("download.peer_retired", six), Some(2.0));
        assert_eq!(
            log.activity_peaks(),
            ActivityPeaks {
                asking: 3,
                queued: 2,
                transferring: 1,
            }
        );
    }
}
