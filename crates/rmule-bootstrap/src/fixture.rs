//! The crate's one test-fixture home: the synthesized `server.met` payload
//! builder and the canned-bytes [`Fetcher`] the pipelines' unit tests drive.
//!
//! Unit tests live inside `src`, so their shared helpers cannot sit in the
//! integration binary's `tests/bootstrap/` — a separate crate the `#[cfg(test)]`
//! modules here cannot import. This module is their single home; nothing in it
//! is compiled into a non-test build.
//!
//! Everything here is a deterministic-tier fixture, **not** an aMule capture:
//! the payloads are built from the eD2k tag primitives the way `rmule_ed2k`'s
//! own decoder vectors are, and the aMule-authored golden remains a documented
//! missing asset (see the crate-level evidence note).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use rmule_ed2k::{ServerMet, ServerMetEntry};
use rmule_primitives::{
    Ed2kText, Ipv4Endpoint, ST_IPV6, Tag, TagName, TagValue, ipv6_address_tag_compact,
};

use crate::fetcher::{FetchError, Fetcher};

const HEADER_AMULE: u8 = 0xE0;
const TAG_SERVERNAME: u8 = 0x01;
const TAG_DESCRIPTION: u8 = 0x0B;
const TAG_PREFERENCE: u8 = 0x0E;

/// The server.met body cap the tests pass, aliased to the shipped default so
/// no test carries its own copy of the number.
pub(crate) const SERVER_MET_CAP: usize = crate::DEFAULT_MAX_SERVER_MET_BYTES;

/// The nodes.dat body cap the tests pass, aliased to the shipped default.
pub(crate) const NODES_DAT_CAP: usize = crate::DEFAULT_MAX_NODES_DAT_BYTES;

/// One server.met row to synthesize: an endpoint plus the optional tags the
/// merge posture reads.
pub(crate) struct RowSpec {
    ip: Ipv4Addr,
    port: u16,
    name: Option<&'static str>,
    description: Option<&'static str>,
    preference: Option<u32>,
    ipv6: Option<Ipv6Addr>,
}

impl RowSpec {
    pub(crate) fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            name: None,
            description: None,
            preference: None,
            ipv6: None,
        }
    }

    pub(crate) fn name(mut self, value: &'static str) -> Self {
        self.name = Some(value);
        self
    }

    pub(crate) fn description(mut self, value: &'static str) -> Self {
        self.description = Some(value);
        self
    }

    pub(crate) fn preference(mut self, value: u32) -> Self {
        self.preference = Some(value);
        self
    }

    /// An `ST_IPV6` address — on a `0.0.0.0` header, an IPv6-only row.
    pub(crate) fn ipv6(mut self, value: Ipv6Addr) -> Self {
        self.ipv6 = Some(value);
        self
    }

    fn encode(&self) -> Vec<u8> {
        let mut tags = Vec::new();
        if let Some(name) = self.name {
            tags.push(Tag::new(
                TagName::compact_id(TAG_SERVERNAME),
                TagValue::String(Ed2kText::from_utf8(name)),
            ));
        }
        if let Some(desc) = self.description {
            tags.push(Tag::new(
                TagName::compact_id(TAG_DESCRIPTION),
                TagValue::String(Ed2kText::from_utf8(desc)),
            ));
        }
        if let Some(pref) = self.preference {
            tags.push(Tag::new(
                TagName::compact_id(TAG_PREFERENCE),
                TagValue::U32(pref),
            ));
        }
        if let Some(address) = self.ipv6 {
            tags.push(ipv6_address_tag_compact(ST_IPV6, address));
        }

        let mut bytes = Ipv4Endpoint::new(self.ip, self.port).encode().to_vec();
        bytes.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
        for tag in &tags {
            bytes.extend(tag.encode());
        }
        bytes
    }
}

/// Valid server.met bytes carrying `rows`.
pub(crate) fn met_bytes(rows: &[RowSpec]) -> Vec<u8> {
    let mut bytes = vec![HEADER_AMULE];
    bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    for row in rows {
        bytes.extend(row.encode());
    }
    bytes
}

/// An installed list, built by round-tripping `rows` through the real decoder
/// so it is exactly what a persisted list would hold.
pub(crate) fn installed_from(rows: &[RowSpec]) -> Vec<ServerMetEntry> {
    ServerMet::decode(&met_bytes(rows))
        .expect("valid installed server.met")
        .into_entries()
}

/// An entry's listname, rendered for comparison.
pub(crate) fn name_of(entry: &ServerMetEntry) -> String {
    entry.name().to_display_string()
}

/// One canned outcome: the URL it answers — `None` answers every URL — and
/// what the seam returns for it.
type CannedResponse = (Option<String>, Result<Vec<u8>, FetchError>);

/// A canned-bytes [`Fetcher`]: the deterministic tier's stand-in for the one
/// I/O corner, recording every URL it is asked for.
#[derive(Default)]
pub(crate) struct FakeFetcher {
    /// Canned outcomes in match order.
    responses: Vec<CannedResponse>,
    /// How many times each URL was fetched.
    call_counts: Mutex<HashMap<String, usize>>,
}

impl FakeFetcher {
    /// A fetcher with nothing configured: every URL fails `Transport`.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Answer *any* URL with `bytes`.
    pub(crate) fn serving(bytes: Vec<u8>) -> Self {
        Self {
            responses: vec![(None, Ok(bytes))],
            call_counts: Mutex::default(),
        }
    }

    /// Fail *any* URL with `error`.
    pub(crate) fn failing(error: FetchError) -> Self {
        Self {
            responses: vec![(None, Err(error))],
            call_counts: Mutex::default(),
        }
    }

    /// Answer exactly `url` with `bytes`.
    pub(crate) fn add_response(mut self, url: impl Into<String>, bytes: Vec<u8>) -> Self {
        self.responses.push((Some(url.into()), Ok(bytes)));
        self
    }

    /// Fail exactly `url` with `error`.
    pub(crate) fn add_error(mut self, url: impl Into<String>, error: FetchError) -> Self {
        self.responses.push((Some(url.into()), Err(error)));
        self
    }

    /// Total [`Fetcher::get`] calls across every URL.
    pub(crate) fn call_count(&self) -> usize {
        self.call_counts.lock().unwrap().values().sum()
    }

    /// [`Fetcher::get`] calls for one URL.
    pub(crate) fn call_count_for(&self, url: &str) -> usize {
        self.call_counts
            .lock()
            .unwrap()
            .get(url)
            .copied()
            .unwrap_or(0)
    }
}

impl Fetcher for FakeFetcher {
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> + Send {
        *self
            .call_counts
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_insert(0) += 1;

        let canned = self
            .responses
            .iter()
            .find(|(key, _)| key.as_deref().is_none_or(|configured| configured == url))
            .map_or_else(
                || {
                    Err(FetchError::Transport {
                        url: url.to_owned(),
                        detail: "not configured".to_owned(),
                    })
                },
                |(_, result)| result.clone(),
            );

        // The cap is the seam's contract, so the fake enforces it too: a
        // pipeline's over-cap path must be reachable without the streaming
        // enforcement that only `ReqwestFetcher` performs.
        let result = match canned {
            Ok(bytes) if bytes.len() > max_bytes => Err(FetchError::TooLarge { cap: max_bytes }),
            other => other,
        };

        async move { result }
    }
}
