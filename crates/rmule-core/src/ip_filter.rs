//! The core-owned **IP filter**: aMule 2.3.3 `CIPFilter` parity —
//! parse the two accepted line formats with malformed-line tolerance, apply the
//! access-level threshold at build time, store the blocked set as sorted
//! disjoint ranges, and answer the client/server filter verdicts the
//! enforcement surfaces consult.
//!
//! Ground truth is aMule 2.3.3 (`src/IPFilter.cpp`, `src/IPFilterScanner.l`):
//!
//! - **Two line formats, decided per line** (`IPFilterScanner.l`): the
//!   PeerGuardian and AntiP2P forms, a comment, a blank, or one malformed line
//!   counted and discarded. The grammar and the flex precedence that resolves
//!   the two are [`parse`]'s; this module consumes its verdict per line.
//! - **Access levels gate at build time** (`IPFilter.cpp:132,143`): only
//!   ranges with `level < threshold` (aMule `FilterLevel`, default 127) enter
//!   the lookup table; `IsFiltered` never consults the level again.
//! - **Last-inserted line wins on overlap** (aMule `CRangeMap::insert`
//!   overwrites/splits existing ranges): this is the mechanism behind
//!   `ipfilter_static.dat` — loaded *second* (`IPFilter.cpp:130`) — taking
//!   precedence over the downloaded `ipfilter.dat`, including punching an
//!   allow-hole (a high-level sub-range) through a blocked range.
//! - **A reversed range is silently discarded but still counted as loaded**
//!   (`AddIPRange` refuses `IPStart > IPEnd`, yet `LoadFromFile` ignores the
//!   return and increments `filtercount` regardless).
//! - **Config gates come first** (`IsFiltered`, `IPFilter.cpp:421`): with
//!   client (or server) filtering off, the verdict is false before the table
//!   is looked at. aMule's defaults: both gates on (`IpFilterClients` /
//!   `IpFilterServers` true), level 127 — an out-of-box aMule filters with an
//!   *empty* table, which is exactly rmule's default posture (no
//!   [`crate::CoreBuilder::ip_filter_dir`] → empty table → nothing blocked).
//!
//! **Representation divergence, deliberate**: aMule compresses the table into
//! parallel `u32`/`u16` arrays where a length ≥ 0x8000 decodes as
//! `((len & 0x7fff) << 12) + 0xfff` and oversized ranges are split across rows
//! (`IPFilter.cpp:146-173,446-449`). The split loop tiles every range exactly
//! — no addresses are gained or lost — so the encoding is a memory
//! optimization with an identical covered set; rmule stores plain
//! `(start, end)` pairs and proves the equivalence on the encoding's own
//! boundary values in tests.
//!
//! **Site inventory**: aMule 2.3.3 consults `IsFiltered` at **16** non-GUI
//! call sites across 9 files — 12 on the eD2k side (PartFile ×2,
//! DownloadQueue, ClientList, BaseClient ×2, ServerList ×2, ClientTCPSocket
//! ×3, ServerSocket) and **4 on the Kad side** (`RoutingZone.cpp` ×3,
//! `KademliaUDPListener.cpp`). The Kad four are covered through
//! `rmule_kad::KadContactAdmission`: `Core`'s Kad factory arms the node with
//! a closure over this filter's client gate (aMule's Kad checks call
//! `IsFiltered(ip)` with `isServer` false), and the node consults it at its
//! contact-store, bootstrap-dial-seed, and lookup-response intakes. Three
//! eD2k sites are reload-motivated and deferred with reload (below); the
//! rest are enforced.
//!
//! **Load-shape divergence, deliberate**: aMule loads on a background thread
//! and `IsFiltered` blocks everything while the filter is not ready
//! (`IPFilter.cpp:424-434`) — a fail-closed window that exists because their
//! load is slow and their networks start concurrently. rmule loads
//! synchronously in [`crate::CoreBuilder::build`] before any listener can
//! bind, so the not-ready window is structurally absent and the same
//! never-serve-unfiltered guarantee holds. Runtime reload (and with it aMule's
//! `FilterQueues`/`FilterServers` post-reload purges, the per-packet recheck
//! in `ClientTCPSocket::OnReceive`, and the Kad probe-refresh upsert — a
//! solicited hello response can only carry an already-admitted IP until a
//! reload changes the table) is deferred until rmule has a reload trigger;
//! the shared handle is already a lock so a reload can swap the table under
//! it exactly as aMule does, and the Kad closure reads the same live handle.
//!
//! Also deferred, with reasons at the deferral site: the systemwide fallback
//! path (`UseIPFilterSystem`, default off in aMule), archive unpacking
//! (`UnpackArchive` — matters mainly for auto-update downloads, itself
//! deferred), the HTTP auto-update (`IPFilterAutoLoad`/`IPFilterURL`), and the
//! dummy-file creation courtesy of aMule's constructor.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, RwLock};

use rmule_primitives::PeerEndpoint;

mod parse;

use parse::{ParsedLine, parse_line};

/// The core-owned shared IP filter, one instance per `Core` (the
/// [`crate::ban_store::SharedBanStore`] ownership pattern): created by
/// `Core::builder`, loaded by `build`, cloned into every enforcement surface.
/// A lock (not a bare `Arc`) so a future reload can swap the table in place
/// while the old one keeps answering — aMule's mutex-guarded swap.
pub(crate) type SharedIpFilter = Arc<RwLock<IpFilter>>;

/// aMule's per-file load report: `filtercount` (lexed range rows — including
/// reversed ranges the map then discards) and `yyip_Bad` (malformed lines).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IpFilterLoadStats {
    pub(crate) accepted: usize,
    pub(crate) malformed: usize,
}

/// The intermediate range map with aMule `CRangeMap` insert semantics: ranges
/// stay disjoint, and an insert *overwrites* whatever it overlaps — existing
/// ranges are trimmed or split around it — so the last-inserted line wins.
/// (aMule additionally merges adjacent equal-level ranges as it inserts; that
/// changes only the internal range count, never a verdict, so rmule coalesces
/// once at build time instead.)
#[derive(Debug, Default)]
struct IpRangeMap {
    /// start → (inclusive end, access level).
    ranges: BTreeMap<u32, (u32, u8)>,
}

impl IpRangeMap {
    /// Insert `[start, end]` at `level`, overwriting overlap. A reversed range
    /// is silently discarded — aMule's `AddIPRange` refuses it while the load
    /// loop still counts the line as loaded.
    fn insert(&mut self, start: u32, end: u32, level: u8) {
        if start > end {
            return;
        }
        // A predecessor straddling `start` is split around the insertion.
        // `pstart < start` (the range query is exclusive), so `start >= 1`
        // and `start - 1` cannot underflow.
        if let Some((&pstart, &(pend, plevel))) = self.ranges.range(..start).next_back()
            && pend >= start
        {
            self.ranges.insert(pstart, (start - 1, plevel));
            if pend > end {
                // `pend > end` bounds `end < u32::MAX`.
                self.ranges.insert(end + 1, (pend, plevel));
            }
        }
        // Ranges beginning inside [start, end] are consumed; a tail sticking
        // out past `end` survives on its own.
        let covered: Vec<u32> = self.ranges.range(start..=end).map(|(&s, _)| s).collect();
        for covered_start in covered {
            let (covered_end, covered_level) = self
                .ranges
                .remove(&covered_start)
                .expect("collected from the map above");
            if covered_end > end {
                self.ranges.insert(end + 1, (covered_end, covered_level));
            }
        }
        self.ranges.insert(start, (end, level));
    }

    /// Parse `text` (raw bytes — descriptions in real dat files are often not
    /// UTF-8, and aMule never validates them) line by line into the map,
    /// returning the file's aMule-shaped load stats.
    fn parse_into(&mut self, text: &[u8]) -> IpFilterLoadStats {
        let mut stats = IpFilterLoadStats::default();
        for line in text.split(|&b| b == b'\n') {
            match parse_line(line) {
                ParsedLine::Range { start, end, level } => {
                    stats.accepted += 1;
                    self.insert(start, end, level);
                }
                ParsedLine::Ignored => {}
                ParsedLine::Malformed => stats.malformed += 1,
            }
        }
        stats
    }

    /// The build step (aMule `CIPFilterTask::Entry`): keep only ranges whose
    /// level is strictly below `level_threshold`, in ascending order, adjacent
    /// survivors coalesced.
    fn build(&self, level_threshold: u8) -> Vec<(u32, u32)> {
        let mut blocked: Vec<(u32, u32)> = Vec::new();
        for (&start, &(end, level)) in &self.ranges {
            if level >= level_threshold {
                continue;
            }
            match blocked.last_mut() {
                Some(last) if last.1 != u32::MAX && last.1 + 1 == start => last.1 = end,
                _ => blocked.push((start, end)),
            }
        }
        blocked
    }
}

/// The built verdict store: the blocked set (level threshold already applied)
/// plus the two config gates aMule checks before the table
/// (`IsFilteringClients` / `IsFilteringServers`, `IPFilter.cpp:421`).
#[derive(Debug)]
pub(crate) struct IpFilter {
    filter_clients: bool,
    filter_servers: bool,
    /// Sorted, disjoint, coalesced `(start, inclusive end)` blocked ranges.
    blocked: Vec<(u32, u32)>,
}

impl Default for IpFilter {
    /// aMule's out-of-box posture: both gates on (`IpFilterClients` /
    /// `IpFilterServers` default true), empty table — filters nothing until a
    /// dat file is loaded.
    fn default() -> Self {
        Self::empty(true, true)
    }
}

impl IpFilter {
    /// An empty filter with the given gates — blocks nothing.
    pub(crate) fn empty(filter_clients: bool, filter_servers: bool) -> Self {
        Self {
            filter_clients,
            filter_servers,
            blocked: Vec::new(),
        }
    }

    /// Build from in-memory file contents, applied in order — later texts'
    /// lines overwrite earlier overlap, which is the whole precedence
    /// mechanism behind `ipfilter_static.dat` loading second. Pure; the fs
    /// edge is [`Self::load_dir`]. Returns per-text stats in input order.
    pub(crate) fn from_texts(
        texts: &[&[u8]],
        level_threshold: u8,
        filter_clients: bool,
        filter_servers: bool,
    ) -> (Self, Vec<IpFilterLoadStats>) {
        let mut map = IpRangeMap::default();
        let stats = texts.iter().map(|text| map.parse_into(text)).collect();
        (
            Self {
                filter_clients,
                filter_servers,
                blocked: map.build(level_threshold),
            },
            stats,
        )
    }

    /// The aMule two-file load (`IPFilter.cpp:113-130`): `<dir>/ipfilter.dat`
    /// then `<dir>/ipfilter_static.dat` on top. A missing file contributes
    /// nothing (aMule returns 0 ranges for it); an unreadable one warns and
    /// contributes nothing (aMule logs "could not open file"). Infallible by
    /// design — filtering degrades toward an empty table, never a failed
    /// `Core`. The systemwide fallback path (`UseIPFilterSystem`, default off
    /// in aMule) and archive unpacking (`UnpackArchive`) are deferred: rmule
    /// reads the two plain-text config-dir files only.
    pub(crate) fn load_dir(
        dir: &Path,
        level_threshold: u8,
        filter_clients: bool,
        filter_servers: bool,
    ) -> Self {
        let mut texts: Vec<Vec<u8>> = Vec::new();
        for name in ["ipfilter.dat", "ipfilter_static.dat"] {
            let path = dir.join(name);
            match std::fs::read(&path) {
                Ok(bytes) => texts.push(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    texts.push(Vec::new());
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "failed to read IP filter file; skipping it");
                    texts.push(Vec::new());
                }
            }
        }
        let borrowed: Vec<&[u8]> = texts.iter().map(Vec::as_slice).collect();
        let (filter, stats) =
            Self::from_texts(&borrowed, level_threshold, filter_clients, filter_servers);
        for (name, file_stats) in ["ipfilter.dat", "ipfilter_static.dat"].iter().zip(&stats) {
            if file_stats.accepted > 0 || file_stats.malformed > 0 {
                tracing::info!(
                    file = name,
                    accepted = file_stats.accepted,
                    malformed = file_stats.malformed,
                    "loaded IP filter ranges"
                );
            }
        }
        tracing::info!(
            blocked_ranges = filter.blocked.len(),
            level = level_threshold,
            "IP filter ready"
        );
        filter
    }

    /// Whether `ip` falls in a blocked range — aMule's binary search
    /// (`IPFilter.cpp:438-460`) over the level-applied table, byte order
    /// already settled: the table holds host-order numeric addresses and
    /// `u32::from(Ipv4Addr)` is exactly that.
    fn covers(&self, ip: u32) -> bool {
        self.blocked
            .partition_point(|&(start, _)| start <= ip)
            .checked_sub(1)
            .is_some_and(|i| self.blocked[i].1 >= ip)
    }

    /// The client-surface verdict (aMule `IsFiltered(ip)`): gated on client
    /// filtering being enabled, then the table.
    pub(crate) fn is_filtered_client(&self, ip: Ipv4Addr) -> bool {
        self.filter_clients && self.covers(u32::from(ip))
    }

    /// The client-surface verdict for a peer of either family (ADR-0085): the
    /// table holds IPv4 ranges only, so a **native** IPv6 peer passes through —
    /// noted on the trace when the gate is armed, since the pass is an
    /// asymmetry the operator should know about, not a verdict. An IPv6 filter
    /// format is not defined by any implementation yet.
    ///
    /// `peer` is unmapped first (`IpAddr::to_canonical`): a mapped address
    /// (`::ffff:a.b.c.d`) is an IPv4 host wearing a v6 literal, and hitting the
    /// v4 table for it is the point — an operator who blocked `a.b.c.d` in
    /// `ipfilter.dat` did not consent to that host reappearing unfiltered just
    /// because a claim spelled it in the other family.
    pub(crate) fn is_filtered_peer(&self, peer: PeerEndpoint) -> bool {
        match peer.ip().to_canonical() {
            IpAddr::V4(ip) => self.is_filtered_client(ip),
            IpAddr::V6(_) => {
                if self.filter_clients && !self.blocked.is_empty() {
                    tracing::debug!(%peer, "IPv6 peer passes the IPv4-only IP filter unchecked");
                }
                false
            }
        }
    }

    /// Whether the server gate could refuse *anything* — gate on and at least
    /// one blocked range. The server-dial path consults this before spending
    /// a DNS resolve on a named host (the post-resolve check): an
    /// empty table or a disabled gate can never filter, so the resolve would
    /// be pure overhead.
    pub(crate) fn has_server_blocks(&self) -> bool {
        self.filter_servers && !self.blocked.is_empty()
    }

    /// The server-surface verdict (aMule `IsFiltered(ip, isServer=true)`):
    /// gated on server filtering being enabled, then the same table. (In
    /// aMule the flag also routes the stats counter — rmule has no filtered
    /// client/server stats surface yet, so tracing at the call sites stands
    /// in.)
    pub(crate) fn is_filtered_server(&self, ip: Ipv4Addr) -> bool {
        self.filter_servers && self.covers(u32::from(ip))
    }

    /// How many blocked ranges the built table holds (aMule `BanCount`, up to
    /// the deliberate representation divergence: aMule counts its split
    /// `u16`-encoded rows, rmule its coalesced ranges).
    #[cfg(test)]
    pub(crate) fn blocked_range_count(&self) -> usize {
        self.blocked.len()
    }
}

/// The source-ingest gate (aMule `PartFile.cpp:1668`/`:2799`,
/// `DownloadQueue.cpp:1563`): a High-ID source row whose IP is
/// client-filtered is dropped at ingest so it never enters a candidate pool;
/// a Low-ID row has no IP to test and passes — aMule's `!IsLowID(userid)`
/// guard — its real address is enforced later at the accept/dial gates.
pub(crate) fn admits_source(filter: &IpFilter, endpoint: Option<PeerEndpoint>) -> bool {
    endpoint.is_none_or(|endpoint| !filter.is_filtered_peer(endpoint))
}

#[cfg(test)]
mod tests;
