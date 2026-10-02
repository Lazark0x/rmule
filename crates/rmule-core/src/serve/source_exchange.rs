//! The sans-I/O source-exchange **serve brain** (ADR-0055 §Serving): the
//! aMule-exact pools, filters, and per-peer throttle that decide which sources
//! [`ServeState`](super::state::ServeState) answers a peer's
//! `OP_REQUESTSOURCES(2)` with. Split out beside the serve state (as the
//! multipacket serve sits beside it) so every pool/filter/throttle rule is
//! assertable as a plain function of explicit inputs — no live task, no clock,
//! no socket.
//!
//! Two things live here: [`select_sources`] (the pool filters + 500-entry cap)
//! and [`SourceExchangeThrottle`] (the 40/160-minute per-peer reask gate).
//! `ServeState` supplies the candidate pool from the state it owns (the
//! upload-engaged clients of a complete shared file) and echoes the result out
//! as an `OP_ANSWERSOURCES` the peer session frames.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_peer::PartBitmap;
use rmule_primitives::{ExchangedSource, PeerEndpoint};

/// aMule's `SOURCEEXCHANGE_MAX_ENTRIES` — the serve answer is capped at 500
/// sources (`CKnownFile::CreateSrcInfoPacket` @4e8f2b3c breaks the loop there).
const SOURCE_EXCHANGE_MAX_ENTRIES: usize = 500;

/// aMule's rare-file threshold: a file with at most this many known sources is
/// "rare" and earns the shorter reask gate (`CUpDownClient::SendSourceRequest`
/// `reqfile->GetSourceCount() <= 50 ? ...`).
const RARE_SOURCE_THRESHOLD: usize = 50;

/// aMule `SOURCECLIENTREASK` — the base reask interval (40 min): the gate for a
/// rare file.
const REASK_RARE: Duration = Duration::from_secs(40 * 60);

/// aMule `SOURCECLIENTREASK * MINCOMMONPENALTY` (40 min × 4 = 160 min): the
/// longer gate for a common file.
const REASK_COMMON: Duration = Duration::from_secs(40 * 4 * 60);

/// Which of aMule's two source-exchange pools a served file draws from — the
/// distinction decides the *unknown source status* asymmetry (ADR-0055).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServedFileKind {
    /// A complete shared file (`CKnownFile::CreateSrcInfoPacket` @4e8f2b3c):
    /// the pool is the upload-engaged client list, and a candidate whose part
    /// status we do not know is **included**.
    Complete,
    /// A file still downloading (`CPartFile::CreateSrcInfoPacket` @4e8f2b3c):
    /// the pool is the download's own source list, and a candidate whose part
    /// status we do not know is **excluded** — the include/exclude asymmetry is
    /// aMule's own.
    ///
    /// Modelled and tested here (the ADR-0055 two-pool asymmetry is the whole
    /// reason the kinds differ), but not yet wired: rmule shares only complete
    /// files today, so [`ServeState`](super::state::ServeState) never builds an
    /// in-progress pool. It flips live with partial-file sharing.
    #[allow(dead_code)]
    InProgress,
}

/// One candidate the serve pool may forward, paired with its part status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SxCandidate {
    /// The source as it goes on the wire (client id + port + any provenance).
    pub(crate) source: ExchangedSource,
    /// The parts the candidate holds — for an upload-engaged client, the
    /// status its own last name ask or UDP reask wrote, through [`held_parts`]
    /// — or `None` when we do not know them: the unknown-status branch of the
    /// needed-chunk filter.
    pub(crate) part_status: Option<PartBitmap>,
}

#[cfg(test)]
impl SxCandidate {
    /// A candidate whose part status we do not know.
    pub(crate) fn unknown_status(source: ExchangedSource) -> Self {
        Self {
            source,
            part_status: None,
        }
    }
}

/// The parts a peer's `<u16 count><bitmap>` says it holds of a file we share,
/// read against the file's `file_size` (ADR-0055 §Serving). One
/// reader for both writers — the name ask (`0x58`) and the UDP reask (`0x90`)
/// — as aMule's `ProcessExtendedInfo` is for both (stock 2.3.3 `4e8f2b3c`
/// `UploadClient.cpp:397`; the UDP caller is `ClientUDPSocket.cpp:202-203`).
/// `None` when the status cannot be read against this file: aMule's uploader
/// clears a status whose count is not the file's ED2K part count
/// (`UploadClient.cpp:418-421`), and so does this.
///
/// The result has aMule's *reader* geometry — the file's real parts only
/// (`m_upPartStatus.setsize(GetPartCount())`, `UploadClient.cpp:424`) — so the
/// phantom last part a writer counts for an exact multiple (`size / PARTSIZE +
/// 1`, [`PartBitmap::downloader`]) is dropped and never reads as a part held
/// or lacked: aMule's answer loops compare `GetPartCount()` parts
/// (`KnownFile.cpp:985`, `:1013`).
///
/// A count of **zero** is a complete file: the writer's own meaning
/// (`OP_FILESTATUS` and the UDP reask write `WriteUInt16(0)` for a file that
/// is not a part file, kno `ab483654` `ClientTCPSocket.cpp:480-484`,
/// `DownloadClient.cpp:1387-1391`). aMule's reader sizes it to all-zero
/// instead (`UploadClient.cpp:415-416`), which would drop a complete source
/// from every answer; rmule reads the writer's meaning.
pub(crate) fn held_parts(file_size: u64, wire: &PartBitmap) -> Option<PartBitmap> {
    let real = rmule_primitives::part_count(file_size);
    if wire.part_count() == 0 {
        return Some(PartBitmap::all_present(real));
    }
    if wire.part_count() != PartBitmap::downloader_empty(file_size).part_count() {
        return None;
    }
    // The wire count is `real` or `real + 1`, so its bytes cover every real
    // part; `decode` zeroes the phantom bit past `real`.
    PartBitmap::decode(real, &wire.encode()[..(real as usize).div_ceil(8)]).ok()
}

/// The requester's context for the needed-chunk filter and the self-skip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SxRequester {
    /// The requester's *own source endpoint* (its advertised id + listen port),
    /// or `None` when it is LowID / unknown. A candidate resolving to this
    /// endpoint is the requester itself (aMule's `cur_src == forClient`,
    /// compared on source identity, not the ephemeral inbound socket) and is
    /// never served back.
    pub(crate) endpoint: Option<PeerEndpoint>,
    /// The requester's part status (its last name ask's or UDP reask's, through
    /// [`held_parts`]), or `None` when unknown — no ask carried one (an
    /// extended-requests-v0 claimant) or its count did not fit the file. An
    /// unknown requester is sent only sources holding at least one part, plus
    /// the unknowns — the rule aMule wrote for it and left unreachable
    /// (`KnownFile.cpp:1000-1024`, stock 2.3.3 `4e8f2b3c`), where aMule itself
    /// refuses such an asker outright (`:929-933`); rmule's divergence is
    /// ADR-0055's.
    pub(crate) part_status: Option<PartBitmap>,
}

/// Filter `candidates` into the source list a serve answer carries, aMule-exact
/// (`CKnownFile`/`CPartFile::CreateSrcInfoPacket` @4e8f2b3c): drop LowID
/// entries and the requester itself, apply the needed-chunk filter against the
/// requester's known part status (with the `kind`-specific unknown-status
/// asymmetry), and cap the result at [`SOURCE_EXCHANGE_MAX_ENTRIES`], preserving
/// pool order.
pub(crate) fn select_sources(
    kind: ServedFileKind,
    requester: &SxRequester,
    candidates: &[SxCandidate],
) -> Vec<ExchangedSource> {
    candidates
        .iter()
        // Skip LowID sources: a firewalled peer's server-assigned id is not a
        // dialable address, so aMule never source-exchanges it. An IPv6-only
        // source has an address and survives; whether the answer's form can
        // carry it is the caller's call. (Runs first, so every survivor's
        // `as_peer_endpoint` is `Some` for the self-skip.)
        .filter(|c| c.source.as_peer_endpoint().is_some())
        // Skip the requester itself (its own source) echoing back as a
        // candidate — compared on source identity, never the socket.
        .filter(|c| {
            requester.endpoint.is_none() || c.source.as_peer_endpoint() != requester.endpoint
        })
        .filter(|c| is_worth_serving(kind, requester, c))
        .take(SOURCE_EXCHANGE_MAX_ENTRIES)
        .map(|c| c.source)
        .collect()
}

/// The needed-chunk filter plus the pool's unknown-status asymmetry for one
/// candidate (aMule's `bNeeded` decision):
///
/// - **Source status unknown** → `Complete` includes, `InProgress` excludes.
/// - **Both statuses known (same geometry)** → keep iff the source holds a part
///   the requester still lacks (`KnownFile.cpp:985-991`).
/// - **Requester status unknown, source known** → keep iff the source holds at
///   least one part — aMule's rule for an asker without chunk status, in both
///   pools (`KnownFile.cpp:1000-1019`, `PartFile.cpp:2621-2632`).
/// - **Geometry mismatch** → drop, as aMule skips a source whose count is not
///   the file's (`KnownFile.cpp:981-984`); unreachable when every status is
///   read through [`held_parts`] for the one file.
fn is_worth_serving(
    kind: ServedFileKind,
    requester: &SxRequester,
    candidate: &SxCandidate,
) -> bool {
    let Some(source_status) = &candidate.part_status else {
        return matches!(kind, ServedFileKind::Complete);
    };
    match &requester.part_status {
        Some(req) if req.part_count() == source_status.part_count() => {
            source_status.iter_present().any(|part| !req.has(part))
        }
        Some(_) => false,
        None => source_status.iter_present().next().is_some(),
    }
}

/// The per-peer source-exchange serve throttle (ADR-0055): mirrors aMule's
/// requester reask cadence onto the serve gate — first ask free, then the same
/// peer must wait 40 minutes (a rare file, ≤ 50 known sources) or 160 minutes
/// (a common one) before it is answered again. Explicit-time (`Instant`), so
/// the gate is asserted without a clock. Shared by standalone and
/// multipacket-sub asks: both route through the one per-peer stamp.
#[derive(Debug, Default)]
pub(crate) struct SourceExchangeThrottle {
    last_answered: HashMap<PeerEndpoint, Instant>,
}

impl SourceExchangeThrottle {
    /// Whether `peer`'s ask at `now` is answered, given `known_source_count`
    /// sources known for the file (which decides rare vs common). A never-asked
    /// peer is always answered ("first ask free"); an answered ask stamps the
    /// clock, a throttled one leaves it untouched.
    pub(crate) fn admit(
        &mut self,
        peer: PeerEndpoint,
        now: Instant,
        known_source_count: usize,
    ) -> bool {
        let interval = if known_source_count <= RARE_SOURCE_THRESHOLD {
            REASK_RARE
        } else {
            REASK_COMMON
        };
        match self.last_answered.get(&peer) {
            Some(prev) if now.saturating_duration_since(*prev) < interval => false,
            _ => {
                self.last_answered.insert(peer, now);
                true
            }
        }
    }

    /// Forget `peer`'s throttle stamp — called when it disconnects, so a
    /// reconnecting peer's first ask is free again (its connection, and the
    /// per-connection gate, is new).
    pub(crate) fn forget(&mut self, peer: PeerEndpoint) {
        self.last_answered.remove(&peer);
    }
}

#[cfg(test)]
mod tests;
