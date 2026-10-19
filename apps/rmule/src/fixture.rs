//! The crate's one test-fixture home: every builder the unit tests share, from
//! the primitives (part maps, ids, endpoints, keystrokes) up to the whole
//! `UiState`s the chrome and the six views render.
//!
//! One home so a fixture's shape is written once and each builder's name says
//! what it builds: a test that wants "three downloads with the second selected
//! and receiving" or "four listed servers, the first connected" says so instead
//! of rebuilding a snapshot by hand. A helper only one module ever needs is not
//! a fixture — it stays in that module's own test block.

mod draw;
pub(crate) use draw::{draw_golden, draw_searches, screen_lines};

mod networks;
mod searches;
mod shared_files;
mod statistics;
mod transfers;
pub(crate) use networks::*;
pub(crate) use searches::*;
pub(crate) use shared_files::*;
pub(crate) use statistics::*;
pub(crate) use transfers::*;
// The captured clients, shared with the words' own tests.
pub(crate) use rmule_testkit::{amule_233, emule_qt};

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use rmule_core::diagnostics::{DiagnosticsSnapshot, PartState, SessionCounters};
use rmule_core::{
    CoreEvent, DownloadEvent, DownloadId, DownloadMetadata, SearchEvent, SearchId, ServeEvent,
    ServerConnectionEvent,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint, SearchResult, ServerEndpoint,
};

use crate::action::Action;
use crate::bridge::BridgeSnapshot;
use crate::rates::TransferRates;
use crate::state::{Ed2kConnection, SessionConfig, UiState};
use crate::theme::Theme;

// --- Primitives every area builds on --------------------------------------

/// A part map from a pattern string: `V`erified, `I`n-flight, `M`issing —
/// `part_map("VVIM")` is a four-part file whose first two parts are held, the
/// third is being fetched and the last is not started.
///
/// Positional by construction, so a test that cares *where* a part is says so
/// in the fixture instead of asserting against a count.
pub(crate) fn part_map(pattern: &str) -> Vec<PartState> {
    pattern
        .chars()
        .map(|glyph| match glyph {
            'V' => PartState::Verified,
            'I' => PartState::InFlight,
            'M' => PartState::Missing,
            other => panic!("part_map pattern takes V/I/M, got {other:?}"),
        })
        .collect()
}

/// Feed `count` data ticks one second apart into `state`, so a view test has a
/// rate history without a bridge or a clock.
///
/// The ramp is a deterministic sawtooth — down peaks every 20 s at 475 KB/s,
/// up every 12 s at 88 KB/s — so a golden carries real shape (rise, peak,
/// drop back to a metered-idle floor) instead of uncheckable noise. `levels` rides every tick unchanged apart from the
/// session counters, which accumulate the ramp: a fixture's uploads or Kad
/// facts survive the latest-state-wins snapshot the ticks apply.
pub(crate) fn rate_ticks(
    state: &mut UiState,
    base: Instant,
    count: u64,
    levels: &DiagnosticsSnapshot,
) {
    let mut down_total = levels.session.down_bytes_total;
    let mut up_total = levels.session.up_bytes_total;
    for tick in 0..count {
        let down_bps = (tick % 20) as f64 * 25.0 * 1024.0;
        let up_bps = (tick % 12) as f64 * 8.0 * 1024.0;
        down_total += down_bps as u64;
        up_total += up_bps as u64;
        let at = base + Duration::from_secs(tick);
        state.apply_snapshot(
            BridgeSnapshot {
                diagnostics: DiagnosticsSnapshot {
                    session: SessionCounters {
                        down_bytes_total: down_total,
                        up_bytes_total: up_total,
                        ..SessionCounters::default()
                    },
                    ..levels.clone()
                },
                rates: TransferRates {
                    down_total_bps: down_bps,
                    up_total_bps: up_bps,
                    ..TransferRates::default()
                },
                taken_at: at,
            },
            at,
        );
    }
}

/// A download handle from a small integer, so a test names its downloads `1`,
/// `2`, … instead of carrying an opaque id around.
pub(crate) fn download_id(n: u64) -> DownloadId {
    DownloadId::from_u64(n)
}

/// `rest` (`/`-separated) under this platform's filesystem root: an absolute
/// path a typed or validated directory accepts everywhere. A leading `/`
/// alone names no drive on Windows, so it is relative there.
pub(crate) fn rooted(rest: &str) -> std::path::PathBuf {
    let root = if cfg!(windows) { r"C:\" } else { "/" };
    rest.split('/')
        .fold(root.into(), |path: std::path::PathBuf, part| {
            path.join(part)
        })
}

/// A content hash of one repeated byte — the byte *is* the file's identity in
/// a test, so two fixtures disagree visibly rather than by accident.
pub(crate) fn file_hash(byte: u8) -> FileHash {
    FileHash::from_bytes([byte; 16])
}

/// The `.part` core names for a fixture download: an absolute path, as
/// core only ever publishes one.
pub(crate) fn part_file() -> std::path::PathBuf {
    rooted("downloads/file.bin.part")
}

/// Metadata for a file core knows the hash of but not the name — the
/// edge-order case every download row must render honestly.
pub(crate) fn unnamed_metadata() -> DownloadMetadata {
    DownloadMetadata::unnamed(0)
}

/// The one eD2k server every connection fixture names.
pub(crate) fn server_endpoint() -> ServerEndpoint {
    ServerEndpoint::new("10.0.0.1", 4661).expect("endpoint")
}

/// An upload-side peer distinguished by its last octet.
pub(crate) fn peer_endpoint(last_octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, last_octet), 4662))
}

/// A peer at a full address, for log lines that print one.
pub(crate) fn peer_at(a: u8, b: u8, c: u8, d: u8, port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::new(a, b, c, d), port))
}

/// A search handle from a small integer; monotonic, so a higher number is a
/// later search.
pub(crate) fn search_id(n: u64) -> SearchId {
    SearchId::from_u64(FIXTURE_SEARCH_IDS + n)
}

/// Where the fixture's search ids start. `SearchId::mint` counts up from 1
/// for the whole process, so a fixed small id and a minted one are the same
/// id whenever the minting test happens to run first; ids from here up cannot
/// meet a minted one.
pub(crate) const FIXTURE_SEARCH_IDS: u64 = 1 << 62;

/// A named result carrying a reported source count — the two facts the
/// Searches table sorts and tints by.
pub(crate) fn search_result(name: &str, sources: u32) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([0xAB; 16]),
        1024,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .expect("valid result")
    .with_reported_availability(sources)
}

/// Lift a download edge onto the core event bus.
pub(crate) fn download_event(event: DownloadEvent) -> CoreEvent {
    CoreEvent::Download(event)
}

/// Lift a serve edge onto the core event bus.
pub(crate) fn serve_event(event: ServeEvent) -> CoreEvent {
    CoreEvent::Serve(event)
}

/// Lift a search edge onto the core event bus.
pub(crate) fn search_event(event: SearchEvent) -> CoreEvent {
    CoreEvent::Search(event)
}

/// Lift a server-connection edge onto the core event bus.
pub(crate) fn server_connection_event(event: ServerConnectionEvent) -> CoreEvent {
    CoreEvent::ServerConnection(event)
}

/// A key press as the app loop sees it: a terminal event wrapped in the one
/// input action the bus carries.
pub(crate) fn key_action(code: KeyCode) -> Action {
    Action::Input(Event::Key(press(code)))
}

/// A key press with no modifiers — the one keystroke shape every view test
/// feeds `handle_key`.
pub(crate) fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A draw instant for a render that asserts nothing about time.
pub(crate) fn now() -> Instant {
    Instant::now()
}

/// The palette every view fixture renders against.
pub(crate) fn theme() -> Theme {
    Theme::default_dark()
}

/// The golden render surface every view snapshot is taken at (spec §3.5).
pub(crate) const GOLDEN_W: u16 = 78;
/// Height of that same surface.
pub(crate) const GOLDEN_H: u16 = 21;

/// The golden render surface as a rect, for a draw that is handed one.
pub(crate) fn golden_area() -> Rect {
    Rect::new(0, 0, GOLDEN_W, GOLDEN_H)
}

/// A pathological but legal eD2k file name: 200 characters, no spaces, with
/// a recognizable tail so a test can prove nothing was cut.
pub(crate) fn long_name() -> String {
    format!("{}END-OF-NAME.iso", "long-".repeat(37))
}

// --- Session and chrome ---------------------------------------------------

/// The startup session config a real command needs: the one server and no
/// download directory.
pub(crate) fn session() -> SessionConfig {
    SessionConfig {
        server: Some(endpoint("10.0.0.1", 4661)),
        download_dir: None,
    }
}

/// A logged-in session with a metered download and a notable fact — the state
/// that makes every status-bar segment carry something.
pub(crate) fn connected_state() -> UiState {
    UiState {
        ed2k: Ed2kConnection::Connected {
            client_id: ClientId::from_u32(ClientId::LOW_ID_THRESHOLD),
        },
        rates: TransferRates {
            down_total_bps: 123.4 * 1024.0,
            ..TransferRates::default()
        },
        notable: Some(crate::words::Sentence::for_test("download completed")),
        ..UiState::default()
    }
}

/// A flash the app really emits, long enough that the status bar must wrap
/// it rather than clip it: the one a download asked for with no download
/// directory set gets. The words' own constant, so it cannot drift from them.
pub(crate) const LONG_FLASH: crate::words::Sentence = crate::words::download::NO_DOWNLOAD_DIR;
