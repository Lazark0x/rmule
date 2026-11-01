//! The Settings tab's labels, headings and the notes beside its fields. A
//! label's width is measured, never assumed: `form` sizes its column to them.

use crate::config::{ObfuscationChoice, ThemeChoice};
use rmule_primitives::ServerEndpoint;

/// The tab's title.
pub const TITLE: &str = " Settings ";

/// The heading over the paths.
pub const PATHS: &str = "Paths";
/// The heading over the network rows.
pub const NETWORK: &str = "Network";
/// The heading over the server rows.
pub const SERVERS: &str = "Servers";
/// The heading over the download rows.
pub const DOWNLOADS: &str = "Downloads";
/// The heading over the Kad rows.
pub const KAD: &str = "Kad";
/// The heading over the look of the app.
pub const APPEARANCE: &str = "Appearance";
/// The heading over the logging row.
pub const DIAGNOSTICS: &str = "Diagnostics";
/// The heading over the identity rows.
pub const IDENTITY: &str = "Identity — minted once, never edited";
/// The heading over the shared directories.
pub const SHARED_DIRECTORIES: &str = "Shared directories";

/// The download directory.
pub const DOWNLOAD_DIR: &str = "Download dir";
/// Where a download dir is unset.
pub const DOWNLOAD_DIR_UNSET: &str = "unset — downloads have nowhere to land";
/// The temp directory.
pub const TEMP_DIR: &str = "Temp dir";
/// The data directory.
pub const DATA_DIR: &str = "Data dir";
/// The nickname.
pub const NICKNAME: &str = "Nickname";
/// The eD2k port.
pub const ED2K_PORT: &str = "eD2k port";
/// The server list's mirror.
pub const SERVER_MET: &str = "server.met";
/// Where the mirror is used.
pub const SERVER_MET_NOTE: &str = "(Networks: U)";
/// The first-run list fetch.
pub const FETCH_LIST: &str = "Fetch list";
/// What it does.
pub const FETCH_LIST_NOTE: &str = "at start when the list is empty  (on restart)";
/// The UDP port.
pub const UDP_PORT: &str = "UDP port";
/// The obfuscation policy.
pub const OBFUSCATION: &str = "Obfuscation";
/// What it covers.
pub const OBFUSCATION_NOTE: &str = "peer TCP/UDP + Kad + server UDP";
/// The router port mapping.
pub const PORT_MAPPING: &str = "Port mapping";
/// What it does.
pub const PORT_MAPPING_NOTE: &str = "opens router ports: UPnP, PCP, NAT-PMP  (on restart)";
/// Connecting at start.
pub const AUTOCONNECT: &str = "Autoconnect";
/// The dead server limit.
pub const DEAD_AFTER: &str = "Dead after";
/// What it counts.
pub const DEAD_AFTER_NOTE: &str = "failed tries in a row; a dead server stays listed";
/// Withholding shares.
pub const HIDE_SHARES: &str = "Hide shares";
/// From whom.
pub const HIDE_SHARES_NOTE: &str = "from servers that answer related searches";
/// The seeds kept per download.
pub const REMEMBER_PEERS: &str = "Remember peers";
/// The player.
pub const PLAYER: &str = "Player";
/// The Kad seed mirror.
pub const NODES_DAT: &str = "nodes.dat";
/// The seed fetch.
pub const FETCH_SEEDS: &str = "Fetch seeds";
/// What it does.
pub const FETCH_SEEDS_NOTE: &str = "nodes.dat on first Kad start  (on restart)";
/// The theme.
pub const THEME: &str = "Theme";
/// What auto reads.
pub const THEME_NOTE: &str = "auto follows the terminal";
/// The terminal's title.
pub const TERMINAL_TITLE: &str = "Terminal title";
/// Reader Mode.
pub const READER_MODE: &str = "Reader mode";
/// The completion bell.
pub const BELL: &str = "Bell";
/// The mouse.
pub const MOUSE: &str = "Mouse";
/// The full Run Log.
pub const FULL_RUN_LOG: &str = "Full run log";
/// What it adds.
pub const FULL_RUN_LOG_NOTE: &str = "adds peers, files and paths to rmule.log";
/// The user hash.
pub const USER_HASH: &str = "User hash";
/// The Kad id.
pub const KAD_NODE_ID: &str = "Kad node ID";
/// A shared directory's row.
pub const SHARED: &str = "Shared";
/// The row a new directory is typed into.
pub const SHARE_A_DIR: &str = "Share a dir";
/// What it takes.
pub const SHARE_A_DIR_HINT: &str = "Enter, type a path, Enter";

/// Where a row takes effect on the next start.
pub const ON_RESTART: &str = "(on restart)";

/// An on/off selector's two options, in index order.
pub const ON_OFF: [&str; 2] = ["off", "on"];

/// A row's note in brackets.
#[must_use]
pub fn bracketed(note: &str) -> String {
    format!("({note})")
}

/// The connect-at-start row's note: which server a start would dial, or that
/// none has been connected to yet.
#[must_use]
pub fn connect_at_start_note(last: Option<&ServerEndpoint>) -> String {
    match last {
        Some(server) => format!(
            "at start, to {}:{}  {ON_RESTART}",
            server.host(),
            server.port()
        ),
        None => format!("at start, to the last server — none yet  {ON_RESTART}"),
    }
}

/// A theme as the selector and a receipt say it.
#[must_use]
pub const fn theme_word(theme: ThemeChoice) -> &'static str {
    match theme {
        ThemeChoice::Auto => "auto",
        ThemeChoice::Dark => "dark",
        ThemeChoice::Light => "light",
        ThemeChoice::Fallback256 => "256",
        ThemeChoice::Ansi16 => "16",
        ThemeChoice::Mono => "mono",
    }
}

/// An obfuscation policy as the selector and a receipt say it.
#[must_use]
pub const fn obfuscation_word(choice: ObfuscationChoice) -> &'static str {
    match choice {
        ObfuscationChoice::Off => "off",
        ObfuscationChoice::Supported => "supported",
        ObfuscationChoice::Requested => "requested",
        ObfuscationChoice::Required => "required",
    }
}
