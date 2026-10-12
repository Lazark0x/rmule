//! Startup-loaded session facts: the default server and the download
//! directory the config store provided. The credentials are core's own
//! (ADR-0069): no command carries them.
//!
//! Configuration is not an event — this is loaded once by `main` and never
//! folded. `None` marks a UI-only run with no core attached, which every view
//! degrades to an honest flash rather than a dead control.

/// Startup-loaded session facts: the server and download directory the
/// config store provided. `None` = a UI-only run (no core
/// attached); views degrade to honest flashes. Loaded once by `main`, never
/// folded — configuration is not an event.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The server every activity command names by default — the first row of
    /// the managed list at startup. `None` when the list was empty: a core
    /// still runs, so the Servers tab can add a server and connect to it, and
    /// only the commands that *need* a default server (search, download)
    /// degrade.
    pub server: Option<rmule_primitives::ServerEndpoint>,
    /// Where a started download writes; `None` leaves the download commands
    /// degraded, since core is given the directory per download.
    pub download_dir: Option<std::path::PathBuf>,
}
