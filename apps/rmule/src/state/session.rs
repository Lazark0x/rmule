//! Startup-loaded session facts: the default server, the client credentials,
//! and the download directory the config store provided.
//!
//! Configuration is not an event — this is loaded once by `main` and never
//! folded. `None` marks a UI-only run with no core attached, which every view
//! degrades to an honest flash rather than a dead control.

/// Startup-loaded session facts: the server, credentials, and download
/// directory the config store provided. `None` = a UI-only run (no core
/// attached); views degrade to honest flashes. Loaded once by `main`, never
/// folded — configuration is not an event.
#[derive(Clone)]
pub struct SessionConfig {
    /// The server every activity command names by default — the first row of
    /// the managed list at startup. `None` when the list was empty: the
    /// credentials still exist, so the Servers tab can add a server and
    /// connect to it, and only the commands that *need* a default server
    /// (search, download) degrade.
    pub server: Option<rmule_primitives::ServerEndpoint>,
    /// The minted identity every session command carries; never printed
    /// (see the `Debug` impl below).
    pub credentials: rmule_core::ClientCredentials,
    /// Where a started download writes; `None` leaves the download commands
    /// degraded, since core is given the directory per download.
    pub download_dir: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for SessionConfig {
    /// Redacted: never print identity or key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("server", &self.server)
            .field("download_dir", &self.download_dir)
            .finish()
    }
}
