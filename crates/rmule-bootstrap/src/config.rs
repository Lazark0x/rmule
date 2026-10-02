//! Bootstrap acquisition defaults and the first-run switch.
//!
//! The URL is aMule's exact live value as an overridable default — honest
//! parity with the ecosystem's mirror, not an invented endpoint (ADR-0065,
//! "Defaults + first-run policy"). The size / redirect / timeout caps are the
//! ADR's documented hardening: unobservable to a legitimate mirror, a floor
//! against a hostile one.

use std::time::Duration;

/// aMule's default eD2k server-list URL
/// ([`Preferences.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Preferences.cpp#L1249)).
/// Plain `http` is aMule's own default (its wxHTTP client cannot do TLS); a
/// [`ReqwestFetcher`](crate::ReqwestFetcher) transparently upgrades to `https`
/// when an operator points `server_met_url` at a TLS mirror — same GET, same
/// payload, hardened transport (ADR-0065, "Dependency").
pub const DEFAULT_SERVER_MET_URL: &str = "http://upd.emule-security.org/server.met";

/// aMule's default Kad nodes.dat bootstrap URL (`Preferences.cpp`'s
/// `KadNodesUrl`, the same commit/file as [`DEFAULT_SERVER_MET_URL`]'s
/// `Ed2kServersUrl` — both mirrors live at the same host). Only ever read by
/// an explicit [`crate::fetch_nodes_dat`] call: unlike the server.met
/// URL, nothing auto-fetches this one.
pub const DEFAULT_NODES_DAT_URL: &str = "http://upd.emule-security.org/nodes.dat";

/// Response-body cap for a server.met fetch. A real list is a few thousand
/// rows of `ip4/port2/tagcount4` + short tags — tens of KiB; 4 MiB is
/// comfortably above any honest list and well below a memory-exhaustion
/// concern.
pub const DEFAULT_MAX_SERVER_MET_BYTES: usize = 4 * 1024 * 1024;

/// Response-body cap for a nodes.dat fetch. A routing-zone dump or a v3
/// bootstrap-edition file (500–1000 contacts × 25–34 bytes/row) is a few tens
/// of KiB; 1 MiB comfortably covers either shape with headroom, well under a
/// memory-exhaustion concern.
pub const DEFAULT_MAX_NODES_DAT_BYTES: usize = 1024 * 1024;

/// Redirect-follow cap. A mirror move is one or two hops; a longer chain is a
/// misconfiguration or a redirect loop, not a server list.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// Per-request deadline for a server.met fetch.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Bootstrap acquisition configuration: the server.met source, the transport
/// hardening caps, and the first-run auto-fetch switch.
///
/// One value carries every acquisition source: the single server.met URL, the
/// auto-update URL list, and the nodes.dat URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// The server.met source URL. Defaults to aMule's mirror
    /// ([`DEFAULT_SERVER_MET_URL`]); an operator may point it at any `http`
    /// or `https` mirror.
    pub server_met_url: String,

    /// Response-body size cap passed to [`Fetcher::get`](crate::Fetcher::get)
    /// for the server.met fetch.
    pub max_server_met_bytes: usize,

    /// How many redirects the fetcher follows before giving up.
    pub max_redirects: usize,

    /// Per-request timeout the fetcher enforces.
    pub request_timeout: Duration,

    /// The first-run server.met auto-fetch switch — **default ON**.
    ///
    /// amuled fetches a server list unconditionally on a cold start (the GUI
    /// "download a server list?" prompt is `#ifndef AMULE_DAEMON`-compiled
    /// out); rmule reproduces that default behaviour byte-for-byte. The sole
    /// divergence is that this off-switch exists at all — operator control a
    /// headless amuled structurally lacks (ADR-0065). Consumed by
    /// [`should_auto_fetch_server_met`](crate::should_auto_fetch_server_met).
    pub auto_fetch_server_met: bool,

    /// Auto-update URL list — the `addresses.dat` role. A list of URLs to
    /// fetch and merge, walked in order when [`Self::auto_update_enabled`] is true
    /// (ADR-0065 execution breakdown 2). No default URLs — the shape is here,
    /// callers populate it. Consumed by
    /// [`fetch_server_met_auto_update`](crate::fetch_server_met_auto_update).
    pub auto_update_urls: Vec<String>,

    /// The auto-update URL list walk toggle — **default OFF**.
    ///
    /// aMule walks the `addresses.dat` URL list, gated on `AutoServerlist`
    /// which defaults OFF and ships with an empty file so the path is dormant
    /// (ADR-0065). rmule mirrors this: the toggle defaults OFF, and when
    /// enabled, the walk iterates [`Self::auto_update_urls`] in order, fetching and
    /// merging each (one failure does not stop the walk; all results are
    /// reported).
    pub auto_update_enabled: bool,

    /// The nodes.dat source URL. Defaults to aMule's mirror
    /// ([`DEFAULT_NODES_DAT_URL`]). Consumed by
    /// [`fetch_nodes_dat`](crate::fetch_nodes_dat) (ADR-0065 execution
    /// breakdown 3).
    pub nodes_dat_url: String,

    /// Response-body size cap passed to [`Fetcher::get`](crate::Fetcher::get)
    /// for the nodes.dat fetch.
    pub max_nodes_dat_bytes: usize,

    /// The first-run nodes.dat acquisition switch — **default OFF**, the
    /// opposite of [`auto_fetch_server_met`](Self::auto_fetch_server_met).
    ///
    /// aMule's asymmetry is the reason: `UpdateNotesDat` is user-/EC-triggered
    /// only, with no first-run auto-fetch in any build, so **OFF is parity**
    /// and every headless/library caller keeps it. ADR-0067 amendment
    /// opts *one* consumer in — the `rmule` TUI, whose product surface
    /// reaches none of the three recovery routes that ADR relied on (it ships
    /// no config seeds, no Kad bootstrap-from-URL action, and the eD2k→Kad
    /// handoff needs a peer session the user may never open). A front door
    /// that leaves Kad permanently stranded is the worse divergence.
    ///
    /// Consumed by
    /// [`should_auto_fetch_nodes_dat`](crate::should_auto_fetch_nodes_dat).
    pub auto_fetch_nodes_dat: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            server_met_url: DEFAULT_SERVER_MET_URL.to_owned(),
            max_server_met_bytes: DEFAULT_MAX_SERVER_MET_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            auto_fetch_server_met: true,
            auto_update_urls: Vec::new(),
            auto_update_enabled: false,
            nodes_dat_url: DEFAULT_NODES_DAT_URL.to_owned(),
            max_nodes_dat_bytes: DEFAULT_MAX_NODES_DAT_BYTES,
            auto_fetch_nodes_dat: false,
        }
    }
}
