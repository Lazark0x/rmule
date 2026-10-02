//! Zero-config bootstrap acquisition: the first HTTP capability in rmule.
//!
//! rmule ships with no server list and no Kad contacts; a fresh install cannot
//! join either network unaided. This crate owns **URL acquisition** — the
//! deterministic pipelines that fetch a server list or a nodes.dat and
//! reconcile it into an install plan — behind a single I/O seam (ADR-0065,
//! ADR-0066).
//!
//! # Shape
//!
//! - [`Fetcher`] is the crate's **only I/O seam**: `get(url) → bounded bytes`.
//!   The pipelines are generic over it, so no unit test opens a socket.
//! - [`fetch_server_met`] is the server.met pipeline: bounded GET →
//!   parse-before-install (through the [`rmule_ed2k::ServerMet`] decoder) →
//!   aMule add-new / update-known merge → a [`ServerMetInstall`] plan.
//!   [`fetch_server_met_auto_update`] walks a whole configured URL list
//!   through it, one failing URL not stopping the walk.
//! - [`fetch_nodes_dat`] / [`decode_nodes_dat`] are the nodes.dat pipeline:
//!   bounded GET → try the normal reader, fall back to the v3
//!   bootstrap-edition reader on `NodesDatError::BootstrapEdition` → a
//!   [`NodesDatInstall`] plan.
//! - [`should_auto_fetch_server_met`] and [`should_auto_fetch_nodes_dat`] are
//!   the cold-start trigger decisions, called by the Join Sequence in
//!   `rmule_core::join`. Their defaults are opposite, and the asymmetry is
//!   aMule's own: a server list is acquired unattended on first run, a
//!   nodes.dat only when a front-end opts in. Exactly one does — the `rmule`
//!   TUI (ADR-0067 amendment).
//! - [`ReqwestFetcher`] (feature `reqwest-fetcher`, on by default) is the sole
//!   production [`Fetcher`] — reqwest with rustls, no native-tls, redirect /
//!   size / timeout caps. It is the crate's only corner that links an HTTP
//!   client; disabling the feature leaves the pure seam, pipelines and
//!   decisions, so a consumer can depend on the machinery without pulling
//!   reqwest or a TLS stack into its tree.
//!
//! Every pipeline returns a *plan*, never an applied effect: nothing here
//! writes a store or reconnects a session, which is what keeps the merge and
//! dispatch semantics assertable as plain values.
//!
//! # Evidence (ADR-0045, HTTP-counterparty adaptation)
//!
//! The deterministic tier drives the pipelines through a fake [`Fetcher`] with
//! canned bytes — the trigger truth tables, the add-new / update-known merge
//! posture, parse-failure-keeps-old-list, one-shot no-retry and size-cap
//! rejection all gate CI without a socket. The `tests/bootstrap` binary's
//! `cold_start_e2e` leg runs the whole cold-start arc in process: empty list →
//! faked fetch → parse/merge → the parsed endpoint logging in against the
//! ADR-0040 `FakeEd2kServer`.
//!
//! The capture tier is a **documented gap, not a fabrication**: its golden
//! would be an aMule-authored `server.met` (a pinned aMule's `SaveServerMet`
//! output) served to rmule over a local HTTP fixture, and no such byte asset
//! exists in the repo. Authoring one needs the pinned aMule image — that is
//! interop-harness territory, gated like its other real-container tests. The
//! deterministic payloads above are crate-built valid server.met bytes and are
//! clearly not captures.

#![warn(missing_docs)]

mod auto_update_walk;
mod config;
mod fetcher;
mod first_run;
mod nodes_dat;
mod server_met;

#[cfg(test)]
mod fixture;

#[cfg(feature = "reqwest-fetcher")]
mod reqwest_fetcher;

pub use auto_update_walk::{AutoUpdateWalkResult, UrlWalkOutcome, fetch_server_met_auto_update};
pub use config::{
    BootstrapConfig, DEFAULT_MAX_NODES_DAT_BYTES, DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_SERVER_MET_BYTES, DEFAULT_NODES_DAT_URL, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SERVER_MET_URL,
};
pub use fetcher::{FetchError, Fetcher};
pub use first_run::{should_auto_fetch_nodes_dat, should_auto_fetch_server_met};
pub use nodes_dat::{NodesDatInstall, NodesDatPipelineError, decode_nodes_dat, fetch_nodes_dat};
pub use server_met::{ServerMetInstall, ServerMetPipelineError, fetch_server_met};

#[cfg(feature = "reqwest-fetcher")]
pub use reqwest_fetcher::ReqwestFetcher;
