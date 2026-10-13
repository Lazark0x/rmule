#![doc = "Terminal front-end for rmule (ADR-0069): an in-process core behind a `CoreClient` seam."]
//!
//! **The core side.**
//!
//! - [`client`] — the [`client::CoreClient`] seam: the only door UI code has
//!   to the core. v1 binds it in-process; the daemon-era remote transport
//!   implements the same trait without touching UI code.
//! - [`bridge`] — the in-process binding: owns the sole `Core` handle, drains
//!   the single-consumer event stream, polls `diagnostics_snapshot()` on the
//!   1 Hz data tick, and synthesizes transfer rates (which exist nowhere in
//!   core) before feeding the single [`action::Action`] bus.
//! - [`state`] — pure `UiState`: `fold(state, event)` for lifecycle edges,
//!   `apply_snapshot(state, frame, now)` for byte levels, time injected and
//!   never read — the whole UI core tests without a terminal, tokio, or a
//!   live core.
//! - [`rates`] — the pure EMA rate synthesizer the bridge drives.
//! - [`attach`] — standing the core up for a run: the one Durable Store,
//!   the identities, and the core built over that store's seams with the
//!   adapters a run needs, the same for `main` and the tests.
//! - [`kad`] — the app's Kad join: assemble the start config from
//!   durable identity + data dir, resolve its seeds through the core's own
//!   ADR-0067 policy, and send the one `EnableKad` the app owes core — armed
//!   by the run's first eD2k login, never at startup.
//! - [`connect`] — the connect at start (ADR-0095): off unless the operator
//!   turned it on, and then the operator's own `ConnectToServer` to the
//!   server they last connected to — nothing else in the app ever dials.
//! - [`player`] — the Player Command (ADR-0114): the operator's player as
//!   words split by POSIX rules, never a shell line.
//! - [`config`] — front-end-owned configuration (ADR-0069): the app-config
//!   seam over the one Durable Store that core's server-list seam and the
//!   Settings tab share, the preference snapshot, and the edit vocabulary that
//!   writes both.
//!
//! **The terminal side.**
//!
//! - [`args`] — the command line, read before anything touches the data
//!   directory, and the one rule that resolves that directory.
//! - [`tui`] — terminal lifecycle: raw mode, alternate screen, and the
//!   optional enhancements this terminal admits to supporting.
//! - [`input`] — key and mouse events mapped to [`action::Action`]s against
//!   the current chrome, so no view sees a raw terminal event.
//! - [`app`] — the loop: one `select!` over the action bus and the render
//!   tick, a synchronous reducer, and the pending terminal/core work it parks
//!   for the loop to flush.
//! - [`chrome`] — the always-on frame: tab bar, status bar, help overlay,
//!   action flash.
//! - [`view`] / [`views`] — which tab is up, and the six that draw into it.
//! - [`theme`] — the semantic palette every widget reads roles off.
//! - [`row_selection`] — the one mark every table puts on its selected row.
//! - `form` — the one field-list editor the add-server modal, the search
//!   options and the Settings tab all run on; validation stays with the view.
//! - `wrap` — width-budgeted wrapping, so a line that does not fit is folded
//!   rather than cut.

#![warn(missing_docs)]

pub mod action;
pub mod app;
pub mod args;
pub mod attach;
pub mod bridge;
pub mod chrome;
pub mod client;
pub mod config;
pub mod connect;
pub(crate) mod form;
pub mod input;
pub mod kad;
pub mod player;
pub mod rates;
pub mod row_selection;
pub mod state;
pub mod table_sort;
pub mod theme;
pub mod tui;
pub mod view;
pub mod views;
pub mod words;
pub(crate) mod wrap;

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
pub(crate) mod golden;
