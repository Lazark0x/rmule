//! The TUI's integration surface: three legs — the app's construction path
//! (`rmule::attach`) over a scratch data directory, the real `Core` behind
//! the bridge, and the built `rmule` binary's front door — and one binary, so
//! it sits under the same `tests/<crate>/main.rs` root as every other crate.
//! `cargo test -p rmule --test tui live_core::` runs the second.
//! Everything else the TUI proves is a unit test beside the view it renders,
//! with the frame goldens in `tests/goldens/`.

mod attach;
mod front_door;
mod live_core;
