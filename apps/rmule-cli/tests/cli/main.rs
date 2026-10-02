//! The CLI's integration surface: `rmule-cli` run as a real process against a
//! throwaway data directory, one binary with a module per leg.
//! `cargo test -p rmule-cli --test cli persistence::` runs one leg; the
//! invocation every leg shares lives in [`fixture`].

mod fixture;

mod add;
mod config;
mod persistence;
