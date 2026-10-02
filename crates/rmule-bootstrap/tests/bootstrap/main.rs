//! The bootstrap crate's integration surface: one leg, and one binary, so it
//! sits under the same `tests/<crate>/main.rs` root as every other crate.
//! `cargo test -p rmule-bootstrap --test bootstrap cold_start_e2e::` runs it.

mod cold_start_e2e;
