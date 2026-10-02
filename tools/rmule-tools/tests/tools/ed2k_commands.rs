//! `rmule-tools ed2k` decoding commands over the CLI, split by what they read:
//! [`link`] takes a string or a local file, [`inspect`] takes one captured
//! frame, [`welcome`] takes a whole recorded stream. The fixture paths below
//! are the eD2k crate's own capture tree, shared by the last two.

use std::path::Path;

mod inspect;
mod link;
mod welcome;

fn login_fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/rmule-ed2k/tests/fixtures/login")
        .join(name)
}

fn server_fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/rmule-ed2k/tests/fixtures/server")
        .join(name)
}

fn client_fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/rmule-ed2k/tests/fixtures/client")
        .join(name)
}
