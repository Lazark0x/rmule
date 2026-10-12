//! The tools binary's integration surface: `rmule-tools` run as a real process
//! (and, for the replay legs, its libraries dialing the testkit fakes), one
//! binary with a module per leg. `cargo test -p rmule-tools --test tools
//! search_cli::` runs one leg; what a second leg shares lives in [`fixture`].
//!
//! The live legs — [`peer_transfer_live`], [`welcome_live_cli`] and the
//! capture legs in [`peer_commands`] — stay `#[ignore]`d behind their env
//! vars, so `cargo test` here never touches the network.

mod fixture;

// Offline decoding: links, hashes, and captured frames read back as text.
mod ed2k_commands;
mod peer_commands;

// Server commands: the welcome handshake and search.
mod search_cli;
mod welcome_capability_tags;
mod welcome_live_cli;

// Download commands: the repository the CLI reads and the transfers it runs.
mod download_cli;
mod download_hermetic;

// Peer transfer: the probe → slot → parts flow, over the CLI and below it.
mod peer_transfer_cli;
mod peer_transfer_live;
mod peer_transfer_replay;
mod peer_transfer_sui_cli;

// Callback: reaching a Low-ID peer through its server.
mod callback_replay;

// NAT-T drivers: a firewalled body's posture before it recruits.
mod natt_buddy_cli;
