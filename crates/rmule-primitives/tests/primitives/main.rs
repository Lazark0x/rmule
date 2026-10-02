//! The shared vocabulary's integration surface: the wire codecs, identities,
//! and value types every other crate builds on, one binary with a module per
//! leg. `cargo test -p rmule-primitives --test primitives tag_codec::` runs
//! one leg; the TOML-case reader lives in [`fixture`].

mod fixture;

// Wire codecs: the tag, packet, endpoint and text encodings every protocol
// crate reads and writes.
mod endpoint_codec;
mod opcode_macro;
mod packet_fixtures;
mod tag_codec;
mod text;

// File identity: the eD2k hash tree and the parts it covers.
mod hash_fixtures;
mod part_count;
mod size_ceiling;

// Links: the `ed2k://` surface a user pastes in.
mod link_fixtures;

// Search: queries, results, and how two reports of one file merge.
mod search;

// Who a peer is: client ids, the sources they project to, the server they
// came from, and the SUI key that proves them.
mod server_identity;
mod source;
mod sui_captured_key;

// Session spine: the framing and close protocol every session shares.
mod session_spine;
