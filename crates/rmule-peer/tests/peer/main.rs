//! The peer crate's integration surface: the sans-I/O peer session and the
//! codecs beneath it, driven by bytes and asserted on outputs — one binary
//! with a module per leg. `cargo test -p rmule-peer --test peer
//! source_exchange_session::` runs one leg; what more than one leg shares
//! lives in [`fixture`], and anything a second crate needs belongs in
//! `rmule-testkit` instead.
//!
//! The capture legs at the end assert against aMule-authored bytes under
//! `tests/fixtures/` — those are evidence and never edited to suit a test.

mod fixture;

// Codecs: one message family per leg, below any session.
mod file_request;
mod hash_set;
mod hello_read_surface;
mod human_layer;
mod ipv6_dialect_capture;
mod multipacket;
mod part_bitmap;
mod parts;
mod peer_event_projection;
mod peer_handshake_context;
mod peer_hello;
mod peer_identity;
mod peer_opcode;
mod peer_packet_umbrella;
mod slot;
mod source_exchange;

// The session's own state: reaching `Identified` from either side, and what it
// does with frames that arrive out of turn.
mod emule_info_exchange;
mod ext_protocol_gates;
mod peer_inbound_handshake;
mod peer_secure_ident;
mod peer_session;
mod peer_session_probe;
mod peer_session_standby;
mod peer_session_unsolicited;
mod session_compressed_frames;

// Downloading through a session: parts, slots, and the exchanges beside them.
mod buddy_session;
mod human_layer_session;
mod multipacket_emit;
mod multipacket_session;
mod peer_session_aich;
mod peer_session_parts;
mod peer_session_slot;
mod source_exchange_session;

// Serving through a session: the upload half of the same state machine.
mod peer_serve_session;
mod source_exchange_serve;

// Captures: aMule-authored bytes decoded, and rmule's answers re-encoded
// against them.
mod amule_capture;
mod amule_source_ask_capture;
mod buddy_callback_capture;
mod client_software_capture;
mod direct_callback_capture;
mod multipacket_forward_capture;
mod natt_transport_capture;
mod obfuscation_capture;
mod packed_source_exchange_capture;
mod peer_udp_reask_answers_capture;
mod peer_udp_reask_capture;
mod peer_udp_reask_crypt_capture;
mod peer_udp_reask_crypt_mirror_capture;
mod reverse_serve_capture;
