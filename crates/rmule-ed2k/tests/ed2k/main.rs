//! The eD2k client-to-server protocol's integration surface: the packets in
//! both directions, the sans-I/O session that sequences them, and the frames
//! genuine servers actually sent us — one binary with a module per leg.
//! `cargo test -p rmule-ed2k --test ed2k session_login::` runs one leg; shared
//! setup lives in [`fixture`].

mod fixture;

// What we send: the client packets, fixture-by-fixture.
mod client_packet_umbrella;
mod get_server_list_fixtures;
mod login_fixtures;
mod login_from_identity;
mod obfu_source_lookup;
mod offer_files;
mod search_packets;
mod source_lookup_packets;
mod truncation;

// What we read: the server packets, and the typed facts they project to.
mod compressed_server_packet;
mod event_projection;
mod login_response_fixtures;
mod peer_callback;
mod sentinel_sources;
mod server_ident_fixtures;
mod server_ident_ipv6;
mod server_list_fixtures;
mod server_message_fixtures;
mod server_met_golden;
mod server_packet_umbrella;
mod server_status_fixtures;
mod server_tcp_flags;

// The session: what a command is allowed to do at each stage of the login
// handshake, and what arriving bytes do to it.
mod login_deadline;
mod session_compressed_frames;
mod session_holepunch;
mod session_login;
mod session_offer_files;
mod session_search;
mod session_shutdown;
mod session_source_lookup;
mod session_welcome;

// Captured: frames a genuine Lugdunum, eserver or eNode actually sent, decoded
// and re-encoded byte-exact.
mod captured_ed2ksrv_callback;
mod captured_ed2ksrv_crypt_ping;
mod captured_ed2ksrv_glob_search;
mod captured_ed2ksrv_holepunch;
mod captured_enode_crypt;
mod captured_fixture_round_trip;
mod captured_search_wire;
mod captured_server_ident;
mod captured_server_list;
mod captured_server_udp;
mod replay_welcome_burst;
