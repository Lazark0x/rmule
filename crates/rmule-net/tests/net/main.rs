//! The net crate's integration surface: real sockets and duplex pipes carrying
//! the sans-I/O sessions, one binary with a module per leg.
//! `cargo test -p rmule-net --test net peer_listener::` runs one leg; shared
//! setup lives in [`fixture`], and anything a second crate needs belongs in
//! `rmule-testkit` instead.
//!
//! Two legs reach the live network and are env-gated: [`live_welcome`] (an
//! eD2k server) and [`live_join`] (the public Kad network).

mod fixture;

// The driver: the loop that carries a sans-I/O session over a socket, and the
// close contract it has to honour whichever side ends the link.
mod driver_duplex;
mod driver_write_error;
mod harness;

// Capture: what the driver writes down as it runs, and how much of it.
mod capture;
mod capture_modes;
mod capture_tap;
mod capture_writer;

// The server link: connecting, timing out, obfuscating, and the datagram
// socket beside it.
mod connection_duplex;
mod connection_timeouts;
mod live_welcome;
mod obfuscated_connect;
mod server_udp;

// Peer links: dialing out, accepting in, and the exchanges that ride them.
mod buddy_relay_loopback;
mod compressed_frame_loopback;
mod connection_loopback;
mod dial_back_loopback;
mod multipacket_reverse_harness;
mod obfuscated_accept;
mod obfuscated_dial;
mod peer_listener;

// NAT-T: two nodes wired back to back over a fake transport — the Tunnel, the
// 0xB2 demux, and both engines with no socket in sight.
mod natt;

// Port prediction: a Fan of real loopback sockets, the route a hit
// installs, and the inlet it joins.
mod prediction_fan;

// Kad: nodes over real UDP, on loopback and on the public network.
mod live_join;
mod loopback;
