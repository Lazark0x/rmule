//! The Kad node's integration surface: the wire codecs, the sans-I/O node that
//! drives them on an explicit clock, the deterministic mesh above it, and the
//! datagrams genuine aMule nodes actually sent us — one binary with a module
//! per leg. `cargo test -p rmule-kad --test kad node_hello::` runs one leg;
//! shared setup lives in [`fixture`], and anything a second crate needs is in
//! `rmule-testkit` (`kad_node`, `kad_mesh`, `kad_source`, `kad_keyword`).

mod fixture;

// The domain's own shapes: ids, distance, opcodes, envelopes.
mod domain_surface;
mod envelope;
mod kad_id_byte_order;
mod opcode;

// Message codecs: every Kad2 message on the wire, and the search tree a
// restrictive keyword request carries.
mod node_messages;
mod publish_messages;
mod search_tree_codec;
mod tag_lists;
mod truncation;

// The routing table: admission, eviction, census, the small-timer aging pass,
// and what a contact must do to become servable.
mod contact_admission;
mod merge_contacts;
mod reserved_contacts;
mod routing_caps;
mod routing_census;
mod routing_table;
mod small_timer;
mod verified_contacts;

// Joining: the cold dial loop, the hello exchange it seats contacts with, and
// the eD2k peer handoff that can seed it.
mod ed2k_kad_handoff;
mod join_dial;
mod nodes_dat;
mod nodes_dat_bootstrap;
mod nodes_dat_golden;

// The node answering: hellos, lookups, bootstraps, and the flood gate in front
// of all of it.
mod flood;
mod node_bootstrap;
mod node_hello;
mod node_lookup;

// Reachability: the firewall self-checks, the UDP helper protocol, and buddy
// recruitment for a node that fails them.
mod node_buddy;
mod node_callback_walk;
mod node_extern_port;
mod node_firewall;
mod node_udp_firewall;

// Verify keys (ADR-0064): the trailer that makes a receiver key valid, the
// `0x22` three-way it gates, verified-only serving, and the gates aMule
// applies before answering.
mod own_public_ip;
mod verify_keys_gates;
mod verify_keys_serving;
mod verify_keys_three_way;
mod verify_keys_trailer;

// Datagram crypt: the obfuscation layer every message above can ride.
mod kad_udp_crypt;

// Sources: publishing one, storing it, and walking the network to find it.
mod buddy_endpoint_gate;
mod buddy_source_row;
mod requester;
mod requester_mesh;
mod source_publisher;
mod source_result;
mod source_storer;

// Keywords: deriving them, indexing a publish, and serving a search.
mod keyword_derivation;
mod keyword_index;
mod keyword_node;
mod keyword_query;
mod keyword_serve;
mod keyword_walk_ownership;
mod keyword_wire;

// Notes: the comment/rating store that rides the same walk.
mod notes_node;

// The mesh: whole networks of nodes on a virtual clock.
mod mesh_sim;
mod source_mesh;

// Source-derived: what a family not on the bench would send, read from its
// source and labelled so.
mod buddy_hash_emule_spelling;

// Captured: datagrams a genuine aMule 2.3.3 (or kno's fork at its Fork Pin)
// actually sent, and the fixtures that record what could not be driven.
mod buddy_publish_capture;
mod buddy_recruit_capture;
mod callback_req_capture;
mod callback_req_findsource_capture;
mod captured_distance_ordering;
mod captured_keyword_answers;
mod captured_keyword_request;
mod captured_source_lookup_fixture;
mod captured_source_result;
mod direct_callback_publish_capture;
mod firewall_selfcheck_capture;
mod firewalled_capture;
mod ipv6_kad_tags_capture;
mod kad2_ping_capture;
mod kad_source_lookup_fixture_spike;
mod source_result_documented;
mod udp_firewall_capture;
mod verify_keys_capture;
mod verify_keys_emuleqt_capture;
