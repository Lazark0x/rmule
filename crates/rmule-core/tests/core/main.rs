//! The core's integration surface: a `Core` driven by commands over real
//! sockets against the fakes in `rmule-testkit`, one binary with a module per
//! leg. `cargo test -p rmule-core --test core download_resume::` runs one leg;
//! shared setup lives in [`fixture`], and anything a second crate needs
//! belongs in `rmule-testkit` instead.

mod fixture;

// Store: the one durable file every seam reads through.
mod durable_store;

// Session join: reaching a server, what the login earns, and what a restart
// re-reads from disk.
mod activity_lifecycle;
mod address_learning_wiring;
mod client_udp_bind_failure;
mod clients_met_restart;
mod connect_on_operators_word;
mod connect_search_race;
mod core_service;
mod core_settings;
mod fake_ed2k_server_probe;
mod fake_orchestration;
mod ip_filter_ingest;
mod join_cold_start_fixture;
mod join_sequence_e2e;
mod listen_before_login;
mod port_mapping_wiring;
mod runtime_adapters;
mod server_list_commands;
mod server_login_steps;
mod server_reconnect;
mod server_session_switch;
mod server_status_sweep;

// Search: the standing session's queries and the results they fold.
mod core_search;
mod independent_legs;
mod related_search;
mod search_attribution;
mod search_more_results;
mod standing_session_search;

// Download: part assignment, verification, and the peer pool feeding them.
mod content_files;
mod download_attach;
mod download_clear;
mod download_connection_wait;
mod download_cross_peer_assembly;
mod download_damaged_parts;
mod download_hello_port;
mod download_loopback;
mod download_multipacket_negotiation;
mod download_part_assignment;
mod download_part_file_held;
mod download_part_verification;
mod download_pause_and_cancel;
mod download_peer_failover;
mod download_placement;
mod download_resume;
mod download_scheduler;
mod download_second_link;
mod download_slot_negotiation;
mod download_source_pool;
mod download_source_seeds;
// Device and inode are how a live part file is known to be the same file.
#[cfg(unix)]
mod live_part_file_guard;

// Serve: the upload half — slots, the shared registry, and credit.
mod credit_accounting;
mod credit_store;
mod download_directory_scan;
mod partial_share;
mod registry_against_disk;
mod serve_lifecycle;
mod serve_loopback;
mod serve_registry;
mod serve_start_contract;
mod shared_directories;
mod shared_file_registry;
mod sui_loopback;
mod upload_slot_queue;

// Callback: reaching a Low-ID source through the server, directly and globally.
mod callback_loopback;
mod direct_callback_route;
mod global_callback_loopback;

// Kad: source discovery without a server in the loop.
mod kad_disable;
mod kad_publish_connect_options;
mod kad_pump_ended;
mod kad_pump_panic;
mod kad_serverless_e2e;
mod kad_source_discovery;
mod kad_udp_crypt;
mod kad_udp_firewall_helper;

// NAT traversal: a download reaching a firewalled source through its buddy.
mod natt_buddy_download;
mod natt_callback_walk;

// Persistence: the repository contract and its durable implementation.
mod durable_types;
mod repository_contract;
mod store_app_config;
mod store_repository;

// Diagnostics: what a front-end reads while a session runs.
mod diagnostics_snapshot;
