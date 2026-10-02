//! eD2k protocol-area commands, one module per command family: link decoding,
//! local file hashing, the offline packet inspectors, the live server-welcome
//! capture, the capability probe, the search-wire probe, the sentinel-safe-reader
//! readiness probe, the sentinel-bearing source-list stimulus, and the server's
//! UDP face with the capture command that records it. The
//! one-line event summary printed during a capture is
//! [`Ed2kEvent`](rmule_ed2k::Ed2kEvent)'s co-located `Display`; the verbose
//! field-level inspectors are genuinely tool-specific and live here.

mod file_hash;
mod inspect;
mod link;
mod probe;
mod search_wire;
mod sentinel_probe;
mod sentinel_stimulus;
mod server_udp;
mod udp_capture;
mod welcome;

pub(crate) use file_hash::{hash_file, part_hashes};
pub(crate) use inspect::{
    inspect_client_packet, inspect_login, inspect_packet, inspect_server_packet,
};
pub(crate) use link::{canonical_link, parse_link};
pub(crate) use probe::{ServerProbeArgs, server_probe};
pub(crate) use search_wire::{SearchWireArgs, search_wire};
pub(crate) use sentinel_probe::sentinel_probe;
pub(crate) use sentinel_stimulus::{SentinelStimulusArgs, sentinel_stimulus};
pub(crate) use udp_capture::server_udp_capture;
pub(crate) use welcome::{
    LiveCaptureArgs, SliceCaptureArgs, slice_capture, welcome_live, welcome_slice,
};
