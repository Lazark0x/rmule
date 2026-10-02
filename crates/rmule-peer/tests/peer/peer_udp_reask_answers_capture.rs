//! Captured **reask error answers** (genuine stock aMule 2.3.3, hand-run
//! `rmule-tools ed2k peer reask-capture`, 2026-07-29): the `0x92
//! OP_FILENOTFOUND` a bare reask for an unshared hash drew, and the `0x93
//! OP_QUEUEFULL` an unknown sender's reask for a shared file drew under
//! `QueueSizePref=0`. Counterparty bytes per ADR-0045; provenance +
//! preconditions live in `meta.toml`.
//!
//! The load-bearing claim is **byte-parity of two independent producers**:
//! aMule's emissions equal rmule's own emitters exactly, and both classify
//! through rmule's consume-side opcode read. The empty body is part of the
//! claim — the codec assumes it on both sides, and these are the first
//! counterparty frames proving it.

use crate::fixture::load;
use rmule_peer::{ClientUdpOpcode, file_not_found_datagram, queue_full_datagram};

const FIXTURE_DIR: &str = "fixtures/peer_udp_reask/captured/amule-233-reask-answers-20260729/";

/// aMule's `0x92` answer is byte-identical to rmule's emitter and classifies
/// as `FileNotFound` on the consume side.
#[test]
fn amule_filenotfound_matches_rmule_wire_form() {
    let captured = load(FIXTURE_DIR, "filenotfound_0x92.bin");
    assert_eq!(
        captured,
        file_not_found_datagram(),
        "aMule's OP_FILENOTFOUND must equal rmule's own emission byte-for-byte"
    );
    // The whole-datagram equality above already pins the `0xC5` marker and the
    // empty body; only the consume-side classification is a separate claim.
    assert_eq!(
        ClientUdpOpcode::try_from_u8(captured[1]),
        Some(ClientUdpOpcode::FileNotFound)
    );
}

/// aMule's `0x93` answer is byte-identical to rmule's emitter and classifies
/// as `QueueFull` on the consume side.
#[test]
fn amule_queuefull_matches_rmule_wire_form() {
    let captured = load(FIXTURE_DIR, "queuefull_0x93.bin");
    assert_eq!(
        captured,
        queue_full_datagram(),
        "aMule's OP_QUEUEFULL must equal rmule's own emission byte-for-byte"
    );
    // As above: the vector equality carries the marker and the empty body.
    assert_eq!(
        ClientUdpOpcode::try_from_u8(captured[1]),
        Some(ClientUdpOpcode::QueueFull)
    );
}
