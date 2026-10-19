//! A slot holder's block request, judged whole before anything is read
//! (ADR-0031): one range past the file's end or longer than three blocks ends
//! the slot with nothing of the request read, and the next waiter takes it; a
//! range of exactly three blocks is read.

use super::*;
use crate::BlockAskFault;

const GIB: u64 = 1 << 30;
const THREE_BLOCKS: u64 = 3 * EMBLOCKSIZE;

fn parts(file_hash: FileHash, ranges: [(u64, u64); 3]) -> ServeInput {
    ServeInput::Server(ServerEvent::PartsRequested {
        file_hash,
        ranges: PartRanges::new(ranges).unwrap(),
    })
}

/// A one-slot state sharing `file_hash` (`file_size` bytes): the slot is the
/// holder's, and a waiter queues behind it.
fn held(file_hash: FileHash, file_size: u64) -> (ServeState, PeerEndpoint, PeerEndpoint, Instant) {
    let mut state = serving_state(1, vec![entry(file_hash, file_size, "big.bin")]);
    let t = Instant::now();
    let (holder, waiter) = (peer(1), peer(2));
    identify(&mut state, holder, user(0x01), t);
    identify(&mut state, waiter, user(0x02), t);
    let _ = slot_request(&mut state, holder, file_hash, t);
    let _ = slot_request(&mut state, waiter, file_hash, t);
    assert!(state.queue.is_granted(holder) && !state.queue.is_granted(waiter));
    (state, holder, waiter, t)
}

/// `decisions` refuse `holder`'s ask of `file_hash` for `fault` and hand the
/// slot to `waiter`, reading nothing.
fn assert_refused(
    decisions: &[ServeDecision],
    holder: PeerEndpoint,
    waiter: PeerEndpoint,
    file_hash: FileHash,
    fault: BlockAskFault,
) {
    assert!(
        matches!(
            decisions,
            [
                ServeDecision::Emit(ServeEvent::BlockAskRefused {
                    peer: refused,
                    file_hash: asked,
                    fault: found,
                }),
                ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: released }),
                ServeDecision::Send {
                    peer: granted,
                    command: ServerCommand::GrantSlot { .. },
                },
                ServeDecision::Emit(ServeEvent::UploadSlotGranted { .. }),
            ] if *refused == holder
                && *asked == file_hash
                && *found == fault
                && *released == holder
                && *granted == waiter
        ),
        "the slot ends for {fault:?} with nothing read, and the waiter takes it: {decisions:?}"
    );
}

#[test]
fn a_four_gib_range_ends_the_slot_and_no_read_is_decided() {
    let file = hash(0x31);
    let (mut state, holder, waiter, t) = held(file, 5 * GIB);

    let decisions = state.on_conn_event(
        t,
        holder,
        parts(file, [(0, 4 * GIB), (0, 0), (0, 0)]),
        &no_modifiers(),
    );
    assert_refused(&decisions, holder, waiter, file, BlockAskFault::TooLong);

    assert_eq!(
        state.on_conn_event(
            t,
            holder,
            parts(file, [(0, 100), (0, 0), (0, 0)]),
            &no_modifiers()
        ),
        Vec::new(),
        "the peer left the queue with its slot: its next ask is read nothing"
    );
}

#[test]
fn a_range_of_exactly_three_blocks_is_read_and_one_byte_more_ends_the_slot() {
    let file = hash(0x32);
    let (mut state, holder, waiter, t) = held(file, 5 * GIB);

    let decisions = state.on_conn_event(
        t,
        holder,
        parts(file, [(GIB, GIB + THREE_BLOCKS), (0, 0), (0, 0)]),
        &no_modifiers(),
    );
    assert!(
        matches!(
            decisions.as_slice(),
            [ServeDecision::ReadRange { offset, len, .. }] if *offset == GIB && *len == THREE_BLOCKS
        ),
        "three blocks are read: {decisions:?}"
    );

    let start = 2 * GIB;
    let decisions = state.on_conn_event(
        t,
        holder,
        parts(file, [(0, 100), (start, start + THREE_BLOCKS + 1), (0, 0)]),
        &no_modifiers(),
    );
    assert_refused(&decisions, holder, waiter, file, BlockAskFault::TooLong);
}

#[test]
fn a_range_past_the_files_end_ends_the_slot_and_nothing_of_the_request_is_read() {
    let file = hash(0x33);
    let (mut state, holder, waiter, t) = held(file, 1000);

    let decisions = state.on_conn_event(
        t,
        holder,
        parts(file, [(0, 100), (900, 1001), (0, 0)]),
        &no_modifiers(),
    );
    assert_refused(&decisions, holder, waiter, file, BlockAskFault::PastEnd);
}
