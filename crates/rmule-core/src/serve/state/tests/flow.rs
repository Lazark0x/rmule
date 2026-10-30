//! A slot holder's Serve Flow (ADR-0031): one read at a time in the order
//! asked, the Send-Ahead between the disk and the socket, and a slot's end
//! ending all of it.

use rmule_peer::PartRanges;

use super::*;

const FILE_SIZE: u64 = 100 * 512;

fn block(file_hash: FileHash, index: u64) -> BlockRead {
    BlockRead {
        file_hash,
        start: index * 512,
        end: (index + 1) * 512,
    }
}

/// `file`'s flow with a slot granted to a peer asking blocks `from`, three at a
/// time, as often as `requests` says.
fn asked(
    state: &mut ServeState,
    p: PeerEndpoint,
    file: FileHash,
    from: u64,
    requests: u64,
    t: Instant,
) -> Vec<ServeDecision> {
    let mut decisions = Vec::new();
    for request in 0..requests {
        let at = from + request * 3;
        let ranges = PartRanges::new([0, 1, 2].map(|i| ((at + i) * 512, (at + i + 1) * 512)));
        let ask = ServeInput::Server(ServerEvent::PartsRequested {
            file_hash: file,
            ranges,
        });
        decisions.extend(state.on_conn_event(t, p, ask, &no_modifiers()));
    }
    decisions
}

fn reads(decisions: &[ServeDecision]) -> Vec<u64> {
    decisions
        .iter()
        .filter_map(|decision| match decision {
            ServeDecision::ReadRange { block, .. } => Some(block.start / 512),
            _ => None,
        })
        .collect()
}

fn holder(t: Instant) -> (ServeState, PeerEndpoint, FileHash) {
    let file = hash(0x61);
    let mut state = serving_state(1, vec![entry(file, FILE_SIZE, "served.bin")]);
    let p = peer(1);
    identify(&mut state, p, user(0x0A), t);
    let _ = slot_request(&mut state, p, file, t);
    (state, p, file)
}

/// Land each block's read in turn, as the reader would.
fn land(state: &mut ServeState, p: PeerEndpoint, file: FileHash, index: u64) -> Vec<ServeDecision> {
    state.on_read_result(p, 1, block(file, index), vec![0; 512])
}

#[test]
fn a_flow_reads_one_block_at_a_time_in_the_order_asked() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);

    assert_eq!(reads(&asked(&mut state, p, file, 0, 2, t)), [0]);

    for next in 1..6 {
        assert_eq!(reads(&land(&mut state, p, file, next - 1)), [next]);
    }
}

#[test]
fn the_send_ahead_holds_the_next_read_until_a_block_has_left() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let _ = asked(&mut state, p, file, 0, 4, t);

    for index in 0..9 {
        assert_eq!(reads(&land(&mut state, p, file, index)), [index + 1]);
    }
    assert_eq!(
        reads(&land(&mut state, p, file, 9)),
        [] as [u64; 0],
        "ten blocks are ahead of the socket",
    );

    let left = ServeInput::Server(ServerEvent::BlockLeft {
        file_hash: file,
        start: 0,
        end: 512,
    });
    let decisions = state.on_conn_event(t, p, left, &no_modifiers());

    assert_eq!(
        decisions,
        vec![
            ServeDecision::RecordCredit {
                user_hash: user(0x0A),
                bytes: 512,
            },
            ServeDecision::CountSent {
                peer: p,
                file_hash: file,
                bytes: 512,
            },
            decisions[2].clone(),
        ],
    );
    assert_eq!(reads(&decisions), [10]);
}

#[test]
fn an_ask_past_the_flows_room_is_dropped_and_not_recorded_as_served() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);

    // Eleven requests of three: one read out, thirty-two waiting.
    let _ = asked(&mut state, p, file, 0, 11, t);
    let past = asked(&mut state, p, file, 33, 1, t);
    assert_eq!(past, Vec::new(), "no room, so nothing");

    // The flow drained, the same ask is new to it.
    for index in 0..33 {
        let _ = land(&mut state, p, file, index);
        let left = ServeInput::Server(ServerEvent::BlockLeft {
            file_hash: file,
            start: index * 512,
            end: (index + 1) * 512,
        });
        let _ = state.on_conn_event(t, p, left, &no_modifiers());
    }
    assert_eq!(reads(&asked(&mut state, p, file, 33, 1, t)), [33]);
}

#[test]
fn a_slots_end_ends_its_flow_and_a_late_read_is_nobodys_though_the_peer_holds_a_new_slot() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let _ = asked(&mut state, p, file, 0, 1, t);

    let cancel = ServeInput::Server(ServerEvent::TransferCancelled { file_hash: file });
    let _ = state.on_conn_event(t, p, cancel, &no_modifiers());
    assert_eq!(
        state.end_slotless_flows(),
        [ServeDecision::EndFlow { peer: p, flow: 1 }]
    );

    let _ = slot_request(&mut state, p, file, t);
    assert_eq!(reads(&asked(&mut state, p, file, 3, 1, t)), [3]);

    assert_eq!(
        state.on_read_result(p, 1, block(file, 0), vec![0; 512]),
        Vec::new(),
        "the old flow's read lands on nothing",
    );
    assert!(matches!(
        state
            .on_read_result(p, 2, block(file, 3), vec![0; 512])
            .as_slice(),
        [
            ServeDecision::SendBlock { flow: 2, .. },
            ServeDecision::ReadRange { .. },
        ]
    ));
}

#[test]
fn a_slot_silent_past_the_bound_with_nothing_to_send_loses_its_slot_and_link() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let bound = Duration::from_secs(40);
    let sweep = |state: &mut ServeState, at| state.on_slot_sweep(at, &no_modifiers());

    assert_eq!(sweep(&mut state, t), Vec::new(), "its clock starts");
    assert_eq!(sweep(&mut state, t + bound), Vec::new());

    // A word from it restarts the clock.
    let later = t + bound;
    let status = ServeInput::Server(ServerEvent::FileIdSet { file_hash: file });
    let _ = state.on_conn_event(later, p, status, &no_modifiers());
    assert_eq!(sweep(&mut state, later + bound), Vec::new());

    let past = later + bound + Duration::from_secs(1);
    assert_eq!(
        sweep(&mut state, past),
        [
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: p }),
            ServeDecision::Disconnect { peer: p },
        ]
    );
    assert!(!state.queue.is_granted(p));
}

/// `bytes` of `file` leave `p`'s flow for the kernel at `at`, its flow drained.
fn all_left(state: &mut ServeState, p: PeerEndpoint, file: FileHash, bytes: u64, at: Instant) {
    let left = ServeInput::Server(ServerEvent::BlockLeft {
        file_hash: file,
        start: 0,
        end: bytes,
    });
    let _ = state.on_conn_event(at, p, left, &no_modifiers());
}

#[test]
fn a_slow_holder_reading_what_the_kernel_holds_keeps_its_slot() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let _ = state.on_slot_sweep(t, &no_modifiers());

    // The tail of a 16 kbit/s transfer: 120 KB in the kernel takes the holder
    // 60 s, and it says nothing until they are read.
    all_left(&mut state, p, file, 120_000, t);
    let next_ask = t + Duration::from_secs(60);
    assert_eq!(state.on_slot_sweep(next_ask, &no_modifiers()), Vec::new());
    assert!(state.queue.is_granted(p));
}

#[test]
fn a_holder_that_stopped_reading_goes_once_the_kernels_bytes_are_spent() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let _ = state.on_slot_sweep(t, &no_modifiers());

    all_left(&mut state, p, file, 10_240, t);
    let lent = Duration::from_secs(10);
    let bound = Duration::from_secs(40);
    assert_eq!(
        state.on_slot_sweep(t + lent + bound, &no_modifiers()),
        Vec::new()
    );
    let past = t + lent + bound + Duration::from_secs(1);
    assert!(
        state
            .on_slot_sweep(past, &no_modifiers())
            .contains(&ServeDecision::Disconnect { peer: p })
    );
}

#[test]
fn what_left_lends_a_dead_fast_holder_only_the_kernels_bound() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let _ = state.on_slot_sweep(t, &no_modifiers());

    // A gigabyte went through it; no kernel still holds that.
    for block in 0..100 {
        all_left(
            &mut state,
            p,
            file,
            10_000_000,
            t + Duration::from_millis(block),
        );
    }
    let past = t + Duration::from_secs(5 * 60 + 41);
    assert!(
        state
            .on_slot_sweep(past, &no_modifiers())
            .contains(&ServeDecision::Disconnect { peer: p })
    );
}

#[test]
fn a_read_or_a_block_on_rmules_side_is_not_the_peers_silence() {
    let t = Instant::now();
    let (mut state, p, file) = holder(t);
    let later = t + Duration::from_secs(600);

    let _ = asked(&mut state, p, file, 0, 1, t);
    assert_eq!(
        state.on_slot_sweep(later, &no_modifiers()),
        Vec::new(),
        "a read is out"
    );

    let _ = land(&mut state, p, file, 0);
    let _ = land(&mut state, p, file, 1);
    let _ = land(&mut state, p, file, 2);
    assert_eq!(
        state.on_slot_sweep(later, &no_modifiers()),
        Vec::new(),
        "blocks are ahead"
    );
}
