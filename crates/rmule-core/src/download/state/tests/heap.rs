//! What a download holds of its in-flight parts on the heap, 500 transfers
//! churning over the real brain, against the Write Cache's cap (ADR-0117 §4).
//! Sources hold half the parts at random and leave after a random session, as
//! the review's model had it. By hand, in release: `cargo test --release -p
//! rmule-core heap_bench -- --ignored --nocapture`.

use std::collections::VecDeque;

use rmule_peer::{PartBitmap, PartIndex};

use super::*;
use crate::download::write_cache::WRITE_CACHE_BYTES;
use crate::planning::BlockPlan;
use rmule_primitives::{ED2K_PART_SIZE, EMBLOCKSIZE};

/// The file: forty times the 4 GiB file the rig's other legs use, so 500
/// transfers run on it without finishing it.
const PARTS: u32 = 4_400;
const LIVE: usize = 500;
const BLOCKS: usize = 60_000;
const MIB: usize = 1024 * 1024;

/// One xorshift step: a seeded walk, so a run repeats.
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn source(index: usize) -> PeerEndpoint {
    let [_, a, b, c] = u32::try_from(index + 1).unwrap().to_be_bytes();
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, a, b, c), 4662))
}

/// A source's Advertised Parts: each part, one chance in two.
fn half_of_the_parts(seed: &mut u64) -> PartBitmap {
    let mut bytes = vec![0_u8; (PARTS as usize).div_ceil(8)];
    for byte in &mut bytes {
        *byte = (next(seed) & 0xFF) as u8;
    }
    PartBitmap::decode(PARTS, &bytes).expect("as long as the file's parts ask")
}

/// One transfer: the blocks it was handed, and how many it delivers yet.
struct Transfer {
    peer: PeerEndpoint,
    blocks: VecDeque<BlockPlan>,
    left: u64,
}

struct Peak {
    parts: usize,
    /// What the records hold.
    records: usize,
    /// What the 180 KiB cells of those parts held before they left the heap.
    cells: usize,
}

fn walk(session: u64) -> Peak {
    let pool: Vec<PeerEndpoint> = (0..LIVE * 40).map(source).collect();
    let size = u64::from(PARTS) * ED2K_PART_SIZE;
    let mut state = pooled_state(file_hash_only_content(size), &pool, QUIET_POSTURE, LIVE);
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut live: Vec<Transfer> = Vec::new();
    let mut queue: VecDeque<Decision> = state.start(t0()).into();
    let mut peak = Peak {
        parts: 0,
        records: 0,
        cells: 0,
    };
    for block in 0..BLOCKS {
        // What the runner would enact.
        while let Some(decision) = queue.pop_front() {
            match decision {
                Decision::Spawn { peer, .. } => {
                    let left = 1 + next(&mut seed) % (2 * session);
                    live.push(Transfer {
                        peer,
                        blocks: VecDeque::new(),
                        left,
                    });
                    let parts = half_of_the_parts(&mut seed);
                    let events = [
                        PeerWorkerEvent::Connected,
                        PeerWorkerEvent::PartsAdvertised {
                            parts: Some(parts),
                            complete: false,
                        },
                        PeerWorkerEvent::SlotGranted,
                    ];
                    for event in events {
                        queue.extend(state.on_worker_event(t0(), peer, event));
                    }
                }
                Decision::Send {
                    peer,
                    command: PeerWorkerCommand::RequestBlocks { blocks, .. },
                } => {
                    if let Some(transfer) = live.iter_mut().find(|t| t.peer == peer) {
                        transfer.blocks.extend(blocks);
                    }
                }
                Decision::PersistPart {
                    part_index, peer, ..
                } => queue.extend(state.on_persist_result(t0(), part_index, peer, Ok(()), None)),
                _ => {}
            }
        }
        if block % 256 == 0 {
            let (mut records, mut cells) = (0, 0);
            for assembled in state.assembly.values() {
                records += assembled.heap_bytes();
                let touched = assembled
                    .arrived()
                    .ranges()
                    .map(|(start, end)| (end.div_ceil(EMBLOCKSIZE) - start / EMBLOCKSIZE) as usize)
                    .sum::<usize>();
                cells += touched * EMBLOCKSIZE as usize;
            }
            peak.parts = peak.parts.max(state.assembly.len());
            peak.records = peak.records.max(records);
            peak.cells = peak.cells.max(cells);
        }
        // One transfer delivers one block, round the fleet.
        if live.is_empty() {
            break;
        }
        let at = block % live.len();
        let peer = live[at].peer;
        match live[at].blocks.pop_front() {
            Some(plan) => {
                live[at].left -= 1;
                let event = PeerWorkerEvent::BlockReceived {
                    part_index: plan.part_index,
                    offset: plan.start,
                    bytes: vec![0; (plan.end - plan.start) as usize],
                };
                queue.extend(state.on_worker_event(t0(), peer, event));
                if live[at].left == 0 {
                    live.swap_remove(at);
                    let ended = PeerWorkerEvent::Disconnected;
                    queue.extend(state.on_worker_event(t0(), peer, ended));
                }
            }
            None => {
                let handout = state.handouts.get(&peer).copied().unwrap_or(0);
                let event = PeerWorkerEvent::BlocksWanted {
                    room: 3,
                    drained: true,
                    handout,
                };
                queue.extend(state.on_worker_event(t0(), peer, event));
            }
        }
    }
    peak
}

#[test]
#[ignore = "by hand, in release: prints the heap at 500 live transfers"]
fn heap_bench() {
    for session in [52, 12] {
        let peak = walk(session);
        println!(
            "500 transfers, mean session {session} blocks: parts holding bytes peak {}, \
             records {} KiB, cells that left the heap {} MiB, cap {} MiB",
            peak.parts,
            peak.records / 1024,
            peak.cells / MIB,
            WRITE_CACHE_BYTES / MIB,
        );
    }
}

#[test]
fn a_part_in_flight_costs_the_heap_a_record() {
    let plan = crate::planning::part_plan(u64::from(PARTS) * ED2K_PART_SIZE, PartIndex::new(0));
    let mut assembled = crate::assembly::PartAssembly::new(plan);
    for cell in 0..plan.cells() {
        let peer = source(cell % 6);
        let at = plan.cell_start(cell);
        assembled.merge(peer, None, at, EMBLOCKSIZE - 1);
    }
    assert!(assembled.heap_bytes() < 16 * 1024, "a record, not a part");
}
