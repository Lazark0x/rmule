//! Reading a part file (ADR-0113 §"Reading a part file"): a Partial Share's
//! block request reads inside its Verified Range only — one sub-range outside
//! it ends the slot with nothing read or sent — every read is checked against
//! the download's Part File Identity, and a read that finds the file changed
//! or gone stops serving it without the Registry Check.

use super::served::{download, state_of};
use super::*;
use crate::file_key::FileKey;
use crate::served_downloads::{PartFileIdentity, PartialEnd, ReadCheck};

const PART: u64 = ED2K_PART_SIZE;

/// One of the brain's answers to a checked read that sent nothing.
type Refusal = fn(
    &mut ServeState,
    Instant,
    PeerEndpoint,
    ReadPurpose,
    &HashMap<PeerEndpoint, f64>,
) -> Vec<ServeDecision>;

fn identity() -> PartFileIdentity {
    PartFileIdentity {
        key: FileKey { volume: 1, file: 7 },
        at_rest: None,
    }
}

/// A Partial Share of `file` holding `verified`, read through [`identity`].
fn partial(file: FileHash, verified: &[u32]) -> ServeState {
    let mut look = download(true, verified, true);
    look.served.identity = Some(identity());
    state_of(Vec::new(), vec![(file, look)])
}

fn parts(ranges: [(u64, u64); 3], file_hash: FileHash) -> ServeInput {
    ServeInput::Server(ServerEvent::PartsRequested {
        file_hash,
        ranges: PartRanges::new(ranges).unwrap(),
    })
}

fn block(file_hash: FileHash, start: u64, end: u64) -> ReadPurpose {
    ReadPurpose::Block {
        file_hash,
        start,
        end,
    }
}

fn read(p: PeerEndpoint, file_hash: FileHash, start: u64, end: u64) -> ServeDecision {
    ServeDecision::ReadRange {
        peer: p,
        path: "/temp/download.bin.part".into(),
        offset: start,
        len: end - start,
        purpose: block(file_hash, start, end),
        check: Some(ReadCheck {
            identity: Some(identity()),
            other: "/downloads/download.bin".into(),
        }),
    }
}

#[test]
fn an_in_range_request_reads_its_part_file_and_a_re_request_checks_only_the_unserved_rest() {
    let file = hash(0x02);
    let mut state = partial(file, &[0, 1]);
    let t = Instant::now();
    let p = peer(4000);
    identify(&mut state, p, user(0x0A), t);
    let _ = slot_request(&mut state, p, file, t);

    assert_eq!(
        state.on_conn_event(
            t,
            p,
            parts([(0, 100), (PART, PART + 100), (0, 0)], file),
            &no_modifiers()
        ),
        [read(p, file, 0, 100), read(p, file, PART, PART + 100)]
    );
    let bytes = vec![0xA5; 100];
    assert_eq!(
        state
            .on_read_result(p, block(file, 0, 100), bytes.clone())
            .last(),
        Some(&send(
            p,
            ServerCommand::SendBlock {
                file_hash: file,
                start: 0,
                end: 100,
                bytes,
            }
        ))
    );

    // The run dropped part 0 as damaged: what was served of it is not asked
    // again, so only the rest is checked, and it lies inside the range.
    let mut look = download(true, &[1], true);
    look.served.identity = Some(identity());
    state.on_served([(file, look)].into());
    assert_eq!(
        state.on_conn_event(
            t,
            p,
            parts([(0, 100), (PART + 100, PART + 200), (0, 0)], file),
            &no_modifiers()
        ),
        [read(p, file, PART + 100, PART + 200)]
    );
}

#[test]
fn a_request_straddling_the_verified_range_ends_the_slot_and_reads_nothing() {
    let file = hash(0x02);
    let mut state = partial(file, &[0]);
    let t = Instant::now();
    let (holder, waiter) = (peer(4000), peer(4001));
    identify(&mut state, holder, user(0x0A), t);
    identify(&mut state, waiter, user(0x0B), t);
    let _ = slot_request(&mut state, holder, file, t);
    let _ = slot_request(&mut state, waiter, file, t);

    let decisions = state.on_conn_event(
        t,
        holder,
        parts([(0, 100), (PART - 50, PART + 50), (0, 0)], file),
        &no_modifiers(),
    );
    assert!(
        matches!(
            decisions.as_slice(),
            [
                ServeDecision::Emit(ServeEvent::BlockAskRefused {
                    peer: refused,
                    file_hash: asked,
                    fault: crate::BlockAskFault::Unverified,
                }),
                ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: released }),
                ServeDecision::Send {
                    peer: granted,
                    command: ServerCommand::GrantSlot { .. },
                },
                ServeDecision::Emit(ServeEvent::UploadSlotGranted { .. }),
            ] if *refused == holder && *asked == file && *released == holder && *granted == waiter
        ),
        "the slot ends, nothing is read or sent to its holder, and the waiter takes it: {decisions:?}"
    );

    assert_eq!(
        state.on_conn_event(
            t,
            holder,
            parts([(0, 100), (0, 0), (0, 0)], file),
            &no_modifiers()
        ),
        Vec::new(),
        "a peer whose slot ended is read nothing"
    );
}

#[test]
fn a_part_file_found_changed_or_gone_stops_serving_and_empties_the_range_without_the_registry_check()
 {
    for (cause, refused) in [
        (
            PartialEnd::Changed,
            ServeState::on_part_file_changed as Refusal,
        ),
        (PartialEnd::Unreadable, ServeState::on_part_file_unreadable),
    ] {
        let file = hash(0x02);
        let mut state = partial(file, &[0]);
        let t = Instant::now();
        let (holder, waiter) = (peer(4000), peer(4001));
        let _ = slot_request(&mut state, holder, file, t);
        let _ = slot_request(&mut state, waiter, file, t);
        let _ = state.on_conn_event(
            t,
            holder,
            parts([(0, 100), (0, 0), (0, 0)], file),
            &no_modifiers(),
        );

        let decisions = refused(&mut state, t, holder, block(file, 0, 100), &no_modifiers());
        for told in [holder, waiter] {
            assert!(decisions.contains(&send(
                told,
                ServerCommand::AnswerFileNotFound { file_hash: file }
            )));
        }
        assert_eq!(
            decisions.last(),
            Some(&ServeDecision::EmptyRange {
                file_hash: file,
                checked: Some(identity()),
                cause,
            })
        );
        assert!(!decisions.iter().any(|decision| matches!(
            decision,
            ServeDecision::ReadFailed(_)
                | ServeDecision::Send {
                    command: ServerCommand::SendBlock { .. },
                    ..
                }
        )));
        assert_eq!(
            state.on_read_result(holder, block(file, 0, 100), vec![0; 100]),
            Vec::new(),
            "a read landing after it sends nothing"
        );
    }
}
