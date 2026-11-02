//! Who is answered from an AICH tree, and when (ADR-0038): one build at a
//! time in the order files were asked, the root owed to a link when the tree
//! lands, a recovery ask refused at once without a tree, and what a leaving
//! file or asker does to a build.

use super::*;
use crate::serve::state::AichBuilt;
use rmule_peer::{ServerCommand, ServerEvent};
use rmule_primitives::{AichHashSet, AichRootHash};

const SIZE: u64 = 3 * EMBLOCKSIZE;

fn tree(seed: u8) -> AichHashSet {
    AichHashSet::from_bytes(&vec![seed; SIZE as usize])
}

fn root_ask(file_hash: FileHash) -> ServeInput {
    ServeInput::Server(ServerEvent::AichFileHashRequested { file_hash })
}

fn recovery_ask(file_hash: FileHash, part: u16, root: AichRootHash) -> ServeInput {
    ServeInput::Server(ServerEvent::AichRequested {
        file_hash,
        part,
        root,
    })
}

fn build_of(file_hash: FileHash) -> ServeDecision {
    ServeDecision::BuildAichTree {
        file_hash,
        path: "/shared/shared.bin".into(),
        file_size: SIZE,
    }
}

fn root_to(peer: PeerEndpoint, file_hash: FileHash, root: AichRootHash) -> ServeDecision {
    send(peer, ServerCommand::AnswerAichFileHash { file_hash, root })
}

fn refused(peer: PeerEndpoint, file_hash: FileHash) -> ServeDecision {
    send(peer, ServerCommand::RefuseAich { file_hash })
}

/// `files`, each `SIZE` bytes at the same path, and peers 1 and 2 identified.
fn sharing(files: &[FileHash]) -> (ServeState, Instant) {
    let entries = files
        .iter()
        .map(|file| entry(*file, SIZE, "shared.bin"))
        .collect();
    let mut state = serving_state(1, entries);
    let t = Instant::now();
    identify(&mut state, peer(1), user(0x01), t);
    identify(&mut state, peer(2), user(0x02), t);
    (state, t)
}

fn ask(
    state: &mut ServeState,
    t: Instant,
    peer: PeerEndpoint,
    input: ServeInput,
) -> Vec<ServeDecision> {
    state.on_conn_event(t, peer, input, &no_modifiers())
}

fn land(
    state: &mut ServeState,
    t: Instant,
    file: FileHash,
    built: AichBuilt,
) -> Vec<ServeDecision> {
    state.on_aich_landed(t, file, built, &no_modifiers())
}

#[test]
fn a_file_is_built_once_for_all_its_askers_and_every_owed_root_goes_out() {
    let file = hash(0x71);
    let (mut state, t) = sharing(&[file]);

    assert_eq!(
        ask(&mut state, t, peer(1), root_ask(file)),
        [build_of(file)]
    );
    assert_eq!(ask(&mut state, t, peer(2), root_ask(file)), []);
    assert_eq!(ask(&mut state, t, peer(1), root_ask(file)), []);

    let root = tree(1).master_root();
    let mut told = land(&mut state, t, file, AichBuilt::Tree(tree(1)));
    told.sort_by_key(|decision| match decision {
        ServeDecision::Send { peer, .. } => peer.port(),
        other => panic!("only the owed roots, not {other:?}"),
    });
    assert_eq!(
        told,
        [root_to(peer(1), file, root), root_to(peer(2), file, root)]
    );

    assert_eq!(
        ask(&mut state, t, peer(2), root_ask(file)),
        [root_to(peer(2), file, root)],
        "a built tree answers at once and is not read again",
    );
}

/// The ask that finds no tree must not wait for one: an aMule asker has no
/// timer on it, so silence would hold its part for the whole build.
#[test]
fn a_recovery_ask_without_a_tree_is_refused_at_once_and_starts_the_build() {
    let file = hash(0x72);
    let (mut state, t) = sharing(&[file]);
    let built = tree(2);
    let root = built.master_root();

    assert_eq!(
        ask(&mut state, t, peer(1), recovery_ask(file, 0, root)),
        [refused(peer(1), file), build_of(file)],
    );
    assert_eq!(
        ask(&mut state, t, peer(2), recovery_ask(file, 0, root)),
        [refused(peer(2), file)],
        "the build out serves this asker too",
    );
    assert_eq!(
        land(&mut state, t, file, AichBuilt::Tree(built.clone())),
        []
    );

    let answered = ask(&mut state, t, peer(1), recovery_ask(file, 0, root));
    assert_eq!(
        answered,
        [send(
            peer(1),
            ServerCommand::AnswerAich {
                file_hash: file,
                part: 0,
                root,
                recovery_data: built.create_part_recovery_data(0).unwrap(),
            }
        )],
    );
}

#[test]
fn every_recovery_ask_that_cannot_be_met_is_refused() {
    let (file, short_tail) = (hash(0x73), hash(0x74));
    let tail_size = rmule_primitives::ED2K_PART_SIZE + EMBLOCKSIZE;
    let mut state = serving_state(
        1,
        vec![
            entry(file, SIZE, "whole.bin"),
            entry(short_tail, tail_size, "tail.bin"),
        ],
    );
    let t = Instant::now();
    let p = peer(1);
    identify(&mut state, p, user(0x01), t);
    let built = tree(3);
    let root = built.master_root();
    let tail_tree = AichHashSet::from_bytes(&vec![9; tail_size as usize]);
    let tail_root = tail_tree.master_root();
    for (asked, tree) in [(file, built), (short_tail, tail_tree)] {
        let _ = ask(&mut state, t, p, root_ask(asked));
        let _ = land(&mut state, t, asked, AichBuilt::Tree(tree));
    }
    let other_root = AichRootHash::from_bytes([0xEE; 20]);

    for (name, input, about) in [
        ("not shared", recovery_ask(hash(0x99), 0, root), hash(0x99)),
        ("not our root", recovery_ask(file, 0, other_root), file),
        ("past the end", recovery_ask(file, 1, root), file),
        (
            "a last part of one block",
            recovery_ask(short_tail, 1, tail_root),
            short_tail,
        ),
    ] {
        assert_eq!(ask(&mut state, t, p, input), [refused(p, about)], "{name}");
    }
}

#[test]
fn builds_run_one_at_a_time_in_the_order_files_were_first_asked() {
    let (first, second, third) = (hash(0x75), hash(0x76), hash(0x77));
    let (mut state, t) = sharing(&[first, second, third]);

    assert_eq!(
        ask(&mut state, t, peer(1), root_ask(first)),
        [build_of(first)]
    );
    assert_eq!(ask(&mut state, t, peer(2), root_ask(second)), []);
    assert_eq!(
        ask(
            &mut state,
            t,
            peer(1),
            recovery_ask(third, 0, tree(1).master_root())
        ),
        [refused(peer(1), third)],
    );
    assert_eq!(
        ask(&mut state, t, peer(2), root_ask(second)),
        [],
        "one place per file"
    );

    let root = tree(1).master_root();
    assert_eq!(
        land(&mut state, t, first, AichBuilt::Tree(tree(1))),
        [root_to(peer(1), first, root), build_of(second)],
    );
    assert_eq!(
        land(&mut state, t, second, AichBuilt::Tree(tree(1))),
        [root_to(peer(2), second, root), build_of(third)],
    );
    assert_eq!(land(&mut state, t, third, AichBuilt::Tree(tree(1))), []);
}

/// aMule keeps a root only for its current request file
/// (`DownloadClient.cpp:1707`), so a link is owed its latest ask's.
#[test]
fn a_link_is_owed_the_root_of_its_latest_ask() {
    let (first, second) = (hash(0x78), hash(0x79));
    let (mut state, t) = sharing(&[first, second]);

    let _ = ask(&mut state, t, peer(1), root_ask(first));
    let _ = ask(&mut state, t, peer(1), root_ask(second));

    assert_eq!(
        land(&mut state, t, first, AichBuilt::Tree(tree(1))),
        [build_of(second)],
    );
    assert_eq!(
        land(&mut state, t, second, AichBuilt::Tree(tree(2))),
        [root_to(peer(1), second, tree(2).master_root())],
    );
}

/// A cancel on hang-up would let a peer buy unlimited reads: ask, leave, ask.
#[test]
fn a_build_outlives_its_asker_and_the_next_asker_finds_the_tree() {
    let file = hash(0x7A);
    let (mut state, t) = sharing(&[file]);

    let _ = ask(&mut state, t, peer(1), root_ask(file));
    assert_eq!(ask(&mut state, t, peer(1), disconnected()), []);

    assert_eq!(land(&mut state, t, file, AichBuilt::Tree(tree(1))), []);
    assert_eq!(
        ask(&mut state, t, peer(2), root_ask(file)),
        [root_to(peer(2), file, tree(1).master_root())],
    );
}

#[test]
fn a_leaving_file_stops_its_build_which_holds_the_one_place_until_it_lands() {
    let (leaving, staying) = (hash(0x7B), hash(0x7C));
    let (mut state, t) = sharing(&[leaving, staying]);
    let _ = ask(&mut state, t, peer(1), root_ask(leaving));
    let _ = ask(&mut state, t, peer(2), root_ask(staying));

    let decisions =
        state.on_share_set(vec![entry(staying, SIZE, "shared.bin")], t, &no_modifiers());
    assert_eq!(decisions[0], ServeDecision::StopAichBuild);
    assert!(!state.aich.leave(leaving), "told once");
    assert_eq!(ask(&mut state, t, peer(1), root_ask(staying)), []);

    // A build told to stop counts for nothing, even one that finished first.
    assert_eq!(
        land(&mut state, t, leaving, AichBuilt::Tree(tree(1))),
        [build_of(staying)],
    );
    assert!(!state.aich.holds(leaving));
}

#[test]
fn a_file_shared_again_while_its_stopped_build_unwinds_builds_afresh() {
    let file = hash(0x7D);
    let (mut state, t) = sharing(&[file]);
    let _ = ask(&mut state, t, peer(1), root_ask(file));
    let _ = state.on_share_set(Vec::new(), t, &no_modifiers());
    let _ = state.on_share_set(vec![entry(file, SIZE, "shared.bin")], t, &no_modifiers());

    assert_eq!(ask(&mut state, t, peer(2), root_ask(file)), []);
    assert_eq!(
        land(&mut state, t, file, AichBuilt::Stopped),
        [build_of(file)]
    );
    assert_eq!(
        land(&mut state, t, file, AichBuilt::Tree(tree(1))),
        [root_to(peer(2), file, tree(1).master_root())],
    );
}

#[test]
fn a_queued_file_that_leaves_is_never_built_and_its_root_is_no_longer_owed() {
    let (running, queued) = (hash(0x7E), hash(0x7F));
    let (mut state, t) = sharing(&[running, queued]);
    let _ = ask(&mut state, t, peer(1), root_ask(running));
    let _ = ask(&mut state, t, peer(2), root_ask(queued));

    let decisions =
        state.on_share_set(vec![entry(running, SIZE, "shared.bin")], t, &no_modifiers());
    assert!(!decisions.contains(&ServeDecision::StopAichBuild));

    assert_eq!(
        land(&mut state, t, running, AichBuilt::Tree(tree(1))),
        [root_to(peer(1), running, tree(1).master_root())],
    );
}

/// A failed read ends the offer whoever asked, and each link waiting on the
/// tree hears the file is not here.
#[test]
fn a_build_that_cannot_read_its_file_ends_the_offer_and_tells_the_owed_links() {
    let file = hash(0x70);
    let (mut state, t) = sharing(&[file]);
    let _ = ask(&mut state, t, peer(1), root_ask(file));

    let decisions = land(&mut state, t, file, AichBuilt::Unreadable);

    assert_eq!(
        decisions,
        [
            send(
                peer(1),
                ServerCommand::AnswerFileNotFound { file_hash: file }
            ),
            ServeDecision::ReadFailed(file),
        ],
    );
    assert_eq!(
        ask(
            &mut state,
            t,
            peer(1),
            recovery_ask(file, 0, tree(1).master_root())
        ),
        [refused(peer(1), file)],
        "no longer offered: nothing to build",
    );
}

#[test]
fn a_peer_claiming_no_aich_is_answered_no_root_and_starts_no_build() {
    let file = hash(0x6F);
    let (mut state, t) = sharing(&[file]);
    let p = peer(3);
    let hello = HelloFacts {
        aich_version: 0,
        ..HelloFacts::of(user(0x03))
    };
    let _ = ask(&mut state, t, p, hello.identified());

    assert_eq!(ask(&mut state, t, p, root_ask(file)), []);
}
