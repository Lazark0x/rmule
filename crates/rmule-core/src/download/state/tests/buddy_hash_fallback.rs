//! The buddy callback's second spelling. A firewalled source's
//! `TAG_BUDDYHASH` is read the eMule way first, and only a primary `0x52` that
//! drew no dial-back in the whole callback wait earns one more, addressed under
//! the reading aMule through 3.1.0 wrote.

use rmule_kad::KadId;
use rmule_primitives::UserHash;

use super::*;

/// The capture's pin: asymmetric per four-byte word, so the two spellings
/// name different IDs.
const PRIMARY: KadId = KadId::from_bytes([
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
]);

fn row(buddy_id: KadId, buddy_udp: Option<Ipv4Endpoint>) -> SourceSighting {
    kad_buddy_sighting(
        Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
        buddy_id,
        buddy_udp,
        0x00,
    )
}

fn buddy_udp() -> Option<Ipv4Endpoint> {
    Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000))
}

/// Every `0x52` a batch of decisions asks for: the buddy ID it addresses, and
/// whether it is the fallback spelling.
fn asks(decisions: &[Decision]) -> Vec<(KadId, bool)> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::RequestBuddyCallback { candidate, .. } => {
                Some((candidate.buddy?.buddy_id, false))
            }
            Decision::RequestFallbackBuddyCallback { candidate, .. } => {
                Some((candidate.buddy?.buddy_id, true))
            }
            _ => None,
        })
        .collect()
}

fn released(decisions: &[Decision], key: CallbackKey) -> bool {
    decisions
        .iter()
        .any(|d| matches!(d, Decision::EndCallback { key: k } if *k == key))
}

/// Source-derived fallback leg: the primary `0x52`, thirty silent seconds,
/// then exactly one more under the word-swapped spelling — same candidate,
/// same slot, the wait re-armed — and after that wait, the road's ordinary
/// end.
#[test]
fn source_derived_a_silent_primary_callback_earns_one_fallback_spelling_callback() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);

    let opened = via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]);
    assert_eq!(
        asks(&opened),
        vec![(PRIMARY, false)],
        "the primary goes first"
    );
    let key = super::buddy_callback::buddy_key(&opened);

    let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
    assert_eq!(
        asks(&lapsed),
        vec![(PRIMARY.word_swapped(), true)],
        "one 0x52 under the other spelling: {lapsed:?}"
    );
    assert_eq!(
        state.next_wake(),
        Some(t0() + CALLBACK_TIMEOUT * 2),
        "the fallback gets the same wait"
    );
    assert!(!released(&lapsed, key), "the slot stays held: {lapsed:?}");

    let ended = state.on_tick(t0() + CALLBACK_TIMEOUT * 2);
    assert!(asks(&ended).is_empty(), "one extra 0x52 at most: {ended:?}");
    assert!(released(&ended, key), "then the road ends: {ended:?}");
}

/// The primary `0x52` left and drew nothing, so the road invited: a fallback
/// spelling refused at our end changes neither, and the key is spent at the
/// road's end, as any lapse with its invitation out
/// (`BaseClient.cpp:1340-1346`).
#[test]
fn a_refused_fallback_spelling_spends_the_key_its_primary_invited() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let opened = via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]);
    let key = super::buddy_callback::buddy_key(&opened);
    let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
    assert_eq!(asks(&lapsed), vec![(PRIMARY.word_swapped(), true)]);

    let refused = state.on_traversal_retired(
        t0() + CALLBACK_TIMEOUT,
        key,
        crate::diagnostics::NattRetirement::CallbackNotSent,
    );
    assert!(released(&refused, key), "{refused:?}");

    let again = via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]);
    assert!(asks(&again).is_empty(), "{again:?}");
}

/// The **Callback Pace** holds the fallback, which the stock window shuts at
/// the end of the primary's wait: it is deferred, and its wait counts from
/// when it leaves, so the road does not end on a `0x52` the buddy has not yet
/// had the chance to relay.
#[test]
fn a_held_fallback_gets_its_whole_wait_from_when_it_leaves() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let opened = via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]);
    let key = super::buddy_callback::buddy_key(&opened);

    let lapsed = t0() + CALLBACK_TIMEOUT;
    assert_eq!(asks(&state.on_tick(lapsed)).len(), 1);
    let leaves_in = Duration::from_secs(35);
    state.on_callback_held(lapsed, key, leaves_in);

    let leaves = lapsed + leaves_in;
    assert_eq!(state.next_wake(), Some(leaves + CALLBACK_TIMEOUT));
    let early = state.on_tick(t0() + CALLBACK_TIMEOUT * 2);
    assert!(!released(&early, key), "still ahead of the wait: {early:?}");
    assert!(released(&state.on_tick(leaves + CALLBACK_TIMEOUT), key));
}

/// A second download's primary, held behind the first's: its silence has not
/// begun, so the fallback waits a whole callback wait past the leaving.
#[test]
fn a_held_primary_earns_no_fallback_until_a_whole_wait_past_its_leaving() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let opened = via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]);
    let key = super::buddy_callback::buddy_key(&opened);
    let leaves_in = Duration::from_secs(64);
    state.on_callback_held(t0(), key, leaves_in);

    assert!(asks(&state.on_tick(t0() + CALLBACK_TIMEOUT)).is_empty());
    assert_eq!(
        asks(&state.on_tick(t0() + leaves_in + CALLBACK_TIMEOUT)),
        vec![(PRIMARY.word_swapped(), true)],
    );
}

/// A primary that drew its dial-back is done: the wait never lapses, so no
/// fallback ever leaves.
#[test]
fn a_primary_callback_that_drew_a_dial_back_sends_no_fallback() {
    let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
    let key =
        super::buddy_callback::buddy_key(&via_kad(&mut state, vec![row(PRIMARY, buddy_udp())]));
    let _ = state.on_callback_connected(t0(), key, peer(9));

    assert!(state.on_tick(t0() + CALLBACK_TIMEOUT).is_empty());
}

/// Where the two spellings are one ID there is nothing else to try, and a
/// buddy named by ID alone was reached by a Callback Walk toward the primary,
/// whose `0x52`s went to contacts near *that* ID — a second spelling there
/// would be a second walk, not one datagram. Both lapse as before.
#[test]
fn no_fallback_for_a_word_palindrome_id_or_a_walked_buddy() {
    for source in [
        row(KadId::from_bytes([0x7A; KadId::BYTE_LEN]), buddy_udp()),
        row(PRIMARY, None),
    ] {
        let mut state = callback_state(Vec::new(), Vec::new(), true, 1);
        let key = super::buddy_callback::buddy_key(&via_kad(&mut state, vec![source]));
        let lapsed = state.on_tick(t0() + CALLBACK_TIMEOUT);
        assert!(asks(&lapsed).is_empty(), "{lapsed:?}");
        assert!(released(&lapsed, key), "{lapsed:?}");
    }
}
