//! The relayed `0x99` callback: consumed and counted, dialed back by the XOR
//! check's spelling, and dropped when the file is not shared.

use super::*;

/// The requester a relayed `0x99` names — the endpoint the front asks the
/// dialer to dial back.
fn the_requester() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4662)
}

fn relayed(callback: Callback) -> PeerEvent {
    PeerEvent::Side(SideEvent::BuddyCallbackReceived { callback })
}

/// A `0x99` naming a file we do not have dials nothing and is counted
/// (the `SharedFileKnown` gate); one naming a file we share dials; one
/// addressed to somebody else's buddy relationship is dropped by the XOR
/// check however it arrived.
#[tokio::test(start_paused = true)]
async fn a_relayed_callback_is_consumed_and_counted() {
    let mut h = quiet_harness();
    let side = h.hold().await;
    // Asymmetric on purpose: the hash crosses the link in Kad's
    // `WriteUInt128` word order and comes back out of it, so a palindromic one
    // would pass whatever order the `0x99` codec used.
    let known_hash = FileHash::from_bytes([
        0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10, 0x62,
        0xD2,
    ]);
    h.file_known.share(known_hash);
    let ours = Callback {
        buddy_id: [BUDDY_ID; 16],
        file_hash: known_hash,
        requester: the_requester(),
    };
    side.send(relayed(ours.clone())).await;
    // A file we neither share nor download — the mirrored predicate never
    // learned this hash, so the dial is refused before it costs a socket.
    side.send(relayed(Callback {
        file_hash: FileHash::from_bytes([0xEE; FileHash::BYTE_LEN]),
        ..ours.clone()
    }))
    .await;
    // Addressed to somebody else's buddy relationship.
    side.send(relayed(Callback {
        buddy_id: [0x12; 16],
        ..ours
    }))
    .await;
    settle().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.relayed_callbacks_dialed_total, 1);
    assert_eq!(session.relayed_callbacks_dropped_total, 2);
    // Plaintext: the `0x99` body names no hash a crypt handshake could key on.
    assert_eq!(
        h.next_dial_back().await,
        DialBack {
            requester: PeerEndpoint::V4(the_requester()),
            obfuscate_toward: None,
        }
    );
    assert!(h.no_dial_back(), "the two drops dial nobody");
}

/// The `0x99` check field addressed to `id` in the **other** `TAG_BUDDYHASH`
/// spelling (ADR-0061): word-swap first, then bit-invert — so
/// `relayed_callback::apply`'s `inverted(check_id).word_swapped() ==
/// our_kad_id` reads true.
fn addressed_to_swapped(id: [u8; 16]) -> [u8; 16] {
    addressed_to(*rmule_kad::KadId::from_bytes(id).word_swapped().as_bytes())
}

/// An asymmetric Kad ID for the front's own identity — unlike this module's
/// palindromic `OUR_KAD_ID`, word-swapping it changes the value, so it can
/// exercise the `TAG_BUDDYHASH` spelling swap.
const ASYMMETRIC_OUR_KAD_ID: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

/// One relayed `0x99` addressed to `ASYMMETRIC_OUR_KAD_ID` by `check_id`,
/// over a fresh front holding a link for that node: the two relayed-callback
/// counters read back as `(dialed_total, swapped_spelling_total)`.
async fn relayed_callback_dials_and_counts(check_id: [u8; 16]) -> (u64, u64) {
    let mut h = quiet_harness();
    h.kad_started_as(ASYMMETRIC_OUR_KAD_ID);
    h.ask_adopt_for(a_buddy(), ASYMMETRIC_OUR_KAD_ID).await;
    let side = h.next_dial().await.answer_as(buddy_hash(), None);
    let known_hash = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);
    h.file_known.share(known_hash);
    side.send(relayed(Callback {
        buddy_id: check_id,
        file_hash: known_hash,
        requester: the_requester(),
    }))
    .await;
    settle().await;

    let session = h.diagnostics.snapshot().session;
    (
        session.relayed_callbacks_dialed_total,
        session
            .buddy_hash_spelling
            .relayed_callbacks_swapped_spelling_total,
    )
}

/// `relayed_callbacks_swapped_spelling_total` — a relayed
/// `0x99` whose check field matches this node's own Kad ID only under the
/// other `TAG_BUDDYHASH` spelling (the eMule 0.70b / eMuleAI reading) still
/// dials the requester back, counted apart from the ordinary correct-spelling
/// dial, which leaves the swapped counter at zero.
#[tokio::test(start_paused = true)]
async fn a_swapped_spelling_relayed_callback_is_dialed_back_and_counted_apart() {
    assert_eq!(
        relayed_callback_dials_and_counts(addressed_to(ASYMMETRIC_OUR_KAD_ID)).await,
        (1, 0),
        "the plain spelling dials back and never touches the swapped counter"
    );
    assert_eq!(
        relayed_callback_dials_and_counts(addressed_to_swapped(ASYMMETRIC_OUR_KAD_ID)).await,
        (1, 1),
        "the swapped spelling also dials back, counted apart"
    );
}
