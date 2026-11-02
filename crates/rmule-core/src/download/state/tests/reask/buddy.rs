//! The reask roads a called-back Low-ID source stands on (ADR-0057, stock
//! 2.3.3 `DownloadClient.cpp:1269-1323`): the direct `0x90` while we are
//! reachable, its buddy's `0x94` while we are not and its record names that
//! buddy, and neither — the TCP full ask on time — when it names none.

use rmule_kad::KadId;

use super::*;

/// Asymmetric per word, so its two layouts differ.
const BUDDY_ID: KadId = KadId::from_bytes([
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
]);

fn buddy_udp() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
}

/// Where the called-back source's connection came from.
fn called_in() -> PeerEndpoint {
    peer(9)
}

/// Connected to Kad but reachable by nobody: firewalled, as aMule's
/// `IsFirewalled()` reads it, yet asking (`IsConnected()`).
fn firewalled() -> CallbackCapability {
    CallbackCapability::UNCALLABLE.with_kad_connected(true)
}

/// A Kad publisher [`SOURCE`] behind its buddy — named with its endpoint when
/// `with_buddy`, by its ID alone otherwise — called back, queued at rank 5
/// and hung up at [`t0`]: its record waits in RemoteQueued with its candidate.
fn standing_called_back(with_buddy: bool) -> DownloadState {
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        live_posture(),
        1,
        no_facts(),
        Vec::new(),
        Vec::new(),
    );
    let row = kad_buddy_sighting(Some(SOURCE), BUDDY_ID, with_buddy.then(buddy_udp), 0x00);
    let key = super::super::buddy_callback::buddy_key(&via_kad(&mut state, vec![row]));
    let _ = state.on_callback_connected(t0(), key, called_in());
    let identity = reaskable(SOURCE).identity();
    queue_and_hang_up_as(&mut state, called_in(), Some(identity), 5, t0());
    state
}

/// The one reask `decisions` send: its destination, its first two bytes and
/// where its answer is matched.
fn the_reask(decisions: &[Decision]) -> (PeerEndpoint, [u8; 2], PeerEndpoint) {
    let reasks: Vec<_> = decisions
        .iter()
        .filter_map(|d| match d {
            Decision::SendReaskPing {
                ping,
                answered_from,
                ..
            } => Some((
                ping.to,
                [ping.datagram[0], ping.datagram[1]],
                *answered_from,
            )),
            _ => None,
        })
        .collect();
    match reasks.as_slice() {
        [one] => *one,
        other => panic!("one reask expected: {other:?} in {decisions:?}"),
    }
}

/// While we are reachable the source is pinged directly, at the address it
/// called in from and the port its hello advertised.
#[test]
fn a_reachable_downloader_pings_a_called_back_source_directly() {
    let mut state = standing_called_back(true);
    assert_eq!(
        the_reask(&state.on_tick(t0() + udp_due())),
        (contact(called_in()), [0xC5, 0x90], contact(called_in()))
    );
}

/// Firewalled, the direct ping could not be answered: the source is reasked
/// through its buddy with a plain `0x94` keyed on the buddy's ID in big-endian
/// bytes, the form a stock buddy stored (`ClientList.cpp:929-930`), and its
/// answer is awaited from the source's own client-UDP endpoint.
#[test]
fn a_firewalled_downloader_reasks_a_low_id_source_through_its_buddy() {
    let mut state = standing_called_back(true);
    let _ = state.on_callback_capability(t0(), firewalled());

    let due = state.on_tick(t0() + low_id_udp_due());
    assert_eq!(
        the_reask(&due),
        (
            PeerEndpoint::V4(buddy_udp()),
            [0xC5, 0x94],
            contact(called_in())
        )
    );
    let Some(Decision::SendReaskPing { ping, .. }) = due.first() else {
        unreachable!()
    };
    assert_eq!(ping.datagram[2..18], BUDDY_ID.big_endian_bytes());
    assert_eq!(&ping.datagram[18..34], state.file_hash.as_bytes());
    assert_eq!(ping.crypt_target, None, "a buddy is sent plaintext");

    assert!(
        pinged(&state.on_tick(t0() + low_id_udp_due() + Duration::from_secs(5))).is_empty(),
        "one reask in flight"
    );
}

/// A source of the row spelling [`BUDDY_ID`] in the layout aMule through 3.1.0
/// wrote: the primary drew nothing, the fallback drew the dial-back, and the
/// source queued us and hung up at the instant returned.
fn standing_through_the_fallback() -> (DownloadState, Instant) {
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        live_posture(),
        1,
        no_facts(),
        Vec::new(),
        Vec::new(),
    );
    let row = kad_buddy_sighting(Some(SOURCE), BUDDY_ID, Some(buddy_udp()), 0x00);
    let key = super::super::buddy_callback::buddy_key(&via_kad(&mut state, vec![row]));
    let answered = t0() + CALLBACK_TIMEOUT;
    let _ = state.on_tick(answered);
    let _ = state.on_callback_connected(answered, key, called_in());
    queue_and_hang_up_as(
        &mut state,
        called_in(),
        Some(reaskable(SOURCE).identity()),
        5,
        answered,
    );
    (state, answered)
}

/// A stock buddy compares a `0x94`'s key exactly (`ClientUDPSocket.cpp:151`),
/// so the key is the reading that drew the dial-back, or every reask of such a
/// source is dropped.
#[test]
fn a_reask_after_the_fallback_answered_is_keyed_by_that_reading() {
    let (mut state, answered) = standing_through_the_fallback();
    let _ = state.on_callback_capability(answered, firewalled());

    let due = state.on_tick(answered + low_id_udp_due());
    let Some(Decision::SendReaskPing { ping, .. }) = due.first() else {
        panic!("a reask through the buddy: {due:?}");
    };
    assert_eq!(
        ping.datagram[2..18],
        BUDDY_ID.word_swapped().big_endian_bytes()
    );
}

/// The next road opens on the reading that answered, not on another whole
/// wait for the one that did not, and a later sighting of the same row does
/// not move it back; the reading that stayed silent is the road's fallback.
#[test]
fn the_road_after_the_fallback_answered_leads_with_that_reading() {
    let (mut state, answered) = standing_through_the_fallback();
    let row = kad_buddy_sighting(Some(SOURCE), BUDDY_ID, Some(buddy_udp()), 0x00);
    let _ = via_kad(&mut state, vec![row]);

    let opened = state.on_tick(answered + FILE_REASK_TIME);
    let asked: Vec<_> = opened
        .iter()
        .filter_map(|decision| match decision {
            Decision::RequestBuddyCallback { candidate, .. } => Some(candidate.buddy?.buddy_id),
            _ => None,
        })
        .collect();
    assert_eq!(asked, vec![BUDDY_ID.word_swapped()], "{opened:?}");

    let lapsed = state.on_tick(answered + FILE_REASK_TIME + CALLBACK_TIMEOUT);
    assert!(
        lapsed.iter().any(|decision| matches!(
            decision,
            Decision::RequestFallbackBuddyCallback { candidate, .. }
                if candidate.buddy.map(|buddy| buddy.buddy_id) == Some(BUDDY_ID)
        )),
        "{lapsed:?}"
    );
}

/// Firewalled, a source whose record names its buddy by ID alone has no road
/// but TCP: nothing is sent in the window, and the full ask falls due on time.
#[test]
fn a_firewalled_downloader_with_no_buddy_endpoint_waits_for_the_full_ask() {
    let mut state = standing_called_back(false);
    let _ = state.on_callback_capability(t0(), firewalled());

    assert!(pinged(&state.on_tick(t0() + low_id_udp_due())).is_empty());
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + LOW_ID_REASK_TIME)),
        vec![called_in()]
    );
}
