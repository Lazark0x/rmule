//! The reask cycle (ADR-0057) as the brain's decisions at the instants a test
//! hands it: a worker that queued us and hung up keeps its standing on its
//! record; the UDP ping leads the TCP full ask by the 20 s grace, one in
//! flight; each reply shape lands on the standing it names; the gates that
//! take a source straight to TCP; and `next_wake` naming when to look next.

use rmule_peer::{ReaskAck, file_not_found_datagram, queue_full_datagram};
use rmule_primitives::Ipv6Endpoint;

use super::*;
use crate::download::source_book::{NO_NEEDED_PARTS_MULTIPLIER, REASK_RECHECK, UDP_REASK_LEAD};
use crate::own_identity::ConnectedSession;
use crate::service::IgnoredReaskReply;

mod buddy;
mod exchange_pool;
mod given_back;
mod no_file;
mod no_needed_parts;
mod on_queue;
mod purge;
mod redial;

/// The port every test source advertises for client UDP.
const UDP_PORT: u16 = 5000;

/// The User Hash these tests' sources name in their hellos.
const SOURCE: UserHash = UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]);

/// `peer`'s client-UDP endpoint: its own address at [`UDP_PORT`].
fn contact(peer: PeerEndpoint) -> PeerEndpoint {
    peer.with_port(UDP_PORT)
}

/// The instant, past a standing's clock origin, its UDP ping falls due.
fn udp_due() -> Duration {
    FILE_REASK_TIME - UDP_REASK_LEAD
}

/// Our own reask position fully live: a client-UDP socket bound and a server
/// High ID, so the UDP-first path is open.
fn live_posture() -> SourcingPosture {
    SourcingPosture {
        callback_capability: CallbackCapability::server_high_id(),
        client_udp: true,
        ..QUIET_POSTURE
    }
}

/// A started one-part download over `pool` under `posture`, a slot for each.
fn started(pool: &[PeerEndpoint], posture: SourcingPosture) -> DownloadState {
    let mut state = pooled_state(file_hash_only_content(ONE_PART), pool, posture, pool.len());
    let _ = state.start(t0());
    state
}

/// `peer`'s worker connects, states its client-UDP contact when `udp`, is
/// queued at `rank` at [`t0`] and hangs up.
fn queue_and_hang_up(state: &mut DownloadState, peer: PeerEndpoint, udp: bool, rank: u16) {
    queue_and_hang_up_at(state, peer, udp, rank, t0());
}

/// [`queue_and_hang_up`] at `at`.
fn queue_and_hang_up_at(
    state: &mut DownloadState,
    peer: PeerEndpoint,
    udp: bool,
    rank: u16,
    at: Instant,
) {
    let identity = udp.then(|| reaskable(SOURCE).identity());
    queue_and_hang_up_as(state, peer, identity, rank, at);
}

/// The hello of a source `user_hash` that states its client-UDP contact at
/// [`UDP_PORT`], UDP version 4.
fn reaskable(user_hash: UserHash) -> HelloFacts {
    HelloFacts {
        udp_port: UDP_PORT,
        udp_version: 4,
        ..HelloFacts::of(user_hash)
    }
}

/// [`queue_and_hang_up_at`] with the `identity` the worker reports, when it
/// reports one.
fn queue_and_hang_up_as(
    state: &mut DownloadState,
    peer: PeerEndpoint,
    identity: Option<rmule_peer::PeerIdentity>,
    rank: u16,
    at: Instant,
) {
    let _ = connect(state, at, peer);
    if let Some(identity) = identity {
        let _ = state.on_worker_event(at, peer, PeerWorkerEvent::Identity(identity));
    }
    let _ = state.on_worker_event(at, peer, PeerWorkerEvent::Queued { rank });
    let hung_up = state.on_worker_event(at, peer, PeerWorkerEvent::Disconnected);
    assert!(
        hung_up.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::SourceRemoteQueued { peer: p, rank: r, .. })
                if *p == peer && *r == Some(rank)
        )),
        "a queued worker that hangs up keeps its standing: {hung_up:?}"
    );
}

/// A started download whose `peer(1)` stands queued at rank 5 with a UDP
/// contact, under the live posture.
fn standing() -> DownloadState {
    let mut state = started(&[peer(1)], live_posture());
    queue_and_hang_up(&mut state, peer(1), true, 5);
    state
}

/// The client-UDP endpoints `decisions` pings, in order.
fn pinged(decisions: &[Decision]) -> Vec<PeerEndpoint> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::SendReaskPing { ping, .. } => Some(ping.to),
            _ => None,
        })
        .collect()
}

/// The sources `decisions` re-asks over TCP, in order.
fn asked_by_tcp(decisions: &[Decision]) -> Vec<PeerEndpoint> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Emit(DownloadEvent::SourceReaskedOverTcp { peer, .. }) => Some(*peer),
            _ => None,
        })
        .collect()
}

/// The one event `decisions` emits.
fn the_event(decisions: &[Decision]) -> &DownloadEvent {
    match decisions {
        [Decision::Emit(event)] => event,
        other => panic!("one event expected: {other:?}"),
    }
}

/// A `0x91 OP_REASKACK` as an uploader sharing the finished file sends it to
/// a UDPv4 pinger: its part status — aMule's part-count-0 complete-source
/// sentinel — rides ahead of the rank.
fn v4_ack(rank: u16) -> Vec<u8> {
    v4_ack_with(PartBitmap::complete_source_sentinel(), rank)
}

fn v4_ack_with(part_status: PartBitmap, rank: u16) -> Vec<u8> {
    ReaskAck {
        part_status: Some(part_status),
        rank,
    }
    .encode_udp()
}

/// Nothing is due before the UDP window opens, and `next_wake` names the
/// instant it does.
#[test]
fn no_reask_before_the_udp_window_opens() {
    let mut state = standing();
    assert_eq!(state.next_wake(), Some(t0() + udp_due()));
    assert!(
        state
            .on_tick(t0() + udp_due() - Duration::from_secs(1))
            .is_empty()
    );
}

/// At period − 20 s the ping goes to the source's client-UDP endpoint, framed
/// for the file; the latch then bars a second ping inside the window, and the
/// brain next wakes for the TCP full ask.
#[test]
fn the_udp_ping_fires_first_and_the_latch_bars_a_second_ping() {
    let mut state = standing();
    let due = state.on_tick(t0() + udp_due());
    assert_eq!(pinged(&due), vec![contact(peer(1))]);
    let Some(Decision::SendReaskPing {
        peer: at,
        ping,
        answered_from,
    }) = due.first()
    else {
        panic!("one ping: {due:?}");
    };
    assert_eq!(*at, peer(1));
    assert_eq!(ping.datagram[..2], [0xC5, 0x90]);
    assert_eq!(
        *answered_from, ping.to,
        "a direct ping is answered where it went"
    );

    assert!(
        pinged(&state.on_tick(t0() + udp_due() + Duration::from_secs(5))).is_empty(),
        "one ping in flight"
    );
    assert_eq!(state.next_wake(), Some(t0() + FILE_REASK_TIME));
}

/// The ping goes toward the identity the source queued under (ADR-0046): its
/// standing keeps the User Hash and stance after the worker that stated them
/// is gone, so the socket boundary obfuscates the `0x90` when that stance
/// accepts it, as aMule's `ShouldReceiveCryptUDPPackets` does.
#[test]
fn a_ping_carries_the_crypt_target_its_source_queued_under() {
    let mut state = started(&[peer(1)], live_posture());
    let identity = HelloFacts {
        crypt: rmule_primitives::CryptStance::new(true, true, false),
        ..reaskable(SOURCE)
    }
    .identity();
    let target = identity.udp_crypt_target();
    queue_and_hang_up_as(&mut state, peer(1), Some(identity), 3, t0());

    let targets: Vec<_> = state
        .on_tick(t0() + udp_due())
        .into_iter()
        .filter_map(|d| match d {
            Decision::SendReaskPing { ping, .. } => Some(ping.crypt_target),
            _ => None,
        })
        .collect();
    assert_eq!(targets, vec![Some(target)]);
}

/// Silence past the grace falls to the TCP full ask: the source leaves the
/// pool for its endpoint's dial — the lost datagram cost 20 s, never the
/// standing — and the rank its next connection earns is the standing again,
/// one period from that rank.
#[test]
fn silence_falls_through_to_the_tcp_full_ask_after_the_grace() {
    let mut state = standing();
    let _ = state.on_tick(t0() + udp_due());
    let asked = state.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&asked), vec![peer(1)]);
    assert_eq!(spawned(&asked), vec![peer(1)]);

    let again = t0() + FILE_REASK_TIME + Duration::from_secs(3);
    queue_and_hang_up_at(&mut state, peer(1), true, 4, again);
    assert_eq!(state.next_wake(), Some(again + udp_due()));
    assert_eq!(
        pinged(&state.on_tick(again + udp_due())),
        vec![contact(peer(1))]
    );
}

/// A `0x91` records the rank, refreshes the clock and clears the latch: the
/// full ask the silence would have brought does not come, and the next cycle
/// runs from the reply.
#[test]
fn a_reask_ack_records_the_rank_refreshes_the_clock_and_cancels_the_fallback() {
    let mut state = standing();
    let _ = state.on_tick(t0() + udp_due());
    let reply_at = t0() + udp_due() + Duration::from_secs(2);
    let heard = state.on_reask_reply(reply_at, contact(peer(1)), &v4_ack(3));
    assert!(matches!(
        the_event(&heard),
        DownloadEvent::SourceReaskAcked { peer: p, rank: 3, .. } if *p == peer(1)
    ));

    assert!(state.on_tick(t0() + FILE_REASK_TIME).is_empty());
    assert_eq!(state.next_wake(), Some(reply_at + udp_due()));
    assert_eq!(
        pinged(&state.on_tick(reply_at + udp_due())),
        vec![contact(peer(1))]
    );
}

/// Only the sentinel names a complete source (ADR-0108; stock 2.3.3
/// `DownloadClient.cpp:405-409`, `:428`, eMule `DownloadClient.cpp:516`): a
/// source asked for sources and answering, then acking with the sentinel, is
/// asked again only on the common cadence; one spelling out every part of a
/// three-part file is a part file whose last part arrived, and one missing a
/// part is plainly not complete — both asked again on the very rare one.
#[test]
fn a_reask_ack_names_a_complete_source_only_by_the_sentinel() {
    for (status, asked_again) in [
        (PartBitmap::decode(3, &[0b0000_0111]).unwrap(), true),
        (PartBitmap::decode(3, &[0b0000_0101]).unwrap(), true),
        (PartBitmap::complete_source_sentinel(), false),
    ] {
        let mut state = pooled_state(
            file_hash_only_content(THREE_PARTS),
            &[peer(1)],
            live_posture(),
            1,
        );
        let _ = state.start(t0());
        let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SourcesAsked);
        let _ = via_exchange(&mut state, peer(1), Vec::new());
        queue_and_hang_up(&mut state, peer(1), true, 5);
        let _ = state.on_tick(t0() + udp_due());
        let reply_at = t0() + udp_due();
        let ack = v4_ack_with(status.clone(), 4);
        let _ = state.on_reask_reply(reply_at, contact(peer(1)), &ack);

        let asked = state.on_tick(reply_at + FILE_REASK_TIME);
        let want = asked.iter().find_map(|d| match d {
            Decision::Spawn { want_sources, .. } => Some(*want_sources),
            _ => None,
        });
        assert_eq!(want, Some(asked_again), "{status:?}");
    }
}

/// A three-part file: `2 × PARTSIZE + 1` bytes, so its status counts three.
const THREE_PARTS: u64 = 2 * rmule_primitives::ED2K_PART_SIZE + 1;

/// A started three-part download whose `peer(1)` stands queued at rank 5 with
/// a UDP contact and was pinged at the window, which is returned.
fn three_part_standing() -> (DownloadState, Instant) {
    let mut state = pooled_state(
        file_hash_only_content(THREE_PARTS),
        &[peer(1)],
        live_posture(),
        1,
    );
    let _ = state.start(t0());
    queue_and_hang_up(&mut state, peer(1), true, 5);
    let window = t0() + udp_due();
    assert_eq!(pinged(&state.on_tick(window)), vec![contact(peer(1))]);
    (state, window)
}

/// A UDPv4 `0x91` whose part status holds no part we lack makes the source
/// no-needed-parts (stock 2.3.3 `ClientUDPSocket.cpp:259`,
/// `DownloadClient.cpp:487-491`): the rank still lands and the clock is
/// fresh, but its next ask is over TCP at twice the period, with no ping.
#[test]
fn a_reask_ack_holding_no_part_we_lack_makes_the_source_no_needed_parts() {
    let (mut state, window) = three_part_standing();
    let empty = PartBitmap::decode(3, &[0b0000_0000]).expect("three parts");
    let heard = state.on_reask_reply(window, contact(peer(1)), &v4_ack_with(empty, 2));
    assert!(matches!(
        the_event(&heard),
        DownloadEvent::SourceReaskAcked { rank: 2, .. }
    ));

    assert!(state.on_tick(window + udp_due()).is_empty(), "no ping");
    assert!(state.on_tick(window + FILE_REASK_TIME).is_empty());
    assert_eq!(
        asked_by_tcp(&state.on_tick(window + FILE_REASK_TIME * NO_NEEDED_PARTS_MULTIPLIER)),
        vec![peer(1)]
    );
}

/// A UDPv4 `0x91`'s part status is the source's Advertised Parts now: it
/// replaces what its worker's probe wrote on the record (ADR-0112), and Part
/// Frequency follows.
#[test]
fn a_reask_acks_part_status_replaces_the_records_parts() {
    let (mut state, window) = three_part_standing();
    assert_eq!(state.sources.part_frequency(), [1, 1, 1]);
    let middle = PartBitmap::decode(3, &[0b0000_0010]).expect("three parts");
    let _ = state.on_reask_reply(window, contact(peer(1)), &v4_ack_with(middle.clone(), 2));
    assert_eq!(state.sources.parts(peer(1)), Some(&middle));
    assert_eq!(
        (state.sources.part_frequency(), state.sources.parts_known()),
        (&[0, 1, 0][..], 1)
    );
}

/// A status counting other than the file's parts is aMule's
/// `ProcessFileStatus` throw (stock 2.3.3 `DownloadClient.cpp:416-424`),
/// which drops the whole `0x91` before its rank is read: the reply is ignored,
/// and the standing falls to the TCP full ask.
#[test]
fn a_reask_ack_counting_other_parts_is_ignored() {
    let (mut state, window) = three_part_standing();
    let two = PartBitmap::decode(2, &[0b0000_0011]).expect("two parts");
    let heard = state.on_reask_reply(window, contact(peer(1)), &v4_ack_with(two, 2));
    assert!(matches!(
        the_event(&heard),
        DownloadEvent::ReaskReplyIgnored {
            reason: IgnoredReaskReply::PartCountMismatch,
            ..
        }
    ));
    assert_eq!(state.next_wake(), Some(t0() + FILE_REASK_TIME));
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A `0x93` keeps the source, rank cleared, and refreshes its clock; a later
/// `0x91` records its rank again.
#[test]
fn a_queue_full_reply_keeps_the_source_and_refreshes_the_clock() {
    let mut state = standing();
    let _ = state.on_tick(t0() + udp_due());
    let reply_at = t0() + udp_due() + Duration::from_secs(1);
    let full = state.on_reask_reply(reply_at, contact(peer(1)), &queue_full_datagram());
    assert!(matches!(
        the_event(&full),
        DownloadEvent::SourceReaskQueueFull { peer: p, .. } if *p == peer(1)
    ));
    assert!(state.on_tick(t0() + FILE_REASK_TIME).is_empty());

    let acked = state.on_reask_reply(reply_at, contact(peer(1)), &v4_ack(9));
    assert!(matches!(
        the_event(&acked),
        DownloadEvent::SourceReaskAcked { rank: 9, .. }
    ));
}

/// A `0x92` spends the source for this download, as aMule dead-lists it
/// (ADR-0090): its record leaves the book, nothing is reasked, and a sighting
/// of it — at its endpoint or by the User Hash its hello named — is refused
/// until two spent turns have passed.
#[test]
fn a_file_not_found_reply_spends_the_source_for_the_re_ask_period() {
    let mut state = standing();
    let dropped = state.on_reask_reply(t0(), contact(peer(1)), &file_not_found_datagram());
    assert!(matches!(
        the_event(&dropped),
        DownloadEvent::SourceReaskDropped { peer: p, .. } if *p == peer(1)
    ));
    assert_eq!(state.known_sources(), 0);
    assert_eq!(
        state.next_wake(),
        Some(t0() + FILE_REASK_TIME),
        "the spent turn alone"
    );
    assert!(
        spawned(&take(&mut state, Channel::Server, plain_sightings(&[peer(1)])).decisions)
            .is_empty(),
        "its endpoint is spent"
    );
    let elsewhere = SourceSighting::new(
        rmule_primitives::PeerSource::HighId(Ipv4Endpoint::new(
            Ipv4Addr::new(45, 55, 200, 9),
            4662,
        )),
        Some(SOURCE),
        None,
        rmule_primitives::Informant::Own,
    );
    assert_eq!(
        take(&mut state, Channel::Server, [elsewhere]).tally.fresh,
        0,
        "its User Hash is spent too"
    );

    let _ = state.on_tick(t0() + FILE_REASK_TIME);
    assert!(
        spawned(&take(&mut state, Channel::Server, plain_sightings(&[peer(1)])).decisions)
            .is_empty(),
        "one turn later it is still spent"
    );
    let _ = state.on_tick(t0() + FILE_REASK_TIME * 2);
    assert_eq!(
        spawned(&take(&mut state, Channel::Server, plain_sightings(&[peer(1)])).decisions),
        vec![peer(1)],
        "two turns later it is a source again"
    );
}

/// A well-formed `0x91` from a client-UDP endpoint no standing advertised is
/// ignored on the source key, not a decode failure, and the standing is
/// untouched.
#[test]
fn a_reply_from_an_unknown_udp_source_is_ignored() {
    let mut state = standing();
    let stranger = contact(peer(99));
    let ignored = state.on_reask_reply(t0(), stranger, &v4_ack(2));
    assert!(matches!(
        the_event(&ignored),
        DownloadEvent::ReaskReplyIgnored {
            peer: p,
            reason: IgnoredReaskReply::NoPooledSource,
            ..
        } if *p == stranger
    ));
    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(peer(1))]
    );
}

/// A reply the requester ignores leaves the standing as it was and names its
/// reason: here a rank-only body where both ends are UDPv4 and the status is
/// owed.
#[test]
fn an_ignored_reply_leaves_the_standing_and_says_why() {
    let mut state = standing();
    let _ = state.on_tick(t0() + udp_due());
    let rank_only = ReaskAck {
        part_status: None,
        rank: 2,
    }
    .encode_udp();
    let ignored = state.on_reask_reply(t0() + udp_due(), contact(peer(1)), &rank_only);
    assert!(matches!(
        the_event(&ignored),
        DownloadEvent::ReaskReplyIgnored {
            reason: IgnoredReaskReply::Misframed,
            ..
        }
    ));
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)],
        "the latch still holds: silence falls to TCP"
    );
}

/// With no client-UDP socket bound our advert is off: every reask is the TCP
/// full ask, and the brain sleeps straight to it.
#[test]
fn our_udp_disabled_takes_every_reask_straight_to_the_tcp_full_ask() {
    let mut state = started(
        &[peer(1)],
        SourcingPosture {
            client_udp: false,
            ..live_posture()
        },
    );
    queue_and_hang_up(&mut state, peer(1), true, 5);
    assert_eq!(state.next_wake(), Some(t0() + FILE_REASK_TIME));
    assert!(state.on_tick(t0() + udp_due()).is_empty());
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A server Low ID and no open Kad verdict: a source cannot answer by UDP a
/// downloader no route reaches, so no ping leaves — but the window is looked
/// at again a second later, since reachability can arrive in it.
#[test]
fn a_firewalled_downloader_never_udp_pings() {
    let mut state = started(
        &[peer(1)],
        SourcingPosture {
            callback_capability: low_id_session(),
            ..live_posture()
        },
    );
    queue_and_hang_up(&mut state, peer(1), true, 5);
    let window = t0() + udp_due();
    assert!(state.on_tick(window).is_empty());
    assert_eq!(state.next_wake(), Some(window + REASK_RECHECK));
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A server Low ID with no Kad: connected, so sources are asked, but
/// firewalled, so never pinged.
fn low_id_session() -> CallbackCapability {
    CallbackCapability::of(
        true,
        Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(7),
        }),
        false,
    )
}

/// Neither reask leaves while we are connected to no network — aMule asks a
/// queued source only while `theApp->IsConnected()` (stock 2.3.3
/// `PartFile.cpp:1460`, `:1475`): a standing that falls due offline waits,
/// and is asked the moment a login, or a Kad node that has heard a contact,
/// connects us again.
#[test]
fn an_offline_downloader_holds_its_reasks_until_it_connects() {
    for connected in [
        low_id_session(),
        CallbackCapability::UNCALLABLE.with_kad_connected(true),
    ] {
        let mut state = started(
            &[peer(1)],
            SourcingPosture {
                callback_capability: CallbackCapability::UNCALLABLE,
                ..live_posture()
            },
        );
        queue_and_hang_up(&mut state, peer(1), true, 5);
        assert!(state.on_tick(t0() + udp_due()).is_empty());
        assert!(state.on_tick(t0() + FILE_REASK_TIME).is_empty());
        let later = t0() + FILE_REASK_TIME + Duration::from_secs(60);
        assert!(asked_by_tcp(&state.on_tick(later)).is_empty());
        assert_eq!(
            asked_by_tcp(&state.on_callback_capability(later, connected)),
            vec![peer(1)],
            "{connected:?}"
        );
    }
}

/// The gate is aMule's `!IsFirewalled()` (`DownloadClient.cpp:1269`), read
/// off the brain's latest Callback Capability sample at every sweep: a server
/// High ID gained opens it, a re-assigned Low ID closes it, and an open Kad
/// TCP verdict opens it again.
#[test]
fn the_reask_gate_reads_our_reachability_at_every_sweep() {
    let session = |id| {
        Some(ConnectedSession {
            server: None,
            client_id: ClientId::from_u32(id),
        })
    };
    let sweep = |capability: CallbackCapability| {
        let mut state = started(
            &[peer(1)],
            SourcingPosture {
                callback_capability: CallbackCapability::UNCALLABLE,
                ..live_posture()
            },
        );
        queue_and_hang_up(&mut state, peer(1), true, 5);
        let _ = state.on_callback_capability(t0(), capability);
        pinged(&state.on_tick(t0() + udp_due()))
    };
    let ping = vec![contact(peer(1))];
    assert!(sweep(CallbackCapability::of(true, None, false)).is_empty());
    assert_eq!(
        sweep(CallbackCapability::of(true, session(0x0A00_0001), false)),
        ping
    );
    assert!(sweep(CallbackCapability::of(true, session(7), false)).is_empty());
    assert_eq!(sweep(CallbackCapability::of(true, session(7), true)), ping);
}

/// A source whose hello threaded no client-UDP port is TCP-only.
#[test]
fn a_source_without_a_udp_contact_is_tcp_only() {
    let mut state = started(&[peer(1)], live_posture());
    queue_and_hang_up(&mut state, peer(1), false, 5);
    assert!(state.on_tick(t0() + udp_due()).is_empty());
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// A source whose hello allows a source ask, never asked: the ask is due
/// (ADR-0108), so its reask waits for the TCP full ask that can carry it
/// (`DownloadClient.cpp:1269-1273`) — and the full ask's dial carries it.
#[test]
fn a_source_exchange_due_source_prefers_the_tcp_full_ask() {
    let mut state = started(&[peer(1)], live_posture());
    let identity = HelloFacts {
        source_exchange: rmule_peer::SourceExchangeSupport::new(true, 0, true),
        ..reaskable(SOURCE)
    }
    .identity();
    queue_and_hang_up_as(&mut state, peer(1), Some(identity), 5, t0());
    assert!(state.on_tick(t0() + udp_due()).is_empty());
    let asked = state.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&asked), vec![peer(1)]);
    assert!(matches!(
        asked.iter().find(|d| matches!(d, Decision::Spawn { .. })),
        Some(Decision::Spawn {
            want_sources: true,
            ..
        })
    ));
}

/// One sweep reasks every standing in the order the book first held them:
/// the two with a contact ping, and at the period all three fall to TCP.
#[test]
fn a_tick_sweeps_every_source_in_book_order() {
    let mut state = started(&[peer(1), peer(2), peer(3)], live_posture());
    queue_and_hang_up(&mut state, peer(1), true, 1);
    queue_and_hang_up(&mut state, peer(2), false, 2);
    queue_and_hang_up(&mut state, peer(3), true, 3);

    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(peer(1)), contact(peer(3))]
    );
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1), peer(2), peer(3)]
    );
}

/// A queued worker granted a slot is live, not standing: when it ends, nothing
/// is reasked.
#[test]
fn a_granted_source_keeps_no_standing() {
    let mut state = started(&[peer(1)], live_posture());
    let _ = connect(&mut state, t0(), peer(1));
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Queued { rank: 2 });
    let _ = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::SlotGranted);
    let ended = state.on_worker_event(t0(), peer(1), PeerWorkerEvent::Disconnected);
    assert!(
        !ended
            .iter()
            .any(|d| matches!(d, Decision::Emit(DownloadEvent::SourceRemoteQueued { .. }))),
        "{ended:?}"
    );
    assert!(asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)).is_empty());
}

/// An IPv6 source holds its queue standing exactly as an IPv4 one does
/// (ADR-0087): the reask quartet packs no address in any body, so the `0x90`
/// goes to the source's own v6 UDP endpoint and its `0x91` matches back on
/// all 128 bits. Two sources in the **same `/64`** stay apart — the `/64` is
/// an accounting bucket, never an identity — so a neighbour's ack never
/// credits the wrong source.
#[test]
fn an_ipv6_source_reasks_over_ipv6_and_its_reply_matches_on_all_128_bits() {
    let v6_peer = |last: u16| {
        PeerEndpoint::V6(Ipv6Endpoint::new(
            std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last),
            4662,
        ))
    };
    let mut state = started(
        &[v6_peer(1), v6_peer(2)],
        SourcingPosture {
            dial: DialPosition {
                known_ipv6: Some("2001:db8:ffff::1".parse().unwrap()),
            },
            ..live_posture()
        },
    );
    queue_and_hang_up(&mut state, v6_peer(1), true, 5);
    queue_and_hang_up(&mut state, v6_peer(2), true, 9);

    assert_eq!(
        pinged(&state.on_tick(t0() + udp_due())),
        vec![contact(v6_peer(1)), contact(v6_peer(2))]
    );
    let acked = state.on_reask_reply(t0() + udp_due(), contact(v6_peer(2)), &v4_ack(3));
    assert!(matches!(
        the_event(&acked),
        DownloadEvent::SourceReaskAcked { peer, rank: 3, .. } if *peer == v6_peer(2)
    ));
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![v6_peer(1)],
        "the neighbour's standing is its own"
    );
}

/// A ping another download holds the endpoint for is handed back (ADR-0107):
/// its window is looked at again a second later, the ping leaves then, and the
/// TCP full ask still falls due at the period, not a period after.
#[test]
fn a_held_ping_is_retried_in_its_window_and_the_tcp_ask_keeps_its_time() {
    let mut state = standing();
    let due = t0() + udp_due();
    assert_eq!(pinged(&state.on_tick(due)), vec![contact(peer(1))]);
    state.on_ping_held(due, peer(1));
    assert_eq!(state.next_wake(), Some(due + REASK_RECHECK));
    assert_eq!(
        pinged(&state.on_tick(due + REASK_RECHECK)),
        vec![contact(peer(1))]
    );
    assert_eq!(
        asked_by_tcp(&state.on_tick(t0() + FILE_REASK_TIME)),
        vec![peer(1)]
    );
}

/// The bench run where stock aMule 2.3.3 queued rmule and answered its UDP
/// reask (`amule-233-reask-ack-to-rmule-20261001`): the sharer's `0x91` — its
/// complete-source status ahead of rank 1 — lands on the source standing at
/// its contact, and the full ask the silence would have brought does not come.
#[test]
fn the_captured_amule_reask_ack_lands_on_its_source() {
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../rmule-peer/tests/fixtures/peer_udp_reask/captured/amule-233-reask-ack-to-rmule-20261001/"
    );
    let read = |name: &str| std::fs::read(format!("{DIR}{name}")).expect("captured datagram");
    let sharer = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 6), 4662));
    let mut state = started(&[sharer], live_posture());
    let _ = connect(&mut state, t0(), sharer);
    let hello = HelloFacts {
        udp_port: 4672,
        udp_version: 4,
        ..HelloFacts::of(SOURCE)
    };
    let _ = state.on_worker_event(t0(), sharer, PeerWorkerEvent::Identity(hello.identity()));
    let _ = state.on_worker_event(t0(), sharer, PeerWorkerEvent::Queued { rank: 1 });
    let _ = state.on_worker_event(t0(), sharer, PeerWorkerEvent::Disconnected);

    let due = t0() + udp_due();
    assert_eq!(pinged(&state.on_tick(due)), vec![sharer.with_port(4672)]);
    let acked = state.on_reask_reply(
        due + Duration::from_millis(108),
        sharer.with_port(4672),
        &read("reask_ack_0x91.bin"),
    );
    assert!(matches!(
        the_event(&acked),
        DownloadEvent::SourceReaskAcked { peer, rank: 1, .. } if *peer == sharer
    ));
    assert!(state.on_tick(t0() + FILE_REASK_TIME).is_empty());
}

/// A called-back Low-ID source is pinged like any other (stock 2.3.3
/// `DownloadClient.cpp:1269-1296`: no `HasLowID` gate): the `0x90` goes to the
/// address it called in from — aMule's `GetConnectIP()` — at the client-UDP
/// port its hello advertised, and its `0x91` keeps the clock fresh, so no
/// callback is asked for at the period.
#[test]
fn a_called_back_source_is_pinged_at_the_address_it_called_in_from() {
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        live_posture(),
        1,
        no_facts(),
        Vec::new(),
        vec![low_candidate(7)],
    );
    let _ = state.start(t0());
    let inbound = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 51_234));
    let _ = state.on_callback_connected(t0(), connected_key(low(7)), inbound);
    queue_and_hang_up(&mut state, inbound, true, 6);

    let window = t0() + udp_due();
    assert_eq!(pinged(&state.on_tick(window)), vec![contact(inbound)]);
    let heard = state.on_reask_reply(window, contact(inbound), &v4_ack(4));
    assert!(matches!(
        the_event(&heard),
        DownloadEvent::SourceReaskAcked { peer, rank: 4, .. } if *peer == inbound
    ));
    assert!(
        state.on_tick(t0() + FILE_REASK_TIME).is_empty(),
        "an answered ping asks for no callback"
    );
    assert_eq!(state.next_wake(), Some(window + udp_due()));
}

/// A called-back Low-ID source that queued us keeps its `CallbackKey` with its
/// standing (ADR-0090): when its ping goes unanswered, its TCP full ask is a
/// callback again — the road a fresh candidate takes — never a dial at the
/// endpoint it called in from, and the connection that answers is the same
/// record, whose rank is the standing again.
#[test]
fn a_called_back_sources_full_ask_takes_its_callback_road() {
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        live_posture(),
        1,
        no_facts(),
        Vec::new(),
        vec![low_candidate(7)],
    );
    let _ = state.start(t0());
    let inbound = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 51_234));
    let _ = state.on_callback_connected(t0(), connected_key(low(7)), inbound);
    queue_and_hang_up(&mut state, inbound, true, 6);

    let asked = state.on_tick(t0() + FILE_REASK_TIME);
    assert_eq!(asked_by_tcp(&asked), vec![inbound]);
    assert!(
        spawned(&asked).is_empty(),
        "no dial at {inbound}: {asked:?}"
    );
    assert!(
        asked.iter().any(|d| matches!(
            d,
            Decision::RequestCallback { low_id, .. } if *low_id == low(7)
        )),
        "the full ask is a callback: {asked:?}"
    );

    let later = t0() + FILE_REASK_TIME + Duration::from_secs(4);
    let next_inbound = inbound.with_port(51_301);
    let landed = state.on_callback_connected(later, connected_key(low(7)), next_inbound);
    assert!(
        landed.worker_slot.is_some(),
        "adopted into the callback's slot"
    );
    queue_and_hang_up_at(&mut state, next_inbound, true, 2, later);
    assert_eq!(state.known_sources(), 1, "one record throughout");
}
