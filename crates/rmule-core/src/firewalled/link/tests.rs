//! The enacted firewalled slot's decisions, driven with explicit time and no
//! socket as its one owner drives it: what fills it, what empties it, what it
//! publishes, and how each of the three inlets is ruled on against the buddy
//! it holds.

use std::net::Ipv4Addr;

use rmule_peer::ReaskCallbackTcp;
use rmule_peer::natt::{NattConnectOptions, PunchTargetSource, RendezvousBody, RendezvousTrigger};
use rmule_primitives::UserHash;

use super::*;
use crate::adapters::tests::held_buddy::{a_buddy, adopt};
use crate::firewalled::front::SharedFirewalledFront;
use crate::firewalled::relayed_callback::CallbackDrop;

fn kad_id(byte: u8) -> KadId {
    KadId::from_bytes([byte; KadId::BYTE_LEN])
}

/// `~0xAA == 0x55`: the walk target a node of ID `0xAA…` recruits toward, and
/// the buddy-ID every answer for it echoes.
fn our_id() -> KadId {
    kad_id(0xAA)
}

fn at(a: u8, b: u8, c: u8, d: u8, port: u16) -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), port)
}

/// The connection identity the dialed link is matched on: the buddy's address
/// at the port we dialed.
fn buddy_link() -> PeerEndpoint {
    PeerEndpoint::V4(a_buddy().tcp)
}

/// A fresh slot for our ID, publishing into a front's snapshot nothing else
/// reads.
fn new_slot() -> FirewalledSlot {
    SharedFirewalledFront::detached_slot(our_id()).0
}

/// The slot's state and, while a link is held, since when — as it publishes
/// them.
fn state(slot: &FirewalledSlot) -> (BuddyState, Option<Instant>) {
    let snapshot = slot.snapshot();
    (snapshot.state, snapshot.held_since)
}

/// Adopt and hold — the whole path to a live link, as the front drives it.
/// Returns the held link's command receiver.
fn held(slot: &mut FirewalledSlot, now: Instant) -> mpsc::Receiver<PeerCommand> {
    held_over(slot, now, buddy_link(), None)
}

/// [`held`], over `remote`, with the buddy's hello having claimed `claimed`.
fn held_over(
    slot: &mut FirewalledSlot,
    now: Instant,
    remote: PeerEndpoint,
    claimed: Option<std::net::Ipv6Addr>,
) -> mpsc::Receiver<PeerCommand> {
    assert_eq!(
        slot.adopt_buddy(
            &FindBuddyRes {
                buddy_id: kad_id(0x55),
                buddy_endpoint: a_buddy().udp,
            },
            a_buddy(),
            CryptStance::disabled(),
        ),
        AdoptOutcome::Adopted
    );
    let (tx, rx) = mpsc::channel(8);
    assert!(slot.hold_link(a_buddy(), remote, tx, claimed, now));
    rx
}

/// A `0x9A` as our buddy frames it: the requester it observed, then the
/// forwarded tail verbatim.
fn relay(forwarded: Vec<u8>) -> ReaskCallbackTcp {
    ReaskCallbackTcp {
        requester: PeerEndpoint::V4(at(45, 55, 200, 7, 5000)),
        forwarded,
    }
}

/// A rendezvous body claiming uTP and nothing else.
fn rendezvous() -> RendezvousBody {
    RendezvousBody {
        requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
        options: NattConnectOptions::from_byte(0x80),
        file_hash: None,
        claimed_endpoint: None,
        transport_hint: None,
    }
}

/// The forwarded tail an embedded rendezvous rides in — exactly the bytes a
/// buddy copies out of the `0x94` it relayed.
fn embedded_rendezvous() -> Vec<u8> {
    rendezvous().embed([0x55; 16]).forwarded
}

/// Every change reaches the readers as one snapshot: adopted, the buddy row
/// a publish names; held, the hello's advert from the link it runs to;
/// lost, nothing named and the loss stamped — what re-arms the walk at once.
#[test]
fn every_change_is_published_to_the_readers() {
    let (mut slot, view) = SharedFirewalledFront::detached_slot(our_id());
    let t0 = Instant::now();
    assert_eq!(view.snapshot(), BuddySnapshot::default());

    adopt(&mut slot);
    let adopted = view.snapshot();
    assert_eq!(adopted.state, BuddyState::Recruited);
    assert_eq!(
        adopted.publish,
        Some(crate::firewalled::BuddyPublish {
            buddy_udp: a_buddy().udp,
            buddy_id: kad_id(0x55),
            buddy_ipv6: None,
        })
    );
    assert_eq!(
        adopted.serving, None,
        "aMule names a buddy only once linked"
    );

    let (tx, _rx) = mpsc::channel(8);
    assert!(slot.hold_link(a_buddy(), buddy_link(), tx, None, t0));
    let held = view.snapshot();
    assert_eq!((held.state, held.held_since), (BuddyState::Held, Some(t0)));
    assert_eq!(
        held.serving,
        Some(rmule_peer::ServingBuddyAdvert {
            buddy_udp: a_buddy().udp,
            ipv6: None,
        })
    );

    let t1 = t0 + Duration::from_secs(5);
    assert!(slot.on_link_closed(buddy_link(), t1));
    assert_eq!(
        view.snapshot(),
        BuddySnapshot {
            lost_at: Some(t1),
            ..BuddySnapshot::default()
        }
    );
}

#[test]
fn losing_the_link_empties_the_slot_and_stamps_the_loss() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let _rx = held(&mut slot, t0);
    assert_eq!(state(&slot), (BuddyState::Held, Some(t0)));
    assert_eq!(slot.buddy(), Some(a_buddy()));

    // Somebody else's connection closing leaves the held link alone.
    let t1 = t0 + Duration::from_secs(1);
    assert!(!slot.on_link_closed(PeerEndpoint::V4(at(45, 55, 200, 9, 4662)), t1));
    assert_eq!(state(&slot).0, BuddyState::Held);
    assert_eq!(slot.snapshot().lost_at, None);

    // The buddy's does not: the slot empties and the loss is stamped, which
    // is what the recruit rule reads as aMule's FindBuddy tick reset.
    assert!(slot.on_link_closed(buddy_link(), t1));
    assert_eq!(state(&slot), (BuddyState::None, None));
    assert_eq!(slot.buddy(), None);
    assert_eq!(slot.snapshot().lost_at, Some(t1));
}

/// A buddy whose `0x5A` connect-options byte *requires* the crypt
/// layer (`0x07`), met by a node whose layer is off, is refused unseated —
/// aMule seats the byte (`ClientList.cpp:1144`) and its
/// `CheckContactPreconditions` then deletes the client before any dial
/// (`BaseClient.cpp:1913-1919`). Nothing is held to dial, publish or name.
/// The same answer, met by a node that speaks the layer, seats.
#[test]
fn a_buddy_requiring_crypt_we_cannot_speak_is_refused_unseated() {
    let mut slot = new_slot();
    let requiring = RecruitedBuddy {
        crypt: Some(rmule_primitives::SourceCryptOptions::from_byte(0x07).crypt_stance()),
        ..a_buddy()
    };
    let res = FindBuddyRes {
        buddy_id: kad_id(0x55),
        buddy_endpoint: requiring.udp,
    };

    assert_eq!(
        slot.adopt_buddy(&res, requiring, CryptStance::disabled()),
        AdoptOutcome::CryptIncompatible
    );
    assert_eq!(slot.buddy(), None);
    assert_eq!(slot.snapshot(), BuddySnapshot::default());

    let supports = CryptStance::new(true, false, false);
    assert_eq!(
        slot.adopt_buddy(&res, requiring, supports),
        AdoptOutcome::Adopted
    );
    assert_eq!(slot.buddy(), Some(requiring));
}

/// A failed dial frees the slot only while it holds the buddy that dial was
/// for, with no link up: a late failure must not throw away a
/// buddy adopted since, nor one whose link another dial already holds.
#[test]
fn a_failed_dial_frees_only_its_own_unlinked_buddy() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    adopt(&mut slot);

    // A dial for a buddy the slot no longer holds frees nothing.
    let gone = RecruitedBuddy {
        tcp: at(45, 55, 200, 9, 4662),
        ..a_buddy()
    };
    assert!(!slot.on_dial_failed(gone, t0));
    assert_eq!(slot.buddy(), Some(a_buddy()));
    assert!(slot.snapshot().holds_buddy());
    assert_eq!(slot.snapshot().lost_at, None);

    // Its own buddy's failure frees the slot and stamps the loss, which arms
    // an instant recruit.
    assert!(slot.on_dial_failed(a_buddy(), t0));
    assert_eq!(state(&slot), (BuddyState::None, None));
    assert_eq!(slot.snapshot().lost_at, Some(t0));

    // A held link is never a failed dial's to free.
    let mut fresh = new_slot();
    let _rx = held(&mut fresh, t0);
    assert!(!fresh.on_dial_failed(a_buddy(), t0));
    assert_eq!(state(&fresh), (BuddyState::Held, Some(t0)));
}

/// A second link landing for the buddy already held is refused and the first
/// stays: two dials to one buddy both land `Held`, and holding
/// the second replaced the link the keepalive and the relays were bound to.
#[test]
fn a_second_link_for_the_held_buddy_is_refused_and_the_first_kept() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let _first = held(&mut slot, t0);

    let (second, _second_rx) = mpsc::channel(8);
    let t1 = t0 + Duration::from_secs(1);
    assert!(!slot.hold_link(a_buddy(), buddy_link(), second.clone(), None, t1));

    assert_eq!(state(&slot), (BuddyState::Held, Some(t0)));
    let keepalive = slot
        .due_keepalive(t0 + BUDDY_PING_INTERVAL)
        .expect("the first link is still paced from its own hold");
    assert!(!keepalive.same_channel(&second));
}

/// A dial claims its buddy until it lands — held, failed, or refused because
/// the buddy was let go meanwhile. A claim outliving its dial
/// would refuse every later dial to that buddy, leaving it adopted and never
/// linked.
#[test]
fn a_dial_claims_its_buddy_until_it_lands_however_it_lands() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    adopt(&mut slot);
    assert!(slot.begin_dial(a_buddy()));
    assert!(!slot.begin_dial(a_buddy()), "one dial per buddy in flight");

    // Let go mid-dial: the late landing is refused, and ends the claim.
    assert!(slot.release(t0).is_none());
    let (tx, _rx) = mpsc::channel(8);
    assert!(!slot.hold_link(a_buddy(), buddy_link(), tx.clone(), None, t0));
    adopt(&mut slot);
    assert!(
        slot.begin_dial(a_buddy()),
        "a refused landing ends its claim"
    );

    // A dial for a buddy since let go leaves this one's claim alone.
    let stranger = RecruitedBuddy {
        tcp: at(45, 55, 200, 9, 4662),
        ..a_buddy()
    };
    assert!(!slot.hold_link(stranger, buddy_link(), tx.clone(), None, t0));
    assert!(!slot.begin_dial(a_buddy()));

    assert!(slot.on_dial_failed(a_buddy(), t0));
    adopt(&mut slot);
    assert!(slot.begin_dial(a_buddy()), "a failed dial ends its claim");
    assert!(slot.hold_link(a_buddy(), buddy_link(), tx, None, t0));
    assert!(slot.on_link_closed(buddy_link(), t0));
    adopt(&mut slot);
    assert!(slot.begin_dial(a_buddy()), "a held dial ends its claim");
}

#[test]
fn becoming_reachable_releases_the_buddy_and_hands_back_its_link() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let _rx = held(&mut slot, t0);

    // The release hands the caller the link's command half so the front can
    // shut that socket rather than leave a stranger holding it open.
    assert!(slot.release(t0).is_some());
    assert_eq!(state(&slot), (BuddyState::None, None));
    // Releasing twice is a no-op with nothing to hand back.
    assert!(slot.release(t0).is_none());
}

#[test]
fn the_keepalive_fires_once_per_interval_on_the_held_link_only() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    assert!(
        slot.due_keepalive(t0).is_none(),
        "nothing to keep alive without a link"
    );
    let _rx = held(&mut slot, t0);

    assert!(
        slot.due_keepalive(t0).is_none(),
        "the hold is the first ping"
    );
    assert!(
        slot.due_keepalive(t0 + BUDDY_PING_INTERVAL / 2).is_none(),
        "half an interval is not due"
    );
    assert!(slot.due_keepalive(t0 + BUDDY_PING_INTERVAL).is_some());
    assert!(
        slot.due_keepalive(t0 + BUDDY_PING_INTERVAL).is_none(),
        "one due instant yields one ping"
    );
    assert!(
        slot.due_keepalive(t0 + BUDDY_PING_INTERVAL * 2).is_some(),
        "and the clock restarts from the ping that went out"
    );
}

#[test]
fn a_relayed_reask_is_split_by_its_forwarded_tail() {
    let mut slot = new_slot();
    let t0 = Instant::now();

    // With no link held nothing can have been relayed to us at all.
    assert_eq!(
        slot.consume_reask_relay(relay(vec![0xDE, 0xAD]), false, |_| false, t0),
        ReaskRelayConsume::NoHeldLink
    );

    let _rx = held(&mut slot, t0);
    // An ordinary tail is handed on verbatim, with the endpoint the buddy
    // injected as the answer's destination.
    assert_eq!(
        slot.consume_reask_relay(relay(vec![0xDE, 0xAD]), false, |_| false, t0),
        ReaskRelayConsume::Reask {
            requester: PeerEndpoint::V4(at(45, 55, 200, 7, 5000)),
            forwarded: vec![0xDE, 0xAD],
        }
    );

    // A tail carrying the marker is the acting path's, and aims at what the
    // buddy observed rather than at anything the requester claimed.
    assert_eq!(
        slot.consume_reask_relay(relay(embedded_rendezvous()), false, |_| false, t0),
        ReaskRelayConsume::Rendezvous(ActingVerdict::Punch {
            requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            file_hash: None,
            target: rmule_peer::natt::PunchTarget {
                endpoint: at(45, 55, 200, 7, 5000),
                source: PunchTargetSource::Observed,
            },
            transport: rmule_peer::natt::NattTransport::Utp,
            trigger: RendezvousTrigger::RendezvousAnswer,
        })
    );

    // A tail that claims the marker and is malformed is never answered as a
    // reask — that would forward a null file hash for us to answer.
    // Truncated *past* the marker: still a claim, and now unreadable. (The
    // marker is a null file hash plus the `0xA0` opcode, so keeping 17 bytes
    // keeps the claim and drops the body.)
    let mut broken = embedded_rendezvous();
    broken.truncate(17);
    assert_eq!(
        slot.consume_reask_relay(relay(broken), false, |_| false, t0),
        ReaskRelayConsume::MalformedRendezvous
    );
}

#[test]
fn the_self_punch_guard_is_asked_on_the_relayed_path_too() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let _rx = held(&mut slot, t0);
    // Correction 4: whatever resolved the target, an address this host holds
    // is never punched at.
    assert_eq!(
        slot.consume_reask_relay(
            relay(embedded_rendezvous()),
            false,
            |ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(45, 55, 200, 7)),
            t0,
        ),
        ReaskRelayConsume::Rendezvous(ActingVerdict::Refuse(ActingRefusal::SelfPunch))
    );
}

#[test]
fn a_standalone_rendezvous_is_held_to_our_buddys_whole_udp_endpoint() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let refused = ActingVerdict::Refuse(ActingRefusal::NotFromOurBuddy);
    let body = RendezvousBody {
        claimed_endpoint: Some(at(45, 55, 200, 66, 9999)),
        ..rendezvous()
    };

    // No buddy: nothing can have been relayed to us.
    assert_eq!(
        slot.consume_standalone_rendezvous(
            &body,
            PeerEndpoint::V4(a_buddy().udp),
            false,
            |_| false,
            t0,
        ),
        refused
    );

    // A buddy adopted but its link not yet held is no live relation: the
    // standalone carrier needs the link the `0x9A` carrier arrives on.
    adopt(&mut slot);
    assert_eq!(
        slot.consume_standalone_rendezvous(
            &body,
            PeerEndpoint::V4(a_buddy().udp),
            false,
            |_| false,
            t0,
        ),
        refused
    );

    let (tx, _rx) = mpsc::channel(8);
    assert!(slot.hold_link(a_buddy(), buddy_link(), tx, None, t0));
    // A datagram has no connection behind it, so the whole endpoint must
    // match — the buddy's address at the wrong port is a stranger.
    assert_eq!(
        slot.consume_standalone_rendezvous(
            &body,
            PeerEndpoint::V4(at(45, 55, 200, 2, 4673)),
            false,
            |_| false,
            t0,
        ),
        refused
    );
    assert!(matches!(
        slot.consume_standalone_rendezvous(
            &body,
            PeerEndpoint::V4(a_buddy().udp),
            false,
            |_| false,
            t0,
        ),
        ActingVerdict::Punch {
            target: rmule_peer::natt::PunchTarget {
                source: PunchTargetSource::PublicClaim,
                ..
            },
            ..
        }
    ));
}

#[test]
fn a_relayed_callback_needs_a_link_and_an_id_that_inverts_to_ours() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let good = CallbackConsume {
        check_id: kad_id(0x55),
        file_shared_or_downloading: true,
        requester: at(45, 55, 200, 7, 4662),
    };

    // A `0x99` with no held link cannot have come from our buddy — our own
    // state, distinct from a genuine wrong-address relay.
    assert_eq!(
        slot.consume_callback(&good, true),
        CallbackVerdict::Drop {
            reason: CallbackDrop::NoBuddyHeld
        }
    );

    let _rx = held(&mut slot, t0);
    assert_eq!(
        slot.consume_callback(&good, true),
        CallbackVerdict::Dial {
            requester: at(45, 55, 200, 7, 4662),
            swapped_spelling: false
        }
    );
    assert_eq!(
        slot.consume_callback(
            &CallbackConsume {
                check_id: kad_id(0x12),
                ..good
            },
            true,
        ),
        CallbackVerdict::Drop {
            reason: CallbackDrop::NotForUs
        }
    );
    assert_eq!(
        slot.consume_callback(&good, false),
        CallbackVerdict::Drop {
            reason: CallbackDrop::KadDown
        }
    );
}

#[test]
fn a_kad_restart_re_seats_the_slot_against_the_new_nodes_id() {
    let mut slot = new_slot();
    let t0 = Instant::now();
    let _rx = held(&mut slot, t0);
    assert!(slot.release(t0).is_some());

    // A restart with a different node ID drops everything the old one had,
    // its loss included: a `0x5A` verified against `~0xAA` says nothing about
    // `~0x33`.
    slot.reseat(kad_id(0x33));
    assert_eq!(slot.snapshot(), BuddySnapshot::default());
    assert_eq!(
        slot.adopt_buddy(
            &FindBuddyRes {
                buddy_id: kad_id(0x55),
                buddy_endpoint: a_buddy().udp,
            },
            a_buddy(),
            CryptStance::disabled(),
        ),
        AdoptOutcome::Rejected
    );
    assert_eq!(
        slot.adopt_buddy(
            &FindBuddyRes {
                buddy_id: kad_id(0xCC),
                buddy_endpoint: a_buddy().udp,
            },
            a_buddy(),
            CryptStance::disabled(),
        ),
        AdoptOutcome::Adopted,
        "~0xCC == 0x33"
    );
}

/// The `bi6` the publish names is the held link's fact. A buddy
/// adopted but not yet held has none; holding the link over IPv4 names the
/// IPv6 its hello claimed; a link verified over a usable IPv6 names that
/// address instead of the claim; and the address leaves with the link.
#[test]
fn the_publish_names_the_held_links_buddy_ipv6_and_drops_it_with_the_link() {
    let claimed: std::net::Ipv6Addr = "3fff:ed2:1::8".parse().unwrap();
    let verified: std::net::Ipv6Addr = "3fff:ed2:1::9".parse().unwrap();
    let bi6 = |slot: &FirewalledSlot| slot.snapshot().publish.map(|p| p.buddy_ipv6);
    let t0 = Instant::now();

    let mut slot = new_slot();
    adopt(&mut slot);
    assert_eq!(
        bi6(&slot),
        Some(None),
        "recruited, not held: no link, no bi6"
    );

    let (tx, _rx) = mpsc::channel(8);
    assert!(slot.hold_link(a_buddy(), buddy_link(), tx, Some(claimed), t0));
    assert_eq!(bi6(&slot), Some(Some(claimed)));

    assert!(slot.on_link_closed(buddy_link(), t0));
    assert!(slot.snapshot().publish.is_none());

    let over_v6 = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(verified, 4662));
    let mut slot = new_slot();
    let _rx = held_over(&mut slot, t0, over_v6, Some(claimed));
    assert_eq!(bi6(&slot), Some(Some(verified)), "verified beats claimed");

    let over_ula = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(
        "fd00::9".parse().unwrap(),
        4662,
    ));
    let mut slot = new_slot();
    let _rx = held_over(&mut slot, t0, over_ula, Some(claimed));
    assert_eq!(
        bi6(&slot),
        Some(Some(claimed)),
        "a link address no tag may name falls back to the claim"
    );
}
