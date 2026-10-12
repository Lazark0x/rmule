//! The socket unification's Kad arms (ADR-0057): the declared `0xE4`/`0xE5`
//! and the unclaimed byte that may be obfuscated Kad both reach the installed
//! inlet, a Kad datagram on the IPv6 half drops and counts (and so, apart,
//! does an obfuscated one our key cannot open there), an absent node
//! drops without counting, and a full inlet costs its own datagrams and not
//! the reasks queued behind them — nor a full reask inbox the Kad datagram
//! queued behind it.

use rmule_kad::KadInstant;
use rmule_kad::KadNodeStart;
use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, UserHash};

use super::super::super::tests::{a_reask_ping, armed_requesting};
use super::{front_with_kad, front_without_kad, scripted};
use crate::buddy_link::SharedBuddySlot;
use crate::diagnostics::DiagnosticsState;
use tokio::sync::mpsc;

/// One genuinely obfuscated Kad datagram, produced by a real
/// [`KadNode`](rmule_kad::KadNode) with the ADR-0046 datagram crypt armed —
/// never hand-framed, because the whole point of the leg below is that the
/// front cannot tell this from noise and must not try.
fn an_obfuscated_kad_datagram() -> Vec<u8> {
    // A fixed nonce keeps the bytes deterministic; the node still overwrites
    // the marker's low bits with the key-family index, so the leading byte is
    // the node's, not the test's.
    let mut node = rmule_kad::KadNode::new(
        KadNodeStart::new(
            rmule_kad::KadNodeConfig {
                id: rmule_kad::KadId::from_bytes([0x77; rmule_kad::KadId::BYTE_LEN]),
                tcp_port: 4662,
                udp_port: 4672,
                user_hash: UserHash::from_bytes([0x77; UserHash::BYTE_LEN]),
            },
            KadInstant::EPOCH,
        )
        .obfuscation(rmule_kad::KadObfuscation::new(|| {
            rmule_primitives::DatagramNonce {
                marker_byte: 0x40,
                random_key: 0xBEEF,
                padding: Vec::new(),
            }
        })),
    );
    // The NodeID key family needs a *stored* contact of a crypt-era version:
    // that ID is the key. A bootstrap dial to a stranger has none and goes out
    // in the clear, which is not the case this leg is about.
    let peer = rmule_kad::KadId::from_bytes([0x99; rmule_kad::KadId::BYTE_LEN]);
    node.handle_command(
        rmule_kad::KadInstant::from_millis(0),
        rmule_kad::KadCommand::MergeContacts {
            contacts: vec![rmule_kad::KadContact::new(
                peer,
                rmule_kad::KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4672),
                4662,
                8,
            )],
        },
    );
    node.handle_command(
        rmule_kad::KadInstant::from_millis(1),
        rmule_kad::KadCommand::SearchSources {
            request: rmule_kad::KadSourceLookupRequest::new(
                rmule_primitives::SourceLookupTarget::new(
                    FileHash::from_bytes([0x24; FileHash::BYTE_LEN]),
                    1024,
                ),
            ),
        },
    );
    loop {
        match node
            .poll_output()
            .expect("the lookup walk emits a datagram")
        {
            rmule_kad::KadOutput::Datagram { bytes, .. } => return bytes,
            rmule_kad::KadOutput::Event(_) => {}
        }
    }
}

/// The unification's first half: a `0xE4`/`0xE5` datagram on the IPv4 half
/// reaches the running node's inlet, with its source in the Kad vocabulary the
/// node stores contacts in.
#[tokio::test]
async fn declared_kad_datagrams_reach_the_running_node() {
    let src_ip = Ipv4Addr::new(198, 51, 100, 4);
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(src_ip, 4672));
    let plain = vec![0xE4, 0x00, 0x01];
    let packed = vec![0xE5, 0x00, 0x02];
    let ping = a_reask_ping(0x33);
    let (engine, mut inboxes, mut kad) = front_with_kad(
        scripted(vec![
            (src, plain.clone()),
            (src, packed.clone()),
            // The reask surface is unaffected by the Kad arms beside it.
            (src, ping.clone()),
        ]),
        None,
        DiagnosticsState::default(),
        8,
    );
    engine.run().await;

    assert_eq!(
        kad.try_recv(),
        Ok((Ipv4Endpoint::new(src_ip, 4672), plain)),
        "the plaintext Kad datagram reaches the node, tagged with its IPv4 source",
    );
    assert_eq!(
        kad.try_recv(),
        Ok((Ipv4Endpoint::new(src_ip, 4672), packed))
    );
    assert_eq!(inboxes.reask_ping.try_recv(), Ok((src, ping)));
}

/// The unification's harder half: an **obfuscated** Kad datagram opens with
/// the sender's random marker byte, so the front cannot recognise it — it only
/// knows the peer-UDP key missed. It reaches the inlet byte for byte, and the
/// node's own key families are what accept or reject it.
#[tokio::test]
async fn an_obfuscated_kad_datagram_the_peer_key_missed_reaches_the_inlet_unaltered() {
    let obfuscated = an_obfuscated_kad_datagram();
    assert!(
        !matches!(obfuscated[0], 0xC5 | 0xB2 | 0xE4 | 0xE5),
        "an obfuscated Kad datagram claims no protocol byte: {:#04x}",
        obfuscated[0],
    );
    let src_ip = Ipv4Addr::new(198, 51, 100, 5);
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(src_ip, 4672));
    let (engine, _inboxes, mut kad) = front_with_kad(
        scripted(vec![(src, obfuscated.clone())]),
        // Armed: the dual-path receive runs first and must *miss*, leaving the
        // bytes untouched — the magic-value check is what rejects it, not a
        // length or a marker guess.
        Some(armed_requesting(
            UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            [203, 0, 113, 9],
        )),
        DiagnosticsState::default(),
        4,
    );
    engine.run().await;

    assert_eq!(
        kad.try_recv(),
        Ok((Ipv4Endpoint::new(src_ip, 4672), obfuscated)),
        "the node's keys decide, so the front must hand over exactly what arrived",
    );
}

/// Kad is IPv4-only end to end (ADR-0085/0087), so the v6 half of the pair
/// carries no Kad: a declared one there drops and is **counted** as the
/// dialect gap it is, while an unclaimed byte — noise in either family — is
/// dropped silently, the same decode-before-you-count rule the `0x94` arm
/// follows.
#[tokio::test]
async fn a_kad_datagram_on_the_ipv6_half_is_dropped_and_counted() {
    let v6_src = PeerEndpoint::V6(Ipv6Endpoint::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xE),
        4672,
    ));
    let diagnostics = DiagnosticsState::default();
    let (engine, _inboxes, mut kad) = front_with_kad(
        scripted(vec![
            (v6_src, vec![0xE4, 0x00, 0x01]),
            (v6_src, vec![0xE5, 0x00, 0x02]),
            // Unclaimed noise on the v6 half: dropped, never counted.
            (v6_src, vec![0x13, 0x37, 0x42]),
        ]),
        None,
        diagnostics.clone(),
        4,
    );
    engine.run().await;

    assert!(
        kad.try_recv().is_err(),
        "no Kad datagram may reach the node from the IPv6 half"
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .unanswerable_family_datagrams_total,
        2,
        "exactly the two declared Kad datagrams count; the unclaimed byte is noise",
    );
}

/// An obfuscated datagram on the IPv6 half that our key does not open has
/// nowhere else to go — no Kad there — so it is **counted** apart rather than
/// lost as noise: that is where eMuleAI's IPv6 datagrams land, whose 35-byte
/// key leaves a byte unwritten (ADR-0087's divergence note; the primitives'
/// `ipv6_key_kat` pins which derivation opens). A plaintext-marker datagram,
/// one too short for a crypt header, and one our key does open are not.
#[tokio::test]
async fn an_undecryptable_obfuscated_datagram_on_the_ipv6_half_is_counted() {
    use rmule_primitives::{
        ClientEncryptKey, DatagramNonce, DatagramSenderAddress, encrypt_datagram_client,
    };

    let our_hash = UserHash::from_bytes([0x11; UserHash::BYTE_LEN]);
    let their_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xF);
    let v6_src = PeerEndpoint::V6(Ipv6Endpoint::new(their_ip, 4672));
    let ping = a_reask_ping(0x45);
    let sealed = |sender: Ipv6Addr| {
        encrypt_datagram_client(
            &ping,
            &ClientEncryptKey::Ed2k {
                user_hash: &our_hash,
                sender: DatagramSenderAddress::V6(sender.octets()),
            },
            &DatagramNonce {
                marker_byte: 0x41,
                random_key: 0x1234,
                padding: Vec::new(),
            },
        )
    };
    // A key we cannot reproduce: here, keyed on an address that is not the
    // source we observe.
    let unopenable = sealed(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xA));
    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (v6_src, unopenable),
            (v6_src, vec![0xD4, 0x96, 0, 0, 0, 0, 0, 0]),
            (v6_src, vec![0x13, 0x37, 0x42]),
            (v6_src, sealed(their_ip)),
        ]),
        Some(armed_requesting(our_hash, [203, 0, 113, 9])),
        SharedBuddySlot::default(),
        diagnostics.clone(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    assert_eq!(
        inboxes.reask_ping.try_recv(),
        Ok((v6_src, ping)),
        "the datagram our key opens routes as before"
    );
    let session = diagnostics.snapshot().session;
    assert_eq!(session.ipv6_undecryptable_datagrams_total, 1);
    assert_eq!(session.unanswerable_family_datagrams_total, 0);
}

/// With no Kad node running the inlet is empty, which is the honest gate: the
/// datagram is dropped, nothing is counted as lost — there was nothing to lose
/// it to — and the reask surface beside it is untouched.
#[tokio::test]
async fn kad_datagrams_are_dropped_uncounted_while_no_node_runs() {
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 6), 4672));
    let ping = a_reask_ping(0x44);
    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes) = front_without_kad(
        scripted(vec![
            (src, vec![0xE4, 0x00, 0x01]),
            (src, an_obfuscated_kad_datagram()),
            (src, ping.clone()),
        ]),
        None,
        SharedBuddySlot::default(),
        diagnostics.clone(),
        mpsc::channel(4).0,
    );
    engine.run().await;

    assert_eq!(inboxes.reask_ping.try_recv(), Ok((src, ping)));
    let session = diagnostics.snapshot().session;
    assert_eq!(session.kad_inlet_drops_total, 0);
    assert_eq!(session.unanswerable_family_datagrams_total, 0);
}

/// The Kad inlet never back-pressures the socket it shares: it drops and
/// counts, exactly as the NAT-T inbox does, so a busy Kad node cannot cost
/// every reask queued behind it. The ping sent *after* the overflow is the
/// proof.
#[tokio::test]
async fn a_full_kad_inlet_drops_without_stalling_the_reask_path() {
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4672));
    let ping = a_reask_ping(0x55);
    let capacity = 4;
    let overflow = capacity + 6;
    let mut script: Vec<_> = std::iter::repeat_n((src, vec![0xE4, 0x00, 0x01]), overflow).collect();
    script.push((src, ping.clone()));

    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes, _kad) =
        front_with_kad(scripted(script), None, diagnostics.clone(), capacity);
    // Nothing drains the inlet: the front must still finish its script.
    engine.run().await;

    assert_eq!(inboxes.reask_ping.try_recv(), Ok((src, ping)));
    assert_eq!(
        diagnostics.snapshot().session.kad_inlet_drops_total,
        (overflow - capacity) as u64,
    );
}

/// The reverse direction, and the one a stranger controls: the `0x90` inbox is
/// parked unpolled until `StartServing` (and again after `StopServing`), so
/// seventeen spoofable pings used to fill it and park the front on an
/// awaiting send — taking Kad, NAT-T and every reply down with it. Now the
/// surplus pings and replies drop and count, and the Kad datagram behind them
/// still reaches the node.
#[tokio::test]
async fn an_undrained_reask_inbox_drops_and_counts_without_stalling_kad() {
    let src_ip = Ipv4Addr::new(198, 51, 100, 8);
    let src = PeerEndpoint::V4(Ipv4Endpoint::new(src_ip, 4672));
    let flood: u8 = 20;
    let mut script: Vec<_> = (0..flood).map(|i| (src, a_reask_ping(i))).collect();
    script.extend(std::iter::repeat_n(
        (src, rmule_peer::queue_full_datagram()),
        usize::from(flood),
    ));
    let kad_datagram = vec![0xE4, 0x00, 0x01];
    script.push((src, kad_datagram.clone()));

    let diagnostics = DiagnosticsState::default();
    let (engine, mut inboxes, mut kad) =
        front_with_kad(scripted(script), None, diagnostics.clone(), 4);
    // Neither reask inbox is drained while the front runs: nobody is serving
    // and no download pool is installed.
    tokio::time::timeout(std::time::Duration::from_secs(5), engine.run())
        .await
        .expect("the front finishes its script with both reask inboxes full");

    assert_eq!(
        kad.try_recv(),
        Ok((Ipv4Endpoint::new(src_ip, 4672), kad_datagram)),
        "the Kad datagram behind the flood reaches the node",
    );
    let mut queued = 0_u64;
    while inboxes.reask_ping.try_recv().is_ok() {
        queued += 1;
    }
    let dropped = diagnostics.snapshot().session.peer_udp_inbox_drops_total;
    assert_eq!(dropped, 2 * (u64::from(flood) - queued));
    assert!(dropped > 0, "the flood overran the parked inbox");
}
