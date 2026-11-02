//! ADR-0064 entry gates: the per-`(IP, opcode)` leaky flood limiter, the
//! port-53 DNS-confusion guard, and the 180 s bootstrap solicitation window
//! — driven purely through `KadNode`'s explicit-time surface, exactly like
//! `tests/node.rs`.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::opcode::KADEMLIA2_HELLO_REQ;
use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadEvent, KadNode, KadNodeDiagnostic, KadNodeEndpoint,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{
    T0, crypt_node, crypt_to_node, datagrams, deliver, diagnostics, drain_outputs, endpoint,
    events, id, node, our_key_for, sent_messages,
};

/// A LAN sender (RFC 1918) — the flood table's bypass case.
fn lan_endpoint(host: u8, port: u16) -> KadNodeEndpoint {
    KadNodeEndpoint::new(Ipv4Addr::new(192, 168, 1, host), port)
}

fn hello(id_byte: u8) -> Kad2Message {
    Kad2Message::HelloReq(Kad2NodeInfo {
        id: id(id_byte),
        tcp_port: 4761,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    })
}

fn bootstrap_res(id_byte: u8) -> Kad2Message {
    Kad2Message::BootstrapRes {
        sender: Kad2NodeInfo {
            id: id(id_byte),
            tcp_port: 4761,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        },
        contacts: vec![],
    }
}

// ---- Port-53 gate (absence-plus-positive-control shape, ADR-0045) ----

#[test]
fn port_53_datagram_is_dropped_before_any_decode() {
    let mut node = node();
    let from = KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, 9), 53);
    deliver(&mut node, T0, from, &Kad2Message::Ping);

    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::Port53Dropped { from }]
    );
    assert!(
        sent_messages(&outputs).is_empty(),
        "no pong for a port-53 datagram"
    );
}

#[test]
fn the_same_datagram_from_an_ordinary_port_is_answered() {
    // The positive control pairing the drop above: identical message, only
    // the source port differs.
    let mut node = node();
    let from = endpoint(9, 4909);
    deliver(&mut node, T0, from, &Kad2Message::Ping);

    let outputs = drain(|| node.poll_output());
    assert!(diagnostics(&outputs).is_empty());
    assert_eq!(
        sent_messages(&outputs),
        vec![(from, Kad2Message::Pong { udp_port: 4909 })]
    );
}

// ---- Flood limiter: fill / drop / offender-threshold boundaries ----

#[test]
fn flood_bucket_admits_up_to_rate_drops_above_and_reports_offender_at_five_times_rate() {
    // HELLO_REQ allows 3/minute (ADR-0064); the report threshold is
    // 5 x rate = 15.
    let mut node = node();
    let from = endpoint(4, 4704);

    for n in 1..=3u32 {
        deliver(&mut node, T0, from, &hello(0x40));
        let outputs = drain(|| node.poll_output());
        assert!(
            !sent_messages(&outputs).is_empty(),
            "request {n} is within the 3/min allowance"
        );
        assert!(diagnostics(&outputs).is_empty());
    }

    for n in 4..=15u32 {
        deliver(&mut node, T0, from, &hello(0x40));
        let outputs = drain(|| node.poll_output());
        assert!(
            sent_messages(&outputs).is_empty(),
            "request {n} is over the rate"
        );
        assert_eq!(
            events(&outputs),
            vec![KadEvent::Diagnostic(KadNodeDiagnostic::FloodLimited {
                from,
                opcode: KADEMLIA2_HELLO_REQ
            })],
            "request {n} drops without yet crossing the 5x offender threshold"
        );
    }

    // The 16th push crosses count > 15: the offender event joins the drop.
    deliver(&mut node, T0, from, &hello(0x40));
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        events(&outputs),
        vec![
            KadEvent::Diagnostic(KadNodeDiagnostic::FloodLimited {
                from,
                opcode: KADEMLIA2_HELLO_REQ
            }),
            KadEvent::FloodOffenderDetected {
                ip: from.ip(),
                opcode: KADEMLIA2_HELLO_REQ,
                proven: false,
            },
        ]
    );
}

/// The offender reports among `outputs`, as `proven`.
fn offender_reports(outputs: &[rmule_kad::KadOutput]) -> Vec<bool> {
    events(outputs)
        .into_iter()
        .filter_map(|event| match event {
            KadEvent::FloodOffenderDetected { proven, .. } => Some(proven),
            _ => None,
        })
        .collect()
}

fn keyed_ping(peer: KadNodeEndpoint) -> Vec<u8> {
    crypt_to_node(
        &Kad2Message::Ping.encode().encode(),
        our_key_for(peer),
        0xB00F_B00F,
    )
}

/// ADR-0064: a valid receiver key proves the sender receives at the address,
/// so a flood of them is an offence the address itself committed.
#[test]
fn a_flood_of_valid_receiver_keys_reports_a_proven_offender() {
    let mut node = crypt_node();
    let from = endpoint(5, 4705);
    let mut reports = Vec::new();

    for _ in 0..11 {
        node.handle_datagram(T0, from, &keyed_ping(from));
        reports.extend(offender_reports(&drain_outputs(&mut node)));
    }

    assert_eq!(reports, vec![true]);
}

/// The two-byte datagram that crosses `5 × rate` costs a forger nothing, and
/// no trailer means no proof, armed or not.
#[test]
fn six_forged_two_byte_datagrams_report_an_unproven_offender() {
    let mut node = crypt_node();
    let victim = endpoint(5, 4705);
    let mut reports = Vec::new();

    for _ in 0..6 {
        node.handle_datagram(T0, victim, &[0xE4, 0x52]);
        reports.extend(offender_reports(&drain_outputs(&mut node)));
    }

    assert_eq!(reports, vec![false]);
}

/// A forger filling the victim's bucket must not make the victim's own keyed
/// datagram the proven one that crosses, nor cost it its allowance.
#[test]
fn a_forged_plaintext_flood_leaves_the_keyed_senders_bucket_untouched() {
    let mut node = crypt_node();
    let victim = endpoint(5, 4705);
    let forged = Kad2Message::Ping.encode().encode();
    for _ in 0..30 {
        node.handle_datagram(T0, victim, &forged);
    }
    drain_outputs(&mut node);

    node.handle_datagram(T0, victim, &keyed_ping(victim));
    let outputs = drain_outputs(&mut node);

    assert_eq!(offender_reports(&outputs), Vec::<bool>::new());
    assert_eq!(datagrams(&outputs).len(), 1, "the keyed ping is answered");
}

/// Under the Hush a datagram that proves nothing stops, and the one that
/// proves a round trip goes on: the forger costs the victim its plaintext
/// and no more.
#[test]
fn a_hushed_address_is_heard_only_by_its_valid_receiver_key() {
    let mut node = crypt_node();
    let from = endpoint(5, 4705);
    let plain = Kad2Message::Ping.encode().encode();

    node.handle_hushed_datagram(T0, from, &plain);
    let outputs = drain_outputs(&mut node);
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::HushedDropped { from }]
    );
    assert!(datagrams(&outputs).is_empty());

    node.handle_hushed_datagram(
        T0,
        from,
        &crypt_to_node(&plain, our_key_for(from) ^ 1, 0xB00F_B00F),
    );
    let outputs = drain_outputs(&mut node);
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::HushedDropped { from }],
        "another address's key proves nothing"
    );

    node.handle_hushed_datagram(T0, from, &keyed_ping(from));
    assert_eq!(
        datagrams(&drain_outputs(&mut node)).len(),
        1,
        "the keyed ping is answered"
    );
}

#[test]
fn flood_bucket_leaks_one_count_per_interval_and_re_admits() {
    // rate = 3 -> leak interval = 60 / 3 = 20s (increment-before-check,
    // decay verbatim per ADR-0064). Fill to exactly the cap at T0 —
    // all three admitted, count == 3.
    let mut node = node();
    let from = endpoint(4, 4704);

    for _ in 1..=3u32 {
        deliver(&mut node, T0, from, &hello(0x40));
        drain(|| node.poll_output());
    }

    // 20s later exactly one count has leaked (3 -> 2); the increment brings
    // it right back to the cap (3) — still within the allowance.
    let leaked = T0 + Duration::from_secs(20);
    deliver(&mut node, leaked, from, &hello(0x40));
    let outputs = drain(|| node.poll_output());
    assert!(
        !sent_messages(&outputs).is_empty(),
        "one slot freed by the leak"
    );
    assert!(diagnostics(&outputs).is_empty());

    // A second request at the very same instant re-exceeds the limit: no
    // further decay has happened since the leak above, so this increment
    // pushes past the cap again.
    deliver(&mut node, leaked, from, &hello(0x40));
    let outputs = drain(|| node.poll_output());
    assert!(sent_messages(&outputs).is_empty());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::FloodLimited {
            from,
            opcode: KADEMLIA2_HELLO_REQ
        }]
    );
}

#[test]
fn lan_sender_bypasses_the_flood_table_entirely() {
    let mut node = node();
    let from = lan_endpoint(4, 4704);
    for n in 1..=20u32 {
        deliver(&mut node, T0, from, &hello(0x40));
        let outputs = drain(|| node.poll_output());
        assert!(
            !sent_messages(&outputs).is_empty(),
            "request {n} from a LAN sender is never limited"
        );
        assert!(diagnostics(&outputs).is_empty());
    }
}

#[test]
fn response_opcodes_are_never_flood_tracked() {
    // PONG is a response; the ADR states responses are untracked
    // (solicitation correlation owns those). Sending far more than any
    // request rate never yields a `FloodLimited` diagnostic — only the
    // pre-existing "unsolicited" diagnostic, proving every datagram reached
    // dispatch untouched by the flood gate.
    let mut node = node();
    let from = endpoint(6, 4906);
    for _ in 1..=20u32 {
        deliver(&mut node, T0, from, &Kad2Message::Pong { udp_port: 4672 });
    }
    let outputs = drain(|| node.poll_output());
    // 20 unsolicited-pong diagnostics — a pong we never pinged for states no
    // port — plus the one silent→heard edge the first accepted
    // datagram emits (`HadContact`).
    assert_eq!(outputs.len(), 21);
    assert!(
        diagnostics(&outputs)
            .iter()
            .all(|d| matches!(d, KadNodeDiagnostic::UnsolicitedPong { .. })),
        "never a FloodLimited diagnostic for a response opcode: {:?}",
        diagnostics(&outputs)
    );
}

// ---- 180 s single-use bootstrap solicitation alignment ----

#[test]
fn bootstrap_solicitation_still_matches_just_inside_the_180s_window() {
    let mut node = node();
    let from = endpoint(2, 4702);
    node.handle_command(T0, KadCommand::Bootstrap { endpoint: from });
    drain(|| node.poll_output());

    let almost = T0 + (KadNode::BOOTSTRAP_SOLICITATION_WINDOW - Duration::from_millis(1));
    deliver(&mut node, almost, from, &bootstrap_res(0x20));
    let outputs = drain(|| node.poll_output());
    assert!(
        diagnostics(&outputs).is_empty(),
        "still within the 180s window"
    );
    assert!(node.routing_table().get(id(0x20)).is_some());
}

#[test]
fn bootstrap_solicitation_expires_unmatched_at_the_180s_deadline() {
    let mut node = node();
    let from = endpoint(2, 4702);
    node.handle_command(T0, KadCommand::Bootstrap { endpoint: from });
    drain(|| node.poll_output());
    assert_eq!(
        node.next_wake(),
        Some(T0 + KadNode::BOOTSTRAP_SOLICITATION_WINDOW)
    );

    node.tick(T0 + KadNode::BOOTSTRAP_SOLICITATION_WINDOW);
    assert!(
        drain(|| node.poll_output()).is_empty(),
        "the expiry itself is silent: nothing was ever added for it"
    );

    // A response arriving after expiry is now unsolicited — the mechanism
    // ADR-0064 asks for: a bounded acceptance window.
    deliver(
        &mut node,
        T0 + KadNode::BOOTSTRAP_SOLICITATION_WINDOW,
        from,
        &bootstrap_res(0x20),
    );
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::UnsolicitedBootstrapRes { from }]
    );
    assert!(
        node.routing_table().is_empty(),
        "a late response is never accepted"
    );
}

#[test]
fn a_matched_bootstrap_solicitation_is_single_use() {
    let mut node = node();
    let from = endpoint(2, 4702);
    node.handle_command(T0, KadCommand::Bootstrap { endpoint: from });
    drain(|| node.poll_output());

    deliver(&mut node, T0, from, &bootstrap_res(0x20));
    drain(|| node.poll_output());
    assert!(node.routing_table().get(id(0x20)).is_some());

    // A second response from the same endpoint: the entry was consumed on
    // the first match, so this one is unsolicited (aMule's single-use
    // out-track semantics, ADR-0064).
    deliver(&mut node, T0, from, &bootstrap_res(0x21));
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        diagnostics(&outputs),
        vec![KadNodeDiagnostic::UnsolicitedBootstrapRes { from }]
    );
    assert!(node.routing_table().get(id(0x21)).is_none());
}
