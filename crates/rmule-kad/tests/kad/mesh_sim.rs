//! Mesh-tier acceptance for the sans-I/O `KadNode` (ADR-0043):
//! deterministic two-node convergence, scripted loss/duplication, the
//! silent-contact eviction path, and an adversarial `FakeKadPeer` barrage.

use std::io::Write as _;
use std::time::Duration;

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadContact, KadContactState, KadEvent, KadInstant,
    KadNode, KadNodeDiagnostic,
};
use rmule_testkit::kad_mesh::{A, A_EP, B, B_EP, config};
use rmule_testkit::kad_node::{endpoint, id};
use rmule_testkit::{FakeKadPeer, KadMeshSim, LinkPolicy, TraceEntry};

fn two_node_sim() -> KadMeshSim {
    KadMeshSim::new()
        .with_node(A, config(id(0xA1), A_EP, 0xA1), A_EP)
        .with_node(B, config(id(0xB1), B_EP, 0xB1), B_EP)
}

fn bootstrap_and_run(mut sim: KadMeshSim) -> KadMeshSim {
    sim.command(A, KadCommand::Bootstrap { endpoint: B_EP });
    sim.run_until_idle(1_000);
    sim
}

#[test]
fn two_node_bootstrap_converges_both_routing_tables() {
    let sim = bootstrap_and_run(two_node_sim());

    let b_in_a = sim
        .node(A)
        .routing_table()
        .get(id(0xB1))
        .expect("A stores B");
    assert_eq!(b_in_a.state(), KadContactState::Responded);
    assert_eq!(b_in_a.endpoint(), B_EP);

    let a_in_b = sim
        .node(B)
        .routing_table()
        .get(id(0xA1))
        .expect("B stores A");
    assert_eq!(a_in_b.state(), KadContactState::Responded);
    assert_eq!(a_in_b.endpoint(), A_EP);

    assert!(sim.node(A).next_wake().is_none(), "no timers left on A");
    assert!(sim.node(B).next_wake().is_none(), "no timers left on B");

    // The exact convergence choreography, as a pinned trace: each side's
    // first inbound datagram is its silent→heard edge (`HadContact`),
    // then A learns B from the bootstrap response, B learns A from A's
    // advertisement hello, and A's probe resolves. Default links add 10ms per
    // hop.
    assert_eq!(
        sim.trace(),
        &[
            (10, B, KadEvent::HadContact { from: A_EP }),
            (20, A, KadEvent::HadContact { from: B_EP }),
            (
                20,
                A,
                KadEvent::ContactAdded {
                    id: id(0xB1),
                    endpoint: B_EP
                }
            ),
            (
                30,
                B,
                KadEvent::ContactAdded {
                    id: id(0xA1),
                    endpoint: A_EP
                }
            ),
            (40, A, KadEvent::ContactResponded { id: id(0xB1) }),
        ]
    );
}

#[test]
fn identical_configs_produce_identical_traces() {
    let run = || {
        let sim = bootstrap_and_run(two_node_sim());
        (sim.trace().to_vec(), sim.now())
    };
    let (first_trace, first_now) = run();
    let (second_trace, second_now) = run();

    assert!(
        !first_trace.is_empty(),
        "the scenario must actually do something"
    );
    assert_eq!(
        first_trace, second_trace,
        "same config, same trace — bit for bit"
    );
    assert_eq!(first_now, second_now, "and the same virtual end instant");
}

#[test]
fn a_dropped_bootstrap_response_leaves_the_mesh_quiet_not_wedged() {
    // B's first datagram back to A (the bootstrap response) is dropped. The
    // node has no retry policy, so the correct behavior is silence: no
    // phantom timers, no partial state.
    let sim = bootstrap_and_run(two_node_sim().with_link(
        B_EP,
        A_EP,
        LinkPolicy {
            drop_first: 1,
            ..LinkPolicy::default()
        },
    ));

    assert!(sim.node(A).routing_table().is_empty());
    assert!(sim.node(B).routing_table().is_empty());
    // B still *heard* A's request — the silent→heard edge is honest
    // either way — but nothing else happened: no contacts, no phantom state.
    assert_eq!(sim.trace(), &[(10, B, KadEvent::HadContact { from: A_EP })]);
    assert!(sim.node(A).next_wake().is_none());
}

#[test]
fn duplicated_responses_are_diagnosed_and_do_not_double_count() {
    // Every B->A datagram arrives twice. The duplicate bootstrap response and
    // duplicate hello response must each surface as an unsolicited-response
    // diagnostic, and the mesh must still converge exactly once.
    let sim = bootstrap_and_run(two_node_sim().with_link(
        B_EP,
        A_EP,
        LinkPolicy {
            duplicate: true,
            ..LinkPolicy::default()
        },
    ));

    assert_eq!(
        sim.node(A).routing_table().len(),
        1,
        "B is stored exactly once"
    );
    let diagnostics: Vec<KadNodeDiagnostic> = sim
        .trace()
        .iter()
        .filter_map(|(_, _, event)| match event {
            KadEvent::Diagnostic(diagnostic) => Some(*diagnostic),
            _ => None,
        })
        .collect();
    assert_eq!(
        diagnostics,
        vec![
            KadNodeDiagnostic::UnsolicitedBootstrapRes { from: B_EP },
            KadNodeDiagnostic::UnsolicitedHelloRes { from: B_EP },
        ]
    );
}

#[test]
fn a_silent_hearsay_contact_fails_and_is_evicted_in_the_mesh() {
    // A fake bootstrap responder hands A one hearsay row pointing at a dead
    // endpoint. The row must go Pending -> Failed -> evicted at the probe
    // deadline. The fake itself never answers its advertisement hello either,
    // so it follows the same path — probe uniformity, asserted end-to-end.
    let fake_ep = endpoint(9, 4909);
    let dead_ep = endpoint(66, 4666);
    let dead_row = KadContact::new(id(0x66), dead_ep, 4662, 8);
    let bootstrap_res = Kad2Message::BootstrapRes {
        sender: Kad2NodeInfo {
            id: id(0xF9),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        },
        contacts: vec![dead_row],
    }
    .encode()
    .encode();

    let mut sim = KadMeshSim::new()
        .with_node(A, config(id(0xA1), A_EP, 0xA1), A_EP)
        .with_fake(
            fake_ep,
            FakeKadPeer::new().once_on_opcode(0x01, vec![bootstrap_res]),
        );
    sim.command(A, KadCommand::Bootstrap { endpoint: fake_ep });
    sim.run_until_idle(1_000);

    assert!(
        sim.node(A).routing_table().is_empty(),
        "both the silent fake and the dead hearsay row are evicted"
    );
    let failure_events: Vec<&TraceEntry> = sim
        .trace()
        .iter()
        .filter(|(_, _, event)| {
            matches!(
                event,
                KadEvent::ContactFailed { .. } | KadEvent::ContactEvicted { .. }
            )
        })
        .collect();
    assert_eq!(
        failure_events
            .iter()
            .map(|(at, _, event)| (*at, event.clone()))
            .collect::<Vec<_>>(),
        vec![
            // Probe send order = expiry order: the fake responder first, the
            // hearsay row second, both at the 10s probe deadline.
            (10_020, KadEvent::ContactFailed { id: id(0xF9) }),
            (10_020, KadEvent::ContactEvicted { id: id(0xF9) }),
            (10_020, KadEvent::ContactFailed { id: id(0x66) }),
            (10_020, KadEvent::ContactEvicted { id: id(0x66) }),
        ]
    );
}

#[test]
fn adversarial_barrage_yields_diagnostics_never_panics_never_poisons() {
    let fake_ep = endpoint(9, 4909);
    let at = |millis: u64| KadInstant::from_millis(millis);

    // A hello whose tag list overruns the payload.
    let malformed_hello = {
        let mut datagram = vec![0xE4, 0x11];
        datagram.extend_from_slice(&[0x42; 16]);
        datagram.extend_from_slice(&4662u16.to_le_bytes());
        datagram.push(8);
        datagram.push(3); // claims three tags
        datagram.extend_from_slice(&[0x08, 0x01, 0x00]); // truncated tag
        datagram
    };
    // A lookup response cut off mid-contact-row.
    let truncated_lookup_res = {
        let mut datagram = vec![0xE4, 0x29];
        datagram.extend_from_slice(&[0x11; 16]);
        datagram.push(2);
        datagram.extend_from_slice(&[0u8; 30]); // 2 rows claimed, 1.2 present
        datagram
    };
    // A bootstrap response declaring an absurd contact count.
    let absurd_count_bootstrap = {
        let mut datagram = vec![0xE4, 0x09];
        datagram.extend_from_slice(&[0x42; 16]);
        datagram.extend_from_slice(&4662u16.to_le_bytes());
        datagram.push(8);
        datagram.extend_from_slice(&u16::MAX.to_le_bytes());
        datagram.extend_from_slice(&[0u8; 25]);
        datagram
    };
    // A hello response A never solicited (wrong-endpoint reply).
    let unsolicited_hello_res = Kad2Message::HelloRes(Kad2NodeInfo {
        id: id(0x50),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    })
    .encode()
    .encode();
    // Packed garbage: not a zlib stream.
    let packed_garbage = vec![0xE5, 0x11, 0x00, 0x01, 0x02];
    // A zlib bomb inflating past the cap.
    let zlib_bomb = {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&vec![0u8; rmule_kad::MAX_INFLATED_KAD_PAYLOAD + 1])
            .expect("in-memory deflate");
        let mut datagram = vec![0xE5, 0x11];
        datagram.extend_from_slice(&encoder.finish().expect("in-memory deflate"));
        datagram
    };
    // A lookup request carrying someone else's check ID.
    let misrouted_lookup = Kad2Message::LookupReq {
        count: 2,
        target: id(0x11),
        check: id(0xBB),
    }
    .encode()
    .encode();
    // The control: one VALID hello, then one VALID lookup, proving the node
    // still works after the barrage.
    let valid_hello = Kad2Message::HelloReq(Kad2NodeInfo {
        id: id(0xF9),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(4909),
        misc_options: 0,
    })
    .encode()
    .encode();
    let valid_lookup = Kad2Message::LookupReq {
        count: 2,
        target: id(0x11),
        check: id(0xA1),
    }
    .encode()
    .encode();

    let build = || {
        let fake = FakeKadPeer::new()
            .unsolicited_at(at(100), A_EP, malformed_hello.clone())
            .unsolicited_at(at(200), A_EP, truncated_lookup_res.clone())
            .unsolicited_at(at(300), A_EP, absurd_count_bootstrap.clone())
            .unsolicited_at(at(400), A_EP, unsolicited_hello_res.clone())
            .unsolicited_at(at(500), A_EP, packed_garbage.clone())
            .unsolicited_at(at(600), A_EP, zlib_bomb.clone())
            .unsolicited_at(at(700), A_EP, misrouted_lookup.clone())
            .unsolicited_at(at(800), A_EP, valid_hello.clone())
            .unsolicited_at(at(900), A_EP, valid_lookup.clone());
        let mut sim = KadMeshSim::new()
            .with_node(A, config(id(0xA1), A_EP, 0xA1), A_EP)
            .with_fake(fake_ep, fake);
        sim.run_until_idle(1_000);
        sim
    };
    let sim = build();

    // Exactly one contact survived: the valid hello sender. Nothing from the
    // malformed/unsolicited datagrams reached the table.
    assert_eq!(sim.node(A).routing_table().len(), 1);
    assert_eq!(
        sim.node(A)
            .routing_table()
            .get(id(0xF9))
            .expect("the valid hello sender")
            .state(),
        KadContactState::Responded
    );

    let diagnostics: Vec<KadNodeDiagnostic> = sim
        .trace()
        .iter()
        .filter_map(|(_, _, event)| match event {
            KadEvent::Diagnostic(diagnostic) => Some(*diagnostic),
            _ => None,
        })
        .collect();
    assert_eq!(diagnostics.len(), 7, "one diagnostic per hostile datagram");
    assert!(matches!(
        diagnostics[0],
        KadNodeDiagnostic::UndecodableMessage { .. }
    ));
    assert!(matches!(
        diagnostics[4],
        KadNodeDiagnostic::UndecodableEnvelope { .. }
    ));
    assert!(matches!(
        diagnostics[6],
        KadNodeDiagnostic::LookupCheckMismatch { .. }
    ));

    // The node answered the valid hello and the valid lookup: hello res, then
    // a lookup res returning the (only) Responded contact — the fake itself.
    let answers = sim.fake(fake_ep).received();
    assert_eq!(answers.len(), 2, "hello res + lookup res: {answers:?}");
    assert_eq!(answers[0].2[1], 0x19, "hello res opcode");
    assert_eq!(answers[1].2[1], 0x29, "lookup res opcode");

    // And the whole adversarial run is itself deterministic.
    assert_eq!(sim.trace(), build().trace());
}

#[test]
fn probe_deadline_wakes_are_scheduled_not_polled() {
    // The sim only advances to instants the node itself announces: after
    // convergence traffic, the only pending instant is the probe deadline.
    // This pins the next_wake contract at mesh scale.
    let fake_ep = endpoint(9, 4909);
    let bootstrap_res = Kad2Message::BootstrapRes {
        sender: Kad2NodeInfo {
            id: id(0xF9),
            tcp_port: 4662,
            version: 8,
            udp_port_tag: None,
            misc_options: 0,
        },
        contacts: vec![],
    }
    .encode()
    .encode();
    let mut sim = KadMeshSim::new()
        .with_node(A, config(id(0xA1), A_EP, 0xA1), A_EP)
        .with_fake(
            fake_ep,
            FakeKadPeer::new().once_on_opcode(0x01, vec![bootstrap_res]),
        );
    sim.command(A, KadCommand::Bootstrap { endpoint: fake_ep });
    sim.run_until_idle(1_000);

    assert_eq!(
        sim.now(),
        KadInstant::EPOCH + Duration::from_millis(20) + KadNode::PROBE_TIMEOUT,
        "the run ends exactly at the probe deadline: 2 hops of delivery delay, \
         then the 10s hello-probe window"
    );
}
