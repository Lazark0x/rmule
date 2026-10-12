//! Sweep-half unit tests: the one-ping-per-tick walk (a named row at its
//! resolved address, within-window servers walked past) and the crypt-ping arm — obfuscation
//! probe first, public-IP precondition, reply-grace timeout to the plain
//! fallback, and the answered-probe fast path.

use std::net::Ipv4Addr;
use std::sync::Arc;

use super::super::tests::{
    ScriptedTransport, fixed_crypt_ping_nonce, fixed_entropy, plain_arm, plain_seal, scripted,
    server, udp,
};
use super::*;
use crate::server_list::{ManagedServer, ServerAuxPorts, test_facts, test_facts_rows};

mod sealed;
mod vouch;

/// An enabled crypt-ping arm with the public-IP precondition satisfied,
/// so the sweep probes obfuscated first.
fn crypt_arm() -> CryptPingArm {
    CryptPingArm {
        policy: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
            rmule_net::peer::ObfuscationPolicy::Requested,
        )),
        own: own_with_public_ip(),
        grace: Duration::from_secs(20),
        nonce: fixed_crypt_ping_nonce,
    }
}

/// Self-facts with a High-ID login's public IP already published — the
/// precondition the obfuscated probe shares with the peer-UDP send gate.
fn own_with_public_ip() -> SharedOwnIdentity {
    let own = SharedOwnIdentity::default();
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            std::net::Ipv4Addr::new(203, 0, 113, 9),
        ));
    own
}

/// One probe per tick across the list, a row listed by name included: it is
/// pinged at the address its name resolves to, in its turn (ADR-0052's
/// listed-by-name amendment).
#[tokio::test]
async fn the_sweep_pings_one_server_per_tick_a_named_one_at_its_address() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let (facts, _diagnostics) = test_facts(&[
        server("10.0.0.1", 4661),
        server("srv.example.org", 4661),
        server("10.0.0.2", 5000),
    ]);
    let sweep = StatusPingSweep {
        seal: plain_seal(Arc::clone(&transport)),
        facts,
        challenges: challenges.clone(),
        entropy: fixed_entropy,
        first_contact_tick: Duration::from_millis(250),
        tick: Duration::from_secs(5),
        reask: Duration::from_secs(16_200),
        crypt: plain_arm(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[(
            "srv.example.org",
            Ipv4Addr::new(192, 0, 2, 44),
        )]),
    };

    let mut state = SweepState::default();
    for _ in 0..3 {
        sweep.ping_next(&mut state).await;
    }

    let sends = transport.sends.lock().unwrap().clone();
    let ping = vec![0xE3, 0x96, 0xCD, 0xAB, 0xAA, 0x55];
    assert_eq!(
        sends,
        vec![
            (udp(&server("10.0.0.1", 4661), 4), ping.clone()),
            (udp(&server("192.0.2.44", 4661), 4), ping.clone()),
            (udp(&server("10.0.0.2", 5000), 4), ping),
        ],
        "one golden 0x96 per tick, the named row at its resolved address"
    );
    // Each ping registered its challenge with the engine's gate before
    // the send, the named row's under its resolved address.
    assert!(
        challenges
            .settle(
                Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 44), 4661),
                0x55AA_ABCD
            )
            .is_some()
    );
}

#[tokio::test(start_paused = true)]
async fn the_sweep_walks_past_recently_pinged_servers_until_reask_elapses() {
    let transport = Arc::new(scripted(vec![]));
    let reask = Duration::from_secs(16_200);
    let (facts, _diagnostics) = test_facts(&[server("10.0.0.1", 4661), server("10.0.0.2", 4661)]);
    let sweep = StatusPingSweep {
        seal: plain_seal(Arc::clone(&transport)),
        facts,
        challenges: StatusChallenges::default(),
        entropy: fixed_entropy,
        first_contact_tick: Duration::from_millis(250),
        tick: Duration::from_secs(5),
        reask,
        crypt: plain_arm(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    };

    let mut state = SweepState::default();
    for _ in 0..3 {
        sweep.ping_next(&mut state).await;
    }
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        2,
        "both pinged once; the third tick idles inside the re-ask window"
    );

    tokio::time::advance(reask).await;
    sweep.ping_next(&mut state).await;
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        3,
        "the window's lapse re-admits the walk"
    );
}

// ----- ADR-0046: server-UDP crypt (crypt-ping arm + dual-path) -----

/// A crypt-enabled sweep over `servers`, fixed cadence, sharing `challenges`
/// with the (notional) engine gate.
fn crypt_sweep(
    transport: Arc<ScriptedTransport>,
    servers: Vec<ServerEndpoint>,
    challenges: StatusChallenges,
    crypt: CryptPingArm,
) -> StatusPingSweep<Arc<ScriptedTransport>> {
    StatusPingSweep {
        seal: plain_seal(transport),
        facts: test_facts(&servers).0,
        challenges,
        entropy: fixed_entropy,
        first_contact_tick: Duration::from_millis(250),
        tick: Duration::from_secs(5),
        reask: Duration::from_secs(16_200),
        crypt,
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    }
}

#[tokio::test]
async fn an_enabled_crypt_arm_probes_the_obfuscation_port_first() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![server("10.0.0.1", 4661)],
        challenges.clone(),
        crypt_arm(),
    );

    let mut state = SweepState::default();
    sweep.ping_next(&mut state).await;

    // A raw crypt-ping — challenge 0x0BADF00D (LE) + the two padding bytes —
    // at the server's standard port + 12, and no plain 0x96.
    assert_eq!(
        transport.obfuscated.lock().unwrap().clone(),
        vec![(
            udp(&server("10.0.0.1", 4661), 12),
            vec![0x0D, 0xF0, 0xAD, 0x0B, 0xDE, 0xAD]
        )],
    );
    assert!(transport.sends.lock().unwrap().is_empty(), "no plain ping");
    // The challenge is registered as the crypt reply's decrypt key.
    assert_eq!(
        challenges.crypt_base_key(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4661)),
        Some(0x0BAD_F00D),
    );
}

/// The obfuscation policy changes live (ADR-0046): the arm reads it at every
/// tick, so the server due after a change is probed under it — a plain ping
/// while off, the crypt-ping first once set.
#[tokio::test]
async fn a_live_policy_change_reaches_the_next_servers_probe() {
    let transport = Arc::new(scripted(vec![]));
    let policy = crate::obfuscation_policy::SharedObfuscationPolicy::default();
    let sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![server("10.0.0.1", 4661), server("10.0.0.2", 4661)],
        StatusChallenges::default(),
        CryptPingArm {
            policy: policy.clone(),
            ..crypt_arm()
        },
    );

    let mut state = SweepState::default();
    sweep.ping_next(&mut state).await;
    assert!(
        transport.obfuscated.lock().unwrap().is_empty(),
        "off: no probe"
    );
    assert_eq!(transport.sends.lock().unwrap().len(), 1, "a plain 0x96");

    policy.set(Some(rmule_net::peer::ObfuscationPolicy::Requested));
    sweep.ping_next(&mut state).await;
    assert_eq!(
        transport.obfuscated.lock().unwrap().clone(),
        vec![(
            udp(&server("10.0.0.2", 4661), 12),
            vec![0x0D, 0xF0, 0xAD, 0x0B, 0xDE, 0xAD]
        )],
        "set: the next server is probed obfuscated first"
    );
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        1,
        "and not pinged plain"
    );
}

#[tokio::test]
async fn the_crypt_probe_stays_plain_while_the_public_ip_is_unknown() {
    // aMule gates the obfuscated probe on `theApp->GetPublicIP()`; a clear
    // flag keeps the sweep on plain pings even with crypt enabled.
    let transport = Arc::new(scripted(vec![]));
    let sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![server("10.0.0.1", 4661)],
        StatusChallenges::default(),
        CryptPingArm {
            policy: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                rmule_net::peer::ObfuscationPolicy::Requested,
            )),
            own: SharedOwnIdentity::default(),
            grace: Duration::from_secs(20),
            nonce: fixed_crypt_ping_nonce,
        },
    );

    let mut state = SweepState::default();
    sweep.ping_next(&mut state).await;

    assert!(
        transport.obfuscated.lock().unwrap().is_empty(),
        "no obfuscated probe without a known public IP"
    );
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        1,
        "a plain 0x96 instead"
    );
}

#[tokio::test(start_paused = true)]
async fn a_timed_out_crypt_ping_falls_back_to_a_plain_ping() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![server("10.0.0.1", 4661)],
        challenges,
        crypt_arm(),
    );
    let mut state = SweepState::default();

    // Probe, then a within-grace tick walks past (no re-send)…
    sweep.ping_next(&mut state).await;
    sweep.ping_next(&mut state).await;
    assert_eq!(transport.obfuscated.lock().unwrap().len(), 1);
    assert!(transport.sends.lock().unwrap().is_empty());

    // …the grace elapses with no reply settling the challenge, so the next
    // tick falls back to a plain 0x96 (aMule's `CryptPingReplyPending`).
    tokio::time::advance(Duration::from_secs(20)).await;
    sweep.ping_next(&mut state).await;
    assert_eq!(
        transport.obfuscated.lock().unwrap().len(),
        1,
        "no second probe"
    );
    assert_eq!(
        transport.sends.lock().unwrap().clone(),
        vec![(
            udp(&server("10.0.0.1", 4661), 4),
            vec![0xE3, 0x96, 0xCD, 0xAB, 0xAA, 0x55]
        )],
        "the plain fallback ping"
    );
}

#[tokio::test(start_paused = true)]
async fn an_answered_crypt_ping_skips_the_plain_fallback() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let key = Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4661);
    let sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![server("10.0.0.1", 4661)],
        challenges.clone(),
        crypt_arm(),
    );
    let mut state = SweepState::default();

    sweep.ping_next(&mut state).await;
    // The engine settles the reply (removes the challenge) within the grace.
    assert!(challenges.settle(key, 0x0BAD_F00D).is_some());

    tokio::time::advance(Duration::from_secs(20)).await;
    sweep.ping_next(&mut state).await;
    assert!(
        transport.sends.lock().unwrap().is_empty(),
        "an answered probe needs no plain fallback"
    );
    // The server is now on the plain re-ask clock: it is walked past.
    sweep.ping_next(&mut state).await;
    assert!(transport.sends.lock().unwrap().is_empty());
}

// ----- first-contact burst, steady refresh -----

/// A freshly imported list is probed in a first-contact burst — one server per
/// `first_contact_tick`, not one per steady `tick` — and once the re-ask window
/// lapses the refreshes come back at the steady pace, never as a second burst.
/// A steady pace alone would take a minute for twelve first contacts (two with
/// the crypt fallback), and the default 4.5 h window would never refresh the values.
#[tokio::test(start_paused = true)]
async fn an_imported_list_is_probed_in_a_burst_then_refreshed_at_the_steady_pace() {
    let transport = Arc::new(scripted(vec![]));
    let servers: Vec<ServerEndpoint> = (1..=12)
        .map(|i| server(&format!("10.0.0.{i}"), 4661))
        .collect();
    let tick = Duration::from_secs(5);
    let first_contact_tick = Duration::from_millis(250);
    let reask = Duration::from_secs(20 * 60);
    let sweep = StatusPingSweep {
        seal: plain_seal(Arc::clone(&transport)),
        facts: test_facts(&servers).0,
        challenges: StatusChallenges::default(),
        entropy: fixed_entropy,
        first_contact_tick,
        tick,
        reask,
        crypt: plain_arm(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    };
    let task = tokio::spawn(sweep.run());

    // The start delay is one steady tick; the burst follows it.
    tokio::time::sleep(tick + first_contact_tick * 12 + Duration::from_millis(100)).await;
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        12,
        "every listed server gets its first probe inside the burst"
    );

    // The first probe's window lapses at start + tick + reask; three steady
    // ticks' worth of refreshes fit before this wake, a burst would be twelve.
    tokio::time::sleep(reask + tick * 2).await;
    assert_eq!(
        transport.sends.lock().unwrap().len(),
        15,
        "refreshes run at one per steady tick"
    );
    task.abort();
}

/// At attach the burst takes the servers with no answer or a stale
/// one; a server that answered inside the re-ask window before the restart is
/// walked past until its window lapses, then refreshed at the steady pace.
#[tokio::test(start_paused = true)]
async fn at_attach_the_burst_takes_the_stale_and_the_unanswered_and_holds_the_fresh() {
    use crate::server_list::{ManagedServer, ServerFigures};
    let reask = Duration::from_secs(20 * 60);
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let answered = |host: &str, ago: u64| {
        let mut row = ManagedServer::listed(server(host, 4661));
        row.figures = Some(ServerFigures::answered(1_000_000 - ago));
        row
    };
    let rows = [
        answered("10.0.0.1", 60),                        // fresh: a minute old
        answered("10.0.0.2", 25 * 60),                   // stale: older than the window
        ManagedServer::listed(server("10.0.0.3", 4661)), // never answered
    ];
    let endpoints: Vec<_> = rows.iter().map(|row| row.endpoint.clone()).collect();
    let transport = Arc::new(scripted(vec![]));
    let (facts, _diagnostics) = test_facts(&endpoints);
    let sweep = StatusPingSweep {
        seal: plain_seal(Arc::clone(&transport)),
        facts,
        challenges: StatusChallenges::default(),
        entropy: fixed_entropy,
        first_contact_tick: Duration::from_millis(250),
        tick: Duration::from_secs(5),
        reask,
        crypt: plain_arm(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    };

    let mut state = SweepState::seeded(&rows, wall, tokio::time::Instant::now(), reask);
    for _ in 0..4 {
        sweep.ping_next(&mut state).await;
    }
    let pinged = |transport: &ScriptedTransport| -> Vec<Ipv4Endpoint> {
        transport
            .sends
            .lock()
            .unwrap()
            .iter()
            .map(|(to, _)| *to)
            .collect()
    };
    assert_eq!(
        pinged(&transport),
        vec![
            udp(&server("10.0.0.2", 4661), 4),
            udp(&server("10.0.0.3", 4661), 4)
        ],
        "the burst takes the stale and the unanswered, not the fresh"
    );

    // The fresh one's window lapses 19 minutes on: refreshed then.
    tokio::time::advance(reask - Duration::from_secs(60)).await;
    sweep.ping_next(&mut state).await;
    assert_eq!(
        pinged(&transport).last(),
        Some(&udp(&server("10.0.0.1", 4661), 4))
    );
}

/// A dead server is still pinged, so it can come back, but never in the
/// first-contact burst: it waits for the steady pace like a refresh, so a
/// list full of dead servers never bursts.
#[tokio::test(start_paused = true)]
async fn dead_servers_are_pinged_at_the_steady_pace_only() {
    let transport = Arc::new(scripted(vec![]));
    let live = [server("192.0.2.14", 4661), server("192.0.2.27", 4242)];
    let dead = [
        server("198.51.100.3", 4661),
        server("198.51.100.58", 5306),
        server("198.51.100.91", 4661),
    ];
    let listed: Vec<ServerEndpoint> = live.iter().chain(&dead).cloned().collect();
    let facts = test_facts(&listed).0;
    for server in &dead {
        for _ in 0..crate::server_list::DEFAULT_DEAD_AFTER {
            facts.silent(server).await.unwrap();
        }
    }
    let tick = Duration::from_secs(5);
    let first_contact_tick = Duration::from_millis(250);
    let sweep = StatusPingSweep {
        seal: plain_seal(Arc::clone(&transport)),
        facts,
        challenges: StatusChallenges::default(),
        entropy: fixed_entropy,
        first_contact_tick,
        tick,
        reask: Duration::from_secs(20 * 60),
        crypt: plain_arm(),
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    };
    let task = tokio::spawn(sweep.run());
    let sent = || {
        transport
            .sends
            .lock()
            .unwrap()
            .iter()
            .map(|(to, _)| *to)
            .collect::<Vec<_>>()
    };

    tokio::time::sleep(tick + first_contact_tick * 8 + Duration::from_millis(100)).await;
    assert_eq!(
        sent(),
        vec![udp(&live[0], 4), udp(&live[1], 4), udp(&dead[0], 4)],
        "the burst takes the live; the dead get one steady tick's probe"
    );
    tokio::time::sleep(tick * 2).await;
    assert_eq!(sent().len(), 5, "then one dead server per steady tick");
    task.abort();
}

/// A row an aux-port login re-ported: dialed on 5000, the server's standard
/// port 4661. aMule aims every datagram at `GetPort()`, the standard one
/// (`ServerUDPSocket.cpp:363`), so the plain ping goes to 4661 + 4 and the
/// obfuscated one to 4661 + 12.
fn aux_row() -> ManagedServer {
    let mut row = ManagedServer::listed(server("10.0.0.1", 5000));
    row.aux_ports = Some(ServerAuxPorts {
        standard_port: 4661,
        ports: vec![5000],
    });
    row
}

#[tokio::test]
async fn a_plain_ping_to_an_aux_port_row_aims_at_its_standard_port() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let mut sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![],
        challenges.clone(),
        plain_arm(),
    );
    sweep.facts = test_facts_rows(vec![aux_row()]).0;

    sweep.ping_next(&mut SweepState::default()).await;

    let sent: Vec<Ipv4Endpoint> = transport
        .sends
        .lock()
        .unwrap()
        .iter()
        .map(|(to, _)| *to)
        .collect();
    assert_eq!(sent, vec![udp(&server("10.0.0.1", 4661), 4)]);
    assert!(
        challenges
            .settle(
                Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4661),
                0x55AA_ABCD
            )
            .is_some(),
        "the reply, from standard + 4, is gated under the standard port"
    );
}

#[tokio::test]
async fn an_obfuscated_ping_to_an_aux_port_row_is_keyed_on_its_standard_port() {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let mut sweep = crypt_sweep(
        Arc::clone(&transport),
        vec![],
        challenges.clone(),
        crypt_arm(),
    );
    sweep.facts = test_facts_rows(vec![aux_row()]).0;

    sweep.ping_next(&mut SweepState::default()).await;

    let aimed: Vec<Ipv4Endpoint> = transport
        .obfuscated
        .lock()
        .unwrap()
        .iter()
        .map(|(to, _)| *to)
        .collect();
    assert_eq!(aimed, vec![udp(&server("10.0.0.1", 4661), 12)]);
    assert_eq!(
        challenges.crypt_base_key(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4661)),
        Some(0x0BAD_F00D),
    );
}
