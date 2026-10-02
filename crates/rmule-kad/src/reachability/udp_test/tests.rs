//! Verdict, silence-budget and retro-correction tests for the UDP firewall
//! self-check.

use super::*;

/// Our own Kad UDP ports the helpers try to reach: the forwarded intern port
/// and a distinct NAT-observed extern port.
const INTERN: u16 = 4672;
const EXTERN: u16 = 5000;

fn ip(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, host)
}

/// `t + s` seconds on the explicit-time scale.
fn at(base: KadInstant, secs: u64) -> KadInstant {
    base + Duration::from_secs(secs)
}

/// A tester whose **Extern Port Round** already ended on `EXTERN`, so its
/// only clock is the six-minute timeout.
fn settled(now: KadInstant) -> UdpFirewallTester {
    let mut tester = UdpFirewallTester::new(now);
    tester.extern_port_mut().settle(EXTERN);
    tester
}

/// A clean positive `0x62` result arriving on `port` from `helper`.
fn positive(
    tester: &mut UdpFirewallTester,
    helper: Ipv4Addr,
    port: u16,
    now: KadInstant,
) -> UdpResultOutcome {
    tester.accept_result(
        UdpHelperResult::Passed { port },
        helper,
        INTERN,
        EXTERN,
        now,
    )
}

/// A helper failure (its peer-TCP dial failed, no `0x62`).
fn failure(tester: &mut UdpFirewallTester, helper: Ipv4Addr, now: KadInstant) -> UdpResultOutcome {
    tester.accept_result(UdpHelperResult::Failed, helper, INTERN, EXTERN, now)
}

#[test]
fn one_positive_result_concludes_open_on_the_reached_port() {
    // aMule: "one positive result is enough". A positive on the intern port
    // concludes open, verified, intern-preferred — and cancels the rest.
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    assert_eq!(
        positive(&mut tester, ip(1), INTERN, t0),
        UdpResultOutcome::Open { port: INTERN }
    );
    assert_eq!(tester.verdict(), UdpVerdict::Open { port: INTERN });
    assert!(!tester.is_running(), "one positive stops the test");
    assert!(
        !tester.use_extern_port,
        "an intern-port result prefers intern"
    );
}

#[test]
fn a_positive_on_the_extern_port_concludes_open_extern() {
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    assert_eq!(
        positive(&mut tester, ip(1), EXTERN, t0),
        UdpResultOutcome::Open { port: EXTERN }
    );
    assert_eq!(tester.verdict(), UdpVerdict::Open { port: EXTERN });
    assert!(
        tester.use_extern_port,
        "an extern-port result prefers extern"
    );
}

#[test]
fn both_helpers_failing_conclude_firewalled() {
    // Two fresh helpers, both unreachable: the second failure crosses
    // CLIENTSTOASK and concludes firewalled (verified).
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    tester.record_engagement(ip(2));
    assert_eq!(
        failure(&mut tester, ip(1), t0),
        UdpResultOutcome::FailedContinue
    );
    assert_eq!(
        tester.verdict(),
        UdpVerdict::Unverified,
        "one failure is not yet a verdict"
    );
    assert_eq!(
        failure(&mut tester, ip(2), t0),
        UdpResultOutcome::Firewalled
    );
    assert_eq!(tester.verdict(), UdpVerdict::Firewalled);
}

#[test]
fn a_failure_then_a_positive_still_concludes_open() {
    // One helper fails, the other succeeds — one positive is enough.
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    tester.record_engagement(ip(2));
    assert_eq!(
        failure(&mut tester, ip(1), t0),
        UdpResultOutcome::FailedContinue
    );
    assert_eq!(
        positive(&mut tester, ip(2), INTERN, t0),
        UdpResultOutcome::Open { port: INTERN }
    );
    assert_eq!(tester.verdict(), UdpVerdict::Open { port: INTERN });
}

#[test]
fn the_six_minute_timeout_concludes_firewalled_only_with_a_firewalled_tcp_verdict() {
    // A test that gets no result: the timeout is the backstop, but ONLY when
    // the TCP verdict is also firewalled (aMule's CKademlia::IsFirewalled()).
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));

    assert!(
        !tester.check_timeout(at(t0, 359), true),
        "inside the six-minute budget"
    );
    assert!(
        !tester.check_timeout(at(t0, 360), false),
        "TCP-open blocks the UDP timeout — no buddy would be needed"
    );
    assert_eq!(tester.verdict(), UdpVerdict::Unverified);
    assert!(
        tester.check_timeout(at(t0, 360), true),
        "TCP-firewalled and six minutes elapsed conclude firewalled-by-timeout"
    );
    assert_eq!(tester.verdict(), UdpVerdict::Firewalled);
    assert!(
        !tester.check_timeout(at(t0, 400), true),
        "the timeout concludes exactly once"
    );
}

#[test]
fn a_verified_open_test_never_times_out() {
    // Having proven open, the six-minute timeout must not later flip us to
    // firewalled (aMule's `!m_isFWVerifiedUDP` gate).
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    let _ = positive(&mut tester, ip(1), INTERN, t0);
    assert!(
        !tester.check_timeout(at(t0, 600), true),
        "a verified-open test is immune to timeout"
    );
    assert_eq!(tester.verdict(), UdpVerdict::Open { port: INTERN });
}

#[test]
fn a_biased_result_is_cancelled_not_a_failure() {
    // A biased helper's result (errorcode != 0 -> cancelled) counts as
    // neither pass nor fail; the test keeps running.
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    assert_eq!(
        tester.accept_result(UdpHelperResult::Cancelled, ip(1), INTERN, EXTERN, t0),
        UdpResultOutcome::Cancelled
    );
    assert!(
        tester.is_running(),
        "a cancelled result does not finish the test"
    );
    assert_eq!(tester.verdict(), UdpVerdict::Unverified);
}

#[test]
fn unrequested_and_duplicate_results_are_ignored() {
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    // From an IP we never engaged.
    assert_eq!(
        positive(&mut tester, ip(9), INTERN, t0),
        UdpResultOutcome::Unrequested
    );
    // The engaged helper answers once...
    assert_eq!(
        positive(&mut tester, ip(1), EXTERN, t0),
        UdpResultOutcome::Open { port: EXTERN }
    );
    // ...a second, non-intern packet from it is a duplicate, not a re-open.
    assert_eq!(
        tester.accept_result(
            UdpHelperResult::Passed { port: EXTERN },
            ip(1),
            INTERN,
            EXTERN,
            t0
        ),
        UdpResultOutcome::Duplicate
    );
}

#[test]
fn the_intern_port_retro_correction_prefers_the_forwarded_port_within_ten_seconds() {
    // A helper's extern-port result concludes open-extern; its intern-port
    // result, arriving within ten seconds, retro-corrects to the more durable
    // intern port (rmule stamps the success time so this works — aMule ships
    // it inert, see the module note).
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    assert_eq!(
        positive(&mut tester, ip(1), EXTERN, t0),
        UdpResultOutcome::Open { port: EXTERN }
    );
    assert!(tester.use_extern_port);
    assert_eq!(
        positive(&mut tester, ip(1), INTERN, at(t0, 9)),
        UdpResultOutcome::InternPortCorrected { port: INTERN }
    );
    assert!(!tester.use_extern_port, "the intern port is now preferred");
    assert_eq!(tester.verdict(), UdpVerdict::Open { port: INTERN });
}

#[test]
fn the_retro_correction_lapses_after_ten_seconds() {
    // Past the ten-second window the late intern packet is just a duplicate.
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    tester.record_engagement(ip(1));
    let _ = positive(&mut tester, ip(1), EXTERN, t0);
    assert_eq!(
        positive(&mut tester, ip(1), INTERN, at(t0, 10)),
        UdpResultOutcome::Duplicate,
        "the ten-second retro window is exclusive at its boundary"
    );
    assert!(tester.use_extern_port, "extern preference stands");
}

#[test]
fn the_two_helper_budget_and_used_memory_track_engagement() {
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    assert!(tester.clients_needed(), "a fresh tester needs helpers");
    tester.record_engagement(ip(1));
    assert!(
        tester.clients_needed(),
        "one of two engaged — one more needed"
    );
    tester.record_engagement(ip(2));
    assert!(!tester.clients_needed(), "two engaged — the budget is full");
    assert!(tester.already_used(ip(1)) && tester.already_used(ip(2)));
    assert!(!tester.already_used(ip(3)));
}

#[test]
fn the_wake_is_the_timeout_while_running_and_none_once_concluded() {
    let t0 = KadInstant::EPOCH;
    let mut tester = settled(t0);
    tester.record_engagement(ip(1));
    assert_eq!(tester.next_wake(true), Some(t0 + UDP_TEST_TIMEOUT));
    let _ = positive(&mut tester, ip(1), INTERN, t0);
    assert_eq!(
        tester.next_wake(true),
        None,
        "a concluded test wakes for nothing"
    );
}

#[test]
fn a_running_test_advertises_no_wake_while_tcp_is_open() {
    // `check_timeout` concludes only under a firewalled TCP verdict — while
    // TCP is open/unknown the six-minute instant must stay out of the wake
    // set, or once elapsed it becomes a permanently-past wake the driver's
    // `sleep_until` fires every iteration (a busy-loop).
    let t0 = KadInstant::EPOCH;
    let mut tester = settled(t0);
    tester.record_engagement(ip(1));
    assert_eq!(
        tester.next_wake(false),
        None,
        "TCP-open: the timeout backstop can never fire, so it must not wake"
    );
    assert!(
        !tester.check_timeout(at(t0, 600), false),
        "the gate this wake mirrors: elapsed-but-TCP-open never concludes"
    );
    assert_eq!(
        tester.next_wake(false),
        None,
        "still no wake after the instant has elapsed unconcluded"
    );
}

#[test]
fn an_open_extern_port_round_wakes_the_node_every_fifteen_seconds_while_the_test_runs() {
    let t0 = KadInstant::EPOCH;
    let mut tester = UdpFirewallTester::new(t0);
    assert_eq!(
        tester.next_wake(false),
        Some(t0),
        "the first ping is due at once"
    );
    tester.extern_port_mut().cadence_ran(t0);
    assert_eq!(tester.next_wake(false), Some(at(t0, 15)));

    tester.record_engagement(ip(1));
    let _ = positive(&mut tester, ip(1), INTERN, t0);
    assert_eq!(
        tester.next_wake(false),
        None,
        "a concluded test pings for nothing (IsFWCheckUDPRunning, Kademlia.cpp:223)"
    );
}
