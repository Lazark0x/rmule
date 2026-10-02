//! The UDP firewall self-check (ADR-0058 breakdown 3): the two-helper test that
//! asks strangers to answer on this node's Kad UDP port, folds their `0x62`
//! results into an open/firewalled verdict, and settles firewalled by the
//! six-minute silence budget when the TCP verdict is firewalled too. Also owns
//! the extern-port retro-correction a forwarded-port answer triggers.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::{KadInstant, UdpFirewallHelper};

mod extern_port;

pub(crate) use self::extern_port::{ExternPortRound, PongOutcome};

/// Fresh helpers the UDP tester engages before concluding
/// (`UDP_FIREWALLTEST_CLIENTSTOASK`,
/// [`UDPFirewallTester.h`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/UDPFirewallTester.h#L45)):
/// "more clients increase the chance of a false positive, while less the chance
/// of a false negative." A single positive concludes open; both failing concludes
/// firewalled.
pub(crate) const UDP_CLIENTS_TO_ASK: u8 = 2;

/// The UDP tester's total silence budget: no conclusive result within six
/// minutes settles firewalled-by-timeout (aMule `IsFirewalledUDP`'s `MIN2MS(6)`
/// gate,
/// [`UDPFirewallTester.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/UDPFirewallTester.cpp#L62)).
/// That conclusion is **gated on the TCP verdict also being firewalled** and on
/// never having verified UDP-open before (see [`UdpFirewallTester::check_timeout`]).
pub(crate) const UDP_TEST_TIMEOUT: Duration = Duration::from_secs(6 * 60);

/// The retro-correction window: a second result arriving on our intern port
/// within ten seconds of an extern-port open flips the preference to the intern
/// port — a forwarded intern port outlives a NAT mapping, so it is preferred
/// even after the extern-port result already concluded open (aMule
/// `SetUDPFWCheckResult`,
/// [`UDPFirewallTester.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/UDPFirewallTester.cpp#L95)).
pub(crate) const UDP_INTERN_RETRO_WINDOW: Duration = Duration::from_secs(10);

/// One helper the UDP tester engaged (aMule `UsedClient_Struct`): the IP we
/// asked to reach our UDP port, and whether its `0x62` result has landed. Kept
/// across rechecks so a helper is never reused (the "fresh" rule's memory).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UdpUsedHelper {
    ip: Ipv4Addr,
    answered: bool,
}

/// One helper's outcome fed into the UDP tester (aMule `SetUDPFWCheckResult`'s
/// `succeeded`/`testCancelled` pair, made a sum type). The node classifies each
/// `0x62` (or a bridged dial failure) into one of these before feeding the tester.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpHelperResult {
    /// A clean `0x62` reached us on `port` (one of our Kad UDP ports) — a pass.
    Passed { port: u16 },
    /// The helper's peer-TCP dial failed or it never answered — a fail.
    Failed,
    /// A biased (`errorcode != 0`) or aborted result — counts as neither.
    Cancelled,
}

/// What feeding one [`UdpHelperResult`] into the UDP tester did — the node maps
/// this to the reachability events the core store projects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpResultOutcome {
    /// A positive result concluded the test **open** on `port` (aMule's "one
    /// positive result is enough"); `port` is intern-preferred.
    Open { port: u16 },
    /// A late result on our intern port, within [`UDP_INTERN_RETRO_WINDOW`] of an
    /// extern-port open, retro-corrected the open port to the more durable intern
    /// port. Still open — only the preferred port changed.
    InternPortCorrected { port: u16 },
    /// Both helpers reported us unreachable — concluded **firewalled** (verified).
    Firewalled,
    /// One helper reported unreachable; the test continues with the other
    /// (`m_fwChecksFinishedUDP < CLIENTSTOASK`). The node engages the next fresh
    /// helper.
    FailedContinue,
    /// A biased or cancelled result — counted as neither pass nor fail (aMule's
    /// `testCancelled`); the test continues.
    Cancelled,
    /// A duplicate answer from a helper that already answered — ignored (both
    /// result packets of one test can arrive; the second is a no-op).
    Duplicate,
    /// A result from an IP we never engaged — unrequested, ignored.
    Unrequested,
    /// The test had already concluded before this result — ignored.
    AlreadyConcluded,
    /// A response for a check we no longer believe in flight: a late packet
    /// straddling a recheck, which forcibly zeroed the running counter while
    /// the abandoned round's responses were still travelling. Dropped without
    /// mutating the verdict — the fresh round produces its own results (aMule's
    /// `m_fwChecksRunningUDP == 0` guard in `SetUDPFWCheckResult`,
    /// `UDPFirewallTester.cpp:135-149`).
    Stale,
}

/// The tester's current UDP reachability verdict — the projection the core store
/// reads (mapped there onto `Open{port}`/`Firewalled`/`Unverified`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpVerdict {
    /// Verified open on `port` (a positive `0x62` landed).
    Open { port: u16 },
    /// Firewalled — both helpers failed (verified) **or** the six-minute timeout
    /// fired (unverified-by-timeout). Both read firewalled for the buddy gate,
    /// matching aMule's `IsFirewalledUDP(true)` (which the recruit path reads
    /// without an `IsVerified` guard).
    Firewalled,
    /// Not yet known — the initial posture and mid-test (aMule assumes open when
    /// unknown, but the buddy gate treats unverified as "not yet known to need a
    /// buddy").
    Unverified,
}

/// The **UDP** half of the Kad firewall self-check (ADR-0058 execution breakdown
/// 3): the sans-I/O counters and verdict of rmule's own UDP reachability test,
/// mirroring aMule's `CUDPFirewallTester`. It holds the candidates the helper
/// lookup offered, engages up to [`UDP_CLIENTS_TO_ASK`] *fresh* ones (the node
/// applies the version / self / routing-zone filters; this owns the possible
/// list and the never-reused memory), concludes open on one positive `0x62`,
/// firewalled on both failing, and firewalled-by-timeout after
/// [`UDP_TEST_TIMEOUT`] of silence — the last gated on the TCP verdict, the one
/// place the two self-checks compose in the node.
///
/// Explicit-time and socket-free per the ADR-0043 doctrine: the node owns every
/// counter and instant, the core store only projects the verdict from the node's
/// typed events. The live leg it drives — the peer-TCP `OP_FWCHECKUDPREQ` dial
/// to each helper — is enacted by core, which reports each dial's end back.
#[derive(Clone, Debug)]
pub(crate) struct UdpFirewallTester {
    /// Candidates offered and not yet tried, newest first (aMule
    /// `m_possibleTestClients`, filled by `AddPossibleTestContact`'s
    /// `push_front`). Emptied when the test concludes; a candidate popped and
    /// found unfit is dropped, not kept for later.
    possible: VecDeque<UdpFirewallHelper>,
    /// Whether this test's helper lookup has been launched (aMule
    /// `m_nodeSearchStarted`): the first Kad datagram launches it once, a
    /// recheck launches a fresh one.
    helper_lookup_started: bool,
    /// Helpers engaged this test-run, with their answered flag (aMule
    /// `m_usedTestClients`). Retained across rechecks: a used IP is never fresh
    /// again.
    used: Vec<UdpUsedHelper>,
    /// Helper checks in flight — engaged, no result yet (`m_fwChecksRunningUDP`).
    running: u8,
    /// Helper checks that produced a pass/fail result (`m_fwChecksFinishedUDP`);
    /// the test runs while this is below [`UDP_CLIENTS_TO_ASK`].
    finished: u8,
    /// The verified verdict: `true` = firewalled (aMule `m_firewalledUDP`).
    firewalled: bool,
    /// Whether the verdict is a real test result, not a default or a timeout
    /// (aMule `m_isFWVerifiedUDP`) — gates the direct-callback path and blocks a
    /// second timeout once we have proven open.
    verified: bool,
    /// Firewalled purely by the six-minute timeout (aMule `m_timedOut`): reads
    /// firewalled though unverified, and a later positive can still overturn it.
    timed_out: bool,
    /// When the current test began (aMule `m_testStart`; `None` = 0 = concluded)
    /// — the anchor the six-minute timeout measures from.
    test_start: Option<KadInstant>,
    /// When the last positive result landed (aMule `m_lastSucceededTime`) — the
    /// anchor the ten-second intern-port retro-correction measures from. **rmule
    /// stamps this on success; aMule 2.3.3 never does, leaving its retro-correction
    /// inert (a documented divergence — see the module note).**
    last_succeeded: Option<KadInstant>,
    /// Prefer the extern (NAT-observed) UDP port over the intern (forwarded) one
    /// (aMule `Prefs::GetUseExternKadPort`). Defaults to the extern port; a positive
    /// result on the intern port flips it, because a forwarded port is more durable.
    use_extern_port: bool,
    /// The concluded open UDP port (`None` until a positive result), intern- or
    /// extern-preferred per [`use_extern_port`](Self::use_extern_port).
    open_port: Option<u16>,
    /// The **Extern Port Round** this test waits on before engaging any
    /// helper (`QueryNextClient`'s `FindExternKadPort(false)` gate).
    extern_port: ExternPortRound,
}

impl UdpFirewallTester {
    /// A fresh tester armed at `now`: the test running (nothing finished), its
    /// six-minute silence budget anchored at `now` (aMule's `Connected()` /
    /// `ReCheckFirewallUDP` stamp `m_testStart` when the check begins), no
    /// verdict yet.
    pub(crate) fn new(now: KadInstant) -> Self {
        Self {
            possible: VecDeque::new(),
            helper_lookup_started: false,
            used: Vec::new(),
            running: 0,
            finished: 0,
            firewalled: false,
            verified: false,
            timed_out: false,
            test_start: Some(now),
            last_succeeded: None,
            use_extern_port: true,
            open_port: None,
            extern_port: ExternPortRound::new(now),
        }
    }

    /// Whether the test still needs results (aMule `IsFWCheckUDPRunning`): fewer
    /// than [`UDP_CLIENTS_TO_ASK`] helpers have finished.
    pub(crate) fn is_running(&self) -> bool {
        self.finished < UDP_CLIENTS_TO_ASK
    }

    /// Whether another helper should be engaged (aMule `GetUDPCheckClientsNeeded`):
    /// in-flight plus finished checks are still below [`UDP_CLIENTS_TO_ASK`].
    pub(crate) fn clients_needed(&self) -> bool {
        u16::from(self.running) + u16::from(self.finished) < u16::from(UDP_CLIENTS_TO_ASK)
    }

    /// Whether `ip` was already engaged in this or a prior test — the "never
    /// reused across tests" half of the fresh-helper rule (aMule's
    /// `m_usedTestClients` scan in `QueryNextClient`).
    pub(crate) fn already_used(&self, ip: Ipv4Addr) -> bool {
        self.used.iter().any(|helper| helper.ip == ip)
    }

    /// Whether the helper lookup is still to be launched for this test (aMule
    /// `Connected()`'s `!m_nodeSearchStarted && IsFWCheckUDPRunning()`).
    pub(crate) fn wants_helper_lookup(&self) -> bool {
        !self.helper_lookup_started && self.is_running()
    }

    /// The helper lookup launched at `now`. Like aMule's `Connected()`, this
    /// re-anchors the six-minute budget: the silence it measures is silence
    /// *after* the tester had a way to find helpers.
    pub(crate) fn begin_helper_lookup(&mut self, now: KadInstant) {
        self.helper_lookup_started = true;
        self.test_start = Some(now);
        self.timed_out = false;
    }

    /// Queue a candidate helper (aMule `AddPossibleTestContact`): ignored once
    /// the test no longer runs, otherwise pushed to the front — no checks in
    /// advance, the node applies them as it pops.
    pub(crate) fn offer(&mut self, helper: UdpFirewallHelper) {
        if self.is_running() {
            self.possible.push_front(helper);
        }
    }

    /// The next candidate to judge, while the test still needs a helper
    /// (aMule `QueryNextClient`'s entry gate and `pop_front`).
    ///
    /// Nothing is popped while the **Extern Port Round** is still open — "wait
    /// till we know our extern port" (`UDPFirewallTester.cpp:254-257`); the
    /// candidates wait in the list for the round's end.
    pub(crate) fn next_candidate(&mut self) -> Option<UdpFirewallHelper> {
        if self.is_running() && self.clients_needed() && self.extern_port.ended() {
            self.possible.pop_front()
        } else {
            None
        }
    }

    /// Record that the node committed a check to `ip` (aMule `QueryNextClient`'s
    /// `m_usedTestClients.push_front` + `m_fwChecksRunningUDP++`). The caller has
    /// already applied the version / self / routing-zone / never-used filters.
    pub(crate) fn record_engagement(&mut self, ip: Ipv4Addr) {
        self.used.push(UdpUsedHelper {
            ip,
            answered: false,
        });
        self.running = self.running.saturating_add(1);
    }

    /// Feed one helper `result` into the tester (aMule `SetUDPFWCheckResult`):
    /// a clean `0x62` on a port, a failure (its dial died / it never answered),
    /// or a cancellation (biased or aborted — counts as neither). `intern_port`
    /// and `extern_port` are our own Kad ports, so the tester can set the open-port
    /// preference and apply the retro-correction.
    pub(crate) fn accept_result(
        &mut self,
        result: UdpHelperResult,
        from_ip: Ipv4Addr,
        intern_port: u16,
        extern_port: u16,
        now: KadInstant,
    ) -> UdpResultOutcome {
        let succeeded = matches!(result, UdpHelperResult::Passed { .. });
        let cancelled = matches!(result, UdpHelperResult::Cancelled);
        let incoming_port = match result {
            UdpHelperResult::Passed { port } => port,
            UdpHelperResult::Failed | UdpHelperResult::Cancelled => 0,
        };
        // Find the helper we engaged at this IP. The retro-correction is checked
        // *before* the answered guard, so a helper's second (intern) packet can
        // still flip the preference (aMule's ordering in SetUDPFWCheckResult).
        let mut requested = false;
        for helper in &mut self.used {
            if helper.ip != from_ip {
                continue;
            }
            let concluded_open_recently = !Self::running_at(self.finished)
                && !self.firewalled
                && self.verified
                && self
                    .last_succeeded
                    .is_some_and(|t| now < t + UDP_INTERN_RETRO_WINDOW);
            if concluded_open_recently && incoming_port == intern_port && self.use_extern_port {
                // A proper forwarded intern port outlives a NAT-set extern port,
                // so prefer it even retroactively.
                self.use_extern_port = false;
                self.open_port = Some(intern_port);
                return UdpResultOutcome::InternPortCorrected { port: intern_port };
            } else if helper.answered {
                return UdpResultOutcome::Duplicate;
            }
            helper.answered = true;
            requested = true;
            break;
        }
        if !requested {
            return UdpResultOutcome::Unrequested;
        }
        if !self.is_running() {
            return UdpResultOutcome::AlreadyConcluded;
        }
        if self.running == 0 {
            // The running counter reads zero though the test is not yet
            // concluded: a recheck reset it out from under an outstanding
            // check, and this is that check's late answer. aMule checks this
            // (`m_fwChecksRunningUDP == 0`) *after* the requested/duplicate
            // gates above and *before* decrementing, so a helper's second
            // (duplicate) packet is still recognised as such even post-recheck.
            return UdpResultOutcome::Stale;
        }
        self.running -= 1;
        if cancelled {
            return UdpResultOutcome::Cancelled;
        }
        self.finished = self.finished.saturating_add(1);
        if succeeded {
            // One positive result is enough: conclude open, cancel the rest.
            self.test_start = None;
            self.firewalled = false;
            self.verified = true;
            self.timed_out = false;
            self.finished = UDP_CLIENTS_TO_ASK;
            self.running = 0;
            self.possible.clear();
            // rmule stamps the success time so the ten-second retro-correction is
            // armed (aMule omits this — its retro-correction never fires; reported).
            self.last_succeeded = Some(now);
            let port = if incoming_port == intern_port {
                self.use_extern_port = false;
                intern_port
            } else if incoming_port == extern_port && incoming_port != 0 {
                self.use_extern_port = true;
                extern_port
            } else {
                incoming_port
            };
            self.open_port = Some(port);
            UdpResultOutcome::Open { port }
        } else if self.finished >= UDP_CLIENTS_TO_ASK {
            // Both helpers failed — verified firewalled.
            self.test_start = None;
            self.firewalled = true;
            self.verified = true;
            self.timed_out = false;
            self.possible.clear();
            UdpResultOutcome::Firewalled
        } else {
            UdpResultOutcome::FailedContinue
        }
    }

    /// A pure mirror of [`is_running`](Self::is_running) taking the finished count
    /// by value, so the retro-correction can read it while `self.used` is borrowed.
    fn running_at(finished: u8) -> bool {
        finished < UDP_CLIENTS_TO_ASK
    }

    /// Advance the six-minute timeout (aMule `IsFirewalledUDP`'s timeout branch).
    /// Concludes firewalled-by-timeout only when the test is still running, has
    /// not verified a result, the TCP verdict is **also** firewalled, and the
    /// budget has elapsed — the one place the UDP and TCP self-checks compose.
    /// Returns whether it just concluded (so the node emits the firewalled event
    /// exactly once). `tcp_firewalled` is the core store's TCP verdict, fed back
    /// to the node through its injected reachability.
    pub(crate) fn check_timeout(&mut self, now: KadInstant, tcp_firewalled: bool) -> bool {
        let elapsed = self
            .test_start
            .is_some_and(|start| now >= start + UDP_TEST_TIMEOUT);
        if self.is_running()
            && !self.timed_out
            && !self.firewalled
            && !self.verified
            && tcp_firewalled
            && elapsed
        {
            self.timed_out = true;
            true
        } else {
            false
        }
    }

    /// Re-run the UDP test (aMule `CUDPFirewallTester::ReCheckFirewallUDP`,
    /// whose sole caller, `CKademlia::RecheckFirewalled`, passes
    /// `setUnverified = false` — `Kademlia.cpp:374`): a fresh six-minute
    /// budget, the helper counters forcibly zeroed — mid-test or not — so two
    /// more can be engaged, and a fresh helper lookup due.
    ///
    /// The verdict itself is **not** forced back to unverified:
    /// `m_isFWVerifiedUDP = (m_isFWVerifiedUDP && !setUnverified)` preserves a
    /// prior verdict rather than clearing it, and `ReCheckFirewallUDP` never
    /// touches `m_firewalledUDP` at all (`UDPFirewallTester.cpp:213-219`) — so
    /// a node that already proved itself open or firewalled keeps reporting
    /// that while the retest runs, and only a fresh result overwrites it. A
    /// tester that was never verified has both flags already false, so this
    /// changes nothing for it.
    ///
    /// The **used-helper memory is deliberately kept**: aMule never clears
    /// `m_usedTestClients`, and it is the whole freshness rule — a helper that
    /// already answered for us is not an independent second opinion, so
    /// re-asking it would let one node's answer settle the verdict twice.
    ///
    /// A response still travelling for the round this abandons is not this
    /// tester's problem to prevent — [`accept_result`](Self::accept_result)'s
    /// `running == 0` guard drops it as [`UdpResultOutcome::Stale`].
    ///
    /// The **Extern Port Round** reopens with it (`FindExternKadPort(true)`,
    /// `UDPFirewallTester.cpp:222`), so the new test again waits for a known
    /// extern port before it engages anyone.
    pub(crate) fn recheck(&mut self, now: KadInstant) {
        self.helper_lookup_started = false;
        self.running = 0;
        self.finished = 0;
        self.timed_out = false;
        self.last_succeeded = None;
        self.test_start = Some(now);
        self.extern_port.restart();
    }

    /// The **Extern Port Round** this test waits on.
    pub(crate) const fn extern_port(&self) -> &ExternPortRound {
        &self.extern_port
    }

    /// The **Extern Port Round**, to fold pings, pongs and core's verdict into.
    pub(crate) const fn extern_port_mut(&mut self) -> &mut ExternPortRound {
        &mut self.extern_port
    }

    /// The extern-port cadence's next instant: only while this test runs
    /// (`IsFWCheckUDPRunning()` in `Kademlia.cpp:223`) and its round collects.
    fn extern_port_wake(&self) -> Option<KadInstant> {
        self.is_running()
            .then(|| self.extern_port.next_wake())
            .flatten()
    }

    /// The current verdict for the core store (see [`UdpVerdict`]).
    pub(crate) fn verdict(&self) -> UdpVerdict {
        if self.firewalled || self.timed_out {
            UdpVerdict::Firewalled
        } else if self.verified {
            UdpVerdict::Open {
                port: self.open_port.unwrap_or(0),
            }
        } else {
            UdpVerdict::Unverified
        }
    }

    /// The six-minute timeout instant, while the test is running and could still
    /// time out, or the extern-port cadence's next ping if sooner — the node
    /// folds it into its wake set so `tick` fires both.
    ///
    /// `tcp_firewalled` mirrors [`check_timeout`](Self::check_timeout)'s gate:
    /// the backstop concludes only under a firewalled TCP verdict, so while TCP
    /// is open/unknown the instant is withheld — otherwise, once elapsed, it
    /// would sit permanently past in the wake set and busy-loop the driver.
    pub(crate) fn next_wake(&self, tcp_firewalled: bool) -> Option<KadInstant> {
        let timeout = if tcp_firewalled
            && self.is_running()
            && !self.timed_out
            && !self.verified
            && !self.firewalled
        {
            self.test_start.map(|start| start + UDP_TEST_TIMEOUT)
        } else {
            None
        };
        timeout.into_iter().chain(self.extern_port_wake()).min()
    }
}

#[cfg(test)]
mod tests;
