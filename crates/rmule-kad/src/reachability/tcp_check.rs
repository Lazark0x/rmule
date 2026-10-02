//! The TCP firewall self-check requester (ADR-0058): the emission budget a
//! recheck spends, the 180 s window an emitted check stays answerable in, and
//! the hourly cadence that reopens both. Holds no verdict — two acks reaching
//! the core's store conclude that; this tracks only what may be asked and what
//! may be believed.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::KadInstant;

/// Firewall self-checks emitted per recheck before emission stops
/// (`KADEMLIAFIREWALLCHECKS`,
/// [`kad/Constants.h`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/kad/Constants.h#L48)):
/// aMule's `GetRecheckIP` gate emits while `m_recheckip < 4`, one `IncRecheckIP`
/// per accepted `0x58`.
pub(crate) const FIREWALL_CHECKS: u32 = 4;

/// The outstanding-check window a firewall request stays valid for
/// (`SEC2MS(180)`,
/// [`ClientList.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L1042)):
/// a `0x58` or TCP ack from an IP checked longer ago than this is unrequested
/// and rejected (aMule's `IsKadFirewallCheckIP`, a strict `<` so the boundary
/// instant is already expired).
pub(crate) const CHECK_WINDOW: Duration = Duration::from_secs(180);

/// How often the requester re-runs its firewall self-check (`HR2S(1)`,
/// [`Kademlia.cpp`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L329):
/// `m_nextFirewallCheck = HR2S(1) + now`). A recheck zeroes the emission budget
/// (aMule `SetRecheckIP`) so the next hellos carry checks again.
pub(crate) const RECHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The minimum spacing between two **externally triggered** rechecks (ADR-0086,
/// matching emule-qt's own `recheckFirewalled` pacing).
///
/// The hourly cadence above is self-paced and cannot run away; an external
/// trigger can. A port-mapping grant, a gateway epoch reset and an operator
/// hitting "recheck" can all land inside a few seconds of each other, and each
/// recheck spends four helper lookups — enough, repeated, to make this node look
/// like a flood source to the very peers whose answers it needs.
pub(crate) const EXTERNAL_RECHECK_SPACING: Duration = Duration::from_secs(5 * 60);

/// What consuming one `0x58` firewall response did to the requester (ADR-0058).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirewallResponseOutcome {
    /// The response came from an IP outside the 180 s outstanding-check window —
    /// unrequested, so it counts nothing (aMule throws "unrequested firewall
    /// response"; rmule diagnoses the drop).
    Unrequested,
    /// The response was counted (`IncRecheckIP`) and the recheck continues — the
    /// emission budget is not yet spent.
    Counted,
    /// The response was counted and it spent the emission budget of an in-flight
    /// recheck (`m_recheckip` reached [`FIREWALL_CHECKS`]); the recheck concludes
    /// on the store's ≥2-ack rule.
    ConcludedRecheck,
}

/// One outstanding firewall check: the IP we asked to prove us reachable and the
/// instant its 180 s window lapses (`inserted + CHECK_WINDOW`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OutstandingCheck {
    ip: Ipv4Addr,
    deadline: KadInstant,
}

/// The **requester** half of the Kad firewall self-check (ADR-0058 execution
/// breakdown 2): the sans-I/O counters and timers that drive rmule's own TCP
/// reachability check. It owns the emission budget (`m_recheckip`), the 180 s
/// outstanding-check windows (`m_firewallCheckRequests`), and the hourly recheck
/// cadence (`m_nextFirewallCheck`) — every one explicit-time, per the ADR-0043
/// doctrine that the node owns all Kad counters and the core store only projects
/// the verdict from the node's typed events.
///
/// The connect-back **acks** it proves reachability with (`0x59` UDP,
/// `OP_KAD_FWTCPCHECK_ACK` TCP) are counted by the core [`Reachability`] store's
/// ≥2-ack rule, not here — this cycle only gates emission, tracks the windows
/// the acks are validated against, and signals the recheck lifecycle.
///
/// [`Reachability`]: https://docs.rs/rmule-core "core-owned verdict store"
#[derive(Clone, Debug)]
pub(crate) struct FirewallSelfCheck {
    /// aMule `m_recheckip`: firewall requests emitted this recheck. Emission
    /// runs while it is below [`FIREWALL_CHECKS`]; each accepted `0x58` bumps it.
    recheckip: u32,
    /// The 180 s outstanding-check windows, in emission order (aMule's
    /// front-pushed `m_firewallCheckRequests`; order is immaterial to the
    /// existence-plus-freshness lookup).
    windows: Vec<OutstandingCheck>,
    /// When the next hourly recheck is due (aMule `m_nextFirewallCheck`).
    next_recheck: KadInstant,
    /// Whether a hourly recheck is in flight — set by [`begin_recheck`], cleared
    /// when the budget is spent or the windows all lapse. A fresh node is *not*
    /// in a recheck: its budget already sits at zero, so the first hellos carry
    /// checks with no `begin_recheck` (and the store stays at its firewalled
    /// default until an ack proves otherwise), exactly aMule's boot posture.
    ///
    /// [`begin_recheck`]: Self::begin_recheck
    in_recheck: bool,
    /// When the last **externally triggered** recheck ran (ADR-0086), or `None`
    /// — never. The hourly cadence does not stamp it: that clock paces itself,
    /// and a scheduled check must never be allowed to block the external
    /// trigger that exists precisely to beat it.
    last_external: Option<KadInstant>,
    /// An external trigger was refused by either guard and is owed (ADR-0095,
    /// "Kad after the listener or a mapping appears"): a grant or a High ID
    /// that landed while a recheck ran, or inside the spacing, still changed
    /// what a check would find, so it runs once both guards let it rather
    /// than being dropped until the hourly check.
    external_owed: bool,
}

impl FirewallSelfCheck {
    /// A fresh requester at `now`: budget zero (so the first hellos already
    /// piggyback checks — no 1 h wait), no outstanding windows, the first hourly
    /// recheck one interval out (aMule `m_nextFirewallCheck = HR2S(1) + now`).
    pub(crate) fn new(now: KadInstant) -> Self {
        Self {
            recheckip: 0,
            windows: Vec::new(),
            next_recheck: now + RECHECK_INTERVAL,
            in_recheck: false,
            last_external: None,
            external_owed: false,
        }
    }

    /// Whether a firewall check should piggyback on the next hello — aMule's
    /// `GetRecheckIP`: the emission budget is not yet spent.
    pub(crate) fn wants_check(&self) -> bool {
        self.recheckip < FIREWALL_CHECKS
    }

    /// Open a 180 s outstanding-check window on `ip` — aMule
    /// `AddKadFirewallRequest`, called for each emitted `0x50`/`0x53`.
    pub(crate) fn record_emission(&mut self, ip: Ipv4Addr, now: KadInstant) {
        self.windows.push(OutstandingCheck {
            ip,
            deadline: now + CHECK_WINDOW,
        });
    }

    /// Whether `ip` has a live outstanding-check window at `now` — aMule
    /// `IsKadFirewallCheckIP`, the guard both the `0x58` response and the
    /// `OP_KAD_FWTCPCHECK_ACK` TCP ack pass. Strict `<`, so a window is already
    /// expired at exactly its 180 s boundary.
    pub(crate) fn is_check_ip(&self, ip: Ipv4Addr, now: KadInstant) -> bool {
        self.windows
            .iter()
            .any(|window| window.ip == ip && now < window.deadline)
    }

    /// Consume one `0x58` firewall response observed from `ip` (aMule
    /// `ProcessFirewalledResponse`): reject it unless `ip` is window-tracked,
    /// else count it (`IncRecheckIP`) and report whether that spent an in-flight
    /// recheck's budget. The response also carries our observed external IP;
    /// rmule has no external-IP consumer yet (the store is TCP-verdict-only), so
    /// that field is dropped until its reader lands.
    pub(crate) fn accept_response(
        &mut self,
        ip: Ipv4Addr,
        now: KadInstant,
    ) -> FirewallResponseOutcome {
        if !self.is_check_ip(ip, now) {
            return FirewallResponseOutcome::Unrequested;
        }
        self.recheckip = self.recheckip.saturating_add(1);
        if self.in_recheck && self.recheckip >= FIREWALL_CHECKS {
            self.in_recheck = false;
            FirewallResponseOutcome::ConcludedRecheck
        } else {
            FirewallResponseOutcome::Counted
        }
    }

    /// Whether the hourly recheck is due at `now`.
    pub(crate) fn recheck_due(&self, now: KadInstant) -> bool {
        now >= self.next_recheck
    }

    /// Begin a hourly recheck (aMule `RecheckFirewalled` → `SetRecheckIP`): zero
    /// the emission budget so the next hellos carry fresh checks, drop the prior
    /// round's windows (always past their 180 s life at the hourly boundary), and
    /// schedule the next recheck one interval out. The caller pairs this with the
    /// store's `begin_tcp_recheck` (snapshot the settled verdict, zero the acks).
    pub(crate) fn begin_recheck(&mut self, now: KadInstant) {
        self.recheckip = 0;
        self.windows.clear();
        self.in_recheck = true;
        self.next_recheck = now + RECHECK_INTERVAL;
    }

    /// Begin a recheck asked for from **outside** the hourly clock (ADR-0086's
    /// amendment to ADR-0058), reporting whether it actually started.
    ///
    /// Two guards, both of them emule-qt's own `recheckFirewalled`:
    ///
    /// - **One at a time.** A recheck already in flight is spending its helper
    ///   lookups; restarting it would zero the budget it is halfway through and
    ///   leave the store's snapshot rule reporting a stale verdict for longer,
    ///   not shorter.
    /// - **At most one per [`EXTERNAL_RECHECK_SPACING`].** An Exact grant, an
    ///   epoch reset and an operator command can all arrive within seconds.
    ///
    /// When it does start, it is the ordinary recheck: the emission budget
    /// reopens, the previous round's windows go, and the next *scheduled* check
    /// moves one hour out — so an external recheck displaces the hourly one
    /// rather than stacking with it. A trigger either guard refuses is owed,
    /// not dropped: [`owed_recheck_due`](Self::owed_recheck_due) starts it
    /// once both let it.
    pub(crate) fn begin_external_recheck(&mut self, now: KadInstant) -> bool {
        if self.in_recheck || self.spacing_holds(now) {
            self.external_owed = true;
            return false;
        }
        self.external_owed = false;
        self.last_external = Some(now);
        self.begin_recheck(now);
        true
    }

    /// Whether the last external recheck is still inside its spacing at `now`.
    fn spacing_holds(&self, now: KadInstant) -> bool {
        self.last_external
            .is_some_and(|last| now < last + EXTERNAL_RECHECK_SPACING)
    }

    /// Start an owed external recheck if both guards now let it, reporting
    /// whether it started.
    pub(crate) fn owed_recheck_due(&mut self, now: KadInstant) -> bool {
        self.external_owed
            && !self.in_recheck
            && !self.spacing_holds(now)
            && self.begin_external_recheck(now)
    }

    /// Expire lapsed windows at `now` and report whether that concluded an
    /// in-flight recheck by timeout: its last outstanding window lapsed before
    /// the emission budget was spent, so no more acks can arrive and the recheck
    /// settles on the store's ≥2-ack rule. A fresh node's boot windows lapsing is
    /// not a recheck timeout (it is not in a recheck).
    pub(crate) fn expire(&mut self, now: KadInstant) -> bool {
        let had_windows = !self.windows.is_empty();
        self.windows.retain(|window| now < window.deadline);
        let timed_out = self.in_recheck
            && had_windows
            && self.windows.is_empty()
            && self.recheckip < FIREWALL_CHECKS;
        if timed_out {
            self.in_recheck = false;
        }
        timed_out
    }

    /// The earliest instant the requester has work — the next hourly recheck,
    /// the nearest window expiry, or the end of the spacing an owed external
    /// recheck waits out.
    pub(crate) fn next_wake(&self) -> KadInstant {
        let owed = self
            .external_owed
            .then_some(self.last_external)
            .flatten()
            .map(|last| last + EXTERNAL_RECHECK_SPACING);
        self.windows
            .iter()
            .map(|window| window.deadline)
            .chain(owed)
            .fold(self.next_recheck, KadInstant::min)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(host: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, host)
    }

    /// `t + s` seconds on the explicit-time scale.
    fn at(base: KadInstant, secs: u64) -> KadInstant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn a_fresh_requester_wants_checks_at_once_and_reschedules_hourly() {
        // aMule boots with m_recheckip = 0 (GetRecheckIP true), so the first
        // hellos already carry checks — no 1 h wait — and the first recheck is
        // scheduled one interval out.
        let t0 = KadInstant::EPOCH;
        let fw = FirewallSelfCheck::new(t0);
        assert!(fw.wants_check(), "a fresh node checks immediately");
        assert!(!fw.recheck_due(t0), "the first recheck is not due at boot");
        assert!(fw.recheck_due(t0 + RECHECK_INTERVAL));
        assert_eq!(fw.next_wake(), t0 + RECHECK_INTERVAL);
    }

    #[test]
    fn the_budget_caps_emission_at_four_accepted_responses() {
        // Four accepted 0x58s spend the budget (m_recheckip reaches
        // KADEMLIAFIREWALLCHECKS); a fifth check never piggybacks. At boot this
        // is not a recheck, so spending the budget concludes nothing.
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        for host in 0..FIREWALL_CHECKS as u8 {
            fw.record_emission(ip(host), t0);
            assert!(
                fw.wants_check(),
                "budget not yet spent before this response"
            );
            assert_eq!(
                fw.accept_response(ip(host), t0),
                FirewallResponseOutcome::Counted,
                "a boot response counts but concludes no recheck"
            );
        }
        assert!(!fw.wants_check(), "the fourth response spends the budget");
    }

    #[test]
    fn a_response_is_accepted_only_inside_the_180s_window() {
        // The window is [emit, emit + 180 s): valid one second short, expired at
        // exactly the 180 s boundary (aMule's strict `<`).
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        fw.record_emission(ip(1), t0);
        assert!(fw.is_check_ip(ip(1), at(t0, 179)));
        assert!(
            !fw.is_check_ip(ip(1), at(t0, 180)),
            "the boundary is expired"
        );
        // A response at the boundary is unrequested and counts nothing.
        assert_eq!(
            fw.accept_response(ip(1), at(t0, 180)),
            FirewallResponseOutcome::Unrequested
        );
        assert!(
            fw.wants_check(),
            "an unrequested response never bumps the budget"
        );
        // A response from an IP we never checked is likewise unrequested.
        assert_eq!(
            fw.accept_response(ip(9), at(t0, 10)),
            FirewallResponseOutcome::Unrequested
        );
    }

    #[test]
    fn an_hourly_recheck_reopens_emission_and_reschedules() {
        // A recheck (SetRecheckIP) zeroes the spent budget so the next hellos
        // carry checks again, and pushes the next recheck one interval on.
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        for host in 0..FIREWALL_CHECKS as u8 {
            fw.record_emission(ip(host), t0);
            let _ = fw.accept_response(ip(host), t0);
        }
        assert!(!fw.wants_check(), "budget spent before the recheck");

        let recheck_at = t0 + RECHECK_INTERVAL;
        fw.begin_recheck(recheck_at);
        assert!(fw.wants_check(), "the recheck reopens the emission budget");
        assert!(
            !fw.is_check_ip(ip(0), recheck_at),
            "prior windows are dropped"
        );
        assert!(!fw.recheck_due(recheck_at));
        assert!(fw.recheck_due(recheck_at + RECHECK_INTERVAL));
    }

    #[test]
    fn a_recheck_concludes_when_its_budget_is_spent() {
        // Under an in-flight recheck the fourth accepted response reports the
        // conclusion (the store then settles on its ≥2-ack rule).
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        fw.begin_recheck(t0);
        for host in 0..FIREWALL_CHECKS as u8 - 1 {
            fw.record_emission(ip(host), t0);
            assert_eq!(
                fw.accept_response(ip(host), t0),
                FirewallResponseOutcome::Counted
            );
        }
        fw.record_emission(ip(3), t0);
        assert_eq!(
            fw.accept_response(ip(3), t0),
            FirewallResponseOutcome::ConcludedRecheck,
            "the budget-spending response concludes the in-flight recheck"
        );
    }

    #[test]
    fn a_recheck_concludes_when_its_windows_lapse_unmet() {
        // Only one responder engaged, its window lapses at 180 s before the
        // budget fills: the recheck times out (no more acks can arrive).
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        fw.begin_recheck(t0);
        fw.record_emission(ip(1), t0);
        assert!(!fw.expire(at(t0, 179)), "still inside the window");
        assert!(
            fw.expire(at(t0, 180)),
            "the last window lapsing concludes the unmet recheck"
        );
        // Idempotent: a second expiry sweep does not re-conclude.
        assert!(!fw.expire(at(t0, 400)));
    }

    #[test]
    fn boot_windows_lapsing_do_not_conclude_a_recheck() {
        // A fresh node is not in a recheck; its boot windows lapsing settles
        // nothing (there is no snapshot to conclude).
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        fw.record_emission(ip(1), t0);
        assert!(
            !fw.expire(at(t0, 180)),
            "boot window expiry is not a recheck timeout"
        );
    }

    #[test]
    fn the_nearest_window_can_precede_the_next_recheck_in_the_wake() {
        // next_wake is the earliest of the hourly recheck and any live window —
        // a 180 s window always precedes the 1 h recheck.
        let t0 = KadInstant::EPOCH;
        let mut fw = FirewallSelfCheck::new(t0);
        fw.record_emission(ip(1), t0);
        assert_eq!(fw.next_wake(), t0 + CHECK_WINDOW);
        // Once it lapses, the wake falls back to the recheck.
        fw.expire(at(t0, 180));
        assert_eq!(fw.next_wake(), t0 + RECHECK_INTERVAL);
    }
}
