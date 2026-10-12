//! The **Port Mapper** state machine (ADR-0086): the sans-I/O brain that races
//! the backends, grades their trials, installs the best, renews it on the RFC
//! ladder, re-adds everything after a gateway reboot, and backs off when there
//! is nothing to talk to.
//!
//! Explicit time throughout — `now` is a parameter of [`start`](PortMapper::start),
//! [`tick`](PortMapper::tick) and [`on_result`](PortMapper::on_result), and the
//! mapper holds no clock, no socket and no channel. Its outputs are
//! [`MappingCommand`]s a runtime enacts and one side effect: a usable grant is
//! handed straight to the **Address Learning** store, which is what puts the
//! granted endpoint on the `CT_EMULE_UDPPORTS` advert and the `0x95` without
//! any advert site knowing a port mapper exists.
//!
//! ## The race, in one paragraph
//!
//! Every enabled protocol probes at once. The round closes when all have
//! answered, or at a 3-second grace — extended **once** to 15 seconds while a
//! backend is still working and nothing is available yet, because an SSDP
//! search plus a description fetch per responder measures about 7 seconds on an
//! ordinary LAN and cutting at 3 s means a permanent LowID on a router that
//! would have answered. A probe that lands after a round that ended with
//! nothing is still adopted. Each survivor is then trialled with the *real*
//! desired set it can express and graded on the exact external port, IPv4
//! first; `Exact` on the lead family ends the race, otherwise the best trial
//! wins and the losers' mappings are released so no
//! duplicates stay on the router. A winner that left any row short of exact is
//! re-raced on a schedule (the `rerace` submodule), because the mapper keeps
//! looking for Exact.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::AddressFamily;

use crate::address_learning::{
    AddressObservation, ObservationOutcome, SharedAddressLearning, SocketRole,
};

use super::desired::DesiredMappingSet;
use super::grade::{Standing, Trial, better};
use super::renewal::{
    Jitter, MAX_LEASE, MAX_RENEW_FAILURES, MIN_ASKED_LEASE, MIN_RENEW_GAP, backoff_delay,
    clamp_hold_off, clamp_lease, renewal_delay,
};
use super::{
    DesiredMapping, GrantAnswer, MappingCommand, MappingDiagnostics, MappingGrade, MappingLease,
    MappingResult, MappingStatus, PortMappingConfig,
};

mod probe;
mod readd;
mod renew;
pub(super) mod rerace;
mod trial;

/// The grace a probe round runs for before it closes on whoever answered.
const PROBE_GRACE: Duration = Duration::from_secs(3);

/// The grace a round is extended to, once, while a backend is still working
/// and nothing is available yet.
const SLOW_PROBE_GRACE: Duration = Duration::from_secs(15);

/// What settling one trial decided, so the decision is taken under the phase
/// borrow and acted on after it.
enum TrialStep {
    /// This trial is `Exact` on the lead family: install it and hand back the
    /// losers'.
    Won(Trial, Standing, Vec<(Trial, Standing)>),
    /// Move on to the next candidate.
    Next(MappingProtocol),
    /// Every candidate has been trialled.
    Exhausted,
}

/// Where the mapper is in its cycle.
#[derive(Debug)]
enum Phase {
    /// Off, or nothing bound — no gateway is being talked to.
    Idle,
    /// A probe round is open.
    Probing {
        /// When the round opened — the anchor both graces measure from.
        started: Instant,
        /// When the round closes if it has not already.
        deadline: Instant,
        /// Whether the grace has already been extended; it is extended once.
        extended: bool,
        /// Whether this is the short round that tries only the learned method.
        learned_only: bool,
        /// Protocols that have not answered yet.
        outstanding: Vec<MappingProtocol>,
        /// Protocols that answered and can map something we want.
        available: Vec<MappingProtocol>,
    },
    /// Candidates are being trialled one at a time.
    Trialling {
        /// Candidates not yet trialled, in preference order.
        queue: VecDeque<MappingProtocol>,
        /// The trial in flight.
        current: Trial,
        /// Finished trials and their standings, kept so the losers' mappings
        /// can be released once a winner is picked.
        completed: Vec<(Trial, Standing)>,
    },
    /// A trial is installed; its leases are renewing.
    Mapped,
    /// Nothing available; the next re-probe is due at `retry_at`.
    BackingOff {
        /// When to race again.
        retry_at: Instant,
    },
}

/// The core-owned **Port Mapper** (ADR-0086). See the module docs.
#[derive(Debug)]
pub(crate) struct PortMapper {
    config: PortMappingConfig,
    /// The one **Address Learning** store, reached the way every other feeder
    /// reaches it. A usable grant is observed here; the store owns the ladder,
    /// the freshness (the lease *is* the freshness) and the
    /// double-NAT/carrier-grade refusal, so none of that is duplicated here.
    addresses: SharedAddressLearning,
    desired: DesiredMappingSet,
    phase: Phase,
    leases: BTreeMap<DesiredMapping, MappingLease>,
    /// The last error each mapping saw, kept after a later success so a
    /// flapping router stays visible instead of erasing its own trail.
    errors: BTreeMap<DesiredMapping, MappingError>,
    /// The method that last won a race — probed alone first next time, which
    /// turns a full race into one short probe.
    learned: Option<MappingProtocol>,
    /// Consecutive failed races; drives the backoff ladder.
    failures: u32,
    /// Whether the connected server last gave us a High-ID — the edge the
    /// "smart LowID" one-shot re-map watches for.
    had_high_id: bool,
    commands: VecDeque<MappingCommand>,
    jitter: Jitter,
    /// Mappings queued for re-add after an epoch reset, and those already
    /// asked for. When both empty out, the set has been re-added and the
    /// reachability recheck fires.
    readd_queue: VecDeque<DesiredMapping>,
    readd_outstanding: BTreeSet<DesiredMapping>,
    /// Whether any mapping in the current re-add round came back granted. A
    /// round that failed outright has nothing for a reachability recheck to
    /// find.
    readd_succeeded: bool,
    next_readd_at: Option<Instant>,
    /// The installed winner's standing, `None` while nothing is installed —
    /// what a re-race must strictly beat, and what tells a fresh lead-family
    /// `Exact` (which earns a recheck) from one already held.
    installed: Option<Standing>,
    /// Whether the open (or last) probe round tried the learned method alone.
    /// A short round's non-Exact winner is re-raced at once: the other
    /// protocols were never asked.
    short_round: bool,
    /// When the installed, not-wholly-Exact winner is re-raced.
    rerace_at: Option<Instant>,
    /// The incumbent's protocol while a re-race runs: it keeps renewing, and
    /// it is not among the candidates.
    reracing: Option<MappingProtocol>,
}

impl PortMapper {
    /// A mapper that has not started. `seed` fixes the renewal jitter, so a
    /// test replays an exact schedule and production draws one per process.
    pub(crate) fn new(
        config: PortMappingConfig,
        addresses: SharedAddressLearning,
        seed: u64,
    ) -> Self {
        let config = PortMappingConfig {
            lease: config.lease.clamp(MIN_ASKED_LEASE, MAX_LEASE),
            ..config
        };
        Self {
            config,
            addresses,
            desired: DesiredMappingSet::default(),
            phase: Phase::Idle,
            leases: BTreeMap::new(),
            errors: BTreeMap::new(),
            learned: None,
            failures: 0,
            had_high_id: false,
            commands: VecDeque::new(),
            jitter: Jitter::seeded(seed),
            readd_queue: VecDeque::new(),
            readd_outstanding: BTreeSet::new(),
            readd_succeeded: false,
            next_readd_at: None,
            installed: None,
            short_round: false,
            rerace_at: None,
            reracing: None,
        }
    }

    /// Adopt a previously learned method, so the first round is one short probe
    /// rather than a full race.
    pub(crate) fn with_learned_method(mut self, method: Option<MappingProtocol>) -> Self {
        self.learned = method;
        self
    }

    /// Re-derive the **Desired Mapping Set** from what bound and open a race if
    /// there is new work.
    ///
    /// Called once at startup and again every time a socket binds, because the
    /// set grows over a session's life: the client-UDP pair comes up with the
    /// core, the eD2k listener when the serve side starts, the Kad socket when
    /// Kad is enabled. A set that has not changed while a race or a set of
    /// leases is already live is left alone — re-racing on every bind would
    /// throw away working mappings to ask the same questions again. A no-op
    /// while nothing bound: with no socket up there is no port to forward.
    pub(crate) fn start(&mut self, now: Instant) {
        let derived = DesiredMappingSet::derive(&self.addresses);
        let unchanged = derived == self.desired;
        self.release_departed(&derived);
        self.desired = derived;
        if self.desired.is_empty() {
            self.phase = Phase::Idle;
            return;
        }
        if unchanged && !matches!(self.phase, Phase::Idle) {
            return;
        }
        // The set changed, so it is raced again. A surviving row keeps its
        // lease until the race re-grants it (ADR-0093): it is still held on
        // the gateway, so a quit that lands mid-race must still release it.
        let desired = self.desired.mappings();
        self.leases.retain(|mapping, _| desired.contains(mapping));
        self.forget_install();
        self.open_probe_round(now);
    }

    /// Release every held lease whose mapping is not in `derived`, before the
    /// set change drops it from the lease table.
    ///
    /// A row that leaves the set — its socket re-bound on another port, or
    /// stopped — is genuinely gone: the gateway keeps forwarding it until its
    /// lease expires unless told otherwise, so this hands it back with the
    /// same [`Release`](MappingCommand::Release) release-on-exit uses, ahead
    /// of the new row's `Map`. A row with no lease here was never granted
    /// (its own trial answer refused while a sibling's succeeded) — there is
    /// nothing to release. This is *not* [`reprobe`](Self::reprobe): a
    /// mapping dropped there is not leaving the set, only being re-raced, and
    /// its finite lease is the real cleanup a release would buy nothing over.
    fn release_departed(&mut self, derived: &DesiredMappingSet) {
        let departed: Vec<_> = self
            .leases
            .iter()
            .filter(|(mapping, _)| !derived.mappings().contains(mapping))
            .map(|(mapping, lease)| (*mapping, lease.protocol, lease.external.port()))
            .collect();
        for (mapping, protocol, external_port) in departed {
            self.commands.push_back(MappingCommand::Release {
                protocol,
                mapping,
                external_port,
            });
        }
    }

    /// Re-derive and open a race, keeping the failure count — the backoff
    /// ladder's retry, which must keep climbing rather than restart at 30 s.
    fn race(&mut self, now: Instant) {
        self.desired = DesiredMappingSet::derive(&self.addresses);
        if self.desired.is_empty() {
            self.phase = Phase::Idle;
            return;
        }
        self.open_probe_round(now);
    }

    /// Re-race from scratch: the operator's recheck, the smart-LowID one-shot,
    /// and the three-failure escape all land here.
    ///
    /// Live leases are dropped **without** a release datagram. A mapping we are
    /// re-probing because its renewals failed is not one we still hold, and its
    /// finite lease is the real cleanup; a release aimed at a gateway that is
    /// already not answering buys nothing.
    pub(crate) fn reprobe(&mut self, now: Instant) {
        self.leases.clear();
        self.readd_queue.clear();
        self.readd_outstanding.clear();
        self.next_readd_at = None;
        self.failures = 0;
        self.forget_install();
        self.race(now);
    }

    /// The connected server's ID verdict. The **first LowID after a High-ID**
    /// triggers one re-probe — the references' "smart LowID": the mapping that
    /// earned the High-ID has evidently stopped working, and nothing else would
    /// notice until the lease ran out.
    pub(crate) fn on_server_id(&mut self, high_id: bool, now: Instant) {
        let lost_high_id = self.had_high_id && !high_id;
        self.had_high_id = high_id;
        if lost_high_id {
            self.reprobe(now);
        }
    }

    /// Advance the clock: close a due probe round, fire due renewals, pace the
    /// epoch re-adds, and leave a backoff when it expires.
    pub(crate) fn tick(&mut self, now: Instant) {
        self.drain_readds(now);
        match &self.phase {
            Phase::Probing { .. } => self.settle_probe_round(now),
            Phase::BackingOff { retry_at } if now >= *retry_at => self.race(now),
            Phase::Mapped if self.rerace_at.is_some_and(|at| now >= at) => self.rerace(now),
            _ => {}
        }
        if matches!(self.phase, Phase::Mapped) || self.reracing.is_some() {
            self.fire_due_renewals(now);
        }
    }

    /// Take one answer from the runtime.
    pub(crate) fn on_result(&mut self, result: MappingResult, now: Instant) {
        match result {
            MappingResult::Probed { protocol, outcome } => self.on_probe(protocol, &outcome, now),
            MappingResult::Mapped {
                protocol,
                mapping,
                outcome,
            } => self.on_map(protocol, mapping, outcome, now),
        }
    }

    /// Withdraw every mapping, if the operator asked for that. A mapping left
    /// behind keeps a port open on the router for a process that is gone — and
    /// on a shared LAN that port is somebody else's.
    pub(crate) fn shutdown(&mut self) {
        if self.config.release_on_exit {
            for (mapping, lease) in &self.leases {
                self.commands.push_back(MappingCommand::Release {
                    protocol: lease.protocol,
                    mapping: *mapping,
                    external_port: lease.external.port(),
                });
            }
        }
        self.leases.clear();
        self.forget_install();
        self.phase = Phase::Idle;
    }

    /// Take the next command the runtime should enact.
    pub(crate) fn next_command(&mut self) -> Option<MappingCommand> {
        self.commands.pop_front()
    }

    /// The earliest instant the mapper has work — what a runtime sleeps until.
    pub(crate) fn next_wake(&self) -> Option<Instant> {
        let phase = match &self.phase {
            Phase::Probing { deadline, .. } => Some(*deadline),
            Phase::BackingOff { retry_at } => Some(*retry_at),
            Phase::Mapped => self.rerace_at,
            Phase::Idle | Phase::Trialling { .. } => None,
        };
        // Only while renewals actually fire: a lease a set change kept while
        // it is re-raced is not renewed until the race concludes, and its
        // past-due instant as the wake would be a runtime that spins.
        let renewing = matches!(self.phase, Phase::Mapped) || self.reracing.is_some();
        let renewals = self
            .leases
            .values()
            .map(|lease| lease.renew_at)
            .min()
            .filter(|_| renewing);
        [phase, renewals, self.next_readd_at]
            .into_iter()
            .flatten()
            .min()
    }

    /// The method that last won, for persisting.
    pub(crate) fn learned_method(&self) -> Option<MappingProtocol> {
        self.learned
    }

    /// One row per **desired** mapping — not per granted one. "The TCP
    /// listener is not mapped" is the fact an operator most needs, and a table
    /// that lists only successes cannot state it.
    pub(crate) fn diagnostics(&self) -> Vec<MappingDiagnostics> {
        self.desired
            .mappings()
            .iter()
            .map(|mapping| {
                let lease = self.leases.get(mapping);
                MappingDiagnostics {
                    mapping: *mapping,
                    status: lease.map_or_else(|| self.unmapped_status(), |lease| lease.status),
                    method: lease.map(|lease| lease.protocol),
                    external: lease.map(|lease| lease.external),
                    lease: lease.and_then(|lease| lease.lease),
                    next_renewal: lease.map(|lease| lease.renew_at),
                    last_error: self.errors.get(mapping).cloned(),
                }
            })
            .collect()
    }

    /// How a mapping with no lease reads, from the phase alone.
    fn unmapped_status(&self) -> MappingStatus {
        match self.phase {
            Phase::Idle => MappingStatus::NotMapped,
            Phase::Probing { .. } | Phase::Trialling { .. } => MappingStatus::Probing,
            Phase::BackingOff { .. } => MappingStatus::Failed,
            // A mapped phase with no lease for this row means its own trial
            // granted nothing while others succeeded.
            Phase::Mapped => MappingStatus::Failed,
        }
    }
}
