//! **Port prediction** (ADR-0091's amendment): the one-symmetric birthday
//! policy, sans-I/O. This module decides which role a node plays toward one
//! introduced peer, draws the random ports a Probe sends to, and holds the
//! two-attempt schedule. The sockets are `rmule_net`'s and the front that
//! drives it is `rmule_core`'s.
//!
//! It is the one exception to ADR-0091's "no NAT-type gate", and it is narrow.
//! The role follows only from our **Own Mapping**, which is what our own Kad
//! observers saw of our UDP port. A peer's claimed port can **veto** a role and
//! never start one, so nothing a stranger says can make rmule scan it.
//!
//! The randomness is handed in, like the rendezvous jitter: a
//! [`PredictionRng`] seeded by the caller, so a test pins an exact port set
//! and production seeds from the OS.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

/// Sockets one Fan opens per attempt (the research's N = 256).
pub const PREDICTION_FAN_SOCKETS: usize = 256;

/// Random ports one Probe attempt sends to (M = N = 256).
pub const PREDICTION_PROBES: usize = 256;

/// Attempts per introduction, both inside the 120 s dial budget.
pub const PREDICTION_ATTEMPTS: u8 = 2;

/// The gap between the two attempts, measured from the introduction.
pub const PREDICTION_ATTEMPT_INTERVAL: Duration = Duration::from_secs(60);

/// How long a plan outlives its last attempt: the rest of the dial budget.
pub const PREDICTION_LINGER: Duration = Duration::from_secs(60);

/// The spacing between two prediction datagrams (100/s, so a burst of 256
/// takes 2.56 s).
pub const PREDICTION_PACE: Duration = Duration::from_millis(10);

/// How long a Probe waits after the introduction. The Fan's burst must have
/// opened its mappings first, so that the probe is the second datagram of the
/// pair: the one that reaches a Fan socket instead of dying at the gateway.
pub const PROBE_DELAY: Duration = Duration::from_secs(3);

/// The ports a Probe draws from. Below 1024 no NAT allocates, and a probe
/// there would only touch well-known services.
pub const PROBE_PORTS: RangeInclusive<u16> = 1024..=65535;

/// The `natt.port_prediction` knob. **`Birthday` by default** since its bench
/// row passed (10 of 10 runs with a Tunnel, a negative run with no scan, the
/// cone server-punch row green): with no Own Mapping known it changes nothing, and with
/// one it only ever adds the one role our own observers justify.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PortPrediction {
    /// eMuleAI's six on target plus the ±16 sweep, and nothing else. Every
    /// datagram is the same as before the policy existed.
    Off,
    /// The one-symmetric birthday policy.
    #[default]
    Birthday,
}

/// What our own observers saw of our UDP mapping in the current Extern Port
/// Round.
///
/// The port most observers name is the best-supported one; every other
/// observer **dissents**. Dissent must be corroborated (ADR-0091): the Fan is
/// the costly role, and one lying Kad contact must not be able to pick it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnMapping {
    /// At least two observers dissent: the NAT allocates per destination. A
    /// symmetric NAT shows it within one round, since each of aMule's three
    /// asked observers sees its own port.
    EndpointDependent,
    /// At least two observers name the best-supported port, and at most one
    /// dissents.
    EndpointIndependent,
    /// Anything less: fewer than two observers, or two that disagree.
    Unknown,
}

impl OwnMapping {
    /// Judge the round's reports, each an observer's address and the external
    /// port it saw, oldest first. One observer counts once however often it
    /// reports — its latest report stands: a second report from the same
    /// address is no second opinion.
    #[must_use]
    pub fn from_reports(reports: impl IntoIterator<Item = (IpAddr, u16)>) -> Self {
        let latest: HashMap<IpAddr, u16> = reports.into_iter().collect();
        let mut support: HashMap<u16, usize> = HashMap::new();
        for port in latest.values() {
            *support.entry(*port).or_default() += 1;
        }
        let best = support.values().copied().max().unwrap_or(0);
        let dissent = latest.len() - best;
        if dissent >= 2 {
            Self::EndpointDependent
        } else if best >= 2 {
            Self::EndpointIndependent
        } else {
            Self::Unknown
        }
    }
}

/// What the peer's own two ports say about it: the port a coordinator
/// observed against the client-UDP port the peer advertised. Only ever a veto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerMapping {
    /// The observed port is not the advertised one.
    Hard,
    /// They are the same.
    Easy,
    /// One of the two is missing.
    Unknown,
}

impl PeerMapping {
    /// Compare the coordinator-observed port with the advertised one. A zero
    /// on either side is no port.
    #[must_use]
    pub fn from_ports(observed: Option<u16>, advertised: Option<u16>) -> Self {
        match (
            observed.filter(|port| *port != 0),
            advertised.filter(|port| *port != 0),
        ) {
            (Some(observed), Some(advertised)) if observed == advertised => Self::Easy,
            (Some(_), Some(_)) => Self::Hard,
            _ => Self::Unknown,
        }
    }
}

/// The half of the birthday pairing a node plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredictionRole {
    /// The endpoint-dependent side: open [`PREDICTION_FAN_SOCKETS`] sockets
    /// and send one empty `0xA1` from each to the punch target.
    Fan,
    /// The endpoint-independent side: send [`PREDICTION_PROBES`] empty `0xA1`
    /// from the advertised bind to random ports at the punch target's IP.
    Probe,
}

/// The policy table. `None` means the baseline alone.
#[must_use]
pub const fn prediction_role(
    knob: PortPrediction,
    own: OwnMapping,
    peer: PeerMapping,
) -> Option<PredictionRole> {
    match (knob, own, peer) {
        (PortPrediction::Off, _, _)
        | (_, OwnMapping::Unknown, _)
        | (_, OwnMapping::EndpointDependent, PeerMapping::Hard)
        | (_, OwnMapping::EndpointIndependent, PeerMapping::Easy) => None,
        (PortPrediction::Birthday, OwnMapping::EndpointDependent, _) => Some(PredictionRole::Fan),
        (PortPrediction::Birthday, OwnMapping::EndpointIndependent, _) => {
            Some(PredictionRole::Probe)
        }
    }
}

/// A seeded SplitMix64 stream. Not cryptographic, and it does not need to be:
/// a probe set is sent in the clear, and all it needs is to be uniform and
/// fresh per attempt.
#[derive(Clone, Debug)]
pub struct PredictionRng(u64);

impl PredictionRng {
    /// A stream from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform port in [`PROBE_PORTS`].
    fn port(&mut self) -> u16 {
        let span = u64::from(*PROBE_PORTS.end() - *PROBE_PORTS.start()) + 1;
        let offset = u16::try_from(self.next_u64() % span).expect("span fits a port");
        *PROBE_PORTS.start() + offset
    }
}

/// One attempt's **Probe Set**: [`PREDICTION_PROBES`] distinct ports in
/// [`PROBE_PORTS`], in send order. A repeat would be a probe that tests no
/// new mapping, so each port is drawn until it is new.
#[must_use]
pub fn probe_ports(rng: &mut PredictionRng) -> Vec<u16> {
    let mut seen = HashSet::with_capacity(PREDICTION_PROBES);
    let mut ports = Vec::with_capacity(PREDICTION_PROBES);
    while ports.len() < PREDICTION_PROBES {
        let port = rng.port();
        if seen.insert(port) {
            ports.push(port);
        }
    }
    ports
}

/// What a plan says to do at `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredictionStep {
    /// Fire attempt `attempt` (0-based) now, then call
    /// [`PredictionPlan::on_fired`].
    Fire {
        /// Which attempt.
        attempt: u8,
    },
    /// The next attempt is due at the carried instant.
    Wait(Instant),
    /// Every attempt has fired and the linger is over. Close what the plan
    /// opened.
    Expired,
}

/// One introduction's **Prediction Plan**: the role, and when each of its
/// two attempts is due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredictionPlan {
    role: PredictionRole,
    introduced: Instant,
    fired: u8,
}

impl PredictionPlan {
    /// A plan for `role`, anchored on the introduction both sides heard at
    /// about the same instant.
    #[must_use]
    pub const fn new(role: PredictionRole, introduced: Instant) -> Self {
        Self {
            role,
            introduced,
            fired: 0,
        }
    }

    /// The role this plan plays.
    #[must_use]
    pub const fn role(&self) -> PredictionRole {
        self.role
    }

    /// When attempt `attempt` is due. A Probe waits [`PROBE_DELAY`] longer
    /// than the Fan it is meant to meet.
    fn due(&self, attempt: u8) -> Instant {
        let offset = PREDICTION_ATTEMPT_INTERVAL * u32::from(attempt);
        match self.role {
            PredictionRole::Fan => self.introduced + offset,
            PredictionRole::Probe => self.introduced + offset + PROBE_DELAY,
        }
    }

    /// When the plan ends if no Tunnel ends it first: the linger after the
    /// last attempt, which is the introduction's 120 s budget.
    #[must_use]
    pub fn expires(&self) -> Instant {
        self.introduced
            + PREDICTION_ATTEMPT_INTERVAL * u32::from(PREDICTION_ATTEMPTS - 1)
            + PREDICTION_LINGER
    }

    /// What to do at `now`.
    #[must_use]
    pub fn poll(&self, now: Instant) -> PredictionStep {
        if now >= self.expires() {
            return PredictionStep::Expired;
        }
        if self.fired >= PREDICTION_ATTEMPTS {
            return PredictionStep::Wait(self.expires());
        }
        let due = self.due(self.fired);
        if now >= due {
            PredictionStep::Fire {
                attempt: self.fired,
            }
        } else {
            PredictionStep::Wait(due)
        }
    }

    /// The attempt [`poll`](Self::poll) asked for went out.
    pub fn on_fired(&mut self) {
        self.fired = self.fired.saturating_add(1).min(PREDICTION_ATTEMPTS);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn observer(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(45, 55, 200, last))
    }

    /// Only a second *observer* is a second opinion: one Kad contact
    /// reporting twice, even two different ports, decides nothing.
    #[test]
    fn own_mapping_needs_two_observers() {
        assert_eq!(OwnMapping::from_reports([]), OwnMapping::Unknown);
        assert_eq!(
            OwnMapping::from_reports([(observer(5), 4672), (observer(5), 31_000)]),
            OwnMapping::Unknown
        );
        assert_eq!(
            OwnMapping::from_reports([(observer(5), 4672), (observer(6), 4672)]),
            OwnMapping::EndpointIndependent
        );
    }

    /// One dissenter cannot pick the Fan: aMule's 5000, 6000, 5000 adopts
    /// 5000, and the mapping stays independent; two observers on two ports are
    /// no verdict either way. Dependence takes two dissenters — what a
    /// symmetric NAT shows each of a round's three observers.
    #[test]
    fn dependence_takes_corroborated_dissent() {
        assert_eq!(
            OwnMapping::from_reports([
                (observer(5), 5000),
                (observer(6), 6000),
                (observer(7), 5000),
            ]),
            OwnMapping::EndpointIndependent
        );
        assert_eq!(
            OwnMapping::from_reports([(observer(5), 5000), (observer(6), 6000)]),
            OwnMapping::Unknown
        );
        assert_eq!(
            OwnMapping::from_reports([
                (observer(5), 31_004),
                (observer(6), 50_219),
                (observer(7), 7_781),
            ]),
            OwnMapping::EndpointDependent
        );
        assert_eq!(
            OwnMapping::from_reports([
                (observer(5), 5000),
                (observer(6), 5000),
                (observer(7), 6000),
                (observer(8), 7000),
            ]),
            OwnMapping::EndpointDependent
        );
    }

    #[test]
    fn peer_mapping_is_the_observed_port_against_the_advertised_one() {
        assert_eq!(
            PeerMapping::from_ports(Some(4672), Some(4672)),
            PeerMapping::Easy
        );
        assert_eq!(
            PeerMapping::from_ports(Some(49_350), Some(4672)),
            PeerMapping::Hard
        );
        assert_eq!(
            PeerMapping::from_ports(Some(4672), None),
            PeerMapping::Unknown
        );
        assert_eq!(
            PeerMapping::from_ports(Some(4672), Some(0)),
            PeerMapping::Unknown
        );
        assert_eq!(
            PeerMapping::from_ports(None, Some(4672)),
            PeerMapping::Unknown
        );
    }

    /// The whole table: the side comes from our own mapping, the peer's only
    /// vetoes, and the knob off or an unknown mapping leaves the baseline.
    #[test]
    fn the_role_follows_our_own_mapping_and_the_peer_only_vetoes() {
        use OwnMapping::{EndpointDependent as Dep, EndpointIndependent as Indep};
        use PeerMapping::{Easy, Hard, Unknown};
        use PredictionRole::{Fan, Probe};
        let birthday = PortPrediction::Birthday;
        for (own, peer, role) in [
            (Dep, Easy, Some(Fan)),
            (Dep, Unknown, Some(Fan)),
            (Dep, Hard, None),
            (Indep, Hard, Some(Probe)),
            (Indep, Unknown, Some(Probe)),
            (Indep, Easy, None),
            (OwnMapping::Unknown, Easy, None),
            (OwnMapping::Unknown, Hard, None),
            (OwnMapping::Unknown, Unknown, None),
        ] {
            assert_eq!(
                prediction_role(birthday, own, peer),
                role,
                "{own:?} {peer:?}"
            );
            assert_eq!(prediction_role(PortPrediction::Off, own, peer), None);
        }
    }

    #[test]
    fn a_probe_set_is_256_distinct_ports_above_1023_and_fresh_per_draw() {
        let mut rng = PredictionRng::new(518);
        let first = probe_ports(&mut rng);
        assert_eq!(first.len(), PREDICTION_PROBES);
        assert_eq!(
            first.iter().collect::<HashSet<_>>().len(),
            PREDICTION_PROBES
        );
        assert!(first.iter().all(|port| PROBE_PORTS.contains(port)));
        let second = probe_ports(&mut rng);
        assert_ne!(first, second, "the second attempt draws its own set");
        assert_eq!(probe_ports(&mut PredictionRng::new(518)), first);
    }

    #[test]
    fn a_fan_fires_at_the_introduction_and_sixty_seconds_later_then_expires() {
        let t0 = Instant::now();
        let mut plan = PredictionPlan::new(PredictionRole::Fan, t0);
        assert_eq!(plan.poll(t0), PredictionStep::Fire { attempt: 0 });
        plan.on_fired();
        assert_eq!(
            plan.poll(t0 + Duration::from_secs(1)),
            PredictionStep::Wait(t0 + PREDICTION_ATTEMPT_INTERVAL)
        );
        assert_eq!(
            plan.poll(t0 + PREDICTION_ATTEMPT_INTERVAL),
            PredictionStep::Fire { attempt: 1 }
        );
        plan.on_fired();
        assert_eq!(
            plan.poll(t0 + Duration::from_secs(90)),
            PredictionStep::Wait(t0 + Duration::from_secs(120))
        );
        assert_eq!(
            plan.poll(t0 + Duration::from_secs(120)),
            PredictionStep::Expired
        );
    }

    #[test]
    fn a_probe_waits_for_the_fan_it_is_meant_to_meet() {
        let t0 = Instant::now();
        let mut plan = PredictionPlan::new(PredictionRole::Probe, t0);
        assert_eq!(plan.poll(t0), PredictionStep::Wait(t0 + PROBE_DELAY));
        assert_eq!(
            plan.poll(t0 + PROBE_DELAY),
            PredictionStep::Fire { attempt: 0 }
        );
        plan.on_fired();
        assert_eq!(
            plan.poll(t0 + Duration::from_secs(10)),
            PredictionStep::Wait(t0 + PREDICTION_ATTEMPT_INTERVAL + PROBE_DELAY)
        );
    }
}
