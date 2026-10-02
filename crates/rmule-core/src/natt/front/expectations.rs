//! The **Punch Expectation** table: what rmule expects back from the addresses
//! it punched at, and which of them a risen or arriving thing belongs to.
//!
//! # Why the key is an IP and the value is a set
//!
//! Keying by IP is the dialect's doing: an `OP_HOLEPUNCH` names nobody, and it
//! may arrive from a port no hint and no `0x61` ever mentioned — that is the
//! whole point of it, since the *observed* source is the mapping that
//! demonstrably works (ADR-0091). So the lookup cannot be by
//! endpoint.
//!
//! But an IP is not a peer. Two clients behind one CGNAT address, or two rmule
//! nodes behind one home NAT, share it; a single-valued table let the second
//! introduction silently overwrite the first, and a tunnel accepted from the
//! first peer was then attributed to the second's `UserHash`. The
//! entry is therefore a small **bounded set**, keyed inside by target hash: the
//! same hash replaces itself, a different one joins it, and at
//! [`EXPECTATIONS_PER_IP`] the oldest is evicted and counted.
//!
//! # Attribution, and when rmule refuses to attribute
//!
//! A wrong `UserHash` is worse than none — the hello names the peer a few round
//! trips later anyway, while a wrong one is believed immediately and by
//! everything downstream. So:
//!
//! - **An accepted tunnel** from an address holding exactly one expectation is
//!   that expectation's. With several, the one whose nominal endpoint's *port*
//!   matches the tunnel's observed source port wins — and only if exactly one
//!   does. Otherwise the tunnel is attributed to **none**, and that is counted.
//! - **A `0xA1`** refreshes every expectation behind its source address, and
//!   dials at most one: the single Dialer expectation, or, among several, the
//!   one whose nominal port matches the observed source. If several Dialer
//!   expectations remain indistinguishable, rmule dials **none** — fanning one
//!   datagram out into several dials is exactly what an unauthenticated trigger
//!   must not be able to do — and waits for a hint or a `0x61` to name a port.
//!
//! Nothing here answers a punch: the dialect has no answer frame, and inventing
//! one would make rmule a reflector.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_primitives::{Ipv4Endpoint, UserHash};

/// How many expectations one address may hold at once.
///
/// Four, because the thing being bounded is *our own* coordinators: an
/// expectation exists only where a rendezvous we emitted was answered or a
/// server introduced us, so the population behind one address is the number of
/// distinct peers rmule is traversing toward there at once. Two is the CGNAT
/// case the single-valued table got wrong; four leaves room for a busy download
/// pulling several sources from one carrier's pool without letting a misbehaved
/// coordinator grow the entry without limit.
pub(super) const EXPECTATIONS_PER_IP: usize = 4;

/// How long an expectation survives without being refreshed.
///
/// The whole attempt's budget (`RENDEZVOUS_TIMEOUT`): past it, no schedule is
/// still working toward that peer, so an expectation left behind can only
/// mis-attribute a later tunnel or admit a punch nothing is waiting for. Every
/// `OP_HOLEPUNCH` from the address refreshes the set, so a live path's
/// expectation never ages out under it.
pub(super) const EXPECTATION_TTL: Duration = rmule_peer::natt::RENDEZVOUS_TIMEOUT;

/// Which side of a punch we are, for one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PunchSide {
    /// We asked for the introduction, so we dial and the peer accepts.
    Dialer,
    /// The peer asked, so it dials and we accept. A `0xA1` here refreshes the
    /// expectation and draws nothing.
    Responder,
}

/// One peer rmule punched at and is now expecting something from.
#[derive(Clone, Copy, Debug)]
struct Expectation {
    /// The peer's user hash — the set's key, and what a risen tunnel is
    /// attributed to.
    peer: UserHash,
    side: PunchSide,
    /// The endpoint the coordinator named. It is what a `0xA1` may *correct*,
    /// so it is never the lookup key — but it is the only thing that can tell
    /// two peers behind one address apart.
    nominal: Ipv4Endpoint,
    /// When this expectation was last recorded or refreshed.
    since: Instant,
}

/// What an `OP_HOLEPUNCH` from one address means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PunchVerdict {
    /// Nothing is expected from that address. Dropped in silence and counted.
    Unexpected,
    /// The set was refreshed and there is nothing to dial: every expectation
    /// behind the address is a Responder's, so the peer dials and we accept.
    Refreshed,
    /// The set was refreshed and the Dialer side could not be told apart. No
    /// dial: one datagram may not fan out into several.
    Ambiguous,
    /// Dial this peer, toward the endpoint the punch was observed from.
    Dial(UserHash),
}

/// Who a risen tunnel belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Attribution {
    /// The one expectation behind the address, or the one its port named.
    Peer(UserHash),
    /// Nothing was expected from that address — an ordinary state for a tunnel
    /// somebody else aimed at us.
    Unexpected,
    /// Several expectations, and nothing discriminates them. Attributed to
    /// none, on purpose, and counted.
    Ambiguous,
}

/// The address → expectation-set table.
#[derive(Debug, Default)]
pub(super) struct Expectations {
    by_ip: HashMap<Ipv4Addr, Vec<Expectation>>,
}

impl Expectations {
    /// Record that `peer` is expected at `nominal`, on `side`.
    ///
    /// Returns whether an older expectation was evicted to make room — the
    /// front counts those, because a steady stream of them means one address
    /// is carrying more traversals than [`EXPECTATIONS_PER_IP`] allows and
    /// some attribution is being lost.
    pub(super) fn record(
        &mut self,
        peer: UserHash,
        nominal: Ipv4Endpoint,
        side: PunchSide,
        now: Instant,
    ) -> bool {
        let entry = self.by_ip.entry(nominal.ip).or_default();
        let fresh = Expectation {
            peer,
            side,
            nominal,
            since: now,
        };
        if let Some(held) = entry.iter_mut().find(|held| held.peer == peer) {
            // The same peer at a new endpoint, or on a new side: one peer is
            // one expectation, however many times it is introduced.
            *held = fresh;
            return false;
        }
        let evicted = entry.len() >= EXPECTATIONS_PER_IP;
        if evicted {
            let oldest = entry
                .iter()
                .enumerate()
                .min_by_key(|(_, held)| held.since)
                .map(|(index, _)| index)
                .unwrap_or(0);
            entry.remove(oldest);
        }
        entry.push(fresh);
        evicted
    }

    /// An `OP_HOLEPUNCH` arrived from `observed`.
    pub(super) fn on_punch(&mut self, observed: Ipv4Endpoint, now: Instant) -> PunchVerdict {
        let Some(entry) = self.by_ip.get_mut(&observed.ip) else {
            return PunchVerdict::Unexpected;
        };
        if entry.is_empty() {
            return PunchVerdict::Unexpected;
        }
        for held in entry.iter_mut() {
            held.since = now;
        }
        match discriminate(
            entry.iter().filter(|held| held.side == PunchSide::Dialer),
            observed,
        ) {
            Discriminated::One(peer) => PunchVerdict::Dial(peer),
            Discriminated::None => PunchVerdict::Refreshed,
            Discriminated::Several => PunchVerdict::Ambiguous,
        }
    }

    /// Who a tunnel accepted from `observed` belongs to.
    pub(super) fn attribute(&self, observed: Ipv4Endpoint) -> Attribution {
        let Some(entry) = self.by_ip.get(&observed.ip) else {
            return Attribution::Unexpected;
        };
        match discriminate(entry.iter(), observed) {
            Discriminated::One(peer) => Attribution::Peer(peer),
            Discriminated::None => Attribution::Unexpected,
            Discriminated::Several => Attribution::Ambiguous,
        }
    }

    /// A **Punched Path** closed: forget what it was expecting.
    ///
    /// The path names an endpoint, and an expectation is keyed by a hash, so
    /// the two are joined by the only fact they share: the nominal endpoint, or
    /// — when the `0xA1` corrected the port and one expectation is all the
    /// address holds — that one. Anything less certain is left to
    /// [`EXPECTATION_TTL`]; guessing here would forget the wrong peer.
    pub(super) fn forget(&mut self, at: Ipv4Endpoint) {
        let Some(entry) = self.by_ip.get_mut(&at.ip) else {
            return;
        };
        if let Some(index) = entry.iter().position(|held| held.nominal == at) {
            entry.remove(index);
        } else if entry.len() == 1 {
            entry.clear();
        }
        if entry.is_empty() {
            self.by_ip.remove(&at.ip);
        }
    }

    /// Drop expectations nothing has refreshed inside [`EXPECTATION_TTL`].
    pub(super) fn prune(&mut self, now: Instant) {
        self.by_ip.retain(|_, entry| {
            entry.retain(|held| now.saturating_duration_since(held.since) < EXPECTATION_TTL);
            !entry.is_empty()
        });
    }

    /// How many addresses hold an expectation — the table's own size, read by
    /// the tests that bound it.
    #[cfg(test)]
    pub(super) fn addresses(&self) -> usize {
        self.by_ip.len()
    }

    /// How many expectations one address holds.
    #[cfg(test)]
    pub(super) fn len_at(&self, ip: Ipv4Addr) -> usize {
        self.by_ip.get(&ip).map_or(0, Vec::len)
    }
}

/// What a set of candidates said about one observed endpoint.
enum Discriminated {
    /// Exactly one candidate, or exactly one whose nominal port matches.
    One(UserHash),
    /// No candidate at all.
    None,
    /// Several, and the port told them apart no better.
    Several,
}

/// Pick the one candidate an observed endpoint names, if anything can.
///
/// One candidate is that candidate — a peer's NAT may well have mapped a port
/// nobody predicted, and there is nothing else it could be. With several, only
/// the port can speak, and only when exactly one carries it.
fn discriminate<'a>(
    candidates: impl Iterator<Item = &'a Expectation>,
    observed: Ipv4Endpoint,
) -> Discriminated {
    let mut only = None;
    let mut several = false;
    let mut by_port = None;
    let mut ports_clash = false;
    for held in candidates {
        if only.is_none() {
            only = Some(held.peer);
        } else {
            several = true;
        }
        if held.nominal.port == observed.port {
            if by_port.is_some() {
                ports_clash = true;
            }
            by_port = Some(held.peer);
        }
    }
    match (only, several) {
        (None, _) => Discriminated::None,
        (Some(peer), false) => Discriminated::One(peer),
        (Some(_), true) => match (by_port, ports_clash) {
            (Some(peer), false) => Discriminated::One(peer),
            _ => Discriminated::Several,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(last: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, last), port)
    }

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    /// The bug this set exists to end: two peers behind one address both
    /// survive, and each is attributed by the port its introduction named.
    #[test]
    fn two_peers_behind_one_address_both_survive_and_are_told_apart() {
        let now = Instant::now();
        let mut table = Expectations::default();
        assert!(!table.record(hash(1), at(9, 4001), PunchSide::Responder, now));
        assert!(!table.record(hash(2), at(9, 4002), PunchSide::Responder, now));
        assert_eq!(table.len_at(at(9, 0).ip), 2);
        assert_eq!(table.attribute(at(9, 4001)), Attribution::Peer(hash(1)));
        assert_eq!(table.attribute(at(9, 4002)), Attribution::Peer(hash(2)));
    }

    /// A wrong hash is worse than none: with several expectations and a source
    /// port that names none of them, the tunnel is attributed to nobody.
    #[test]
    fn a_tunnel_nothing_discriminates_is_attributed_to_none() {
        let now = Instant::now();
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Responder, now);
        table.record(hash(2), at(9, 4002), PunchSide::Responder, now);
        assert_eq!(table.attribute(at(9, 51515)), Attribution::Ambiguous);
        assert_eq!(table.attribute(at(10, 4001)), Attribution::Unexpected);
    }

    /// One expectation takes the tunnel whatever port it came from — the NAT
    /// mapping is exactly the thing nobody could predict, and there is nothing
    /// else it could be.
    #[test]
    fn a_lone_expectation_takes_a_tunnel_from_any_port() {
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Responder, Instant::now());
        assert_eq!(table.attribute(at(9, 51515)), Attribution::Peer(hash(1)));
    }

    /// The same peer introduced twice is one expectation, at its newest
    /// endpoint. Nothing is evicted for it.
    #[test]
    fn one_peer_is_one_expectation_however_often_it_is_introduced() {
        let now = Instant::now();
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Dialer, now);
        assert!(!table.record(hash(1), at(9, 4009), PunchSide::Dialer, now));
        assert_eq!(table.len_at(at(9, 0).ip), 1);
        assert_eq!(table.attribute(at(9, 4009)), Attribution::Peer(hash(1)));
    }

    /// The bound holds and the oldest goes, so one address can never grow the
    /// table without limit.
    #[test]
    fn the_set_is_bounded_and_the_oldest_expectation_is_what_goes() {
        let t0 = Instant::now();
        let mut table = Expectations::default();
        for (index, fill) in (1..=EXPECTATIONS_PER_IP as u8).enumerate() {
            let at_time = t0 + Duration::from_secs(index as u64);
            assert!(!table.record(
                hash(fill),
                at(9, 4000 + u16::from(fill)),
                PunchSide::Dialer,
                at_time
            ));
        }
        let overflow = t0 + Duration::from_secs(EXPECTATIONS_PER_IP as u64);
        assert!(table.record(hash(99), at(9, 4099), PunchSide::Dialer, overflow));
        assert_eq!(table.len_at(at(9, 0).ip), EXPECTATIONS_PER_IP);
        assert_eq!(table.attribute(at(9, 4001)), Attribution::Ambiguous);
        assert_eq!(table.attribute(at(9, 4099)), Attribution::Peer(hash(99)));
    }

    /// A `0xA1` dials the one Dialer expectation its port names, refreshes
    /// every expectation behind the address, and dials **none** when several
    /// Dialer expectations remain indistinguishable.
    #[test]
    fn a_punch_dials_at_most_one_and_never_fans_out() {
        let now = Instant::now();
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Dialer, now);
        table.record(hash(2), at(9, 4002), PunchSide::Dialer, now);
        table.record(hash(3), at(9, 4003), PunchSide::Responder, now);

        assert_eq!(
            table.on_punch(at(9, 4002), now),
            PunchVerdict::Dial(hash(2))
        );
        assert_eq!(table.on_punch(at(9, 51515), now), PunchVerdict::Ambiguous);
        assert_eq!(table.on_punch(at(11, 4001), now), PunchVerdict::Unexpected);

        // Responders alone draw nothing: the peer dials, and a dial of our own
        // would put two handshakes on one pinhole.
        let mut responders = Expectations::default();
        responders.record(hash(3), at(9, 4003), PunchSide::Responder, now);
        assert_eq!(
            responders.on_punch(at(9, 32100), now),
            PunchVerdict::Refreshed
        );
    }

    /// A punch refreshes what it reaches, so a live path's expectation never
    /// ages out — while a silent one does, and takes its address with it.
    #[test]
    fn silence_ages_an_expectation_out_and_a_punch_keeps_it() {
        let t0 = Instant::now();
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Dialer, t0);
        table.record(hash(2), at(10, 4002), PunchSide::Dialer, t0);

        let late = t0 + EXPECTATION_TTL - Duration::from_secs(1);
        assert_eq!(
            table.on_punch(at(9, 4001), late),
            PunchVerdict::Dial(hash(1))
        );
        table.prune(t0 + EXPECTATION_TTL);
        assert_eq!(table.addresses(), 1, "only the refreshed address survives");
        assert_eq!(table.attribute(at(9, 4001)), Attribution::Peer(hash(1)));
    }

    /// A closed path forgets its own expectation and leaves the peer it shared
    /// an address with alone.
    #[test]
    fn a_closed_path_forgets_only_what_it_can_name() {
        let now = Instant::now();
        let mut table = Expectations::default();
        table.record(hash(1), at(9, 4001), PunchSide::Dialer, now);
        table.record(hash(2), at(9, 4002), PunchSide::Dialer, now);
        table.forget(at(9, 4001));
        assert_eq!(table.len_at(at(9, 0).ip), 1);
        assert_eq!(table.attribute(at(9, 4002)), Attribution::Peer(hash(2)));
        table.forget(at(9, 32100));
        assert_eq!(table.addresses(), 0, "the last one goes with its path");
    }
}
