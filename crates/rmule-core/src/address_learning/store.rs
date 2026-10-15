//! The store itself: the remembered ladders, the bind table, the interface
//! set, and the rules that turn all four into one **External Endpoint**
//! verdict (ADR-0084).
//!
//! Everything here is sans-I/O and explicit-time — `now` is a parameter of
//! every rule, so a test drives thirty minutes of freshness in a microsecond.
//! The one place a clock is read is [`SharedAddressLearning`] at the bottom,
//! which is the edge, exactly as the Kad driver is the edge that maps real
//! time onto the sans-I/O node's explicit scale.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmule_net::family::{FamilyBinds, HalfBound};
use rmule_peer::natt::OwnMapping;
use rmule_primitives::{
    AccountingKey, AddressFamily, ClientId, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint,
};
use tokio::sync::watch;

use crate::reachability::Ipv6Probe;

use super::admissible::{is_carrier_grade_nat, is_publicly_usable};
use super::ladder::{KadAgreement, Ladder, Rung};
use super::{
    AddressObservation, AdvertReachability, AdvertisedEndpoints, AssignedAddress, ConfidenceTier,
    EndpointVerdict, ExternalAddressOverride, NatHint, ObservationOutcome, ObservationSource,
    SocketRole,
};

/// The core-owned **Address Learning** store: typed observations in, one
/// **External Endpoint** verdict per family and role out. Sans-I/O and
/// explicit-time; see the module docs.
#[derive(Debug, Default)]
pub(crate) struct AddressLearning {
    /// One address ladder per family — an external address is a fact about
    /// the host, not about one socket.
    addresses: BTreeMap<AddressFamily, Ladder<IpAddr>>,
    /// One port ladder per role — one port pair serves both families.
    ports: BTreeMap<SocketRole, Ladder<u16>>,
    /// What each role's **Family Pair** actually bound: the families that came
    /// up and the port they share. The truth an advert derives from — never
    /// the configured selection, which says only what was *attempted*.
    binds: BTreeMap<SocketRole, RoleBind>,
    /// The port each role first bound in this process, kept after its socket
    /// closed: a socket the settings leave to the OS (port `0`) binds it
    /// again, as aMule changes its ports only on a restart of the program.
    held_ports: BTreeMap<SocketRole, u16>,
    /// The publicly usable addresses this host currently holds, newest
    /// refresh wins. Both a tier of its own and the corroboration filter's
    /// evidence.
    interfaces: Vec<IpAddr>,
    /// Every address the last refresh enumerated, routable or not — the
    /// evidence a hairpin needs: a refused reflection naming one of these
    /// never left our NAT.
    enumerated: Vec<IpAddr>,
    /// Hints raised when an observation was refused; the disagreement hint is
    /// derived on read instead, because it changes as tiers age.
    hints: BTreeMap<AddressFamily, NatHint>,
}

/// What one role's **Family Pair** bound.
#[derive(Clone, Debug, Default)]
struct RoleBind {
    families: Vec<AddressFamily>,
    port: u16,
    /// The **Half-Bound Pair** fact, when one selected family refused and
    /// another came up. Kept here because this table is already
    /// the one place every role's bind reports to — deriving it anywhere else
    /// would mean a second writer that could disagree with the families above.
    half_bound: Option<HalfBound>,
}

impl AddressLearning {
    /// An empty store: nothing observed, nothing bound.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Take one observation at `now`.
    pub(crate) fn observe(
        &mut self,
        observation: AddressObservation,
        now: Instant,
    ) -> ObservationOutcome {
        let source = observation.source();
        let tier = source.tier();
        match observation {
            AddressObservation::Address { address, .. } => {
                self.record_address(source, address, now)
            }
            // A `0` is no port (ADR-0084): recorded, it would dissent in the
            // Own Mapping as if an observer had seen one.
            AddressObservation::Port { port: 0, .. } => ObservationOutcome::PortZeroRefused,
            AddressObservation::Endpoint { endpoint, .. } if endpoint.port() == 0 => {
                ObservationOutcome::PortZeroRefused
            }
            AddressObservation::Port { role, port, .. } => {
                self.ports.entry(role).or_insert_with(port_ladder).record(
                    tier,
                    port,
                    source.observer(),
                    now,
                    source.lease(),
                );
                ObservationOutcome::Recorded
            }
            AddressObservation::Endpoint { role, endpoint, .. } => {
                let outcome = self.record_address(source, endpoint.ip(), now);
                // The port ladder is one per role, and what it learns is the
                // IPv4 NAT's translation. An IPv6 pinhole translates nothing —
                // its port is the one we bound — so recording it would only
                // overwrite a mismatched IPv4 grant's port with the internal
                // one, and the v4 endpoint and the Kad extern port with it.
                if outcome == ObservationOutcome::Recorded && endpoint.family() == AddressFamily::V4
                {
                    self.ports.entry(role).or_insert_with(port_ladder).record(
                        tier,
                        endpoint.port(),
                        source.observer(),
                        now,
                        source.lease(),
                    );
                }
                outcome
            }
        }
    }

    /// Apply the operator's configured override. Idempotent; an override
    /// cleared back to `None` withdraws the tier, so a session started with
    /// one and reconfigured without it does not keep advertising it.
    pub(crate) fn set_override(&mut self, over: ExternalAddressOverride, now: Instant) {
        for (family, address) in [
            (AddressFamily::V4, over.v4.map(IpAddr::V4)),
            (AddressFamily::V6, over.v6.map(IpAddr::V6)),
        ] {
            match address {
                // Through the one entry point, so an operator who types a
                // private address is refused exactly as a gateway that grants
                // one is — an unroutable address is nobody's External
                // Endpoint. The corroboration filter still exempts this tier:
                // an operator stating an address is not a stranger claiming
                // one.
                Some(address) => {
                    self.observe(
                        AddressObservation::Address {
                            source: ObservationSource::Override,
                            address,
                        },
                        now,
                    );
                }
                None => self
                    .addresses
                    .entry(family)
                    .or_default()
                    .withdraw(ConfidenceTier::Override),
            }
        }
    }

    /// The connected server's `OP_IDCHANGE` verdict: `client_id`, the
    /// `public_ip` the session projected from it, and `server_ip`, the address
    /// that session is connected to.
    ///
    /// A High ID publishes its address at the [`Server`](ConfidenceTier::Server)
    /// tier and withdraws any Low-ID report. A Low ID **withdraws** the
    /// `Server` tier — it is not an ageing-out but the server contradicting
    /// itself: keeping the old value as a stale last-known would re-arm the UDP
    /// crypt send with a key the peer cannot reproduce. Its report, if any, is
    /// a [`LowIdReport`](ConfidenceTier::LowIdReport), and a report naming
    /// `server_ip` is refused (ADR-0084): a server is
    /// never us, and ed2k-rust writes its own address there. A *disconnect*
    /// ([`end_server_session`](Self::end_server_session)) is the opposite case
    /// and keeps the value. Returns what the answer established, the refusal
    /// among it, for the login step that reports it.
    pub(crate) fn observe_server_assigned(
        &mut self,
        client_id: ClientId,
        public_ip: Option<Ipv4Addr>,
        server_ip: Option<IpAddr>,
        now: Instant,
    ) -> AssignedAddress {
        let (tier, withdrawn) = if client_id.is_high_id() {
            (ConfidenceTier::Server, ConfidenceTier::LowIdReport)
        } else {
            (ConfidenceTier::LowIdReport, ConfidenceTier::Server)
        };
        let v4 = self.addresses.entry(AddressFamily::V4).or_default();
        v4.withdraw(withdrawn);
        match public_ip {
            Some(address)
                if tier == ConfidenceTier::LowIdReport
                    && server_ip == Some(IpAddr::V4(address)) =>
            {
                v4.withdraw(tier);
                AssignedAddress::ServerOwnRefused(address)
            }
            Some(address) => {
                let observation = if tier == ConfidenceTier::Server {
                    AddressObservation::server_high_id(address)
                } else {
                    AddressObservation::low_id_report(address)
                };
                self.observe(observation, now);
                AssignedAddress::Ours(address)
            }
            None => {
                v4.withdraw(tier);
                AssignedAddress::Unnamed
            }
        }
    }

    /// The server session ended: its tier stops being fresh but keeps its
    /// value as the stale last-known, so a reconnect never blanks the UDP
    /// crypt key mid-reask.
    pub(crate) fn end_server_session(&mut self, now: Instant) {
        for ladder in self.addresses.values_mut() {
            ladder.end_session(ConfidenceTier::Server, now);
            ladder.end_session(ConfidenceTier::LowIdReport, now);
        }
        for ladder in self.ports.values_mut() {
            ladder.end_session(ConfidenceTier::Server, now);
        }
    }

    /// Replace the set of addresses this host holds. Wholesale, because that
    /// is how an enumeration reads: an address absent from the new set is one
    /// this host no longer holds, so a prefix renumber or an RFC 4941 privacy
    /// rotation drops every reflected IPv6 that rested on it at the next read.
    pub(crate) fn refresh_interfaces(&mut self, addresses: &[IpAddr]) {
        self.interfaces = addresses
            .iter()
            .copied()
            .filter(|address| is_publicly_usable(*address))
            .collect();
        self.enumerated = addresses.to_vec();
    }

    /// Record what one role's **Family Pair** bound — the families that came
    /// up and the port they share (ADR-0085). The port is the floor every
    /// verdict falls back to: with no NAT in the path, the port the world
    /// reaches us on *is* the bound one.
    pub(crate) fn record_bind(&mut self, role: SocketRole, binds: &FamilyBinds, port: u16) {
        self.held_ports.entry(role).or_insert(port);
        self.binds.insert(
            role,
            RoleBind {
                families: binds.bound.clone(),
                port,
                half_bound: HalfBound::read(role.pair_role(), binds),
            },
        );
    }

    /// Forget `role`'s bind (ADR-0093): the socket that recorded it closed.
    /// The Desired Mapping Set derives from this table, so the role's mapping
    /// leaves the set and its lease is released (ADR-0086), and
    /// the port stops being the floor any verdict falls back to.
    pub(crate) fn forget_bind(&mut self, role: SocketRole) {
        self.binds.remove(&role);
    }

    /// The **Half-Bound Pair** fact for `role` — a family it selected refused
    /// while another came up, and what that costs. `None` for a
    /// whole pair, for a role that never bound, and for a family that was
    /// never selected at all: an operator who configured one family has lost
    /// nothing.
    pub(crate) fn half_bound(&self, role: SocketRole) -> Option<HalfBound> {
        self.binds.get(&role).and_then(|bind| bind.half_bound)
    }

    /// Whether `role` bound `family` — the chooser's gate, read from what
    /// actually came up rather than from what was configured.
    pub(crate) fn bound(&self, role: SocketRole, family: AddressFamily) -> bool {
        self.binds
            .get(&role)
            .is_some_and(|bind| bind.families.contains(&family))
    }

    /// What `role`'s **Family Pair** bound: the families that came up and the
    /// port they share, or `None` when the role never bound.
    ///
    /// The **Desired Mapping Set** (ADR-0086) is derived from exactly this and
    /// never from config. The bound *port* is the one a mapping must ask for:
    /// [`port`](Self::port) answers what the world currently reaches us at,
    /// which after a mismatched grant is the gateway's port, not ours — asking
    /// a router to map that would be asking it to forward its own answer.
    pub(crate) fn bind(&self, role: SocketRole) -> Option<(Vec<AddressFamily>, u16)> {
        self.binds
            .get(&role)
            .map(|bind| (bind.families.clone(), bind.port))
    }

    /// The port `role` first bound in this process, whether or not its socket
    /// is open now; `None` before it ever bound.
    pub(crate) fn held_port(&self, role: SocketRole) -> Option<u16> {
        self.held_ports.get(&role).copied()
    }

    /// Our external address in `family` **only while a fresh tier holds it** —
    /// the [`Known`](EndpointVerdict::Known) half of [`address`](Self::address).
    ///
    /// The port-mapping gate for an IPv6 pinhole reads this: a pinhole is a
    /// hole punched to an address we hold, so asking for one while our own v6
    /// is merely a stale last-known would open it at the wrong address.
    pub(crate) fn known_address(&self, family: AddressFamily, now: Instant) -> Option<IpAddr> {
        let rungs = self.address_rungs(family, now);
        best_fresh(&rungs, family, now).map(|rung| rung.value)
    }

    /// Which tier `family`'s address verdict currently rests on, or `None` when
    /// none holds.
    ///
    /// The **Port Mapping** runtime reads this as the connected server's ID
    /// verdict: [`Server`](ConfidenceTier::Server) holding an IPv4 *is* a
    /// High-ID, since that tier exists only while a session assigned us one. It
    /// is read here rather than plumbed from the session because the session
    /// layer does not know a port mapper exists, and "what the server says our
    /// address is" already lives in exactly one place.
    pub(crate) fn address_tier(
        &self,
        family: AddressFamily,
        now: Instant,
    ) -> Option<ConfidenceTier> {
        let rungs = self.address_rungs(family, now);
        best_fresh(&rungs, family, now).map(|rung| rung.tier)
    }

    /// The **External Endpoint** verdict for one socket in one family.
    pub(crate) fn endpoint(
        &self,
        family: AddressFamily,
        role: SocketRole,
        now: Instant,
    ) -> EndpointVerdict {
        let rungs = self.address_rungs(family, now);
        let port = self.port(role, now);
        if let Some(rung) = best_fresh(&rungs, family, now)
            && let Some(port) = port
            && let Some(endpoint) = join(rung.value, port)
        {
            return EndpointVerdict::Known {
                endpoint,
                tier: rung.tier,
            };
        }
        // Nothing fresh: the most recently lapsed rung is the last-known.
        let lapsed = rungs
            .iter()
            .filter(|rung| !rung.is_fresh(now))
            .max_by_key(|rung| rung.expires);
        match (lapsed, port) {
            (Some(rung), Some(port)) => match (join(rung.value, port), rung.expires) {
                (Some(endpoint), Some(since)) => EndpointVerdict::Stale { endpoint, since },
                _ => EndpointVerdict::Unknown,
            },
            _ => EndpointVerdict::Unknown,
        }
    }

    /// Our external **address** in `family`, fresh or stale — the half of a
    /// verdict that needs no port.
    ///
    /// The UDP crypt keys read exactly this: the key is
    /// `MD5(hash ‖ our address ‖ …)`, with no port in it, and the gate must
    /// answer before any socket has bound (aMule's `GetPublicIP() != 0`).
    /// Asking for a full endpoint there would make the crypt layer wait on a
    /// listener it has nothing to do with.
    pub(crate) fn address(&self, family: AddressFamily, now: Instant) -> Option<IpAddr> {
        let rungs = self.address_rungs(family, now);
        best_fresh(&rungs, family, now)
            .map(|rung| rung.value)
            .or_else(|| {
                rungs
                    .iter()
                    .filter(|rung| !rung.is_fresh(now))
                    .max_by_key(|rung| rung.expires)
                    .map(|rung| rung.value)
            })
    }

    /// The disagreement or refusal hint for one family, if any (ADR-0084's
    /// "disagreement is a fact, not an error"). A live disagreement outranks a
    /// remembered refusal: it is the one that describes the path right now.
    pub(crate) fn nat_hint(&self, family: AddressFamily, now: Instant) -> Option<NatHint> {
        let rungs = self.address_rungs(family, now);
        best_fresh(&rungs, family, now)
            .and_then(|adopted| {
                rungs
                    .iter()
                    .filter(|rung| rung.is_fresh(now) && rung.value != adopted.value)
                    .min_by_key(|rung| rung.tier.address_rank(family))
                    .map(|rung| NatHint::Disagreement {
                        adopted_tier: adopted.tier,
                        adopted: adopted.value,
                        dissenting_tier: rung.tier,
                        dissenting: rung.value,
                    })
            })
            .or_else(|| self.hints.get(&family).copied())
    }

    /// Whether anything at all has been observed — the "no learning has
    /// happened yet" case a diagnostics consumer renders as unknown rather
    /// than as an empty result.
    pub(crate) fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.addresses.values().all(Ladder::is_empty)
            && self.ports.values().all(Ladder::is_empty)
    }

    /// The **Own Address** at `now`: everything a reader of our own address
    /// can project — per family the fresh-or-stale address and the fresh one,
    /// per (family, role) the External Endpoint verdict, and each role's
    /// learned port — with the NAT facts read beside it, each family's **NAT
    /// Hint** and each role's **Own Mapping**. Two equal projections mean no
    /// reader can tell the store moved, which is what the **Own Address
    /// Generation** compares.
    fn own_address(&self, now: Instant) -> OwnAddress {
        let families = [AddressFamily::V4, AddressFamily::V6];
        OwnAddress {
            addresses: families
                .map(|family| (self.address(family, now), self.known_address(family, now))),
            endpoints: families
                .map(|family| SocketRole::ALL.map(|role| self.endpoint(family, role, now))),
            learned_ports: SocketRole::ALL.map(|role| self.learned_port(role, now)),
            hints: families.map(|family| self.nat_hint(family, now)),
            own_mappings: SocketRole::ALL.map(|role| self.own_mapping(role, now)),
        }
    }

    /// The earliest instant after `now` at which the projection can move with
    /// nobody writing — the edge the **Own Address Generation** never
    /// announces. `None` while nothing remembered can lapse.
    pub(crate) fn next_lapse(&self, now: Instant) -> Option<Instant> {
        let addresses = self
            .addresses
            .values()
            .filter_map(|ladder| ladder.next_lapse(now));
        let ports = self
            .ports
            .values()
            .filter_map(|ladder| ladder.next_lapse(now));
        addresses.chain(ports).min()
    }

    /// The **Extern Kad Port** when `role` is UDP: the best fresh port tier
    /// alone, `None` while no tier holds one. Unlike [`port`](Self::port) it
    /// never falls back to the bound port — a fallback would answer "known"
    /// before any observer agreed, and the Kad node's helper gate waits on
    /// exactly that answer.
    pub(crate) fn learned_port(&self, role: SocketRole, now: Instant) -> Option<u16> {
        self.ports.get(&role).and_then(|ladder| {
            ladder
                .rungs(now)
                .into_iter()
                .filter(|rung| rung.is_fresh(now) && rung.tier.port_rank().is_some())
                .min_by_key(|rung| rung.tier.port_rank())
                .map(|rung| rung.value)
        })
    }

    /// Our **Own Mapping** for `role` (ADR-0091's amendment): whether the
    /// current round's Kad observers saw one external port or several. The
    /// round boundary already forgets the previous round's reports, so what
    /// is read here is one round's.
    pub(crate) fn own_mapping(&self, role: SocketRole, now: Instant) -> OwnMapping {
        self.ports.get(&role).map_or(OwnMapping::Unknown, |ladder| {
            OwnMapping::from_reports(ladder.kad_reports(now))
        })
    }

    /// Forget `role`'s port ladder's [`KadCheck`](ConfidenceTier::KadCheck)
    /// reports at a round boundary (ADR-0084's amendment): aMule starts
    /// every **Extern Port Round** with empty observer lists
    /// (`FindExternKadPort(true)`, `Prefs.cpp:305-322`), so a report from
    /// before the boundary must not back one named after it. Only `role`'s
    /// Kad reports go — the address ladders and every other tier are a
    /// separate `BTreeMap` entry and untouched.
    pub(crate) fn forget_kad_port_round(&mut self, role: SocketRole) {
        if let Some(ladder) = self.ports.get_mut(&role) {
            ladder.withdraw(ConfidenceTier::KadCheck);
        }
    }

    /// The external port for `role`: the best fresh port tier, else the port
    /// the role actually bound.
    pub(super) fn port(&self, role: SocketRole, now: Instant) -> Option<u16> {
        self.learned_port(role, now).or_else(|| {
            self.binds
                .get(&role)
                .map(|bind| bind.port)
                .filter(|port| *port != 0)
        })
    }

    /// Every address rung `family` offers, corroboration filter applied, plus
    /// the interface rung the ladder cannot produce on its own.
    fn address_rungs(&self, family: AddressFamily, now: Instant) -> Vec<Rung<IpAddr>> {
        let mut rungs: Vec<Rung<IpAddr>> = self
            .addresses
            .get(&family)
            .map(|ladder| ladder.rungs(now))
            .unwrap_or_default()
            .into_iter()
            .filter(|rung| {
                rung.tier.address_rank(family).is_some() && self.corroborated(family, rung)
            })
            .collect();
        if let Some(address) = self.first_global_unicast(family) {
            rungs.push(Rung {
                tier: ConfidenceTier::Interface,
                value: address,
                expires: None,
            });
        }
        rungs
    }

    /// The **local-interface corroboration filter** — the security control
    /// (ADR-0084). A reflected IPv6 address is adopted only when this host
    /// also holds it, so corroboration can only pick *which of our own*
    /// addresses the outside world sees, never make us advertise a stranger's.
    ///
    /// IPv4 is deliberately exempt: behind NAT the external IPv4 is never on a
    /// local interface, so the same filter would refuse every true answer.
    /// There the tier order is the defence.
    fn corroborated(&self, family: AddressFamily, rung: &Rung<IpAddr>) -> bool {
        if family == AddressFamily::V4 || !is_reflected_tier(rung.tier) {
            return true;
        }
        self.interfaces.contains(&rung.value)
    }

    /// The first global-unicast address this host holds in `family` — the
    /// IPv6 dialect's tier-4 rule, applied to both families.
    fn first_global_unicast(&self, family: AddressFamily) -> Option<IpAddr> {
        self.interfaces
            .iter()
            .copied()
            .find(|address| family_of(*address) == family)
    }

    /// Record an address observation, applying the admissibility rules and
    /// raising whatever NAT hint the refusal implies.
    fn record_address(
        &mut self,
        source: ObservationSource,
        address: IpAddr,
        now: Instant,
    ) -> ObservationOutcome {
        let tier = source.tier();
        let family = family_of(address);
        if tier == ConfidenceTier::PeerVote && family == AddressFamily::V4 {
            return ObservationOutcome::Ipv4PeerVoteRefused;
        }
        if !is_publicly_usable(address) {
            if let Some(hint) = self.refusal_hint(source, address) {
                self.hints.insert(family, hint);
            }
            return ObservationOutcome::NotPubliclyUsable;
        }
        if tier == ConfidenceTier::PeerVote && !self.interfaces.contains(&address) {
            return ObservationOutcome::UnheldPeerVoteRefused;
        }
        self.addresses.entry(family).or_default().record(
            tier,
            address,
            source.observer().map(observer_identity),
            now,
            source.lease(),
        );
        ObservationOutcome::Recorded
    }

    /// What an unroutable observation says about the path it came over.
    fn refusal_hint(&self, source: ObservationSource, address: IpAddr) -> Option<NatHint> {
        if source.tier() == ConfidenceTier::MappingGrant {
            return Some(if is_carrier_grade_nat(address) {
                NatHint::CarrierGradeNat { granted: address }
            } else {
                NatHint::DoubleNat { granted: address }
            });
        }
        // A reflection naming an address this host holds and the world cannot
        // route means the datagram never left the NAT.
        (source.is_reflection() && self.interfaces_hold_locally(address)).then_some(
            NatHint::Hairpin {
                reflected: address,
                tier: source.tier(),
            },
        )
    }

    /// Whether `address` is on one of this host's own interfaces — exactly,
    /// with no widening. ADR-0091's **self-punch guard** asks this rather
    /// than "is it our public IP": an unknown public IP reads as loopback in
    /// the trees that built the guard that way, and the guard then called
    /// every punch target "ourselves" (amule#1177 correction 4).
    ///
    /// The set holds only publicly usable addresses, which is the right set
    /// for this question: a punch target has already passed the public-address
    /// test, so an unroutable interface could never equal one.
    pub(crate) fn holds_interface(&self, address: IpAddr) -> bool {
        self.interfaces.contains(&address)
    }

    /// Whether this host holds `address` on some interface, routable or not,
    /// or it is loopback. The interface *tier* keeps only publicly usable
    /// addresses; hairpin detection needs the unroutable ones too, so the
    /// enumeration's whole set answers it — a private address some other
    /// host holds is no hairpin (ADR-0084).
    fn interfaces_hold_locally(&self, address: IpAddr) -> bool {
        self.enumerated.contains(&address) || address.is_loopback()
    }
}

/// The best fresh rung on `family`'s ladder, or `None` when nothing holds.
/// A port ladder: its Kad reports follow `SetExternKadPort`'s any-earlier
/// agreement, where the address ladders keep the consecutive rule.
fn port_ladder() -> Ladder<u16> {
    Ladder::with_agreement(KadAgreement::AnyEarlier)
}

fn best_fresh(
    rungs: &[Rung<IpAddr>],
    family: AddressFamily,
    now: Instant,
) -> Option<&Rung<IpAddr>> {
    rungs
        .iter()
        .filter(|rung| rung.is_fresh(now))
        .min_by_key(|rung| rung.tier.address_rank(family))
}

/// Whether `tier` is the outside world telling us our own address.
/// The identity an observer votes under: its [`AccountingKey`] — the IPv4
/// address, or the IPv6 `/64` — spelled as an address. One delegated prefix
/// mints any number of `/128`s, so keying votes per address would let one
/// host be a quorum; `interval_limiter` keys the same senders the same way.
fn observer_identity(observer: IpAddr) -> IpAddr {
    match AccountingKey::of(observer) {
        AccountingKey::V4(address) => IpAddr::V4(address),
        AccountingKey::V6Prefix(prefix) => {
            IpAddr::V6(std::net::Ipv6Addr::from_bits(u128::from(prefix) << 64))
        }
    }
}

const fn is_reflected_tier(tier: ConfidenceTier) -> bool {
    matches!(
        tier,
        ConfidenceTier::Server
            | ConfidenceTier::LowIdReport
            | ConfidenceTier::KadCheck
            | ConfidenceTier::PeerVote
    )
}

/// The family an address belongs to.
const fn family_of(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::V4,
        IpAddr::V6(_) => AddressFamily::V6,
    }
}

/// The projection the **Own Address Generation** compares (see
/// [`AddressLearning::own_address`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnAddress {
    addresses: [(Option<IpAddr>, Option<IpAddr>); 2],
    endpoints: [[EndpointVerdict; SocketRole::ALL.len()]; 2],
    learned_ports: [Option<u16>; SocketRole::ALL.len()],
    hints: [Option<NatHint>; 2],
    own_mappings: [OwnMapping; SocketRole::ALL.len()],
}

/// An address and a port as the endpoint the two name together.
const fn join(address: IpAddr, port: u16) -> Option<PeerEndpoint> {
    match address {
        IpAddr::V4(ip) => Some(PeerEndpoint::V4(Ipv4Endpoint::new(ip, port))),
        IpAddr::V6(ip) => Some(PeerEndpoint::V6(Ipv6Endpoint::new(ip, port))),
    }
}

/// The shared handle every writer and reader holds — and the **clock edge**.
///
/// [`AddressLearning`] itself reads no clock: every rule takes `now` as a
/// parameter, so a test drives thirty minutes of freshness in a microsecond.
/// This wrapper is where real time enters, exactly as the Kad driver is where
/// real time enters the sans-I/O node. A `std::sync::Mutex` guards it because
/// every write is a point-in-time update that never crosses an `.await`.
#[derive(Clone, Debug)]
pub(crate) struct SharedAddressLearning {
    store: Arc<Mutex<AddressLearning>>,
    /// The **Bind Generation**: a counter every [`record_bind`] bumps, so a
    /// consumer can wait on "a socket came up" instead of being told.
    ///
    /// The **Desired Mapping Set** (ADR-0086) is derived from this store's bind
    /// table and from nothing else, so the table's own writes are the only
    /// honest trigger. A notice sent *beside* the bind is a race — the one the
    /// eD2k listener lost, which costs a whole session its High-ID mapping —
    /// and it is silent when it loses. A `watch` coalesces, so a burst of binds
    /// costs one re-derivation and none can be dropped for a full inbox.
    ///
    /// [`record_bind`]: Self::record_bind
    binds: Arc<watch::Sender<u64>>,
    /// The **Own Address Generation**: a counter bumped by every
    /// write that moved the [`OwnAddress`] projection — the one change event
    /// every reader of our own address that caches (the Kad node, the port
    /// mapper, the reachability trail) subscribes to. A write that moved nothing a reader can see
    /// bumps nothing, so an unchanged re-observation costs no wake.
    own_address: Arc<watch::Sender<u64>>,
}

impl Default for SharedAddressLearning {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedAddressLearning {
    /// An empty store behind a fresh handle.
    pub(crate) fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(AddressLearning::new())),
            binds: Arc::new(watch::Sender::new(0)),
            own_address: Arc::new(watch::Sender::new(0)),
        }
    }

    /// A receiver that wakes on every recorded bind — what the **Port
    /// Mapping** runtime waits on to re-derive its **Desired Mapping Set**
    /// The generation value itself is immaterial; the wake is
    /// the fact.
    pub(crate) fn binds_changed(&self) -> watch::Receiver<u64> {
        self.binds.subscribe()
    }

    /// A receiver that wakes on every **Own Address Generation** — any write
    /// that moved our own address, in either family, a learned port, a NAT
    /// Hint or an Own Mapping. The value is immaterial; the wake is the fact,
    /// and the subscriber re-reads the store. Time alone never wakes it: a
    /// freshness window that lapses with nobody writing is the one edge a
    /// subscriber that caches must still catch, at
    /// [`next_lapse`](Self::next_lapse) or on a clock of its own.
    pub(crate) fn own_address_changed(&self) -> watch::Receiver<u64> {
        self.own_address.subscribe()
    }

    /// Take one observation, stamped now.
    pub(crate) fn observe(&self, observation: AddressObservation) -> ObservationOutcome {
        self.write(|store, now| store.observe(observation, now))
    }

    /// Apply the operator's configured override.
    pub(crate) fn set_override(&self, over: ExternalAddressOverride) {
        self.write(|store, now| store.set_override(over, now));
    }

    /// The connected server's `OP_IDCHANGE` verdict (see
    /// [`AddressLearning::observe_server_assigned`]).
    pub(crate) fn observe_server_assigned(
        &self,
        client_id: ClientId,
        public_ip: Option<Ipv4Addr>,
        server_ip: Option<IpAddr>,
    ) -> AssignedAddress {
        self.write(|store, now| store.observe_server_assigned(client_id, public_ip, server_ip, now))
    }

    /// The server session ended (see [`AddressLearning::end_server_session`]).
    pub(crate) fn end_server_session(&self) {
        self.write(|store, now| store.end_server_session(now));
    }

    /// Replace the set of addresses this host holds.
    pub(crate) fn refresh_interfaces(&self, addresses: &[IpAddr]) {
        self.write(|store, _| store.refresh_interfaces(addresses));
    }

    /// Record what one role's **Family Pair** bound, then publish the **Bind
    /// Generation** — in that order, so a consumer woken by the bump always
    /// reads the bind that woke it.
    pub(crate) fn record_bind(&self, role: SocketRole, binds: &FamilyBinds, port: u16) {
        self.write(|store, _| store.record_bind(role, binds, port));
        self.binds.send_modify(|generation| *generation += 1);
    }

    /// Forget one role's bind, then publish the **Bind Generation** — the
    /// [`record_bind`](Self::record_bind) order, for the same reason.
    pub(crate) fn forget_bind(&self, role: SocketRole) {
        self.write(|store, _| store.forget_bind(role));
        self.binds.send_modify(|generation| *generation += 1);
    }

    /// The **External Endpoint** verdict for one socket in one family.
    pub(crate) fn endpoint(&self, family: AddressFamily, role: SocketRole) -> EndpointVerdict {
        self.with(|store, now| store.endpoint(family, role, now))
    }

    /// The learned port for `role`, with no bound-port fallback (see
    /// [`AddressLearning::learned_port`]).
    pub(crate) fn learned_port(&self, role: SocketRole) -> Option<u16> {
        self.with(|store, now| store.learned_port(role, now))
    }

    /// See [`AddressLearning::own_mapping`].
    pub(crate) fn own_mapping(&self, role: SocketRole) -> OwnMapping {
        self.with(|store, now| store.own_mapping(role, now))
    }

    /// When the projection can next move with nobody writing (see
    /// [`AddressLearning::next_lapse`]): where a reader that caches it reads
    /// again, instead of on a clock of its own.
    pub(crate) fn next_lapse(&self) -> Option<Instant> {
        self.with(|store, now| store.next_lapse(now))
    }

    /// See [`AddressLearning::forget_kad_port_round`].
    pub(crate) fn forget_kad_port_round(&self, role: SocketRole) {
        self.write(|store, _| store.forget_kad_port_round(role));
    }

    /// Our external address in one family, fresh or stale (see
    /// [`AddressLearning::address`]).
    pub(crate) fn address(&self, family: AddressFamily) -> Option<IpAddr> {
        self.with(|store, now| store.address(family, now))
    }

    /// Whether `role` bound `family` (see [`AddressLearning::bound`]).
    pub(crate) fn bound(&self, role: SocketRole, family: AddressFamily) -> bool {
        self.with(|store, _| store.bound(role, family))
    }

    /// The **Half-Bound Pair** fact for `role` (see
    /// [`AddressLearning::half_bound`]).
    pub(crate) fn half_bound(&self, role: SocketRole) -> Option<HalfBound> {
        self.with(|store, _| store.half_bound(role))
    }

    /// What `role`'s **Family Pair** bound (see [`AddressLearning::bind`]).
    pub(crate) fn bind(&self, role: SocketRole) -> Option<(Vec<AddressFamily>, u16)> {
        self.with(|store, _| store.bind(role))
    }

    /// The port `role` first bound (see [`AddressLearning::held_port`]).
    pub(crate) fn held_port(&self, role: SocketRole) -> Option<u16> {
        self.with(|store, _| store.held_port(role))
    }

    /// See [`AddressLearning::holds_interface`].
    pub(crate) fn holds_interface(&self, address: IpAddr) -> bool {
        self.with(|store, _| store.holds_interface(address))
    }

    /// Our external address in one family while a fresh tier holds it (see
    /// [`AddressLearning::known_address`]).
    pub(crate) fn known_address(&self, family: AddressFamily) -> Option<IpAddr> {
        self.with(|store, now| store.known_address(family, now))
    }

    /// Which tier one family's verdict rests on (see
    /// [`AddressLearning::address_tier`]).
    pub(crate) fn address_tier(&self, family: AddressFamily) -> Option<ConfidenceTier> {
        self.with(|store, now| store.address_tier(family, now))
    }

    /// The one chooser every advert reads (ADR-0084).
    pub(crate) fn advertised_endpoints(&self, reach: AdvertReachability) -> AdvertisedEndpoints {
        self.with(|store, now| AdvertisedEndpoints::choose(store, reach, now))
    }

    /// The port the chooser advertises for `role`'s IPv4 endpoint — the
    /// learned external one, `None` while no endpoint is Known. The IPv4
    /// half of the chooser reads no reachability verdict, so none is taken.
    pub(crate) fn advertised_v4_port(&self, role: SocketRole) -> Option<u16> {
        self.advertised_endpoints(AdvertReachability::unproven())
            .endpoint(AddressFamily::V4, role)
            .map(|endpoint| endpoint.port())
    }

    /// The **Advertised IPv6** under the server's `probe` verdict — the
    /// chooser's IPv6 answer (ADR-0087). It reads the probe and the store
    /// alone, never the TCP verdict, so the TCP half is the unproven default.
    pub(crate) fn advertised_ipv6(&self, probe: Ipv6Probe) -> Option<std::net::Ipv6Addr> {
        self.advertised_endpoints(AdvertReachability {
            ipv6: probe,
            ..AdvertReachability::unproven()
        })
        .advertised_ipv6()
    }

    /// The per-family hint, if the sources disagree.
    pub(crate) fn nat_hint(&self, family: AddressFamily) -> Option<NatHint> {
        self.with(|store, now| store.nat_hint(family, now))
    }

    /// Whether anything at all has been learned yet.
    pub(crate) fn is_empty(&self) -> bool {
        self.with(|store, _| store.is_empty())
    }

    /// Apply one write, then publish the **Own Address Generation** if the
    /// projection moved — after the lock is released, so a subscriber woken
    /// by the bump always reads the write that woke it.
    fn write<R>(&self, act: impl FnOnce(&mut AddressLearning, Instant) -> R) -> R {
        let (result, moved) = self.with(|store, now| {
            let before = store.own_address(now);
            let result = act(store, now);
            (result, store.own_address(now) != before)
        });
        if moved {
            self.own_address.send_modify(|generation| *generation += 1);
        }
        result
    }

    fn with<R>(&self, act: impl FnOnce(&mut AddressLearning, Instant) -> R) -> R {
        let mut store = self.store.lock().expect("address-learning mutex poisoned");
        act(&mut store, Instant::now())
    }
}
