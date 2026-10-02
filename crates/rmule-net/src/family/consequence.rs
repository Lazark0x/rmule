//! What a **Half-Bound Pair** costs, stated once per socket role (ADR-0085 amendment).
//!
//! ADR-0085's rule stands: one Address Family refusing must not take the
//! other down. What that refusal *means*, though, is role-specific — and
//! until it was written down here every consumer inferred it, or did not
//! infer it at all: a client-UDP pair that came up on `::` alone left Kad and
//! the NAT-T punch path dead while every surface still read "bound".
//!
//! One table, three roles. The bind sites read it to decide what to say; the
//! capability gates read it to decide what to refuse. Nobody re-derives it.

use std::fmt;
use std::io;

use rmule_primitives::AddressFamily;

use super::FamilyBinds;

/// A role whose **Family Pair** rmule binds (ADR-0085, "two sockets per role
/// and port").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PairRole {
    /// The one client-UDP socket (ADR-0057's socket unification): the
    /// peer-UDP reask surface, the NAT-T transport frames and the Kad node
    /// all ride it.
    ClientUdp,
    /// The eD2k peer listener — the port a server's High-ID check dials back
    /// and every hello advertises.
    Ed2kListener,
    /// The server-UDP socket: the global source sweep, the status ping and
    /// the server description ask.
    ServerUdp,
}

impl PairRole {
    /// Every role, in the order a diagnostics reader walks them.
    pub const ALL: [Self; 3] = [Self::ClientUdp, Self::Ed2kListener, Self::ServerUdp];

    /// The name an operator reads.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ClientUdp => "client-UDP",
            Self::Ed2kListener => "the eD2k listener",
            Self::ServerUdp => "server-UDP",
        }
    }

    /// What this role forfeits when `missing` is the family that refused —
    /// the consequence table itself, and the only copy of it.
    ///
    /// The IPv4 rows are the sharp ones, because the eD2k network's main
    /// family is IPv4: Kad is IPv4-only by construction (ADR-0087), the
    /// server punch and the buddy rendezvous are IPv4 end to end (ADR-0091),
    /// a server's High-ID port check dials IPv4, and the server-UDP sweep is
    /// IPv4-first (ADR-0087's server-UDP family ruling). The IPv6 rows cost
    /// only what the IPv6 dialect itself would have carried.
    #[must_use]
    pub const fn forfeits(self, missing: AddressFamily) -> &'static [Consequence] {
        match (self, missing) {
            (Self::ClientUdp, AddressFamily::V4) => &[
                Consequence::Kad,
                Consequence::NatTraversal,
                Consequence::Ipv4UdpAdvert,
            ],
            (Self::ClientUdp, AddressFamily::V6) => &[Consequence::Ipv6Reask],
            (Self::Ed2kListener, AddressFamily::V4) => {
                &[Consequence::Ipv4Dials, Consequence::HighId]
            }
            (Self::Ed2kListener, AddressFamily::V6) => {
                &[Consequence::Ipv6Dials, Consequence::Ipv6Advert]
            }
            (Self::ServerUdp, AddressFamily::V4) => &[Consequence::ServerUdpSweep],
            // Nothing rides the server-UDP pair's `::` half: every request
            // rmule makes of a server over UDP names an IPv4 server address.
            (Self::ServerUdp, AddressFamily::V6) => &[],
        }
    }
}

impl fmt::Display for PairRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One capability a [`HalfBound`] pair costs — a clause in the sentence an
/// operator reads, and a token a capability gate matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Consequence {
    /// The Kad node cannot run at all: it rides the
    /// client-UDP pair, and only its IPv4 half (ADR-0087).
    Kad,
    /// NAT traversal cannot run: the ed2k-server punch and the buddy
    /// rendezvous are IPv4 end to end (ADR-0091).
    NatTraversal,
    /// No IPv4 UDP port may be advertised — neither the login's `0xF9` nor
    /// the hello's `CT_EMULE_UDPPORTS`, because both name a port an IPv4
    /// datagram must reach.
    Ipv4UdpAdvert,
    /// The IPv6 peer-UDP reask surface is gone; the IPv4 one is untouched.
    Ipv6Reask,
    /// No IPv4 peer can dial our listener.
    Ipv4Dials,
    /// No IPv4 server's port check can reach the listener, so no High ID is
    /// possible on one — and with it every callback-capable posture
    /// (ADR-0039) goes.
    HighId,
    /// No IPv6 peer can dial our listener.
    Ipv6Dials,
    /// `CT_MOD_IP_V6` is withheld (ADR-0087): the chooser names no IPv6 TCP
    /// endpoint, so rmule cannot claim one. Everything IPv4 is untouched.
    Ipv6Advert,
    /// The UDP server sweep — global source discovery, status pings and the
    /// description ask — has no socket.
    ServerUdpSweep,
}

impl Consequence {
    /// The subject of the "… is/are off until restart" clause.
    ///
    /// [`HalfBound`]'s `Display` picks the verb from the *count*, so every
    /// one-element row of [`PairRole::forfeits`] names a grammatically
    /// singular phrase and every plural phrase appears only beside another.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::Kad => "Kad",
            Self::NatTraversal => "NAT traversal",
            Self::Ipv4UdpAdvert => "the IPv4 UDP advert",
            Self::Ipv6Reask => "the IPv6 reask surface",
            Self::Ipv4Dials => "IPv4 dials",
            Self::HighId => "any High ID",
            Self::Ipv6Dials => "IPv6 dials",
            Self::Ipv6Advert => "the IPv6 advert",
            Self::ServerUdpSweep => "the UDP server sweep",
        }
    }
}

impl fmt::Display for Consequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.phrase())
    }
}

/// A **Half-Bound Pair**: one role's Family Pair came up, but a family it
/// *selected* refused, so the role runs on the other family alone.
///
/// A family that was never selected is not this fact — an operator who
/// configured IPv4 only has lost nothing, and saying otherwise would make the
/// honest case noisy. [`read`](Self::read) therefore fires on
/// [`FamilyBinds::refused`] and never on a merely absent family.
///
/// Permanent for the session: there is no re-bind (ADR-0057's failed-bind
/// amendment), so this is the whole session's answer to "why is Kad off".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HalfBound {
    /// Which role's pair came up half.
    pub role: PairRole,
    /// The family that refused, and is therefore absent.
    pub missing: AddressFamily,
    /// The OS's reason for the refusal, as [`FamilyBinds::refused`] recorded
    /// it. The full message is logged once at `warn` at the bind site.
    pub kind: io::ErrorKind,
}

impl HalfBound {
    /// Read `role`'s pair as a half-bound fact, or `None` when the pair is
    /// whole — every selected family bound — or when nothing bound at all
    /// (a *total* refusal, which `UdpFamilyPair::bind` returns as an `Err`
    /// and the failed-bind facts already name).
    #[must_use]
    pub fn read(role: PairRole, binds: &FamilyBinds) -> Option<Self> {
        if binds.bound.is_empty() {
            return None;
        }
        let (missing, kind, _) = *binds.refused.first()?;
        Some(Self {
            role,
            missing,
            kind,
        })
    }

    /// What this pair forfeits — [`PairRole::forfeits`] for the family that
    /// actually refused.
    #[must_use]
    pub const fn forfeits(&self) -> &'static [Consequence] {
        self.role.forfeits(self.missing)
    }

    /// Whether `consequence` is one of them — the shape a capability gate
    /// asks in ("may Kad start?"), so no gate re-derives the table.
    #[must_use]
    pub fn forfeited(&self, consequence: Consequence) -> bool {
        self.forfeits().contains(&consequence)
    }
}

impl fmt::Display for HalfBound {
    /// The CLI's and the logs' one line for a half-bound pair. The TUI words
    /// the pair's codes itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} came up without {} — its bind was refused ({}): ",
            self.role, self.missing, self.kind
        )?;
        let forfeits = self.forfeits();
        let Some((last, rest)) = forfeits.split_last() else {
            return write!(f, "nothing rides that family");
        };
        for (index, consequence) in rest.iter().enumerate() {
            let separator = if index + 1 == rest.len() {
                " and "
            } else {
                ", "
            };
            write!(f, "{consequence}{separator}")?;
        }
        let verb = if forfeits.len() == 1 { "is" } else { "are" };
        write!(f, "{last} {verb} off until restart")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binds(bound: &[AddressFamily], refused: AddressFamily) -> FamilyBinds {
        FamilyBinds {
            bound: bound.to_vec(),
            refused: vec![(refused, io::ErrorKind::AddrInUse, "in use".to_owned())],
        }
    }

    #[test]
    fn a_whole_pair_is_not_a_half_bound_fact() {
        let whole = FamilyBinds {
            bound: vec![AddressFamily::V4, AddressFamily::V6],
            refused: Vec::new(),
        };
        assert_eq!(HalfBound::read(PairRole::ClientUdp, &whole), None);
    }

    #[test]
    fn a_family_that_refused_is_told_apart_from_one_never_selected() {
        // v4-only selection: v6 was never attempted, so nothing was lost.
        let selected_v4_only = FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: Vec::new(),
        };
        assert_eq!(
            HalfBound::read(PairRole::ClientUdp, &selected_v4_only),
            None
        );
        // The same single bound family, but v6 was asked for and refused.
        assert!(
            HalfBound::read(
                PairRole::ClientUdp,
                &binds(&[AddressFamily::V4], AddressFamily::V6)
            )
            .is_some()
        );
    }

    #[test]
    fn a_client_udp_pair_without_ipv4_forfeits_kad_natt_and_the_advert() {
        let half = HalfBound::read(
            PairRole::ClientUdp,
            &binds(&[AddressFamily::V6], AddressFamily::V4),
        )
        .expect("a refused family with another bound is half-bound");
        assert!(half.forfeited(Consequence::Kad));
        assert!(half.forfeited(Consequence::NatTraversal));
        assert!(half.forfeited(Consequence::Ipv4UdpAdvert));
        assert_eq!(
            half.to_string(),
            "client-UDP came up without IPv4 — its bind was refused (address in use): \
             Kad, NAT traversal and the IPv4 UDP advert are off until restart"
        );
    }

    #[test]
    fn a_client_udp_pair_without_ipv6_keeps_kad_and_the_punch_path() {
        let half = HalfBound::read(
            PairRole::ClientUdp,
            &binds(&[AddressFamily::V4], AddressFamily::V6),
        )
        .expect("half-bound");
        assert!(!half.forfeited(Consequence::Kad));
        assert!(!half.forfeited(Consequence::NatTraversal));
        assert_eq!(
            half.to_string(),
            "client-UDP came up without IPv6 — its bind was refused (address in use): \
             the IPv6 reask surface is off until restart"
        );
    }

    #[test]
    fn a_listener_without_ipv4_forfeits_every_high_id() {
        let half = HalfBound::read(
            PairRole::Ed2kListener,
            &binds(&[AddressFamily::V6], AddressFamily::V4),
        )
        .expect("half-bound");
        assert!(half.forfeited(Consequence::HighId));
        assert_eq!(
            half.to_string(),
            "the eD2k listener came up without IPv4 — its bind was refused (address in use): \
             IPv4 dials and any High ID are off until restart"
        );
    }

    #[test]
    fn a_server_udp_pair_without_ipv6_loses_nothing_and_says_so() {
        let half = HalfBound::read(
            PairRole::ServerUdp,
            &binds(&[AddressFamily::V4], AddressFamily::V6),
        )
        .expect("half-bound");
        assert_eq!(half.forfeits(), &[]);
        assert_eq!(
            half.to_string(),
            "server-UDP came up without IPv6 — its bind was refused (address in use): \
             nothing rides that family"
        );
    }
}
