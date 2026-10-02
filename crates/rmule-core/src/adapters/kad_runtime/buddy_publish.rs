//! The two directions the ADR-0061 buddy crosses between core's firewalled
//! slot and the live Kad node: adopting a verified `0x5A` into the slot, and
//! telling the node which buddy its source publishes should name
//! — and the connect options those publishes state beside it,
//! without which a Low-ID downloader has no road to the buddy row.
//!
//! Split out of `node.rs` because it is one concern with several call sites in that
//! pump, and because the pump is at its file ceiling.

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{CryptStance, Ipv4Endpoint, SourceCryptOptions};

use crate::adapters::HelloAdverts;
use crate::firewalled::link::SharedFirewalledSlot;
use crate::firewalled::recruit::AdoptOutcome;

/// The buddy-publish verdict's one writer into the node, and
/// the memory of what it last told it — so a resync that changes nothing costs
/// no command. The pump's other feeds (`TcpVerdictFeed`, `PublicIpFeed`) keep
/// the same shape.
pub(super) struct BuddyPublishFeed {
    slot: SharedFirewalledSlot,
    /// The stance this node runs under — the side of the buddy dial's crypt
    /// rule that is ours.
    ours: CryptStance,
    /// Where a crypt-incompatible refusal is counted.
    diagnostics: crate::diagnostics::DiagnosticsState,
    /// The posture last told — `None` until the first sync, which therefore
    /// always states one.
    published: Option<rmule_kad::KadPublishPosture>,
}

impl BuddyPublishFeed {
    /// The feed over `hello`'s firewalled slot, under its crypt policy,
    /// counting its refusals into `diagnostics`.
    pub(super) fn new(
        hello: &HelloAdverts,
        diagnostics: crate::diagnostics::DiagnosticsState,
    ) -> Self {
        Self {
            slot: hello.firewalled_slot.clone(),
            ours: ObfuscationPolicy::stance_of(hello.crypt_policy),
            diagnostics,
            published: None,
        }
    }

    /// Seat a verified `0x5A` in the slot and, if it took, tell the front to
    /// dial and the node to publish through it.
    ///
    /// The node already applied the tracked-packet and XOR-inversion guards;
    /// the slot applies the same XOR check against its own Kad ID — one gate,
    /// two owners, because a slot that trusted the event could be filled by a
    /// node it was never re-seated for.
    ///
    /// The `0x5A`'s connect-options byte rides into the slot as the buddy's
    /// stance: the dial meets it with ours, and a pair that cannot
    /// meet is refused here, never dialled. `found` is the pump's
    /// `KadEvent::BuddyFound`; any other event is ignored.
    pub(super) fn adopt_found_buddy(
        &mut self,
        found: rmule_kad::KadEvent,
        handle: &rmule_net::kad::KadNetHandle,
        front: &crate::firewalled::front::SharedFirewalledFront,
        firewalled: bool,
    ) {
        if self.seat(found) == Some(AdoptOutcome::Adopted) {
            front.send(crate::firewalled::front::FirewalledCommand::BuddyAdopted);
            // The slot filled, so every source publish from here names this
            // buddy.
            self.sync(firewalled, handle);
        }
    }

    /// The slot's verdict on `found` — `None` for any other event — with each
    /// refusal logged and a crypt-incompatible one counted beside the other
    /// buddy-dial refusals: a buddy refused on the crypt rule is
    /// a dial that never happens, and a count of them is what tells an
    /// operator their policy is turning buddies away.
    fn seat(&self, found: rmule_kad::KadEvent) -> Option<AdoptOutcome> {
        let rmule_kad::KadEvent::BuddyFound {
            buddy,
            buddy_id,
            buddy_hash,
            buddy_tcp_port,
            connect_options,
        } = found
        else {
            return None;
        };
        let res = crate::firewalled::recruit::FindBuddyRes {
            buddy_id,
            buddy_endpoint: buddy,
        };
        let recruited = crate::firewalled::link::RecruitedBuddy {
            udp: buddy,
            tcp: Ipv4Endpoint::new(buddy.ip, buddy_tcp_port),
            hash: buddy_hash,
            // No byte (a pre-v7 buddy) is silence, not a stated "off"
            // (ADR-0049) — `peer_crypt` folds it to all lights
            // dark at the dial, the same read aMule's own `connectOptions = 0`
            // gets (`KademliaUDPListener.cpp:1756`), but the record does not
            // itself claim the buddy said so.
            crypt: connect_options.map(|byte| SourceCryptOptions::from_byte(byte).crypt_stance()),
        };
        let outcome = self.slot.adopt_buddy(&res, recruited, self.ours);
        match outcome {
            AdoptOutcome::Adopted => {
                tracing::info!(
                    ?recruited.tcp,
                    "buddy recruited; dialing its link (ADR-0061)"
                );
            }
            AdoptOutcome::Rejected => {
                tracing::debug!(
                    ?buddy,
                    "0x5A rejected: its buddy-ID does not invert to our Kad ID"
                );
            }
            AdoptOutcome::CryptIncompatible => {
                self.diagnostics.record_buddy_dial_crypt_incompatible();
                tracing::info!(
                    ?buddy,
                    ?connect_options,
                    "buddy refused: CryptLayer-Settings (Obfuscation) incompatible (ADR-0049)"
                );
            }
        }
        Some(outcome)
    }

    /// Tell the node its publish posture: whether it is
    /// firewalled and, if so, which buddy its source publishes should name.
    ///
    /// `FirewalledSlot::publish_buddy_info` is the only place the buddy is
    /// decided — a firewalled node with a held buddy publishes aMule's type-3/5
    /// row, a firewalled one with none publishes nothing (aMule's
    /// `PrepareToStop`), a reachable one the direct row — and this is the one
    /// place it crosses into the node. Same discipline as `SetAdvertisedIpv6`: the node
    /// never reads its own reachability. `firewalled` is the ADR-0060 union
    /// ([`SharedSelfReach::firewalled`](crate::reachability::SharedSelfReach::firewalled),
    /// Server High ID **or** Kad TCP open), the same fact
    /// `ConnectOptionsFeed` composes the direct-callback bit from — a server
    /// High ID withdraws the buddy row exactly as it withdraws that bit.
    ///
    /// The verdict also moves where no pump event marks it: the front holds
    /// the buddy link — and with it the buddy's IPv6, the `bi6` tag
    /// — and loses it on its own task. The pump's recruit tick resyncs
    /// for that, so the node trails the slot by at most one tick.
    ///
    /// A momentarily-full inbox drops the update and logs it; the next
    /// transition or tick resends, and until then the node publishes the
    /// previous verdict — which is at worst a stale buddy, never an invented
    /// one.
    pub(super) fn sync(&mut self, firewalled: bool, handle: &rmule_net::kad::KadNetHandle) {
        let posture = if firewalled {
            rmule_kad::KadPublishPosture::Firewalled {
                buddy: self.slot.publish_buddy_info(true).map(|publish| {
                    rmule_kad::KadBuddyContact {
                        buddy_id: publish.buddy_id,
                        buddy_udp: Some(publish.buddy_udp),
                        buddy_ipv6: publish.buddy_ipv6,
                        buddy_udp_ipv6: None,
                    }
                }),
            }
        } else {
            rmule_kad::KadPublishPosture::Reachable
        };
        if Some(posture) == self.published {
            return;
        }
        match handle.try_command(rmule_kad::KadCommand::SetPublishPosture { posture }) {
            Ok(true) => self.published = Some(posture),
            Ok(false) => tracing::warn!(
                "kad command inbox full; buddy-publish verdict deferred to the next transition"
            ),
            Err(_) => {}
        }
    }
}

/// The **Publish Connect Options**: the `TAG_ENCRYPTION`
/// byte this node's source publishes state, composed from three facts the
/// caller fetched from their owners — our crypt policy, whether the ADR-0060
/// verdicts earn the direct-UDP-callback bit, and the NAT-T transports the
/// front on the Kad node's socket serves (the one socket a punch toward a
/// published row lands on).
///
/// What the byte means depends on who wrote it, and this writes the widest
/// family's form:
///
/// - **aMule** (Fork Pin `ab483654`) `CPrefs::GetMyConnectOptions(true, true)`,
///   `src/kademlia/kademlia/Prefs.cpp:214-233`, at the publish site
///   `src/kademlia/kademlia/Search.cpp:883-884`: four reserved high bits, then
///   direct callback (`IsFirewalled() && Kad running && !IsFirewalledUDP(true)
///   && IsVerified()`) and the crypt ladder — `0x0F` at most.
/// - **eMule 0.70b** (`irwir/eMule@13983526`) `CPrefs::GetMyConnectOptions`
///   delegates (`srchybrid/kademlia/kademlia/Prefs.cpp:461-464`) to the global
///   `::GetMyConnectOptions` (`srchybrid/OtherFunctions.cpp:3855-3871`), which
///   assembles the same four bits — `0x0F` at most; publish site
///   `srchybrid/kademlia/kademlia/Search.cpp:691`.
/// - **eMuleAI** (`a2f05dc8`) delegates the same way
///   (`srchybrid/kademlia/kademlia/Prefs.cpp:486-489`) to a global
///   `::GetMyConnectOptions` (`srchybrid/OtherFunctions.cpp:4122-4147`) that
///   also ORs `0x80` (uTP NAT-T) and `0x40` (QUIC NAT-T) while its NAT-T
///   endpoint is ready; publish site `srchybrid/kademlia/kademlia/Search.cpp:913`.
///
/// An aMule or eMule reader ignores the high bits it reserves; an eMuleAI or
/// rmule reader takes `0x80` as a punchable source. `natt` is what the front
/// serves, not what the build can speak: QUIC stays dark until a live
/// handshake proves it (ADR-0091).
///
/// Always a byte, zero included: every bit has an owner that answered, so a
/// zero is their joint answer — the one a crypt-less aMule states too — and
/// not a default. Silence belongs to a node with no owners behind it.
pub(super) fn publish_connect_options(
    crypt_policy: Option<rmule_net::peer::ObfuscationPolicy>,
    direct_udp_callback: bool,
    natt: rmule_peer::natt::HelloNattClaim,
) -> u8 {
    let crypt = crate::client_udp::direct_callback_connect_options(
        crypt_policy.map_or(rmule_primitives::CryptStance::disabled(), |policy| {
            policy.crypt_stance()
        }),
    );
    rmule_peer::natt::NattConnectOptions::advertise(crypt, natt.utp, natt.quic).as_byte()
        | if direct_udp_callback {
            CONNECT_OPT_DIRECT_UDP_CALLBACK
        } else {
            0
        }
}

/// `CONNECT_OPT_DIRECT_UDP_CALLBACK`: this node accepts an
/// `OP_DIRECTCALLBACKREQ` (`0x95`) at its Kad UDP port.
const CONNECT_OPT_DIRECT_UDP_CALLBACK: u8 = 0x08;

/// The Publish Connect Options composition, bit by bit against the three
/// families' `GetMyConnectOptions`.
#[cfg(test)]
mod tests {
    use rmule_net::peer::ObfuscationPolicy;
    use rmule_peer::natt::HelloNattClaim;

    use super::{BuddyPublishFeed, publish_connect_options};

    const NO_NATT: HelloNattClaim = HelloNattClaim {
        utp: false,
        quic: false,
    };
    const UTP: HelloNattClaim = HelloNattClaim {
        utp: true,
        quic: false,
    };

    /// The captured aMule publish (`amule-233-publish-source-req-20260922`)
    /// carries `0x00`: a crypt-less publisher, firewalled behind a buddy (so
    /// no direct callback), with no NAT-T. The same three facts compose the
    /// same byte here — the capture KAT's told input is this function's
    /// output, stated rather than left silent.
    #[test]
    fn a_crypt_less_buddy_publisher_without_natt_composes_the_captured_zero() {
        assert_eq!(publish_connect_options(None, false, NO_NATT), 0x00);
    }

    /// Each owner lights only its own bits: the crypt ladder `0x07`, the
    /// ADR-0060 direct-callback verdict `0x08`, and the served NAT-T
    /// transports `0x80`/`0x40` — never the reserved `0x10` or the
    /// endpoint-hint request `0x20`, which is a rendezvous request, not a
    /// capability.
    #[test]
    fn each_fact_lights_only_its_own_bits() {
        let both = HelloNattClaim {
            utp: true,
            quic: true,
        };
        let requested = Some(ObfuscationPolicy::Requested);
        let required = Some(ObfuscationPolicy::Required);
        for (policy, callback, natt, byte) in [
            (None, false, UTP, 0x80),
            (requested, false, NO_NATT, 0x03),
            (required, false, NO_NATT, 0x07),
            (None, true, NO_NATT, 0x08),
            (requested, false, UTP, 0x83),
            (required, true, UTP, 0x8F),
            (None, false, both, 0xC0),
        ] {
            assert_eq!(
                publish_connect_options(policy, callback, natt),
                byte,
                "{policy:?} callback={callback} {natt:?}"
            );
        }
    }

    /// A buddy whose `0x5A` requires the crypt layer (`0x07`),
    /// met by a node whose layer is off, is refused before any dial — and the
    /// refusal is counted beside the other buddy-dial refusals, not only
    /// logged.
    #[test]
    fn a_crypt_incompatible_buddy_refusal_is_counted() {
        use std::net::Ipv4Addr;

        use rmule_kad::KadId;
        use rmule_primitives::{Ipv4Endpoint, UserHash};

        use crate::firewalled::recruit::{AdoptOutcome, RecruitContext, RecruitDecision};

        let ours = KadId::from_bytes([0xAA; KadId::BYTE_LEN]);
        let hello = crate::adapters::HelloAdverts {
            firewalled_slot: std::sync::Arc::new(crate::firewalled::link::FirewalledSlot::new(
                ours,
            )),
            ..crate::adapters::HelloAdverts::default()
        };
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let feed = BuddyPublishFeed::new(&hello, diagnostics.clone());
        let walking = hello.firewalled_slot.consider_recruitment(
            &RecruitContext {
                kad_connected: true,
                tcp: crate::reachability::TcpReachability::Firewalled,
                udp: crate::buddy::BuddyUdpPosture::Firewalled,
                last_recheck: None,
                crypt_required: false,
            },
            std::time::Instant::now(),
        );
        assert!(matches!(walking, RecruitDecision::Recruit { .. }));

        let found = rmule_kad::KadEvent::BuddyFound {
            buddy: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672),
            // `~0xAA…`: the buddy-ID our walk's answer echoes.
            buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
            buddy_hash: UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
            buddy_tcp_port: 4662,
            connect_options: Some(0x07),
        };
        assert_eq!(feed.seat(found), Some(AdoptOutcome::CryptIncompatible));
        assert_eq!(
            diagnostics
                .snapshot()
                .session
                .buddy_dials_crypt_incompatible_total,
            1
        );
    }

    /// A pre-v7 `0x5A` that carries no connect-options byte
    /// seats a buddy whose `crypt` is `None` — silence, not a stated "off"
    /// (`CryptStance::disabled()`) — mirroring `PeerCrypt::stance`'s own
    /// "stated" vs "silent" split (ADR-0049).
    #[test]
    fn a_pre_v7_buddys_missing_connect_options_byte_seats_as_silence() {
        use std::net::Ipv4Addr;

        use rmule_kad::KadId;
        use rmule_primitives::{Ipv4Endpoint, UserHash};

        use crate::firewalled::recruit::{AdoptOutcome, RecruitContext, RecruitDecision};

        let ours = KadId::from_bytes([0xAA; KadId::BYTE_LEN]);
        let hello = crate::adapters::HelloAdverts {
            firewalled_slot: std::sync::Arc::new(crate::firewalled::link::FirewalledSlot::new(
                ours,
            )),
            ..crate::adapters::HelloAdverts::default()
        };
        let diagnostics = crate::diagnostics::DiagnosticsState::default();
        let feed = BuddyPublishFeed::new(&hello, diagnostics);
        let walking = hello.firewalled_slot.consider_recruitment(
            &RecruitContext {
                kad_connected: true,
                tcp: crate::reachability::TcpReachability::Firewalled,
                udp: crate::buddy::BuddyUdpPosture::Firewalled,
                last_recheck: None,
                crypt_required: false,
            },
            std::time::Instant::now(),
        );
        assert!(matches!(walking, RecruitDecision::Recruit { .. }));

        let found = rmule_kad::KadEvent::BuddyFound {
            buddy: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672),
            buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
            buddy_hash: UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
            buddy_tcp_port: 4662,
            connect_options: None,
        };
        assert_eq!(feed.seat(found), Some(AdoptOutcome::Adopted));
        assert_eq!(hello.firewalled_slot.buddy().unwrap().crypt, None);
    }
}
