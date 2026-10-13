//! The **Low-ID Candidate Record**: everything a download learned about a
//! source it cannot dial, kept together so a callback that goes silent can be
//! re-routed (ADR-0039 / ADR-0051 / ADR-0091).
//!
//! A Low-ID source used to be a bare `ClientId`, which is all a server callback
//! needs — the `0x1C` names an id and the server does the rest. ADR-0091's rung
//! 1 needs more: the target's user hash keys the rendezvous ledger, its buddy is
//! the second coordinator's address, and its NAT-T bit is the buddy
//! coordinator's only voucher. None of that can be recovered later, because a
//! Low-ID candidate never speaks to us until the callback works.
//!
//! **Every field is what its channel's bytes said, or nothing.** A server
//! answer names an id and a port; an obfuscation-aware `0x44` or a v≥2
//! source-exchange answer adds a User Hash; a **Kad source row** of type 3/5
//! adds the buddy, the Kad UDP endpoint and the connect-options byte
//! ([`LowIdCandidate::from_sighting`]) — it is the only channel that
//! names a buddy at all, and the only one that can name a NAT-T bit, which it
//! does only when the publisher was eMuleAI. Those fields are `None`/`false`
//! until a channel names them — never guessed from the others.

use std::net::Ipv4Addr;

use rmule_kad::KadId;
use rmule_primitives::{
    ClientId, Ipv4Endpoint, Ipv6Endpoint, PeerCrypt, PeerEndpoint, SourceCryptOptions, SourceRoad,
    SourceSighting, UserHash,
};

use crate::adapters::CallbackKey;
use crate::callback::{BuddyContact, NattFacts};
use crate::service::{PeerBuddy, PeerReach};

/// One Low-ID candidate with the facts the channel that named it carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LowIdCandidate {
    /// The server-assigned Low ID a callback names. Unique only per server,
    /// which is why `source_server` travels with it.
    pub(crate) low_id: ClientId,
    /// The server that assigned the id, whose namespace it belongs to: the
    /// server we were logged into when a server answer or a source exchange
    /// named it, or the server that answered a per-server global lookup
    /// (ADR-0051). A low id means something only beside it, as aMule keeps
    /// `m_dwServerIP`/`m_nServerPort` on every source (stock 2.3.3
    /// `ClientList.cpp:283-297`). `None` when no IPv4-literal server was known
    /// at the sighting: then the id is read against whichever server we are on
    /// when its callback is asked (ADR-0039 — the runner resolves it), and it
    /// is never a name its facts outlive the record under. Whether it is on
    /// *our* server ([`Self::on_server`]) is asked at each decision, because
    /// our server can change while the record waits.
    pub(crate) source_server: Option<Ipv4Endpoint>,
    /// The port the record carried. Meaningless for a callback (the peer dials
    /// *us*), kept because the reach record wants a port beside the id.
    pub(crate) tcp_port: u16,
    /// The candidate's eD2k **User Hash**, when the channel carried one: an
    /// obfuscation-aware `0x44` source item (ADR-0046) or a source-exchange
    /// answer of version ≥ 2 (ADR-0042). The rendezvous ledger is keyed by it,
    /// so rung 1's buddy coordinator cannot be enacted without one.
    pub(crate) user_hash: Option<UserHash>,
    /// The candidate's Kad serving buddy, when a channel named one — the
    /// second **Rendezvous coordinator** (ADR-0091).
    pub(crate) buddy: Option<BuddyContact>,
    /// The candidate advertised `SupportsDirectUDPCallback` (ADR-0047, bit 3
    /// of a connect-options byte). Kept for what it still states — the advert
    /// itself, read by [`Self::reach`]'s projection and by aMule's own type-6
    /// gate upstream in the Kad row's [`SourceRoad::DirectUdpCallback`]
    /// — but **not** the admission rule's fact: a type-3/5 buddy row can carry
    /// this bit too, and aMule still relays through the buddy for one
    /// [`Self::direct_udp_callback`] is the fact
    /// [`crate::download::state::LowIdRoad::of`] gates on.
    pub(crate) supports_direct_udp_callback: bool,
    /// The row was a Kad **type-6** row — firewalled, bit 3 stated, and a
    /// `0x95` endpoint observed by the storer
    /// ([`SourceRoad::DirectUdpCallback`]).
    /// This is the fact the admission rule gates `DirectUdp` on: aMule keeps
    /// the observed IP for the `0x95` only on a type-6 row
    /// (`DownloadQueue.cpp:1797`), so a type-3/5 buddy row with bit 3 set
    /// (`supports_direct_udp_callback` true here too) still falls to its
    /// buddy. Always `false` for a source-exchange record — only
    /// a Kad row can be type 6.
    pub(crate) direct_udp_callback: bool,
    /// The candidate's Kad UDP endpoint — where a `0x95` would go.
    pub(crate) kad_udp: Option<Ipv4Endpoint>,
    /// The candidate's usable IPv6, when a channel named one (ADR-0087): rung
    /// 0 dials it directly, Low ID included.
    pub(crate) ipv6: Option<Ipv6Endpoint>,
    /// The candidate's obfuscation stance, when a channel stated one: an
    /// ExtSX / v4 source-exchange crypt byte, or a Kad row's `TAG_ENCRYPTION`.
    /// With [`Self::user_hash`] it is the crypt side a rung-0 dial meets with
    /// our policy ([`Self::peer_crypt`]), exactly as a
    /// High-ID source's is.
    pub(crate) crypt_options: Option<SourceCryptOptions>,
    /// The candidate speaks eMuleAI's NAT-T (ADR-0091).
    pub(crate) supports_natt: bool,
    /// The candidate came from a **Kad source row**, so it is in no server's
    /// namespace at all.
    ///
    /// A Kad type-3/5 row names a firewalled publisher by User Hash and buddy —
    /// never by a server-assigned Low ID — so no server can be asked to relay a
    /// callback for it, whatever our own `callback_capability` says. aMule
    /// makes the same statement by constructing such a client with the sentinel
    /// id `1` and no server (`CDownloadQueue::KademliaSearchFile` case 3/5,
    /// `src/DownloadQueue.cpp:1758-1774`); rmule states it as a fact on the
    /// record instead, because [`Self::key`] still needs an id that tells two
    /// candidates apart.
    pub(crate) from_kad: bool,
}

impl LowIdCandidate {
    /// The candidate a sighting names, or `None` when its road is not a callback
    /// at all: a dialable record has no callback, and an id of `0` is
    /// unassigned and names nobody.
    ///
    /// **An eD2k Low-ID record** is read in the namespace it was learned in:
    /// `source_server` is the server that assigned it — the one we are logged
    /// into for a server-lookup answer or a peer source exchange (ADR-0039),
    /// the answering server for an ADR-0051 global source — or `None` when
    /// no server was known by address. A
    /// global answer carries no crypt material, so its caller wraps the plain
    /// record with [`SourceSighting::plain`] and the User Hash below is
    /// honestly `None`.
    ///
    /// **A Kad callback row** is in no server's namespace, whatever
    /// `source_server` says. Two row shapes name one: a buddy row (type 3/5),
    /// the one channel that can give a download a *buddy* — the relay of
    /// ADR-0061's buddy callback and rung 1's second coordinator (ADR-0091) —
    /// and a type-6 **Direct UDP Callback** row, which needs no buddy because
    /// its own `0x95` endpoint is on the row. Every field is what the row's
    /// bytes said — the User Hash from its source ID, the Kad UDP endpoint
    /// from `SOURCEIP`+`SOURCEUPORT`, the crypt and direct-callback bits from
    /// `TAG_ENCRYPTION`, and `supports_natt` from that byte's bit 7, which only
    /// an eMuleAI publisher ever sets (see
    /// [`SourceCryptOptions::supports_natt_utp`](rmule_primitives::SourceCryptOptions::supports_natt_utp)).
    /// No bit is invented: an aMule or eMule publisher's row leaves
    /// `supports_natt` false, and such a candidate is reached by its buddy's
    /// callback alone. [`Self::direct_udp_callback`] is the road itself rather
    /// than bit 3: a type-3/5 buddy row can state bit 3 too, and aMule only
    /// keeps the observed IP for the `0x95` on a type-6 row
    /// (`DownloadQueue.cpp:1797`). The id is the publisher's own observed
    /// address read as a [`ClientId`]. It is **not** a server-assigned Low ID —
    /// [`Self::from_kad`] says so, and is what keeps a server from being asked
    /// to relay for it — but it is the one value on the row that tells two
    /// firewalled publishers apart, which is what [`Self::key`] needs.
    pub(crate) fn from_sighting(
        sighting: SourceSighting,
        source_server: Option<Ipv4Endpoint>,
    ) -> Option<Self> {
        let crypt_options = sighting.crypt_options();
        let advertised = |bit: fn(SourceCryptOptions) -> bool| crypt_options.is_some_and(bit);
        let (kad_udp, buddy, direct_udp_callback) = match sighting.road() {
            SourceRoad::Record(record) => {
                let low_id = record.low_id().filter(|id| id.as_u32() != 0)?;
                return Some(Self {
                    low_id,
                    source_server,
                    tcp_port: sighting.tcp_port(),
                    user_hash: sighting.user_hash(),
                    // No eD2k record ever carries a buddy: neither the
                    // server's `0x42`/`0x44` nor source exchange has a field
                    // for one.
                    buddy: None,
                    supports_direct_udp_callback: advertised(
                        SourceCryptOptions::supports_direct_udp_callback,
                    ),
                    // A source-exchange record names no row type at all —
                    // only a Kad row can be type 6.
                    direct_udp_callback: false,
                    kad_udp: None,
                    // An ExtSX record's IPv6 half (ADR-0087): rung 0 dials it.
                    ipv6: sighting.ipv6(),
                    crypt_options,
                    // Bit 7 of an exchanged crypt byte means "a User Hash
                    // follows" (aMule `CPartFile::AddSources`), not eMuleAI's
                    // NAT-T bit, which only a Kad `TAG_ENCRYPTION` states.
                    supports_natt: false,
                    from_kad: false,
                });
            }
            SourceRoad::Buddy { buddy, kad_udp, .. } => (kad_udp, Some(buddy), false),
            SourceRoad::DirectUdpCallback { kad_udp, .. } => (kad_udp, None, true),
        };
        Some(Self {
            low_id: ClientId::from_u32(u32::from_le_bytes(kad_udp.ip.octets())),
            source_server: None,
            tcp_port: sighting.tcp_port(),
            user_hash: sighting.user_hash(),
            buddy: buddy.map(|buddy| BuddyContact {
                buddy_id: KadId::from_bytes(buddy.buddy_id),
                buddy_udp: buddy.buddy_udp,
            }),
            supports_direct_udp_callback: advertised(
                SourceCryptOptions::supports_direct_udp_callback,
            ),
            direct_udp_callback,
            kad_udp: Some(kad_udp),
            // The row's `ip6` beside its callback road (ADR-0087): rung 0
            // dials it, exactly as it does an ExtSX Low ID's half.
            ipv6: sighting.ipv6(),
            supports_natt: advertised(SourceCryptOptions::supports_natt_utp),
            // `TAG_ENCRYPTION` keys the rung-0 dial as an ExtSX crypt byte
            // does.
            crypt_options,
            from_kad: true,
        })
    }

    /// Whether the id is in the namespace of `ours`, the server we are logged
    /// into: aMule's `IsLocalServer(m_dwServerIP, m_nServerPort)`, which
    /// picks the server callback over every other road (stock 2.3.3
    /// `BaseClient.cpp:1530`). An id minted with no known server is read
    /// against ours; a Kad row is on no server.
    pub(crate) fn on_server(&self, ours: Option<Ipv4Endpoint>) -> bool {
        !self.from_kad
            && match self.source_server {
                None => true,
                Some(assigned) => ours == Some(assigned),
            }
    }

    /// The key this candidate's record and its roads are held under: its id
    /// in its namespace, with a Kad row's Kad UDP port beside the observed
    /// address it reads its id from (ADR-0090).
    pub(crate) const fn key(&self) -> CallbackKey {
        CallbackKey {
            server: self.source_server,
            low_id: self.low_id,
            kad_port: match self.kad_udp {
                Some(kad_udp) if self.from_kad => Some(kad_udp.port),
                _ => None,
            },
        }
    }

    /// Whether `newer`, sighted under this candidate's key, names another User
    /// Hash than this one: **another owner** of the key, whose sighting
    /// replaces this candidate whole rather than merging into it (ADR-0090).
    /// A channel silent about the hash names no other owner.
    pub(crate) fn names_another_owner(&self, newer: &Self) -> bool {
        matches!((self.user_hash, newer.user_hash), (Some(held), Some(named)) if held != named)
    }

    /// Fold a later sighting of the same owner into this record.
    ///
    /// **Newer non-`None` wins, and an advert is never withdrawn.** A channel
    /// that did not mention a fact is silent about it, not denying it — the
    /// server's plain `0x42` carries no User Hash whether or not the source has
    /// one — so `None` and `false` never overwrite something another channel
    /// stated. Between two channels that both stated a fact the later one wins,
    /// because a source's buddy and endpoints change under it while its id does
    /// not. A sighting of another owner ([`Self::names_another_owner`]) is not
    /// merged at all.
    pub(crate) fn merge(&mut self, newer: Self) {
        self.tcp_port = if newer.tcp_port == 0 {
            self.tcp_port
        } else {
            newer.tcp_port
        };
        self.user_hash = newer.user_hash.or(self.user_hash);
        // The same buddy named again without its endpoint keeps the endpoint
        // another channel stated — an ID-only Kad row is silent about where
        // the buddy is, not denying the endpoint a hello named.
        self.buddy = match (newer.buddy, self.buddy) {
            (Some(newer), Some(held)) if newer.buddy_id == held.buddy_id => Some(BuddyContact {
                buddy_udp: newer.buddy_udp.or(held.buddy_udp),
                ..newer
            }),
            (newer, held) => newer.or(held),
        };
        self.kad_udp = newer.kad_udp.or(self.kad_udp);
        self.ipv6 = newer.ipv6.or(self.ipv6);
        self.crypt_options = newer.crypt_options.or(self.crypt_options);
        self.supports_direct_udp_callback |= newer.supports_direct_udp_callback;
        self.direct_udp_callback |= newer.direct_udp_callback;
        self.supports_natt |= newer.supports_natt;
    }

    /// Fold the buddy endpoint the candidate's **own hello** named
    /// (`CT_EMULE_BUDDYIP`/`CT_EMULE_BUDDYUDP`) into its buddy
    /// contact — the latest sighting, so it replaces whatever endpoint a Kad
    /// row stated, exactly as a newer row's would in [`Self::merge`].
    ///
    /// Only a contact that already has its buddy's **ID** takes it: the hello
    /// names where the buddy is, never the relationship ID the buddy verifies
    /// a callback against, and aMule's buddy road is gated on that ID as much
    /// as on the endpoint (`HasValidBuddyID()`, `DownloadClient.cpp:1409`;
    /// `BaseClient.cpp:2134`). A candidate no Kad row named a buddy for keeps
    /// none.
    pub(crate) fn learn_hello_buddy(&mut self, buddy_udp: Ipv4Endpoint) {
        if let Some(buddy) = self.buddy.as_mut() {
            buddy.buddy_udp = Some(buddy_udp);
        }
    }

    /// The crypt side this candidate's records stated — stance and User Hash
    /// — which a rung-0 dial meets with our policy by aMule's outbound rule
    /// ([`PeerCrypt::outbound`], ADR-0049), exactly as a High ID's is.
    pub(crate) const fn peer_crypt(&self) -> PeerCrypt {
        PeerCrypt::from_record(self.crypt_options, self.user_hash)
    }

    /// The target's half of rung 1's condition (ADR-0091), read by the brain to
    /// decide whether this candidate's callback deserves the 12 s fallback
    /// deadline at all, with `ours` the server we are logged into. Our own
    /// position is the selector's to judge.
    pub(crate) fn natt_facts(&self, ours: Option<Ipv4Endpoint>) -> NattFacts {
        NattFacts {
            // A candidate in our server's namespace is on the server that can
            // introduce us; one another server assigned is on somebody else's;
            // a Kad row is in no server's, so nobody's server can.
            on_our_server: self.on_server(ours),
            supports_natt: self.supports_natt,
            buddy: self.buddy,
            advertised_udp: self.kad_udp.map(|kad_udp| kad_udp.port),
        }
    }

    /// Project the record into the public counterparty-facts record the one
    /// ADR-0061 selector routes on.
    ///
    /// `tcp` is the one field with nothing behind it: a Low-ID source has no
    /// address — that is what its id *means* — so the unspecified address
    /// carries the port and nothing more. The selector never reads it for a
    /// Low-ID candidate (its only reader is the High-ID direct dial), and
    /// naming a fabricated address here would put a lie where a diagnostic
    /// reads a peer. `ours` is the server we are logged into.
    pub(crate) fn reach(&self, ours: Option<Ipv4Endpoint>) -> PeerReach {
        PeerReach {
            id: self.low_id,
            tcp: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, self.tcp_port)),
            supports_direct_udp_callback: self.supports_direct_udp_callback,
            kad_udp: self.kad_udp,
            on_our_server: self.on_server(ours),
            buddy: self.buddy.map(|buddy| PeerBuddy {
                buddy_id: buddy.buddy_id,
                buddy_udp: buddy.buddy_udp,
            }),
            ipv6: self.ipv6,
            supports_natt: self.supports_natt,
            user_hash: self.user_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_kad::KadId;
    use rmule_primitives::{PeerSource, SourceCryptOptions};

    use super::*;
    use crate::download::state::CallbackCapability;

    fn callable() -> CallbackCapability {
        CallbackCapability::server_high_id()
    }

    fn low(n: u32) -> ClientId {
        ClientId::from_u32(n)
    }

    fn hash(byte: u8) -> UserHash {
        UserHash::from_bytes([byte; UserHash::BYTE_LEN])
    }

    fn buddy_contact() -> BuddyContact {
        BuddyContact {
            buddy_id: KadId::from_bytes([0x7A; KadId::BYTE_LEN]),
            buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
        }
    }

    /// A server's plain `0x42` answer names an id and a port and nothing else,
    /// and the record says so: no hash to key a ledger with, no buddy, no
    /// NAT-T bit — so its callback can never fall to a buddy punch.
    #[test]
    fn a_record_built_from_a_plain_server_answer_is_honestly_empty() {
        let candidate = LowIdCandidate::from_sighting(
            SourceSighting::plain(PeerSource::new(low(7), 4662)),
            None,
        )
        .expect("a Low-ID source is a candidate");
        assert_eq!(candidate.user_hash, None);
        assert_eq!(candidate.buddy, None);
        assert!(!candidate.supports_natt);
        assert_eq!(candidate.kad_udp, None);
        assert_eq!(candidate.ipv6, None);

        // A dialable source is nobody's callback, and id 0 names nobody.
        assert!(
            LowIdCandidate::from_sighting(
                SourceSighting::plain(PeerSource::new(
                    ClientId::from_u32(u32::from_le_bytes([45, 55, 200, 3])),
                    4662,
                )),
                None,
            )
            .is_none()
        );
        assert!(
            LowIdCandidate::from_sighting(
                SourceSighting::plain(PeerSource::new(low(0), 4662)),
                None
            )
            .is_none()
        );
    }

    /// An obfuscation-aware `0x44` item (ADR-0046) and a v≥2 source-exchange
    /// answer (ADR-0042) both carry the target's User Hash — the one rung-1
    /// fact a source channel really names today.
    #[test]
    fn a_source_that_carried_a_user_hash_keeps_it() {
        let candidate = LowIdCandidate::from_sighting(
            SourceSighting::new(
                PeerSource::new(low(7), 4662),
                Some(hash(0xAB)),
                Some(SourceCryptOptions::from_byte(0x01)),
            ),
            None,
        )
        .expect("a Low-ID source is a candidate");
        assert_eq!(candidate.user_hash, Some(hash(0xAB)));
        assert_eq!(candidate.reach(None).user_hash, Some(hash(0xAB)));
    }

    /// A source-exchange crypt byte states the direct UDP callback (bit 3) and
    /// the record keeps it; bit 7 there means "a User Hash follows"
    /// (`CPartFile::AddSources`), so it never reads as NAT-T, and no exchanged
    /// record carries a buddy.
    #[test]
    fn an_exchanged_crypt_byte_states_the_direct_callback_and_never_nat_t() {
        let candidate = LowIdCandidate::from_sighting(
            SourceSighting::new(
                PeerSource::new(low(7), 4662),
                Some(hash(0xAB)),
                Some(SourceCryptOptions::from_byte(0x89)),
            ),
            None,
        )
        .expect("a Low-ID source is a candidate");
        assert!(candidate.supports_direct_udp_callback);
        assert!(!candidate.supports_natt);
        assert_eq!(candidate.buddy, None);
    }

    /// The merge rule: a later sighting fills what it knows and withdraws
    /// nothing. The server answer has no hash, the exchange answer has one;
    /// the reverse order must not lose it.
    #[test]
    fn a_source_learned_twice_keeps_every_fact_either_sighting_stated() {
        let bare = LowIdCandidate::from_sighting(
            SourceSighting::plain(PeerSource::new(low(7), 4662)),
            None,
        )
        .expect("candidate");
        let rich = LowIdCandidate {
            user_hash: Some(hash(0xAB)),
            buddy: Some(buddy_contact()),
            supports_natt: true,
            ..bare
        };

        let mut filled = bare;
        filled.merge(rich);
        assert_eq!(filled, rich, "a later sighting fills what it knows");

        let mut kept = rich;
        kept.merge(bare);
        assert_eq!(
            kept, rich,
            "a silent channel withdraws nothing another one stated"
        );

        // Between two stated values the later one wins: a buddy moves, an id
        // does not.
        let moved = LowIdCandidate {
            buddy: Some(BuddyContact {
                buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 10), 9100)),
                ..buddy_contact()
            }),
            ..bare
        };
        let mut latest = rich;
        latest.merge(moved);
        assert_eq!(latest.buddy, moved.buddy);
        assert_eq!(latest.user_hash, Some(hash(0xAB)));
    }

    /// The headline case: a captured-shape Kad buddy row
    /// decodes to a candidate whose coordinator is its **buddy** — never our
    /// server, because a Kad row is in no server's namespace. Also covers
    /// the rule that only a type-6 row keeps a direct connect IP: this row
    /// states bit 3 but is type 3/5, so it
    /// still falls to the buddy rather than the direct road.
    #[test]
    fn a_kad_buddy_row_admits_its_buddy_as_the_coordinator_and_no_server() {
        use rmule_primitives::{Ipv4Endpoint, SightedBuddy};
        let kad_udp = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672);
        let row = |connect_options: u8| {
            SourceSighting::by_road(
                SourceRoad::Buddy {
                    buddy: SightedBuddy {
                        buddy_id: [0x7A; KadId::BYTE_LEN],
                        buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
                    },
                    kad_udp,
                    tcp_port: 4662,
                },
                Some(hash(0xAB)),
                Some(SourceCryptOptions::from_byte(connect_options)),
            )
        };

        // eMuleAI's byte: uTP NAT-T + direct UDP callback + crypt.
        let candidate =
            LowIdCandidate::from_sighting(row(0x89), None).expect("a buddy row names a candidate");

        assert!(candidate.from_kad);
        assert!(
            !candidate.natt_facts(None).on_our_server,
            "Kad has no server"
        );
        assert_eq!(candidate.buddy, Some(buddy_contact()));
        assert_eq!(candidate.user_hash, Some(hash(0xAB)));
        assert_eq!(candidate.kad_udp, Some(kad_udp));
        assert!(candidate.supports_direct_udp_callback);
        assert!(candidate.supports_natt);
        assert!(
            candidate.natt_facts(None).admits_coordinator(),
            "the buddy is the coordinator"
        );
        // The admission rule: never a server callback — there is no server to
        // ask. This is a type-3/5 row (`direct_udp_callback: false` above) —
        // bit 3 is stated in its connect-options byte, but aMule keeps the
        // observed IP for the `0x95` only on a type-6 row
        // (`DownloadQueue.cpp:1797`), so bit 3 alone does not open the direct
        // road here: it falls to its buddy's callback when we
        // can be dialed back at all, and the punch when we cannot.
        use crate::download::state::LowIdRoad;
        assert_eq!(
            LowIdRoad::of(&callable(), &candidate),
            Some(LowIdRoad::BuddyCallback)
        );
        assert_eq!(
            LowIdRoad::of(&CallbackCapability::UNCALLABLE, &candidate),
            Some(LowIdRoad::Punch)
        );

        // A publisher that never claimed NAT-T (aMule, eMule: their Kad
        // TAG_ENCRYPTION stops at 0x08) cannot be punched — the bit is read,
        // never invented — but its buddy still relays a callback.
        let plain = LowIdCandidate::from_sighting(row(0x01), None).expect("still a candidate");
        assert!(!plain.supports_natt);
        assert!(!plain.natt_facts(None).admits_coordinator());
        assert_eq!(
            LowIdRoad::of(&callable(), &plain),
            Some(LowIdRoad::BuddyCallback)
        );
        assert_eq!(LowIdRoad::of(&CallbackCapability::UNCALLABLE, &plain), None);
    }

    /// A buddy row carrying `ip6` keeps its buddy road — the IPv6 is
    /// its half, not a replacement — and hands the half to the route tree,
    /// whose rung 0 dials it exactly when we hold an IPv6 of our own: the
    /// ExtSX Low-ID-with-a-half reading. An IPv6-only reading would
    /// drop the row outright at an IPv4-only downloader, buddy and all.
    #[test]
    fn a_kad_buddy_row_with_ip6_keeps_its_buddy_road_and_carries_the_half_to_rung_0() {
        use rmule_kad::{KadBuddyContact, KadSourceRow, decode_source_result};
        use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint};

        use crate::callback::{RoutePosition, callback_target, select_callback_route};
        use crate::dialable::DialPosition;
        use crate::download::state::LowIdRoad;

        let ipv6: std::net::Ipv6Addr = "3fff:ed2:1::2".parse().unwrap();
        let key = KadId::from_bytes([0x60; KadId::BYTE_LEN]);
        let served = rmule_kad::encode_source_result(
            key,
            key,
            &[KadSourceRow {
                source_id: [0xAB; 16],
                source_type: 3,
                ip: Ipv4Addr::new(198, 51, 100, 77),
                tcp_port: 4662,
                udp_port: 4672,
                encryption: None,
                buddy: Some(KadBuddyContact {
                    buddy_id: KadId::from_bytes([0x7A; KadId::BYTE_LEN]),
                    buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)),
                    buddy_ipv6: None,
                    buddy_udp_ipv6: None,
                }),
                ipv6: Some(ipv6),
            }],
        );
        let rows = decode_source_result(&served[0]).expect("rmule reads its own storer's row");
        let row = rows[0].sighting().expect("a buddy row is a sighting");
        assert_eq!(row.peer_source(), None, "a row with a road is not rescued");

        let candidate =
            LowIdCandidate::from_sighting(row, None).expect("a buddy row names a candidate");
        assert_eq!(
            LowIdRoad::of(&callable(), &candidate),
            Some(LowIdRoad::BuddyCallback)
        );
        let half = Ipv6Endpoint::new(ipv6, 4662);
        assert_eq!(candidate.reach(None).ipv6, Some(half));
        let holding_ipv6 = RoutePosition {
            reachable: true,
            udp_on: true,
            kad_running: true,
            dial: DialPosition {
                known_ipv6: Some("3fff:ed2:1::7".parse().unwrap()),
            },
            server_punch: false,
        };
        assert_eq!(
            select_callback_route(&callback_target(&candidate.reach(None)), &holding_ipv6),
            crate::service::PeerReachRoute::Direct {
                endpoint: rmule_primitives::PeerEndpoint::V6(half)
            },
            "rung 0 dials the half the row carried, ahead of the buddy road"
        );
    }

    /// A type-6 row names a candidate with no buddy at all: its
    /// own `0x95` endpoint is the road, taken only when we can be dialed back.
    /// A downloader that cannot be has no road to it, as aMule drops the row
    /// when it is firewalled itself (`src/DownloadQueue.cpp:1781-1784`).
    #[test]
    fn a_type_6_row_names_a_buddyless_candidate_only_a_callable_downloader_reaches() {
        use rmule_primitives::Ipv4Endpoint;
        let candidate = LowIdCandidate::from_sighting(
            SourceSighting::by_road(
                SourceRoad::DirectUdpCallback {
                    kad_udp: Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 77), 4672),
                    tcp_port: 4662,
                },
                Some(hash(0xAB)),
                Some(SourceCryptOptions::from_byte(0x08)),
            ),
            None,
        )
        .expect("a type-6 row names a candidate");

        use crate::download::state::LowIdRoad;
        assert_eq!(candidate.buddy, None);
        assert_eq!(
            LowIdRoad::of(&callable(), &candidate),
            Some(LowIdRoad::DirectUdp)
        );
        assert_eq!(
            LowIdRoad::of(&CallbackCapability::UNCALLABLE, &candidate),
            None
        );
    }

    /// The namespace is the `on_our_server` fact: a candidate our server
    /// assigned can be introduced by it, one another server assigned cannot —
    /// and one our former server assigned stops being ours when we move.
    #[test]
    fn the_server_namespace_decides_whether_our_server_can_introduce_us() {
        let ours = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661);
        let next = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4661);
        let connected = LowIdCandidate::from_sighting(
            SourceSighting::plain(PeerSource::new(low(7), 4662)),
            Some(ours),
        )
        .expect("candidate");
        assert!(connected.natt_facts(Some(ours)).admits_coordinator());
        assert!(!connected.natt_facts(Some(next)).admits_coordinator());

        let global = LowIdCandidate::from_sighting(
            SourceSighting::plain(PeerSource::new(low(7), 4662)),
            Some(next),
        )
        .expect("candidate");
        assert!(!global.natt_facts(Some(ours)).admits_coordinator());
        assert!(!global.reach(Some(ours)).on_our_server);

        // …until it names a buddy and the NAT-T bit, which is the other half of
        // the rung.
        let punchable = LowIdCandidate {
            buddy: Some(buddy_contact()),
            supports_natt: true,
            ..global
        };
        assert!(punchable.natt_facts(Some(ours)).admits_coordinator());
    }
}
