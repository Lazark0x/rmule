//! What a driver asks the DHT for and what it gets back: a source-lookup
//! request naming a file, a publish request offering one, and the candidate
//! sources and diagnostics a finished walk reports.

use rmule_primitives::{
    ClientId, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SightedBuddy, SourceCryptOptions,
    SourceLookupTarget, SourceRoad, SourceSighting, UserHash,
};

use crate::KadId;

/// A **Kad Requester** ask: find sources for this file.
///
/// It carries the file's identity, not the DHT key — the key is derived
/// ([`Self::kad_target`]), so no caller can search under a key that does not
/// belong to the file it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadSourceLookupRequest {
    target: SourceLookupTarget,
}

impl KadSourceLookupRequest {
    /// A lookup for this file.
    #[must_use]
    pub const fn new(target: SourceLookupTarget) -> Self {
        Self { target }
    }

    /// The file being looked up, hash and size.
    #[must_use]
    pub const fn target(self) -> SourceLookupTarget {
        self.target
    }

    /// The Kad key this lookup walks toward: the file hash with each 32-bit
    /// word's bytes reversed. Capture-proven (`KadEvidence::KadIdByteOrder`):
    /// the captured `0x34`'s target equalled the searched file hash under
    /// exactly this transform (docs/reference/notes/kad-source-lookup.md).
    #[must_use]
    pub fn kad_target(self) -> KadId {
        KadId::from_bytes(kad_wire_id(*self.target.file_hash().as_bytes()))
    }
}

/// The self-inverse per-32-bit-word byte swap between an MD4 hash's raw
/// bytes and its Kad wire form. Capture-proven for file-hash lookup targets
/// (`KadEvidence::KadIdByteOrder`); documentation-backed for the publish
/// source ID, which aMule writes through the same 128-bit accessor.
///
/// The transform itself lives in `rmule-primitives` — the peer-TCP `0x99`
/// relay codec crosses the same boundary from the other side and must agree
/// with this one byte for byte.
pub(crate) use rmule_primitives::kad_wire_id;

/// A **Kad Publisher** announcement: which shared file (and size) to publish
/// this node as a source for. Mirrors [`KadSourceLookupRequest`] — the walk
/// toward the key is identical; only the terminal action differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadPublishRequest {
    target: SourceLookupTarget,
}

impl KadPublishRequest {
    /// A publish announcement for this file.
    #[must_use]
    pub const fn new(target: SourceLookupTarget) -> Self {
        Self { target }
    }

    /// The file being published, hash and size.
    #[must_use]
    pub const fn target(self) -> SourceLookupTarget {
        self.target
    }

    /// The Kad key the publish walks toward (same word-swap as
    /// [`KadSourceLookupRequest::kad_target`]).
    #[must_use]
    pub fn kad_target(self) -> KadId {
        KadId::from_bytes(kad_wire_id(*self.target.file_hash().as_bytes()))
    }
}

/// A firewalled publisher's Kad **serving buddy**, as a type-3/5 source row
/// names it: the relationship ID the requester addresses a callback with, and
/// the buddy's UDP endpoint when the row carried one.
///
/// Wire shape, from the publisher (eMule 0.70b
/// `srchybrid/kademlia/kademlia/Search.cpp:667-669`; aMule Fork Pin
/// `ab483654` `src/kademlia/kademlia/Search.cpp:840-855`; eMuleAI
/// `srchybrid/kademlia/kademlia/Search.cpp:885-889`):
///
/// - `TAG_SERVERIP` (`0xFB`) — the buddy's IPv4, as the buddy client's own
///   `GetIP()` word, **not** byte-swapped by either side (contrast
///   `TAG_SOURCEIP`, which the storer synthesises in host order);
/// - `TAG_SERVERPORT` (`0xFA`) — the buddy's **UDP** port (`GetUDPPort()`);
/// - `TAG_BUDDYHASH` (`0xF8`, eMuleAI's `TAG_SERVINGBUDDYHASH`, same byte) —
///   32 hex characters of `~publisherKadID`.
///
/// The hash's byte order is **capture-pinned** to aMule's
/// (`tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`): a
/// firewalled aMule whose buddy ID spells `FFEEDDCC…` on the wire wrote
/// `CCDDEEFF8899AABB4455667700112233`, which is `CUInt128::ToByteArray`'s true
/// big-endian order (`src/kademlia/utils/UInt128.cpp`) in **upper-case** hex,
/// not the wire order. eMule 0.70b and eMuleAI encode the same tag from
/// `CUInt128::GetData()` (the raw word-ordered bytes,
/// `md4str(uBuddyID.GetData())`), which on a little-endian host is the other
/// string — so the two families disagree on this tag and cannot address each
/// other's buddies. That half stays a source reading: neither client is on the
/// bench. rmule reads and writes aMule's form, converting to [`KadId`]'s wire
/// order with the same self-inverse word swap the row's source ID uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadBuddyContact {
    /// The buddy relationship ID: `~publisherKadID`, in [`KadId`] wire order.
    pub buddy_id: KadId,
    /// The buddy's UDP endpoint, when the row carried both `TAG_SERVERIP` and
    /// a non-zero `TAG_SERVERPORT`, and the address lies in no Reserved Range
    /// (ADR-0085): both readers refuse `0/8`, loopback, link-local, multicast
    /// and `240/4` (which holds `255.255.255.255`). `None` leaves a Kad walk
    /// toward [`Self::buddy_id`] as the only way to find it. That is where
    /// eMuleAI's IPv6-buddy row lands, since its `TAG_SERVERIP` is
    /// `CAddress::ToUInt32`'s `UINT_MAX` stand-in, never an address
    /// (eMuleAI `Search.cpp:886`, `Address.cpp:91-92`).
    pub buddy_udp: Option<Ipv4Endpoint>,
    /// The buddy's IPv6 — the `bi6` string tag (ADR-0087), the v6 half of
    /// this contact, already past `IsUsableTagIdentity`. It belongs to the
    /// contact rather than to the row because it means nothing without the
    /// ID a callback is verified against: a `bi6` on a row that named no
    /// buddy is dropped with it. Written upper-case like `TAG_BUDDYHASH`
    /// (eMuleAI `CUInt128::ToHexString`, kno `CMD4Hash::Encode`).
    pub buddy_ipv6: Option<std::net::Ipv6Addr>,
    /// The buddy's IPv6 UDP endpoint as eMuleAI reads a row: [`Self::buddy_ipv6`]
    /// paired with the row's non-zero `TAG_SERVERPORT`, whatever
    /// `TAG_SERVERIP` said (eMuleAI `DownloadQueue.cpp:5005-5008` replaces the
    /// buddy IP with `bi6` and keeps the port). Only the two readers set it; a
    /// publisher leaves it `None`. A stored row whose IPv4 half was refused
    /// re-serves this port beside `bi6`, so an eMuleAI searcher still gets
    /// the endpoint its publisher wrote. No rmule road dials it, because the
    /// buddy roads are IPv4 (ADR-0087: "`bi6` never decides a road").
    pub buddy_udp_ipv6: Option<Ipv6Endpoint>,
}

/// What core states about this node's reachability for its source publishes
/// (ADR-0060 "Self Reach") — the row's `IsFirewalled()` half,
/// read with the byte's direct-callback bit (`Search.cpp:596-633`,
/// `4e8f2b3c`):
///
/// - the direct-callback bit set → type 6, whatever this says;
/// - [`Firewalled`](Self::Firewalled) with a buddy → type 3/5 naming it;
/// - [`Firewalled`](Self::Firewalled) with none → **no row**: aMule stops the
///   publish (`PrepareToStop`, `:626-628`), because a direct row for a node
///   nobody can dial is unreachable to every asker;
/// - [`Reachable`](Self::Reachable) → the direct type 1/4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KadPublishPosture {
    /// Not firewalled (a server High ID or an open Kad TCP verdict) — and the
    /// node's resting state until core states otherwise.
    #[default]
    Reachable,
    /// Firewalled, with the buddy the slot holds, if any.
    Firewalled {
        /// The held buddy — the buddy row of core's Buddy Snapshot.
        buddy: Option<KadBuddyContact>,
    },
}

impl KadBuddyContact {
    /// The same `TAG_BUDDYHASH` read in the eMule 0.70b / eMuleAI spelling —
    /// `md4str(GetData())`, eMuleAI `srchybrid/kademlia/kademlia/Search.cpp:888`
    /// — which is [`Self::buddy_id`] one per-word swap away
    /// ([`KadId::word_swapped`]). A requester tries it only after the primary
    /// drew no dial-back. **Source-derived**: no eMule-family row
    /// has been captured. `None` when the swap is a no-op, so both spellings
    /// already name the one ID.
    #[must_use]
    pub fn fallback_buddy_id(&self) -> Option<KadId> {
        let swapped = self.buddy_id.word_swapped();
        (swapped != self.buddy_id).then_some(swapped)
    }
}

/// Every rung-1 fact one `KADEMLIA2_SEARCH_RES` source row carries — the
/// widened **Kad Source Row Projection**.
///
/// Before this, the decoder read four tags and threw the rest away: the row's
/// 16-byte source ID was skipped, and `TAG_ENCRYPTION` and the buddy tags fell
/// through the tag loop. Every field here is what the row's bytes said, or
/// `None` — nothing is inferred from another field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadSourceRowFacts {
    /// The publisher's eD2k **User Hash**, recovered from the row's 16-byte
    /// source ID by the self-inverse per-32-bit-word byte swap.
    ///
    /// Capture-proven by the 2026-07-07 controlled-identity `0x3B` capture
    /// (ADR-0043, `KadEvidence::SourceIdMeaning`); the publisher writes
    /// `CKademlia::GetPrefs()->GetClientHash()` — its User Hash, loaded with
    /// `SetValueBE` (aMule `src/kademlia/kademlia/Prefs.cpp:84`) and written by
    /// `WriteUInt128` as four little-endian words, most significant first — and
    /// the reader hands the same 128 bits straight to `SetUserHash`
    /// (`src/DownloadQueue.cpp:1752-1770`).
    pub user_hash: UserHash,
    /// `TAG_SOURCETYPE` (`0xFF`) verbatim: 1/4 direct, 3/5 firewalled behind a
    /// buddy, 6 firewalled with direct UDP callback, 2 deprecated.
    pub source_type: u8,
    /// `TAG_SOURCEPORT` (`0xFD`): the publisher's eD2k TCP listen port. `0`
    /// when the row omitted it, which makes a direct row unusable.
    pub tcp_port: u16,
    /// The publisher's Kad UDP endpoint: `TAG_SOURCEIP` (the address the
    /// *storer* observed the publish arrive from, never a published claim)
    /// paired with `TAG_SOURCEUPORT`. `None` when either was missing or zero.
    ///
    /// aMule keeps only the port here (`SetKadPort(udp)`), because its
    /// `CUpDownClient` already carries an address; rmule keeps the pair,
    /// because a `0x95` direct callback needs somewhere to go.
    pub kad_udp: Option<Ipv4Endpoint>,
    /// `TAG_ENCRYPTION` (`0xF3`): the publisher's **connect-options** byte —
    /// crypt stance, the direct-UDP-callback bit, and (from an eMuleAI or an
    /// rmule publisher only — its **Publish Connect Options**) the NAT-T bits. See
    /// [`SourceCryptOptions::supports_natt_utp`] for why this byte, unlike a
    /// source-exchange record's, is safe to read bit 7 from.
    pub connect_options: Option<SourceCryptOptions>,
    /// The publisher's serving buddy, when the row named one.
    pub buddy: Option<KadBuddyContact>,
    /// The row's `ip6` tag (ADR-0087), already past `IsUsableTagIdentity`,
    /// paired with [`Self::tcp_port`]: the source's **IPv6 Half** beside the
    /// road the row kept (a direct High ID, a buddy, a `0x95` endpoint), or
    /// the one address of a row that had no road and was rescued to it.
    pub ipv6: Option<Ipv6Endpoint>,
}

/// A projected source-lookup result row.
///
/// The repr is sealed: `Direct(PeerSource)`, `Buddy` and `DirectUdp` are
/// unconstructible outside this crate, so no caller can manufacture a reachable source without
/// a proven decoder. Only diagnostics are publicly constructible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadSourceCandidate {
    repr: Repr,
    /// Every fact the row carried. `None` only for a diagnostic a *caller*
    /// built by hand — a decoded row always has facts, reachable or not.
    facts: Option<KadSourceRowFacts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Repr {
    Direct(PeerSource),
    /// A type-3/5 row that named a usable buddy: not dialable, but reachable
    /// through that buddy, so it is a candidate rather than a diagnostic
    /// (aMule `CDownloadQueue::KademliaSearchFile` case 3/5, `src/DownloadQueue.cpp:1758-1774`).
    Buddy,
    /// A type-6 row that stated bit 3 of its connect options and whose Kad
    /// UDP endpoint the storer observed: not dialable, but reachable by a
    /// `0x95` direct callback to that endpoint (aMule
    /// `CDownloadQueue::KademliaSearchFile` case 6,
    /// `src/DownloadQueue.cpp:1779-1797`).
    DirectUdp,
    Diagnostic(KadSourceDiagnostic),
}

impl KadSourceCandidate {
    /// Build a diagnostic candidate. Diagnostics stay representable so the
    /// runtime can report skipped, unsupported, or non-direct source rows.
    #[must_use]
    pub const fn diagnostic(diagnostic: KadSourceDiagnostic) -> Self {
        Self {
            repr: Repr::Diagnostic(diagnostic),
            facts: None,
        }
    }

    /// Build a direct High ID candidate.
    ///
    /// Crate-internal on purpose: only the source-result decoder may project a
    /// proven direct-connectable High ID row into a direct candidate. This is
    /// the privileged path that keeps the public surface unable to turn an
    /// arbitrary `PeerSource` into a `Direct`.
    #[must_use]
    pub(crate) const fn direct(source: PeerSource) -> Self {
        Self {
            repr: Repr::Direct(source),
            facts: None,
        }
    }

    /// A buddy-reachable (type-3/5) candidate — decoder-only, like
    /// [`Self::direct`].
    #[must_use]
    pub(crate) const fn buddy_reachable() -> Self {
        Self {
            repr: Repr::Buddy,
            facts: None,
        }
    }

    /// A direct-UDP-callback (type-6) candidate — decoder-only, like
    /// [`Self::direct`]. Its endpoint is the row's
    /// [`KadSourceRowFacts::kad_udp`], which the decoder checked is present.
    #[must_use]
    pub(crate) const fn direct_udp_reachable() -> Self {
        Self {
            repr: Repr::DirectUdp,
            facts: None,
        }
    }

    /// Attach the row's facts to a projected candidate.
    #[must_use]
    pub(crate) const fn with_facts(self, facts: KadSourceRowFacts) -> Self {
        Self {
            repr: self.repr,
            facts: Some(facts),
        }
    }

    /// The dialable source this row projected to, or `None` when the row was
    /// refused or is reachable only by a callback — in which case the reason
    /// is the candidate's diagnostic, its [`Self::buddy`], or its
    /// [`Self::direct_udp_callback`].
    #[must_use]
    pub const fn peer_source(self) -> Option<PeerSource> {
        match self.repr {
            Repr::Direct(source) => Some(source),
            Repr::Buddy | Repr::DirectUdp | Repr::Diagnostic(_) => None,
        }
    }

    /// Why this row projected to no route at all: `Some` exactly when it is
    /// neither dialable, buddy-reachable nor direct-UDP-callable. The
    /// counterpart of [`Self::peer_source`], [`Self::buddy`] and
    /// [`Self::direct_udp_callback`] — every candidate answers exactly one of
    /// the four.
    #[must_use]
    pub const fn refusal(self) -> Option<KadSourceDiagnostic> {
        match self.repr {
            Repr::Diagnostic(diagnostic) => Some(diagnostic),
            Repr::Direct(_) | Repr::Buddy | Repr::DirectUdp => None,
        }
    }

    /// The Kad UDP endpoint a `0x95` **Direct UDP Callback** goes to: `Some`
    /// only for a type-6 row that stated bit 3 and carried an observed
    /// endpoint. A buddy row's bit 3, which no reference publisher sets
    /// beside a buddy, stays in [`Self::facts`].
    #[must_use]
    pub const fn direct_udp_callback(self) -> Option<Ipv4Endpoint> {
        match (self.repr, self.facts) {
            (Repr::DirectUdp, Some(facts)) => facts.kad_udp,
            _ => None,
        }
    }

    /// Every fact the decoded row carried — user hash, connect options, Kad
    /// UDP endpoint, buddy contact — whatever its route.
    #[must_use]
    pub const fn facts(self) -> Option<KadSourceRowFacts> {
        self.facts
    }

    /// The serving buddy this row is reachable through: `Some` only for a
    /// type-3/5 row that named one. A direct row's buddy tags (which no
    /// reference publisher emits) stay in [`Self::facts`] and do not make it a
    /// buddy candidate.
    #[must_use]
    pub const fn buddy(self) -> Option<KadBuddyContact> {
        match (self.repr, self.facts) {
            (Repr::Buddy, Some(facts)) => facts.buddy,
            _ => None,
        }
    }

    /// The **Source Sighting** this row is to a download: its one road and every
    /// fact beside it — the publisher's User Hash, its `TAG_ENCRYPTION` byte and
    /// its `ip6`. The road is the seal's verdict carried over, never re-derived
    /// from the bytes: a direct row is its record, a buddy row reaches its
    /// buddy, a type-6 row takes the `0x95` at its observed endpoint.
    ///
    /// `None` for a refusal, and for a buddy row whose publisher's Kad UDP
    /// endpoint the storer did not observe: that address is the one value that
    /// tells two firewalled publishers apart, so nothing could hold the row.
    #[must_use]
    pub fn sighting(self) -> Option<SourceSighting> {
        let facts = self.facts;
        let road = match self.repr {
            Repr::Direct(source) => SourceRoad::Record(source),
            Repr::Buddy => {
                let facts = facts?;
                SourceRoad::Buddy {
                    buddy: facts.buddy?.into(),
                    kad_udp: facts.kad_udp?,
                    tcp_port: facts.tcp_port,
                }
            }
            Repr::DirectUdp => SourceRoad::DirectUdpCallback {
                kad_udp: self.direct_udp_callback()?,
                tcp_port: facts?.tcp_port,
            },
            Repr::Diagnostic(_) => return None,
        };
        Some(
            SourceSighting::by_road(
                road,
                facts.map(|facts| facts.user_hash),
                facts.and_then(|facts| facts.connect_options),
            )
            .with_ipv6_half(facts.and_then(|facts| facts.ipv6)),
        )
    }
}

impl From<KadBuddyContact> for SightedBuddy {
    /// The contact as a sighting carries it: the ID's wire bytes and the IPv4
    /// endpoint, the one family a buddy road dials (ADR-0087).
    fn from(contact: KadBuddyContact) -> Self {
        Self {
            buddy_id: *contact.buddy_id.as_bytes(),
            buddy_udp: contact.buddy_udp,
        }
    }
}

/// Why a source row did not project to a dialable source.
///
/// Every refusal stays representable rather than being dropped: a walk that
/// found only unreachable sources is a different outcome from one that found
/// nothing, and a driver has to be able to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadSourceDiagnostic {
    /// The row names a Low ID source — reachable only through its server, so
    /// not dialable from a Kad answer.
    LowId {
        /// The client id as published.
        client_id: ClientId,
        /// The TCP port it published, kept for a later brokered route.
        tcp_port: u16,
    },
    /// The row declares itself firewalled.
    Firewalled,
    /// The row can only be reached through a buddy callback.
    BuddyCallback,
    /// The row carried no usable endpoint at all.
    MissingEndpoint,
    /// The row's source type is one rmule has no route for.
    UnsupportedSourceType(
        /// The unmodelled source-type byte.
        u8,
    ),
}
