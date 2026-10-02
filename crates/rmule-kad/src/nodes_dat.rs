//! The nodes.dat **normal** reader (ADR-0066 execution breakdown 2): the
//! file-version matrix, the per-contact admission filters, and the
//! verified-bit-or-heuristic mapping onto [`KadContact::verified`] — the
//! ADR-0064 `Verified Contact` seam.
//!
//! ## Scope
//!
//! This module is the **normal** reader ([`NodesDat::decode`]) and the v2
//! production writer ([`NodesDat::encode_v2`]) — the two halves of the same
//! `CRoutingZone` file format. The reader spans file versions 1, 2, and
//! 3-without-bootstrap-edition (which folds into the v2 row layout); the writer
//! emits version 2, the one live-2.3.3 `WriteFile` form. A
//! version-3 file with `bootstrapEdition == 1` is a *different* file shape
//! entirely (500-1000 contacts, an exact `count × 25` bound, closest-50
//! selection into a bootstrap dial list, never merged into a routing table)
//! and is recognized here only far enough to hand off — [`NodesDatError::BootstrapEdition`] —
//! to the dedicated v3 bootstrap-edition reader. Feeding
//! decoded contacts into a live `KadRoutingTable`, and deciding *when* to flush
//! the writer's bytes to disk, are pipeline concerns (the `rmule-net`
//! driver); this module only decodes and encodes.
//!
//! ## Provenance
//!
//! Byte-for-byte from aMule 2.3.3's `CRoutingZone::ReadFile`
//! (`kademlia/routing/RoutingZone.cpp`, commit `4e8f2b3c`) and
//! `CKadUDPKey::ReadFromFile` (`kademlia/utils/KadUDPKey.h`, same commit).
//! `docs/reference/notes/kad-packet-framing.md` independently confirms the
//! 25-byte contact row shape (id/ip/udp/tcp/version) is identical to the
//! capture-proven `0x09`/`0x29` wire contact rows, including the "IPv4, low
//! octet first" encoding — the "machinery-shared" fact ADR-0066's evidence
//! section leans on for the v1/v3 forms that have no living 2.3.3 writer to
//! capture from.
//!
//! ## Documented divergences
//!
//! - **ipfilter.dat**: aMule additionally drops a contact whose IP is
//!   ipfilter.dat-blocked. rmule has no ipfilter.dat equivalent (ADR-0066:
//!   "out-of-scope") — not implemented.
//!
//! The v2 UDP key (`CKadUDPKey`) round-trips onto [`KadContact::udp_key`] (the
//! sink ADR-0066 left to the ADR-0046 keys): a restarted node keeps the
//! sender keys it earned, and the binding IP keeps them honest — a key learned
//! under a different public address reads back as no key at all.

use std::net::Ipv4Addr;

use crate::net::is_good_ip_port;
use crate::udp_key::KadUdpKey;
use crate::{KadContact, KadId, KadNodeEndpoint};

/// The DNS port aMule's port-53 filter singles out (a stray "kad node" that
/// is actually a DNS resolver, or a spoofed low-numbered-port contact).
///
/// `pub(crate)`: the v3 bootstrap-edition reader (`nodes_dat_bootstrap.rs`)
/// applies the identical filter to its own rows.
pub(crate) const DNS_PORT: u16 = 53;

/// Contact versions at or below this are dropped when advertised on
/// [`DNS_PORT`] — crypt-capable v6+ contacts on port 53 are kept
/// (`RoutingZone.cpp#L196`; ADR-0066 calls this "finer than ADR-0064's
/// datagram gate, different layer").
pub(crate) const PORT_53_VERSION_CEILING: u8 = 5;

/// aMule's `CONTACT_FILE_LIMIT` (`RoutingZone.cpp#L76`): the ceiling
/// `WriteFile` caps the persisted contact count at. [`NodesDat::encode_v2`]
/// honours it so a pathologically large table never writes an out-of-spec
/// file the reader's `count × 25` pre-checks would balk at.
pub const CONTACT_FILE_LIMIT: usize = 500;

/// aMule's `WriteFile` floor (`RoutingZone.cpp#L304`): below 25 contacts it
/// logs "nodes.dat not written" and skips the write, so a nearly-empty table
/// is not persisted over a good one. The *codec* ([`NodesDat::encode_v2`])
/// does not enforce this — it is a write **policy** the flush edge applies
/// (the `rmule-net` driver), since only the edge knows whether skipping
/// leaves a better file in place.
pub const MIN_CONTACTS_TO_WRITE: usize = 25;

/// The fixed byte width of a v2 contact row: `id(16) ip(4) udp(2) tcp(2)
/// version(1) UDPKey(8) verified(1)` (aMule `WriteFile`, the 34-byte row the
/// v2 golden's metadata records).
const V2_ROW_LEN: usize = 34;

/// The v2 file header width: `u32` old-client guard, `u32` version, `u32`
/// contact count.
const V2_HEADER_LEN: usize = 12;

/// Whole-file reasons the normal reader cannot produce a [`NodesDat`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodesDatError {
    /// The leading `u32` was nonzero: a legacy version-0 nodes.dat, whose
    /// contacts' Kad protocol versions are unknowable. aMule refuses it
    /// outright (`RoutingZone.cpp#L170`, "too old ... not supported
    /// anymore").
    TooOld,
    /// Version 3 with bootstrap-edition 1: the special bootstrap-only file
    /// shape (`RoutingZone.cpp#L156`) — not this reader's job. See the v3
    /// bootstrap-edition reader.
    BootstrapEdition,
}

/// A parsed nodes.dat normal-format payload (file version 1, 2, or
/// 3-folded-into-the-v2-layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodesDat {
    contacts: Vec<KadContact>,
    kad1_skipped: usize,
}

impl NodesDat {
    /// Decode a nodes.dat payload with the normal reader.
    ///
    /// Truncation anywhere after the leading marker keeps every contact
    /// parsed so far and is never an error — matching aMule's own
    /// exception-swallowed-at-`ReadFile` posture (ADR-0066: "truncation
    /// keeps rows parsed so far"). aMule's loose `count × 25` whole-row
    /// pre-check is deliberately not replicated (it does not account for
    /// the v2 extension bytes); this streams row by row instead, for the
    /// same observable partial-load-on-truncation outcome.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodesDatError> {
        let mut cursor = Cursor::new(bytes);

        let Some(leading) = cursor.read_u32() else {
            return Ok(Self::empty());
        };
        if leading != 0 {
            return Err(NodesDatError::TooOld);
        }

        // `leading == 0` is the new-format sentinel: a version word follows.
        let Some(file_version) = cursor.read_u32() else {
            return Ok(Self::empty());
        };

        if file_version == 3 {
            let Some(bootstrap_edition) = cursor.read_u32() else {
                return Ok(Self::empty());
            };
            if bootstrap_edition == 1 {
                return Err(NodesDatError::BootstrapEdition);
            }
        }

        if !(1..=3).contains(&file_version) {
            // aMule only re-reads the contact count for a declared version in
            // 1..=3; any other value (0, or > 3) leaves it at its sentinel
            // `0`, so the contact loop trivially never runs. Not an error —
            // aMule's own branching (RoutingZone.cpp#L163).
            return Ok(Self::empty());
        }

        Ok(Self::decode_rows(file_version, &mut cursor))
    }

    const fn empty() -> Self {
        Self {
            contacts: Vec::new(),
            kad1_skipped: 0,
        }
    }

    fn decode_rows(file_version: u32, cursor: &mut Cursor<'_>) -> Self {
        let Some(declared_count) = cursor.read_u32() else {
            return Self::empty();
        };

        // Decode every row we can, tracking whether *any* row -- regardless
        // of whether it later survives the per-contact filters below --
        // carried a set verified bit. aMule computes this before filtering
        // (`RoutingZone.cpp#L185` precedes the filter block at `#L193`), so a
        // verified row that gets dropped for some other reason (Kad1, port
        // 53) must still suppress the all-verified fallback.
        let mut rows = Vec::new();
        let mut any_verified_bit = false;
        for _ in 0..declared_count {
            let Some(row) = decode_row(cursor, file_version) else {
                break;
            };
            if row.verified_bit == Some(true) {
                any_verified_bit = true;
            }
            rows.push(row);
        }

        let mut kad1_skipped = 0usize;
        let mut contacts = Vec::with_capacity(rows.len());
        for row in rows {
            // Kad2 only: Kad1 rows are counted and skipped
            // (`RoutingZone.cpp#L196`).
            if row.contact.version() <= 1 {
                kad1_skipped += 1;
                continue;
            }
            // aMule's `IsGoodIPPort` gate, in aMule's filter order
            // (`RoutingZone.cpp#L193`, after Kad2 and before port-53): a
            // contact needs a nonzero port and a routable IP. Silently dropped,
            // uncounted — like aMule.
            if !is_good_ip_port(
                row.contact.endpoint().ip(),
                row.contact.endpoint().udp_port(),
            ) {
                continue;
            }
            // Port-53 DNS-confusion guard, versions <= 5 only.
            if row.contact.endpoint().udp_port() == DNS_PORT
                && row.contact.version() <= PORT_53_VERSION_CEILING
            {
                continue;
            }
            let verified = row.verified_bit.unwrap_or(false);
            contacts.push(if verified {
                row.contact.into_verified()
            } else {
                row.contact
            });
        }

        // The all-verified heuristic (`RoutingZone.cpp#L215`): a v1 file
        // structurally carries no verified bit, and a v2/v3 file might
        // happen to carry none set either. Either way, aMule marks every
        // loaded contact verified rather than leave Kad bootstrapping with
        // zero servable contacts until 0x22 handshakes complete.
        if !any_verified_bit {
            contacts = contacts
                .into_iter()
                .map(KadContact::into_verified)
                .collect();
        }

        Self {
            contacts,
            kad1_skipped,
        }
    }

    /// The loaded, filtered, verified-mapped contacts, in file order.
    #[must_use]
    pub fn contacts(&self) -> &[KadContact] {
        &self.contacts
    }

    /// Take the loaded contacts, consuming the file's decoded form.
    #[must_use]
    pub fn into_contacts(self) -> Vec<KadContact> {
        self.contacts
    }

    /// How many rows were dropped for being Kad1 (`version <= 1`) — aMule's
    /// `kad1Count` (debug-only there; a real counter here, since the
    /// evidence discipline wants it observable).
    #[must_use]
    pub const fn kad1_skipped(&self) -> usize {
        self.kad1_skipped
    }

    /// Encode `contacts` as a **version-2 nodes.dat**, byte-for-byte in aMule
    /// 2.3.3's `CRoutingZone::WriteFile` layout: the 12-byte header
    /// `[u32 0][u32 2][u32 count]` then a 34-byte row per contact —
    /// `id(16) ip(4) udp(2) tcp(2) version(1) UDPKey(8) verified(1)`, all
    /// multi-byte integers little-endian. This is the exact inverse of
    /// [`decode`](Self::decode)'s v2 row, so decoding aMule's own golden and
    /// re-encoding reproduces its bytes.
    ///
    /// More than [`CONTACT_FILE_LIMIT`] contacts are truncated to it, aMule's
    /// own `std::min(numContacts, CONTACT_FILE_LIMIT)` safety cap; the write
    /// **policy** ([`MIN_CONTACTS_TO_WRITE`], the bootstrap-unfinished skip)
    /// lives at the flush edge, so this codec faithfully encodes whatever set it
    /// is handed.
    ///
    /// The contact's [`KadUdpKey`] round-trips: the 8-byte `key ‖ ip` pair
    /// aMule persists (`CKadUDPKey::StoreToFile`) is read back by the reader
    /// and re-emitted here, so a restarted node keeps the sender keys it
    /// earned instead of re-handshaking every contact. An unkeyed contact
    /// writes eight zero bytes, which aMule reads as an unset key.
    #[must_use]
    pub fn encode_v2(contacts: &[KadContact]) -> Vec<u8> {
        let written = contacts.len().min(CONTACT_FILE_LIMIT);
        let count = u32::try_from(written).expect("written <= CONTACT_FILE_LIMIT (500) fits u32");

        let mut out = Vec::with_capacity(V2_HEADER_LEN + written * V2_ROW_LEN);
        // Header: the leading 0 locks out pre-v2 clients, then the version word.
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());

        for contact in contacts.iter().take(written) {
            out.extend_from_slice(contact.id().as_bytes());
            // The reader takes the IP "low octet first" (a.b.c.d on disk as
            // [d,c,b,a]); the writer is its exact inverse.
            let octets = contact.endpoint().ip().octets();
            out.extend_from_slice(&[octets[3], octets[2], octets[1], octets[0]]);
            out.extend_from_slice(&contact.endpoint().udp_port().to_le_bytes());
            out.extend_from_slice(&contact.tcp_port().to_le_bytes());
            out.push(contact.version());
            // `CKadUDPKey::StoreToFile` writes `key(u32) ‖ ip(u32)`; the IP is
            // the binding address — and its on-disk octet order DIFFERS from
            // the contact IP above. `m_ip` holds `theApp->GetPublicIP(false)`,
            // a network-order u32 (`amule.cpp#L1455` swaps the Kad-internal IP
            // with `wxUINT32_SWAP_ALWAYS`; the `!IsLowID` assert in
            // `SetPublicIP` pins the convention), so aMule's LE `WriteUInt32`
            // lands it in NATURAL `a.b.c.d` order — while the contact IP
            // (`GetIPAddress()`, host-order) lands reversed. One row, two
            // octet orders.
            out.extend_from_slice(&contact.udp_key().key().to_le_bytes());
            out.extend_from_slice(&contact.udp_key().bound_ip().octets());
            out.push(u8::from(contact.verified()));
        }
        out
    }
}

/// One decoded contact row, before the per-contact filters apply.
struct RawRow {
    contact: KadContact,
    /// `Some(bit)` for a v2/v3-folded row's verified byte; `None` for a v1
    /// row, which has no extension to carry one.
    verified_bit: Option<bool>,
}

fn decode_row(cursor: &mut Cursor<'_>, file_version: u32) -> Option<RawRow> {
    let id = cursor.read_kad_id()?;
    let ip = cursor.read_ipv4_low_octet_first()?;
    let udp_port = cursor.read_u16()?;
    let tcp_port = cursor.read_u16()?;
    let version = cursor.read_u8()?;

    let (udp_key, verified_bit) = if file_version >= 2 {
        // `CKadUDPKey::ReadFromFile`: `key` then `ip`, each `u32` LE. The IP is
        // *our own* public address when the key was learned (the binding that
        // retires the key if we move) — and it sits on disk in NATURAL octet
        // order, unlike the reversed contact IP earlier in the same row (see
        // the writer for the aMule derivation). Reading it reversed would
        // octet-flip every binding on an aMule-authored file, so
        // `key_value(own_ip)` misses and every earned key silently retires on
        // migration — the exact failure persisting the key exists to prevent.
        let key = cursor.read_u32()?;
        let key_ip = cursor.read_ipv4_natural_order()?;
        (KadUdpKey::new(key, key_ip), Some(cursor.read_u8()? != 0))
    } else {
        (KadUdpKey::EMPTY, None)
    };

    let contact = KadContact::new(id, KadNodeEndpoint::new(ip, udp_port), tcp_port, version)
        .with_udp_key(udp_key);
    Some(RawRow {
        contact,
        verified_bit,
    })
}

/// A forward-only byte reader that answers `None` on truncation rather than
/// surfacing a per-field error — a truncated row simply ends the walk here
/// (see [`NodesDat::decode`]'s truncation posture).
///
/// `pub(crate)`: shared with the v3 bootstrap-edition reader
/// (`nodes_dat_bootstrap.rs`), whose row shape is byte-identical to
/// this reader's v1 rows.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
    }

    pub(crate) fn read_kad_id(&mut self) -> Option<KadId> {
        let bytes = self.take(KadId::BYTE_LEN)?;
        Some(KadId::from_bytes(bytes.try_into().expect("16-byte slice")))
    }

    /// The contact-row IPv4 serialization: `a.b.c.d` on the wire as `[d, c,
    /// b, a]` — the same "low octet first" order the wire contact row and
    /// hello messages use
    /// (`docs/reference/notes/kad-packet-framing.md`).
    pub(crate) fn read_ipv4_low_octet_first(&mut self) -> Option<Ipv4Addr> {
        let bytes = self.take(4)?;
        Some(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))
    }

    /// The `CKadUDPKey` binding-IP serialization: `a.b.c.d` on disk as `[a, b,
    /// c, d]` — natural order, NOT the low-octet-first order of the contact IP
    /// in the same row. aMule's `m_ip` is a network-order u32
    /// (`theApp->GetPublicIP(false)`, `amule.cpp#L1455`), so its LE
    /// `WriteUInt32` emits the octets as-is.
    fn read_ipv4_natural_order(&mut self) -> Option<Ipv4Addr> {
        let bytes = self.take(4)?;
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    /// Bytes not yet consumed -- the v3 bootstrap-edition reader's exact
    /// `count * 25 == remaining` check needs this; the normal reader (this
    /// module) never does, since it streams and keeps partial rows.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}
