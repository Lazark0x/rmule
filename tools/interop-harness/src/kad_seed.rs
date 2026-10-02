//! Kad identity seeding for the private capture mesh.
//!
//! aMule reads its 128-bit Kad ID from `preferencesKad.dat` at startup
//! (`CPrefs::ReadFile`) and keeps it verbatim when the stored ID is non-zero, so
//! the harness can pre-seed a chosen identity instead of letting aMule randomise
//! one. By giving a dedicated storer node a Kad ID equal to the synthetic file's
//! hash target, both the publisher's `KADEMLIA2_PUBLISH_SOURCE_REQ` and the
//! requester's `KADEMLIA2_SEARCH_SOURCE_REQ` converge on it, so it emits a
//! genuine `KADEMLIA2_SEARCH_RES` (`0x3B`).
//!
//! The harness only *arranges* identities to provoke the exchange; every
//! captured byte is still produced by real aMule. See
//! `docs/adr/0043-kad-full-node-for-source-discovery.md`.

/// Build the 23-byte `preferencesKad.dat` for a chosen 16-byte Kad ID.
///
/// Layout (`CPrefs::WriteFile`, all little-endian): `[0..4)` last-known IP (left
/// zero — harmless, aMule relearns it), `[4..6)` an unused u16, `[6..22)` the Kad
/// ID, `[22]` a trailing "no tags" byte. This function is agnostic to the Kad
/// ID's own byte order; the caller decides what 16 bytes to seed.
#[must_use]
pub fn build_preferences_kad_dat(kad_id: [u8; 16]) -> [u8; 23] {
    let mut out = [0u8; 23];
    out[6..22].copy_from_slice(&kad_id);
    out
}

/// Derive the storer node's Kad ID from the synthetic file's ED2K hash.
///
/// The on-wire Kad target is the file hash with each 32-bit word's bytes
/// reversed — proven directly by the captured `0x34`, whose target equalled the
/// file hash under exactly this transform. Seeding the storer to this value
/// makes it XOR-closest to the searched key so the publish and the search
/// rendezvous on it.
///
/// The transform here matches the *observed wire target*. Whether
/// `preferencesKad.dat`'s `ReadUInt128` wants this wire form or the verbatim file
/// hash is the one byte-order question no existing evidence settles; it is
/// verified against the live `0x34` capture before any fixture is promoted. If
/// verification shows aMule expects the verbatim hash,
/// this is the single function to change.
#[must_use]
pub fn storer_kad_id_for_file_hash(file_hash: [u8; 16]) -> [u8; 16] {
    rmule_primitives::kad_wire_id(file_hash)
}

/// The Kad keyword target a storer must be pinned to so aMule's publish and
/// search for that keyword rendezvous on it (inverted-role flow).
///
/// Computed with rmule's OWN keyword derivation (`rmule_kad::keyword`): tokenize
/// the query on aMule's separator set, keep the first >= 3-byte token, lowercase,
/// MD4, then map to Kad wire form. Seeding a storer's Kad ID to this value makes
/// it XOR-closest (distance 0) to the keyword key, so it clears aMule's publish
/// tolerance zone (`SEARCHTOLERANCE = 2^24`) as the closest node.
///
/// Because the pin uses rmule's derivation, it is byte-identical to what rmule
/// serves; and *if* that fold matches aMule's `GetKeywordHash`, aMule routes to
/// the pinned storer — so the routing itself is a live test of the fold's aMule
/// parity (a divergent fold would misroute aMule away and the capture would come
/// up empty). `None` when the query has no >= 3-byte token (nothing to pin to).
#[must_use]
pub fn keyword_target_kad_id(query: &str) -> Option<[u8; 16]> {
    rmule_kad::keyword::search_target(query).map(|id| *id.as_bytes())
}

/// A single bootstrap-edition contact for a private `nodes.dat`.
///
/// aMule only sends `KADEMLIA2_BOOTSTRAP_REQ` to contacts present in a
/// bootstrap-edition `nodes.dat` (version 3, edition 1), not the contacts in a
/// normal routing-zone file, so the private mesh must be seeded with these.
#[derive(Clone, Copy)]
pub struct KadContact {
    /// The contact's 16-byte Kad ID (verbatim, as stored on the wire).
    pub kad_id: [u8; 16],
    /// The contact's IPv4 address as dotted octets, e.g. `[172, 18, 0, 2]`.
    pub ipv4: [u8; 4],
    /// The contact's Kad UDP port.
    pub udp_port: u16,
    /// The contact's eD2k TCP port.
    pub tcp_port: u16,
    /// The contact's Kad protocol version (8 for current Kad2 aMule).
    pub version: u8,
}

/// Build a bootstrap-edition `nodes.dat` for a set of private contacts.
///
/// Layout (eMule `CRoutingZone::WriteFile` bootstrap edition, all multi-byte
/// integers little-endian, confirmed against pinned aMule
/// `src/kademlia/routing/RoutingZone.cpp` and
/// `docs/reference/notes/kad-source-lookup.md`):
///
/// - header: `u32` zero marker (locks out old clients), `u32` version `3`,
///   `u32` edition `1` (bootstrap-only marker), `u32` contact count;
/// - per 25-byte contact: 16-byte Kad ID, 4-byte IP, `u16` UDP port, `u16` TCP
///   port, `u8` contact version.
///
/// The IP is written as the reversed dotted octets (`172.18.0.2` → `02 00 12
/// ac`): aMule keeps the address in host order and `WriteUInt32` emits it
/// little-endian, which reverses the octets on disk. This byte order is the one
/// aMule logged the correct target IP for in the live capture (see the note).
#[must_use]
pub fn build_bootstrap_nodes_dat(contacts: &[KadContact]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + contacts.len() * 25);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(contacts.len() as u32).to_le_bytes());
    for contact in contacts {
        out.extend_from_slice(&contact.kad_id);
        // Reversed dotted octets: WriteUInt32 of the host-order IP is LE on disk.
        out.extend_from_slice(&[
            contact.ipv4[3],
            contact.ipv4[2],
            contact.ipv4[1],
            contact.ipv4[0],
        ]);
        out.extend_from_slice(&contact.udp_port.to_le_bytes());
        out.extend_from_slice(&contact.tcp_port.to_le_bytes());
        out.push(contact.version);
    }
    out
}

/// Build a **routing-zone** (version 1) `nodes.dat` that aMule loads directly into
/// its live routing tree, unlike [`build_bootstrap_nodes_dat`].
///
/// `CRoutingZone::ReadFile` dispatches a version-3 **edition-1** file to
/// `ReadBootstrapNodesDat` and returns *without adding any contact to the tree* —
/// that format only feeds the bootstrap list. To make a seeded contact queryable
/// (returnable in a `KADEMLIA2_RES`), the file must be a routing-zone version 1–3
/// file whose contacts are added via `AddUnfiltered`. Version 1 is the simplest:
/// no per-contact UDP key or verified flag.
///
/// Layout (`CRoutingZone::ReadFile`, all little-endian): `u32` zero marker (so old
/// clients skip it), `u32` version `1`, `u32` contact count, then 25-byte contacts
/// (16-byte Kad ID, 4-byte IP, `u16` UDP port, `u16` TCP port, `u8` version). The
/// IP is the reversed dotted octets, matching [`build_bootstrap_nodes_dat`] (aMule
/// byte-swaps it back on read via `wxUINT32_SWAP_ALWAYS`).
#[must_use]
pub fn build_routing_zone_nodes_dat(contacts: &[KadContact]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + contacts.len() * 25);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(contacts.len() as u32).to_le_bytes());
    for contact in contacts {
        out.extend_from_slice(&contact.kad_id);
        out.extend_from_slice(&[
            contact.ipv4[3],
            contact.ipv4[2],
            contact.ipv4[1],
            contact.ipv4[0],
        ]);
        out.extend_from_slice(&contact.udp_port.to_le_bytes());
        out.extend_from_slice(&contact.tcp_port.to_le_bytes());
        out.push(contact.version);
    }
    out
}

/// How many contacts the v2 nodes.dat harvest seed offers (flow H
/// leg 3). aMule refuses to write nodes.dat below 25 contacts
/// (`CRoutingZone::WriteFile`) and admits roughly its fresh-table capacity from a
/// seed, so 45 clears the threshold with margin (an observed ~30 admitted).
pub const V2_HARVEST_SEED_CONTACTS: usize = 45;

// The seed must offer at least aMule's own WriteFile threshold, or a full-
// admission harvest could still fall below 25 and write nothing.
const _: () = assert!(V2_HARVEST_SEED_CONTACTS >= 25);

/// Build the routing-zone seed for a genuine **v2 nodes.dat** harvest.
///
/// A v2 nodes.dat can only come from `CRoutingZone::WriteFile`, which needs a
/// live Kad routing table of >= 25 contacts. aMule's `CRoutingBin` caps non-LAN
/// contacts at 10 per `/24` globally and 2 per `/24` per bin, and only splits a
/// bin once it fills to `K` (10) — so a >= 25 table cannot come from a few
/// crowded `/24`s (the per-bin cap starves the split). This seed sidesteps all
/// three caps: [`V2_HARVEST_SEED_CONTACTS`] contacts, **one per distinct
/// non-reserved `/24`** (`45.55.N.0/24`), with Kad IDs bit-reversed-spread so the
/// XOR-distance top nibbles scatter them across the routing bins. aMule loads
/// them via `ReadFile` -> `AddUnfiltered`, the root bin fills and the tree
/// splits, and `WriteFile` persists >= 25 as v2 on shutdown.
///
/// The `/24`s are `45.55.x` public space, NOT the RFC 5737 documentation ranges:
/// aMule 2.3.3's `IsGoodIP` `reserved_ranges` rejects `192.0.2.0/24` and
/// `198.18.0.0/15` (two of the three the fake-public plan suggests), so only
/// `198.51.100`/`203.0.113` of that trio would load.
///
/// Feeds [`build_routing_zone_nodes_dat`], which reverses each contact's octets
/// into aMule's file order.
#[must_use]
pub fn build_v2_harvest_seed_nodes_dat() -> Vec<u8> {
    let contacts: Vec<KadContact> = (0..V2_HARVEST_SEED_CONTACTS)
        .map(|i| {
            let host = u8::try_from(i + 1).expect("seed size fits a /24 third octet");
            let mut kad_id = [0x5Eu8; 16];
            kad_id[0] = bit_reverse(u8::try_from(i % 256).unwrap());
            kad_id[1] = bit_reverse(u8::try_from((i * 5) % 256).unwrap());
            kad_id[2] = u8::try_from((i * 17) % 256).unwrap();
            kad_id[3] = host;
            KadContact {
                kad_id,
                // 45.55.N.2 — one distinct non-reserved /24 per contact.
                ipv4: [45, 55, host, 2],
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
            }
        })
        .collect();
    build_routing_zone_nodes_dat(&contacts)
}

/// Reverse a byte's bits (spreads a linear index across the Kad ID's top byte so
/// the XOR distances scatter across routing bins rather than clustering).
const fn bit_reverse(mut value: u8) -> u8 {
    let mut reversed = 0u8;
    let mut bit = 0;
    while bit < 8 {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
        bit += 1;
    }
    reversed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_zone_nodes_dat_is_version1_and_loads_into_the_tree() {
        // Version 1 (not the bootstrap edition 3/1) so ReadFile's AddUnfiltered
        // path runs and the contacts become queryable.
        let contact = KadContact {
            kad_id: [0x80; 16],
            ipv4: [172, 30, 0, 5],
            udp_port: 4675,
            tcp_port: 4662,
            version: 8,
        };
        let bytes = build_routing_zone_nodes_dat(&[contact]);

        assert_eq!(bytes.len(), 12 + 25, "12-byte header + one 25-byte contact");
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0], "zero marker");
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes(), "routing-zone version 1");
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes(), "contact count");
        assert_eq!(&bytes[12..28], &[0x80; 16], "verbatim Kad ID");
        assert_eq!(&bytes[28..32], &[5, 0, 30, 172], "172.30.0.5 reversed");
        assert_eq!(&bytes[32..34], &4675u16.to_le_bytes(), "udp port LE");
        assert_eq!(&bytes[34..36], &4662u16.to_le_bytes(), "tcp port LE");
        assert_eq!(bytes[36], 8, "contact version");
    }

    #[test]
    fn keyword_target_pins_the_first_folded_token() {
        // The inverted-role pin must resolve a (possibly multi-word, mixed-case)
        // query to the FIRST >= 3-byte token's keyword id — exactly aMule's Kad
        // search target (SearchManager.cpp#L128) — so a storer seeded to it is
        // XOR-closest to what aMule publishes/searches. If the wrapper picked the
        // wrong token or skipped the lowercase fold, aMule would route elsewhere
        // and the capture would come up empty.
        let target = keyword_target_kad_id("RMuleKadKeyword parityProbe").unwrap();
        let expected = *rmule_kad::keyword::keyword_id("rmulekadkeyword").as_bytes();
        assert_eq!(
            target, expected,
            "first token, lowercased, is the pin target"
        );
        // A query with no >= 3-byte token has nothing to pin to.
        assert_eq!(keyword_target_kad_id("a b"), None);
    }

    #[test]
    fn preferences_kad_dat_layout_matches_amule_cprefs() {
        let kad_id = [
            0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10,
            0x62, 0xD2,
        ];
        let bytes = build_preferences_kad_dat(kad_id);

        assert_eq!(bytes.len(), 23, "CPrefs::WriteFile is 23 bytes");
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0], "IP slot zero");
        assert_eq!(&bytes[4..6], &[0, 0], "unused u16 zero");
        assert_eq!(&bytes[6..22], &kad_id, "Kad ID verbatim at offset 6");
        assert_eq!(bytes[22], 0, "trailing no-tags byte zero");
    }

    #[test]
    fn storer_kad_id_equals_on_wire_target_for_file_hash() {
        // File hash bytes as eMule stores/prints them, and the matching target
        // observed in the captured 0x34 (`b52d308e 5ca206b8 23fc8593 d26210f2`).
        let file_hash = [
            0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10,
            0x62, 0xD2,
        ];
        let expected_target = [
            0xB5, 0x2D, 0x30, 0x8E, 0x5C, 0xA2, 0x06, 0xB8, 0x23, 0xFC, 0x85, 0x93, 0xD2, 0x62,
            0x10, 0xF2,
        ];
        assert_eq!(storer_kad_id_for_file_hash(file_hash), expected_target);
    }

    #[test]
    fn storer_transform_is_its_own_inverse() {
        // Reversing each 32-bit word twice is the identity, so the transform is
        // self-inverse — a guard against accidentally introducing a 16-byte full
        // reverse or a no-op.
        let hash = [
            0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD, 0xFE, 0xED,
            0xBE, 0xEF,
        ];
        let once = storer_kad_id_for_file_hash(hash);
        assert_ne!(once, hash, "transform actually permutes bytes");
        assert_eq!(storer_kad_id_for_file_hash(once), hash, "self-inverse");
    }

    #[test]
    fn bootstrap_nodes_dat_is_v3_edition1_with_reversed_ip_octets() {
        let contact = KadContact {
            kad_id: [0x11; 16],
            ipv4: [172, 18, 0, 2],
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        };
        let bytes = build_bootstrap_nodes_dat(&[contact]);

        // 16-byte header + one 25-byte contact.
        assert_eq!(bytes.len(), 16 + 25);
        // Header: zero marker, version 3, edition 1, contact count 1 (all LE).
        assert_eq!(
            &bytes[0..4],
            &[0, 0, 0, 0],
            "zero marker locks out old clients"
        );
        assert_eq!(&bytes[4..8], &3u32.to_le_bytes(), "bootstrap version 3");
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes(), "bootstrap edition 1");
        assert_eq!(&bytes[12..16], &1u32.to_le_bytes(), "contact count");
        // Contact: 16-byte id, then IP as reversed dotted octets (02 00 12 ac).
        assert_eq!(&bytes[16..32], &[0x11; 16], "verbatim Kad ID");
        assert_eq!(
            &bytes[32..36],
            &[0x02, 0x00, 0x12, 0xAC],
            "172.18.0.2 reversed"
        );
        // UDP port, TCP port (LE u16), then contact version byte.
        assert_eq!(&bytes[36..38], &4672u16.to_le_bytes(), "udp port LE");
        assert_eq!(&bytes[38..40], &4662u16.to_le_bytes(), "tcp port LE");
        assert_eq!(bytes[40], 8, "contact version byte");
    }

    #[test]
    fn bootstrap_nodes_dat_packs_multiple_contacts_back_to_back() {
        let contacts = [
            KadContact {
                kad_id: [0x22; 16],
                ipv4: [10, 0, 0, 7],
                udp_port: 4673,
                tcp_port: 4662,
                version: 8,
            },
            KadContact {
                kad_id: [0x33; 16],
                ipv4: [192, 168, 1, 9],
                udp_port: 4674,
                tcp_port: 4662,
                version: 8,
            },
        ];
        let bytes = build_bootstrap_nodes_dat(&contacts);

        assert_eq!(bytes.len(), 16 + 2 * 25);
        assert_eq!(&bytes[12..16], &2u32.to_le_bytes(), "count is 2");
        // Second contact starts immediately after the first 25-byte contact.
        let second = 16 + 25;
        assert_eq!(&bytes[second..second + 16], &[0x33; 16]);
        assert_eq!(
            &bytes[second + 16..second + 20],
            &[9, 1, 168, 192],
            "192.168.1.9 reversed"
        );
    }

    #[test]
    fn v2_harvest_seed_puts_each_contact_on_a_distinct_non_reserved_24() {
        // The load-bearing invariant of the v2 harvest: one contact per DISTINCT
        // /24, so aMule's 10-per-/24 global cap and 2-per-/24-per-bin cap never
        // bind and the routing tree splits to hold >= 25. If a change ever crowds
        // contacts onto shared /24s the harvest silently falls below aMule's
        // 25-contact WriteFile threshold — this guards against that regression at
        // CI level (the live harvest itself is Docker-gated).
        let bytes = build_v2_harvest_seed_nodes_dat();
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes(), "routing-zone version 1");
        assert_eq!(
            &bytes[8..12],
            &(V2_HARVEST_SEED_CONTACTS as u32).to_le_bytes()
        );

        let mut subnets = std::collections::HashSet::new();
        for i in 0..V2_HARVEST_SEED_CONTACTS {
            let row = 12 + i * 25;
            // The file stores reversed octets, so the /24 network is the last
            // three stored bytes; the per-contact version must be Kad2 (> 1) or
            // aMule's ReadFile skips the row entirely.
            let stored = &bytes[row + 16..row + 20];
            assert!(bytes[row + 24] > 1, "contact {i} must be Kad2");
            assert!(
                subnets.insert([stored[1], stored[2], stored[3]]),
                "contact {i} shares a /24 with an earlier one — the cap would bind"
            );
        }
    }
}
