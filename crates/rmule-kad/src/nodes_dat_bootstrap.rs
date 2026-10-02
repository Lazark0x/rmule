//! The nodes.dat **v3 bootstrap-edition** reader (ADR-0066 execution
//! breakdown 3) — the dedicated reader the normal reader
//! ([`crate::nodes_dat`]) hands off to via
//! [`NodesDatError::BootstrapEdition`](crate::NodesDatError::BootstrapEdition)
//! rather than parsing itself.
//!
//! ## Scope
//!
//! This module decodes the bytes into the closest-50-by-XOR-distance
//! selection; [`crate::BootstrapDialList`] (the CONTEXT.md **Bootstrap Dial
//! List**) is the type that selection lands in and the only public entry
//! point ([`BootstrapDialList::load_v3_bootstrap_edition`](crate::BootstrapDialList::load_v3_bootstrap_edition)). Feeding a
//! *live* dial loop (pop-one, dial, discard, cadence) is join-sequence work
//! (ADR-0067) — this module only decodes and selects.
//!
//! ## Handoff contract with the normal reader
//!
//! The normal reader recognizes the version-3/bootstrap-edition-1 marker
//! only far enough to hand off, deliberately leaving open whether this
//! reader would re-parse the full bytes or resume from an offset. Decided
//! here: **this reader re-parses the full nodes.dat byte buffer from the
//! leading marker on**, independent of how far the normal reader's cursor
//! got. A pipeline can therefore try the normal reader first
//! and, on `BootstrapEdition`, hand the *identical, unmodified* bytes to
//! [`decode`] — no shared cursor state, no offset bookkeeping between the
//! two readers.
//!
//! ## Provenance
//!
//! Byte-for-byte from aMule 2.3.3's `CRoutingZone::ReadBootstrapNodesDat`
//! (`kademlia/routing/RoutingZone.cpp#L228`, commit `4e8f2b3c`): v1-shape
//! 25-byte rows (`id16/ip4/udp2/tcp2/ver1`, `#L177`) regardless of the outer
//! file version, an **exact** `count * 25 == remaining` check (`#L242` —
//! unlike the normal reader, which deliberately does not replicate aMule's
//! loose pre-check), the same Kad2-only and port-53 filters the normal
//! reader applies (`#L193`-equivalent), and closest-50-by-XOR-distance
//! selection (`#L257`, cap `#L261`). Row shape is machinery-shared with the
//! capture-proven wire contact row (`0x09`/`0x29`,
//! `docs/reference/notes/kad-packet-framing.md`) — the same justification
//! the normal reader leans on, since this format too has no living 2.3.3 writer
//! (`WriteBootstrapFile` is `#if 0` dead code).
//!
//! ## Documented divergences
//!
//! - **The "500–1000 contacts expected" note** (ADR-0066) describes real
//!   bootstrap files aMule's node maintainers publish; aMule's own reader
//!   enforces no such numeric bound (only the exact length check), so
//!   neither does this one.
//! - **ipfilter.dat**: not implemented, same documented gap as the normal
//!   reader (`crate::nodes_dat`'s module doc). The `IsGoodIPPort`
//!   reserved/LAN-range filter *is* applied, identically to that reader.

use crate::net::is_good_ip_port;
use crate::nodes_dat::{Cursor, DNS_PORT, PORT_53_VERSION_CEILING};
use crate::{KadBootstrapNode, KadContact, KadId, KadNodeEndpoint};

/// How many of the closest contacts (by XOR distance to the own Kad ID) are
/// kept — aMule's fixed cap (`RoutingZone.cpp#L261`).
const CLOSEST_COUNT: usize = 50;

/// Whole-file reasons the v3 bootstrap-edition reader cannot produce a
/// [`crate::BootstrapDialList`] load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BootstrapEditionError {
    /// The bytes don't carry this format's marker (leading `0`, file version
    /// `3`, bootstrap-edition flag `1`) — including too short to tell. Not
    /// this reader's shape; the normal reader
    /// ([`NodesDat::decode`](crate::NodesDat::decode)) is the one for
    /// anything else, including a truncated-before-the-marker file (which
    /// the normal reader tolerates as zero contacts, not an error).
    NotBootstrapEdition,
    /// The declared row count times 25 doesn't exactly match the remaining
    /// bytes (`RoutingZone.cpp#L242`) — a hard refusal, unlike the normal
    /// reader's forgiving keep-what-parsed-so-far truncation.
    LengthMismatch,
    /// A [`crate::BootstrapDialList`] already holds candidates; refuses a
    /// second bootstrap-file load onto the same list rather than appending
    /// or replacing (`RoutingZone.cpp#L237`).
    AlreadyLoaded,
}

impl std::fmt::Display for BootstrapEditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotBootstrapEdition => "not a bootstrap-edition file",
            Self::LengthMismatch => "the row count does not match the file's length",
            Self::AlreadyLoaded => "the dial list already holds candidates",
        })
    }
}

/// Decode a v3 bootstrap-edition nodes.dat payload into its closest-50
/// dial candidates, ordered closest-first by XOR distance to `own_id`.
///
/// Pure and total over its inputs: never panics, never partially mutates
/// anything (there is nothing to mutate) — the caller
/// ([`crate::BootstrapDialList::load_v3_bootstrap_edition`]) owns the
/// already-loaded guard, since that is about the *list's* state, not this
/// decode.
pub(crate) fn decode(
    bytes: &[u8],
    own_id: KadId,
) -> Result<Vec<KadBootstrapNode>, BootstrapEditionError> {
    let mut cursor = Cursor::new(bytes);

    let Some(leading) = cursor.read_u32() else {
        return Err(BootstrapEditionError::NotBootstrapEdition);
    };
    let Some(file_version) = cursor.read_u32() else {
        return Err(BootstrapEditionError::NotBootstrapEdition);
    };
    let Some(bootstrap_edition) = cursor.read_u32() else {
        return Err(BootstrapEditionError::NotBootstrapEdition);
    };
    if leading != 0 || file_version != 3 || bootstrap_edition != 1 {
        return Err(BootstrapEditionError::NotBootstrapEdition);
    }

    let Some(declared_count) = cursor.read_u32() else {
        return Err(BootstrapEditionError::NotBootstrapEdition);
    };

    let expected_row_bytes = usize::try_from(declared_count)
        .ok()
        .and_then(|count| count.checked_mul(25));
    if expected_row_bytes != Some(cursor.remaining()) {
        return Err(BootstrapEditionError::LengthMismatch);
    }

    let mut contacts = Vec::with_capacity(declared_count as usize);
    for _ in 0..declared_count {
        let Some(contact) = decode_row(&mut cursor) else {
            // Unreachable given the exact length check above; a broken
            // Cursor invariant would land here rather than panic.
            return Err(BootstrapEditionError::LengthMismatch);
        };
        contacts.push(contact);
    }

    // Same per-contact filters as the normal reader, in aMule's order: Kad2
    // only, `IsGoodIPPort` (nonzero port + routable IP), then the port-53
    // DNS-confusion guard for versions <= 5.
    contacts.retain(|contact| {
        contact.version() > 1
            && is_good_ip_port(contact.endpoint().ip(), contact.endpoint().udp_port())
            && !(contact.endpoint().udp_port() == DNS_PORT
                && contact.version() <= PORT_53_VERSION_CEILING)
    });

    // Closest-50 by XOR distance to `own_id`, closest first. Distinct IDs
    // have distinct XOR distances (routing.rs's own comment on this same
    // pattern), so there is no tie-breaking ambiguity.
    contacts.sort_by_key(|contact| contact.id().distance(&own_id));
    contacts.truncate(CLOSEST_COUNT);

    Ok(contacts
        .into_iter()
        .map(|contact| KadBootstrapNode::new(contact.endpoint(), Some(contact.id())))
        .collect())
}

/// One decoded row: the pure v1 shape (`id16/ip4/udp2/tcp2/ver1`), no UDP-key
/// or verified-bit extension — the bootstrap-edition format uses this row
/// shape unconditionally, unlike the normal reader's version-gated rows.
fn decode_row(cursor: &mut Cursor<'_>) -> Option<KadContact> {
    let id = cursor.read_kad_id()?;
    let ip = cursor.read_ipv4_low_octet_first()?;
    let udp_port = cursor.read_u16()?;
    let tcp_port = cursor.read_u16()?;
    let version = cursor.read_u8()?;
    Some(KadContact::new(
        id,
        KadNodeEndpoint::new(ip, udp_port),
        tcp_port,
        version,
    ))
}
