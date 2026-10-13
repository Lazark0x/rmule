//! Evidence-gated boundary for decoding `KADEMLIA2_SEARCH_RES` source rows.
//!
//! This routes a decoded envelope by opcode and, for the proven plain-`0xE4`
//! row shape, parses the source rows into [`KadSourceCandidate`] values. Only a
//! direct-connectable High ID row becomes a sealed `Direct` **Peer Source**;
//! every other row form stays a diagnostic. The blocked evidence is the
//! canonical [`KadEvidence`] list, shared with `KadId` distance metadata.
//!
//! ## Provenance
//!
//! Every byte-order-sensitive fact this decoder relies on is now
//! *capture-proven*. The row framing and `KadId` byte order came from the prior
//! `0x34`/`0x29` captures ([`KadEvidence::KadIdByteOrder`]). The source tag byte
//! order ([`KadEvidence::SourceIpTagByteOrder`]) and per-row source-ID meaning
//! ([`KadEvidence::SourceIdMeaning`]) were upgraded from documentation to
//! captured by the 2026-07-07 controlled-identity `0x3B` capture (ADR-0043):
//! rmule published a source to a real aMule storer and captured
//! aMule's genuine answer (fixture
//! `source_lookup/captured/private-amule-kad-source-result-20260707`). So
//! [`SOURCE_RESULT_BLOCKED_BY`] is now empty. The handwritten documentation
//! fixture stays committed alongside — it exercises the Low ID / buddy /
//! firewalled / missing-port / deprecated diagnostic branches the single-row
//! genuine capture does not.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    ClientId, Ipv4Endpoint, PeerSource, SourceCryptOptions, Tag, TagName, TagValue, UserHash,
    WireReader, WireTruncated,
};

use crate::opcode::Kad2Opcode;
use crate::{
    KadBuddyContact, KadEnvelope, KadEvidence, KadId, KadSourceCandidate, KadSourceDiagnostic,
    KadSourceRowFacts,
};

/// Evidence still missing before the source-result row shape can be decoded
/// with capture-grade confidence.
///
/// **Empty as of the 2026-07-07 `0x3B` capture (ADR-0043).** The
/// plain-`0xE4` direct-High-ID shape is fully capture-proven: `KadIdByteOrder`
/// from the prior `0x34`/`0x29` captures, and `SourceIpTagByteOrder` +
/// `SourceIdMeaning` from the controlled-identity `0x3B` capture (rmule as Kad
/// Stimulus Node publishing to a real aMule storer). [`KadEvidence`] stays the
/// canonical vocabulary — no variant is deleted — but nothing blocks this
/// decoder any longer.
pub const SOURCE_RESULT_BLOCKED_BY: &[KadEvidence] = &[];

/// Why a source-result envelope could not be decoded into candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadSourceResultDecodeError {
    /// The envelope opcode is not `KADEMLIA2_SEARCH_RES`.
    NotASearchResult {
        /// The opcode that arrived instead.
        opcode: u8,
    },
    /// The plain-`0xE4` payload was truncated or otherwise malformed: it ended
    /// mid-field, a tag ran past the row, or the row count disagreed with the
    /// bytes present. Carries a static reason for diagnostics; never panics.
    MalformedPayload {
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
}

// eMule Kad source-tag single-byte names, used in the explicit length-prefixed
// form `[type][01 00][nameByte][value]` (see the documented layout cited in the
// module docs). These appear as the one-byte tag *name*, not as the tag type.
const TAG_SOURCETYPE: u8 = 0xFF;
const TAG_SOURCEIP: u8 = 0xFE;
const TAG_SOURCEPORT: u8 = 0xFD;
const TAG_SOURCEUPORT: u8 = 0xFC;
/// `TAG_SERVERIP` (`0xFB`) — in a source row this is the **buddy's** IPv4, not
/// any server's (eMule 0.70b `Search.cpp:667`, aMule Fork Pin `ab483654`
/// `src/kademlia/kademlia/Search.cpp:848`). The name is the historical one.
const TAG_SERVERIP: u8 = 0xFB;
/// `TAG_SERVERPORT` (`0xFA`) — the buddy's **UDP** port (`GetUDPPort()`).
const TAG_SERVERPORT: u8 = 0xFA;
/// `TAG_BUDDYHASH` (`0xF8`, eMuleAI's `TAG_SERVINGBUDDYHASH`) — 32 hex
/// characters of `~publisherKadID`, in aMule's big-endian form.
const TAG_BUDDYHASH: u8 = 0xF8;

// eMule Kad source-type values (aMule `Search.cpp` `ProcessResultFile`):
//   1 = HighID direct source, 4 = >4GB HighID direct source,
//   3 = firewalled (buddy callback), 5 = >4GB firewalled (buddy callback),
//   6 = firewalled with direct UDP callback, 2 = deprecated (rejected).
pub(crate) const SOURCETYPE_DIRECT: u8 = 1;
pub(crate) const SOURCETYPE_DIRECT_LARGE: u8 = 4;
pub(crate) const SOURCETYPE_BUDDY: u8 = 3;
pub(crate) const SOURCETYPE_BUDDY_LARGE: u8 = 5;
pub(crate) const SOURCETYPE_FIREWALLED_UDP: u8 = 6;

/// Decode the source rows of a `KADEMLIA2_SEARCH_RES` envelope into candidates.
///
/// Handles the proven plain-`0xE4` row shape: `[16B sender][16B target]
/// [2B count LE]` followed by `count` rows of `[16B source ID][1B tag count]
/// [tags...]`. Each row is projected into a [`KadSourceCandidate`]:
///
/// - a direct High ID source (source type 1/4, a `SOURCEIP`, a non-zero
///   `SOURCEPORT`, and a resulting `ClientId` that
///   [`is_high_id`](rmule_primitives::ClientId::is_high_id)) becomes a sealed
///   `Direct` **Peer Source**;
/// - a direct source whose `SOURCEIP` resolves below the Low ID threshold
///   becomes [`KadSourceDiagnostic::LowId`];
/// - a direct source missing its `SOURCEIP` or `SOURCEPORT` becomes
///   [`KadSourceDiagnostic::MissingEndpoint`];
/// - a buddy row (type 3/5) that names its buddy becomes a buddy-reachable
///   candidate, one that does not [`KadSourceDiagnostic::BuddyCallback`];
/// - a type-6 row that states the direct-UDP-callback bit and carries an
///   observed Kad UDP endpoint becomes a direct-UDP-callable candidate
///   ([`KadSourceCandidate::direct_udp_callback`]), one that does not
///   [`KadSourceDiagnostic::Firewalled`];
/// - any other source type becomes
///   [`KadSourceDiagnostic::UnsupportedSourceType`].
///
/// Packed `0xE5` datagrams arrive here already inflated to their logical plain
/// envelope (`decode_exact` returns `Packed`). A non-`0x3B` opcode returns
/// [`KadSourceResultDecodeError::NotASearchResult`]; a truncated or malformed
/// plain payload returns [`KadSourceResultDecodeError::MalformedPayload`].
pub fn decode_source_result(
    envelope: &KadEnvelope,
) -> Result<Vec<KadSourceCandidate>, KadSourceResultDecodeError> {
    if !matches!(
        Kad2Opcode::try_from_u8(envelope.opcode()),
        Some(Kad2Opcode::SearchRes)
    ) {
        return Err(KadSourceResultDecodeError::NotASearchResult {
            opcode: envelope.opcode(),
        });
    }

    let mut reader = WireReader::new(envelope.payload());
    // `[16B sender][16B target]` precede the rows; the sender/target identities
    // are not needed for projection, but skipping them validates the framing.
    reader.skip(KAD_ID_LEN, "sender Kad ID")?;
    reader.skip(KAD_ID_LEN, "target Kad ID")?;
    let count = reader.read_u16_le("result count")?;

    // Bound the pre-allocation against the untrusted count: a row is at least
    // `[16B source ID][1B tag count]` = 17 bytes, so the payload can hold no
    // more than `remaining / 17` rows however large `count` claims to be — a
    // tiny malformed `0x3B` cannot force a 64K-entry reservation.
    const MIN_ROW_BYTES: usize = KAD_ID_LEN + 1;
    let capacity = (count as usize).min(reader.remaining() / MIN_ROW_BYTES);
    let mut candidates = Vec::with_capacity(capacity);
    for _ in 0..count {
        candidates.push(decode_row(&mut reader)?);
    }

    if !reader.is_exhausted() {
        return Err(KadSourceResultDecodeError::MalformedPayload {
            reason: "trailing bytes after the declared result count",
        });
    }

    Ok(candidates)
}

const KAD_ID_LEN: usize = 16;

/// One parsed source entry as the **Kad Storer** re-serializes it into a
/// `KADEMLIA2_SEARCH_RES` row.
///
/// Every field is typed, parsed state — the row an indexed publish produces
/// after projection, never retained datagram bytes. `ip` is the IP the storer
/// *observed* the publish arrive from (the storer substitutes it for whatever
/// the publisher claims, aMule-style), which is what makes a stored entry
/// re-encoding evidence-grade rather than an echo.
///
/// `source_id` stays raw bytes: its meaning is the publisher's User Hash
/// word-swapped per 32-bit word — capture-proven by the 2026-07-07 `0x3B`
/// capture ([`KadEvidence::SourceIdMeaning`]), not the publisher's Kad ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadSourceRow {
    /// The publisher's identity as published: its User Hash, word-swapped —
    /// kept raw because the swap is the wire's, not ours.
    pub source_id: [u8; 16],
    /// `TAG_SOURCETYPE`: stored as published (the storer indexes any type;
    /// the *requester's* sealed projection decides direct vs diagnostic).
    pub source_type: u8,
    /// The publish datagram's observed sender IP.
    pub ip: Ipv4Addr,
    /// From `TAG_SOURCEPORT`: where the source serves files. A row without a
    /// usable one is never indexed.
    pub tcp_port: u16,
    /// From `TAG_SOURCEUPORT`, falling back to the observed sender UDP port.
    pub udp_port: u16,
    /// The publisher's `TAG_ENCRYPTION` crypt options, when sent.
    pub encryption: Option<u8>,
    /// The publisher's serving buddy, from a type-3/5 publish's
    /// `TAG_SERVERIP`/`TAG_SERVERPORT`/`TAG_BUDDYHASH`.
    ///
    /// aMule's storer passes these through its index verbatim
    /// (`Process2PublishSourceRequest`'s `entry->AddTag(tag, ip)` default arm,
    /// `src/kademlia/net/KademliaUDPListener.cpp:1406`) and re-serializes them
    /// with the rest of the entry (`CIndexed::SendValidSourceResult` →
    /// `CEntry::WriteTagList`). rmule keeps them as parsed state instead, so a
    /// served row can never echo attacker-shaped opaque bytes. The contact
    /// carries the row's `bi6` too (`buddy_ipv6`, ADR-0087), past the publish
    /// reader's usability gate, and the answer re-serves it last.
    pub buddy: Option<KadBuddyContact>,
    /// The publisher's `ip6` tag (ADR-0087), already past the publish
    /// reader's usability gate. kno's storer re-serves the tag verbatim
    /// (`KademliaUDPListener.cpp:1402`); rmule keeps the parsed address
    /// and re-serves it the same way, so a searcher reaching the source
    /// through an rmule storer sees the same dual-stack row it would through
    /// kno's.
    pub ipv6: Option<Ipv6Addr>,
}

/// Batch size aMule's storer uses when answering a source search: rows go
/// out 50 per `0x3B` datagram.
pub const SOURCE_RESULT_ROWS_PER_DATAGRAM: usize = 50;

/// Re-encode stored source rows into `KADEMLIA2_SEARCH_RES` envelopes, 50
/// rows per datagram (documentation-backed batching; framing note,
/// "Source-publish layouts"). Zero rows encode to zero envelopes — a storer
/// with nothing to say stays silent, like aMule.
///
/// Row tags are written in the stored-entry order the aMule storer produces
/// (SOURCEIP, SOURCETYPE, SOURCEPORT, SOURCEUPORT, the buddy trio on a
/// type-3/5 row, then ENCRYPTION when present, then the string-named `ip6` and
/// `bi6` last), each in the explicit length-prefixed name form and at a fixed
/// width (`decode_source_result` tolerates narrower variable-width forms; the
/// encoder never emits them). The caller applies result budgets and start
/// offsets — this is pure serialization of already-selected rows.
#[must_use]
pub fn encode_source_result(sender: KadId, key: KadId, rows: &[KadSourceRow]) -> Vec<KadEnvelope> {
    rows.chunks(SOURCE_RESULT_ROWS_PER_DATAGRAM)
        .map(|batch| {
            let mut payload = Vec::with_capacity(34 + batch.len() * 48);
            payload.extend_from_slice(sender.as_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(
                &u16::try_from(batch.len())
                    .expect("a batch never exceeds 50 rows")
                    .to_le_bytes(),
            );
            for row in batch {
                encode_row(&mut payload, row);
            }
            KadEnvelope::plain(Kad2Opcode::SearchRes.as_u8(), payload)
        })
        .collect()
}

fn encode_row(payload: &mut Vec<u8>, row: &KadSourceRow) {
    payload.extend_from_slice(&row.source_id);

    // eMule's TAG_SOURCEIP value is the host-order u32 of `a.b.c.d`
    // (see `project_direct` for the inverse used by the sealed projection).
    let ip_host_order = u32::from_be_bytes(row.ip.octets());
    let mut tags = vec![
        (TAG_SOURCEIP, TagValue::U32(ip_host_order)),
        (TAG_SOURCETYPE, TagValue::U8(row.source_type)),
        (TAG_SOURCEPORT, TagValue::U16(row.tcp_port)),
        (TAG_SOURCEUPORT, TagValue::U16(row.udp_port)),
    ];
    // The buddy tags follow the source ones, in the publisher's own order
    // (`TAG_SERVERIP`, `TAG_SERVERPORT`, `TAG_BUDDYHASH`) — the storer keeps
    // the tags it received in arrival order, and that is the order they arrive
    // in. `TAG_BUDDYHASH` goes out as the 32 hex characters aMule writes.
    if let Some(buddy) = row.buddy {
        if let Some(udp) = buddy.buddy_udp {
            let [a, b, c, d] = udp.ip.octets();
            tags.push((
                TAG_SERVERIP,
                TagValue::U32(u32::from_le_bytes([a, b, c, d])),
            ));
            tags.push((TAG_SERVERPORT, TagValue::U16(udp.port)));
        } else if let Some(udp) = buddy.buddy_udp_ipv6 {
            // eMuleAI's IPv6-buddy row, its `UINT_MAX` `TAG_SERVERIP` refused
            // at store: the port alone goes back out, for `bi6` below. An
            // eMuleAI searcher pairs the two (`DownloadQueue.cpp:5005-5008`);
            // an aMule one reads IP 0 and walks toward the buddy ID
            // (`BaseClient.cpp:2133-2170`) instead of sending to broadcast.
            tags.push((TAG_SERVERPORT, TagValue::U16(udp.port)));
        }
        tags.push((
            TAG_BUDDYHASH,
            TagValue::String(rmule_primitives::Ed2kText::from_utf8(md4_hex(
                crate::lookup::kad_wire_id(*buddy.buddy_id.as_bytes()),
            ))),
        ));
    }
    if let Some(options) = row.encryption {
        tags.push((TAG_ENCRYPTION, TagValue::U8(options)));
    }
    // The two IPv6 tags close the row, `ip6` then `bi6`, where the publisher
    // wrote them — eMuleAI's `0x44` ends `ENCRYPTION, ip6, bi6`
    // (`Search.cpp:913-923`, `a2f05dc8`), kno's ends in `ip6`
    // (`Search.cpp:886-902`) — and where kno's storer re-serves them, in
    // arrival order. Both were gated by `IsUsableTagIdentity` when the publish
    // was read, so an address this storer refused was never stored to re-serve.
    let ipv6_tags: Vec<Tag> = [
        row.ipv6
            .map(|address| crate::ipv6_tags::ipv6_tag(crate::ipv6_tags::TAG_SOURCE_IPV6, address)),
        row.buddy
            .and_then(|buddy| buddy.buddy_ipv6)
            .map(|address| crate::ipv6_tags::ipv6_tag(crate::ipv6_tags::TAG_BUDDY_IPV6, address)),
    ]
    .into_iter()
    .flatten()
    .collect();
    payload.push(u8::try_from(tags.len() + ipv6_tags.len()).expect("at most ten row tags"));
    for (name, value) in tags {
        payload.extend_from_slice(&Tag::new(TagName::length_prefixed_id(name), value).encode());
    }
    for tag in ipv6_tags {
        payload.extend_from_slice(&tag.encode());
    }
}

/// The 32 **upper-case** hex characters of a 16-byte hash — the inverse of
/// [`hex_md4`], and the case a captured `TAG_BUDDYHASH` carries
/// (`tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`:
/// `CMD4Hash::Encode` emits upper-case, and the tag's 32 bytes are all `0x43`
/// for a `0xCC…` buddy ID). Both decoders are case-insensitive
/// (`to_digit(16)`), so the case is cosmetic to a reader and byte-parity to a
/// differ.
pub(crate) fn md4_hex(bytes: [u8; KAD_ID_LEN]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(32), |mut out, b| {
        let _ = write!(out, "{b:02X}");
        out
    })
}

/// `TAG_ENCRYPTION` — the crypt-options byte a publisher may attach.
const TAG_ENCRYPTION: u8 = 0xF3;

/// The target key echoed in a `KADEMLIA2_SEARCH_RES` header
/// (`[16B sender][16B target] …`), read without touching any row — the node
/// matches it against its active walks *before* rows are projected.
pub(crate) fn search_res_target(
    envelope: &KadEnvelope,
) -> Result<KadId, KadSourceResultDecodeError> {
    if !matches!(
        Kad2Opcode::try_from_u8(envelope.opcode()),
        Some(Kad2Opcode::SearchRes)
    ) {
        return Err(KadSourceResultDecodeError::NotASearchResult {
            opcode: envelope.opcode(),
        });
    }
    let bytes = envelope.payload().get(KAD_ID_LEN..2 * KAD_ID_LEN).ok_or(
        KadSourceResultDecodeError::MalformedPayload {
            reason: "target Kad ID",
        },
    )?;
    let mut id = [0u8; KadId::BYTE_LEN];
    id.copy_from_slice(bytes);
    Ok(KadId::from_bytes(id))
}

/// Tags decoded from a single source row, projected to scalars.
#[derive(Default)]
struct RowTags {
    /// The publisher's User Hash, recovered from the row's 16-byte source ID.
    user_hash: Option<UserHash>,
    source_type: Option<u8>,
    /// `SOURCEIP` as eMule's host-order IP `u32` (`GetInt()` of the tag).
    source_ip_host_order: Option<u32>,
    tcp_port: Option<u16>,
    /// `SOURCEUPORT`: the publisher's Kad UDP port.
    udp_port: Option<u16>,
    /// `TAG_ENCRYPTION`: the publisher's connect-options byte, verbatim.
    connect_options: Option<u8>,
    /// `TAG_SERVERIP`: the *buddy's* IPv4 as the eD2k address word — **not**
    /// byte-swapped by either side, unlike `SOURCEIP`. Publisher writes
    /// `GetBuddy()->GetIP()` (aMule `src/updownclient.h:319`, the network-order
    /// word) and the reader feeds it straight to `SendPacket`
    /// (`src/DownloadClient.cpp:1433`) with no swap in between, while the same
    /// reader swaps `SOURCEIP` (`src/DownloadQueue.cpp:1713`).
    buddy_ip_network_order: Option<u32>,
    /// `TAG_SERVERPORT`: the buddy's UDP port.
    buddy_port: Option<u16>,
    /// `TAG_BUDDYHASH`, decoded from its 32 hex characters into the 16
    /// big-endian bytes aMule's `CUInt128::ToByteArray` produced.
    buddy_id_be: Option<[u8; KAD_ID_LEN]>,
    /// The row's `ip6` tag (ADR-0087), already past `IsUsableTagIdentity`.
    ipv6: Option<std::net::Ipv6Addr>,
    /// The row's `bi6` tag, gated alike; folded into the buddy contact, so a
    /// row that named no buddy drops it.
    buddy_ipv6: Option<std::net::Ipv6Addr>,
}

fn decode_row(
    reader: &mut WireReader<'_>,
) -> Result<KadSourceCandidate, KadSourceResultDecodeError> {
    // Each row is `[16B source ID][1B tag count][tags...]`. The source ID is
    // the publisher's User Hash word-swapped (ADR-0043's controlled-identity
    // `0x3B` capture); the swap is self-inverse, so reading it back is the
    // same transform.
    let id_bytes = reader.take(KAD_ID_LEN, "source row ID")?;
    let mut source_id = [0u8; KAD_ID_LEN];
    source_id.copy_from_slice(id_bytes);
    let tag_count = reader.read_u8("row tag count")?;

    let mut tags = RowTags {
        user_hash: Some(UserHash::from_bytes(crate::lookup::kad_wire_id(source_id))),
        ..RowTags::default()
    };
    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes()).map_err(|_| {
            KadSourceResultDecodeError::MalformedPayload {
                reason: "source row tag is truncated or malformed",
            }
        })?;
        reader.advance_clamped(consumed);
        apply_tag(&mut tags, &tag);
    }

    Ok(project_row(&tags))
}

/// Fold one decoded eD2k tag into the row's recognized source scalars.
///
/// Recognizes every tag aMule's `CSearch::ProcessResultFile` reads
/// (`src/kademlia/kademlia/Search.cpp:1179-1201`): the four source tags, the
/// two buddy-endpoint tags, the buddy hash and the connect-options byte. Any
/// other tag is ignored without failing the row, matching that loop's tolerance.
fn apply_tag(tags: &mut RowTags, tag: &Tag) {
    let Some(name) = tag.name().id() else {
        // `ip6` and `bi6` are string-named, so they never reach the numeric
        // match below. A link-local or unique-local address is refused here
        // rather than stored: a scope-less tag cannot tell two of them apart.
        for (name, slot) in [
            (crate::ipv6_tags::TAG_SOURCE_IPV6, &mut tags.ipv6),
            (crate::ipv6_tags::TAG_BUDDY_IPV6, &mut tags.buddy_ipv6),
        ] {
            if let Some(address) = crate::ipv6_tags::ipv6_from_tag(tag, name)
                && rmule_primitives::is_usable_tag_identity(address)
                && slot.is_none()
            {
                *slot = Some(address);
            }
        }
        return;
    };
    match (name, tag.value()) {
        (TAG_SOURCETYPE, value) => {
            if let Some(byte) = as_u8(value) {
                tags.source_type = Some(byte);
            }
        }
        (TAG_SOURCEIP, &TagValue::U32(ip)) => tags.source_ip_host_order = Some(ip),
        (TAG_SOURCEPORT, value) => tags.tcp_port = as_u16(value),
        (TAG_SOURCEUPORT, value) => tags.udp_port = as_u16(value),
        (TAG_ENCRYPTION, value) => tags.connect_options = as_u8(value),
        // Both buddy-endpoint tags are written with eMule's *variable* integer
        // tag (`CKadTagUInt` / aMule `CTagVarInt`), which narrows to the
        // smallest width that fits — so a u8 or u16 body is legal here.
        (TAG_SERVERIP, value) => tags.buddy_ip_network_order = as_u32(value),
        (TAG_SERVERPORT, value) => tags.buddy_port = as_u16(value),
        (TAG_BUDDYHASH, TagValue::String(text)) => {
            tags.buddy_id_be = text.try_as_str().ok().and_then(hex_md4);
        }
        _ => {}
    }
}

/// Decode 32 hexadecimal characters into 16 bytes — aMule's
/// `CMD4Hash::Decode`. A malformed tag yields `None`, which downgrades the row
/// to a plain buddy-callback diagnostic rather than failing the datagram
/// (aMule logs and continues, `src/kademlia/kademlia/Search.cpp:1195`).
pub(crate) fn hex_md4(text: &str) -> Option<[u8; KAD_ID_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * KAD_ID_LEN {
        return None;
    }
    let mut out = [0u8; KAD_ID_LEN];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).expect("two hex digits are one byte");
    }
    Some(out)
}

fn project_row(tags: &RowTags) -> KadSourceCandidate {
    let Some(source_type) = tags.source_type else {
        return KadSourceCandidate::diagnostic(KadSourceDiagnostic::MissingEndpoint);
    };
    let facts = row_facts(tags, source_type);

    let classic = match source_type {
        SOURCETYPE_DIRECT | SOURCETYPE_DIRECT_LARGE => project_direct(tags),
        // A buddy row is a candidate only when it actually named a buddy; one
        // that did not is the diagnostic it always was — there is nothing to
        // address a callback to.
        SOURCETYPE_BUDDY | SOURCETYPE_BUDDY_LARGE => {
            if facts.buddy.is_some() {
                KadSourceCandidate::buddy_reachable()
            } else {
                KadSourceCandidate::diagnostic(KadSourceDiagnostic::BuddyCallback)
            }
        }
        // aMule admits a type-6 row only when bit 3 is set
        // (`src/DownloadQueue.cpp:1786-1792`) and dials its `0x95` at the
        // address the storer observed (`:1797`); without either there is
        // nowhere to send the invitation.
        SOURCETYPE_FIREWALLED_UDP
            if facts.kad_udp.is_some()
                && facts
                    .connect_options
                    .is_some_and(SourceCryptOptions::supports_direct_udp_callback) =>
        {
            KadSourceCandidate::direct_udp_reachable()
        }
        SOURCETYPE_FIREWALLED_UDP => {
            KadSourceCandidate::diagnostic(KadSourceDiagnostic::Firewalled)
        }
        other => KadSourceCandidate::diagnostic(KadSourceDiagnostic::UnsupportedSourceType(other)),
    };
    // The `ip6` tag rescues a row the 32-bit projection found **no road** to —
    // a Kad Low ID (no server in a Kad row to broker it), a buddy row that
    // named no buddy, a firewalled row with no `0x95` endpoint — into an
    // IPv6-only source (ADR-0087): the ExtSX placeholder's reading, where an id
    // nobody can broker makes the IPv6 the source's one address. A row that
    // has a road keeps it, and its `ip6` rides beside it in the facts as the
    // source's **IPv6 Half**, for core's Dial Chooser to pick: a direct High ID
    // dials IPv4 or IPv6 by the chooser's AND, and a buddy or type-6 row stays
    // a callback candidate whose rung 0 dials the IPv6 when we hold one — the
    // ExtSX Low-ID-with-a-half reading. A deprecated type 2 or an
    // unknown type is no source at all, `ip6` or not: eMuleAI's
    // `KademliaSearchFile` switch builds nothing for either
    // (`DownloadQueue.cpp:4924-4926`, no `default` arm), so neither is rescued.
    let rescued = match (classic.refusal(), tags.ipv6, tags.tcp_port) {
        (Some(KadSourceDiagnostic::UnsupportedSourceType(_)), _, _) => classic,
        (Some(_), Some(address), Some(tcp_port)) if tcp_port != 0 => KadSourceCandidate::direct(
            PeerSource::Ipv6(rmule_primitives::Ipv6Endpoint::new(address, tcp_port)),
        ),
        _ => classic,
    };
    rescued.with_facts(facts)
}

/// Assemble the row's facts, whatever route it projected to.
fn row_facts(tags: &RowTags, source_type: u8) -> KadSourceRowFacts {
    KadSourceRowFacts {
        user_hash: tags.user_hash.unwrap_or(UserHash::from_bytes([0; 16])),
        source_type,
        tcp_port: tags.tcp_port.unwrap_or(0),
        kad_udp: endpoint(
            tags.source_ip_host_order.map(u32::swap_bytes),
            tags.udp_port,
            crate::net::may_name_a_host,
        ),
        connect_options: tags.connect_options.map(SourceCryptOptions::from_byte),
        buddy: tags.buddy_id_be.map(|be| KadBuddyContact {
            // The tag's big-endian bytes become `KadId`'s wire order under the
            // same self-inverse word swap the row's source ID uses.
            buddy_id: KadId::from_bytes(crate::lookup::kad_wire_id(be)),
            buddy_udp: endpoint(
                tags.buddy_ip_network_order,
                tags.buddy_port,
                crate::net::is_claimed_udp_target,
            ),
            buddy_ipv6: tags.buddy_ipv6,
            buddy_udp_ipv6: tags
                .buddy_ipv6
                .zip(tags.buddy_port.filter(|port| *port != 0))
                .map(|(address, port)| rmule_primitives::Ipv6Endpoint::new(address, port)),
        }),
        ipv6: tags
            .ipv6
            .zip(tags.tcp_port.filter(|port| *port != 0))
            .map(|(address, port)| rmule_primitives::Ipv6Endpoint::new(address, port)),
    }
}

/// Pair an eD2k address word (`a | b<<8 | c<<16 | d<<24`, rmule's [`ClientId`]
/// order) with a port, dropping the pair when either half is missing, the
/// port is zero, or `admit` refuses the address.
pub(crate) fn endpoint(
    address_word: Option<u32>,
    port: Option<u16>,
    admit: fn(Ipv4Addr) -> bool,
) -> Option<Ipv4Endpoint> {
    let [a, b, c, d] = address_word?.to_le_bytes();
    let ip = Ipv4Addr::new(a, b, c, d);
    let port = port.filter(|port| *port != 0)?;
    admit(ip).then(|| Ipv4Endpoint::new(ip, port))
}

/// Project a direct (type 1/4) source row.
///
/// eMule's `TAG_SOURCEIP` is the source IP as the host-order `u32`
/// `(a<<24)|(b<<16)|(c<<8)|d` for `a.b.c.d`. rmule's [`ClientId`] is the IP read
/// as little-endian octets (`a | b<<8 | c<<16 | d<<24`) so that
/// [`PeerSource::as_peer_endpoint`] reconstructs `a.b.c.d`. The two differ only
/// by a byte swap. A `ClientId` below
/// [`ClientId::LOW_ID_THRESHOLD`](rmule_primitives::ClientId) is a Low ID source.
fn project_direct(tags: &RowTags) -> KadSourceCandidate {
    let (Some(ip_host_order), Some(tcp_port)) = (tags.source_ip_host_order, tags.tcp_port) else {
        return KadSourceCandidate::diagnostic(KadSourceDiagnostic::MissingEndpoint);
    };
    if tcp_port == 0 {
        return KadSourceCandidate::diagnostic(KadSourceDiagnostic::MissingEndpoint);
    }

    let client_id = ClientId::from_u32(ip_host_order.swap_bytes());
    if client_id.is_high_id() {
        KadSourceCandidate::direct(PeerSource::new(client_id, tcp_port))
    } else {
        KadSourceCandidate::diagnostic(KadSourceDiagnostic::LowId {
            client_id,
            tcp_port,
        })
    }
}

const fn as_u8(value: &TagValue) -> Option<u8> {
    match *value {
        TagValue::U8(byte) => Some(byte),
        _ => None,
    }
}

const fn as_u16(value: &TagValue) -> Option<u16> {
    match *value {
        TagValue::U16(short) => Some(short),
        TagValue::U8(byte) => Some(byte as u16),
        TagValue::U32(_) | TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// Widen any integer tag body to a `u32` — eMule's variable integer tag narrows
/// to the smallest width that fits, so a `u8` or `u16` body is a legal
/// `TAG_SERVERIP`. A source-result row never carries `TAG_FILESIZE` (rmule's
/// own storer synthesizes no such tag on a `0x3B` row), so `UINT64` is
/// unrecognized here, same as a string or hash.
const fn as_u32(value: &TagValue) -> Option<u32> {
    match *value {
        TagValue::U32(word) => Some(word),
        TagValue::U16(short) => Some(short as u32),
        TagValue::U8(byte) => Some(byte as u32),
        TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

impl From<WireTruncated> for KadSourceResultDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        KadSourceResultDecodeError::MalformedPayload {
            reason: truncated.field,
        }
    }
}
