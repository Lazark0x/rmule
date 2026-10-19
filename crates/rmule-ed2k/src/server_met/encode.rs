//! The server.met writer: a learned-server list encoded as a file aMule
//! reads, the decoder's inverse field for field (not byte for byte; see
//! [`ServerMet::encode`]).

use rmule_primitives::{Ed2kText, ST_IPV6, Tag, TagName, TagValue, ipv6_address_tag_compact};

use super::{
    HEADER_AMULE, ServerMet, ServerMetEntry, TAG_AUXPORTSLIST, TAG_DESCRIPTION, TAG_PREFERENCE,
    TAG_SERVERNAME, synthesize_name,
};

impl ServerMet {
    /// Wrap a learned-server list for [`encode`](Self::encode); the declared
    /// count is the entry count, so the result is never [`is_truncated`](Self::is_truncated).
    #[must_use]
    pub fn from_entries(entries: Vec<ServerMetEntry>) -> Self {
        let declared_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        Self {
            entries,
            declared_count,
            count_truncated: false,
        }
    }

    /// Encode a learned-server list as an aMule-readable server.met, the
    /// symmetric writer for [`decode`](Self::decode). Header
    /// `0xE0` (aMule's own `SaveServerMet` marker), a `u32` server count, then
    /// per row `ip4/port2/tagcount4` and the tags.
    ///
    /// ## Documented divergence — a lossy, not byte-exact, re-encode
    ///
    /// This does **not** reproduce aMule's `SaveServerMet` bytes, and cannot:
    /// aMule writes twelve-plus tags per row (users/files/ping/… and each
    /// string tag twice, a BOM-unicode copy then a plain one), but the decoder
    /// models only name/description/priority and the figures — every other tag
    /// is dropped on read (ADR-0066: "server.met has no production re-encoder
    /// for a preserved tail"). So the writer emits exactly those, each string
    /// tag once;
    /// the file **field**-round-trips through [`decode`](Self::decode) and reads
    /// cleanly in aMule (`ST_SERVERNAME`/`ST_DESCRIPTION`/`ST_PREFERENCE` are
    /// `AddTagFromFile`-recognised), it is simply smaller than aMule's own.
    /// `ST_PREFERENCE` is always written (aMule always does); the name and
    /// description tags only when non-empty, matching `SaveServerMet`'s
    /// `!IsEmpty()` guards.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![HEADER_AMULE];
        // Count the rows actually written below — never the (possibly larger)
        // declared count a truncated decode carried, which would promise rows
        // the body lacks.
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.endpoint.encode());

            let mut tags = Vec::with_capacity(4);
            // aMule synthesises "Server <ip:port>" for a nameless server on
            // read; the writer materialises it so a decode → encode → decode
            // round-trip is a fixed point (no name flips to empty).
            let name = if entry.name.as_bytes().is_empty() {
                synthesize_name(entry.endpoint, entry.ipv6)
            } else {
                entry.name.clone()
            };
            tags.push(Tag::new(
                TagName::compact_id(TAG_SERVERNAME),
                TagValue::String(name),
            ));
            if !entry.description.as_bytes().is_empty() {
                tags.push(Tag::new(
                    TagName::compact_id(TAG_DESCRIPTION),
                    TagValue::String(entry.description.clone()),
                ));
            }
            tags.push(Tag::new(
                TagName::compact_id(TAG_PREFERENCE),
                TagValue::U32(entry.priority.to_raw()),
            ));
            // `ST_IPV6` rides as a new-format `TAGTYPE_HASH` — `81 99` then
            // sixteen raw network-order bytes (ADR-0087 §4.8). Written only
            // when the row holds one, so a v4 file stays byte-identical to
            // what it was before this tag existed.
            if let Some(address) = entry.ipv6 {
                tags.push(ipv6_address_tag_compact(ST_IPV6, address));
            }
            // The figures the row holds, each only when present, in
            // the tags aMule reads them from.
            tags.extend(entry.figures.tags());
            tags.extend(entry.obfuscation.tags());
            if !entry.aux_ports.is_empty() {
                tags.push(Tag::new(
                    TagName::compact_id(TAG_AUXPORTSLIST),
                    TagValue::String(Ed2kText::from_utf8(aux_ports_text(&entry.aux_ports))),
                ));
            }

            let tag_count = u32::try_from(tags.len()).expect("a row's tags fit u32");
            out.extend_from_slice(&tag_count.to_le_bytes());
            for tag in &tags {
                out.extend(tag.encode());
            }
        }
        out
    }
}

fn aux_ports_text(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
