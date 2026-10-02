//! Global search over server UDP (ADR-0051): the `OP_GLOBSEARCHREQ`
//! variant family (0x98/0x92/0x90) — one query tree under three wrappers,
//! chosen by the server's advertised UDP flags — and the `OP_GLOBSEARCHRES`
//! (0x99) walk across every result packed into one datagram.

use rmule_primitives::{Packet, PacketProtocol, SearchResult, Tag, TagName, TagValue};

use crate::search_request::SearchRequest;
use crate::search_result::{SearchResultSkipReason, decode_row_prefix};
use crate::{Ed2kError, Opcode, Result};

/// Which `OP_GLOBSEARCHREQ` wrapper a server gets (ADR-0051): one wire
/// behavior, three opcodes chosen per the server's advertised UDP flags
/// (aMule `SearchList.cpp` — the capability store supplies the flags the
/// selection reads). The 64-bit-query skip toward servers without
/// large-file support is the caller's pacing rule, not encoded here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GlobSearchVariant {
    /// `OP_GLOBSEARCHREQ` (0x98): the baseline every server accepts.
    Baseline,
    /// `OP_GLOBSEARCHREQ2` (0x92): the server advertises `EXT_GETFILES`
    /// (new-tags result rows) without large-file UDP support.
    ExtGetFiles,
    /// `OP_GLOBSEARCHREQ3` (0x90): the server advertises `EXT_GETFILES` +
    /// `LARGEFILES`; the query is prefixed with a `CT_SERVER_UDPSEARCH_FLAGS`
    /// tag set announcing rmule's own new-tags + large-files understanding.
    LargeFiles,
}

impl GlobSearchVariant {
    /// The opcode this variant is sent under.
    #[must_use]
    pub const fn opcode(self) -> Opcode {
        match self {
            Self::Baseline => Opcode::GlobSearchReq,
            Self::ExtGetFiles => Opcode::GlobSearchReq2,
            Self::LargeFiles => Opcode::GlobSearchReq3,
        }
    }
}

/// `CT_SERVER_UDPSEARCH_FLAGS` (aMule `ClientTags.h`): the tag the `0x90`
/// variant prepends, announcing the searcher's own UDP capabilities.
const CT_SERVER_UDPSEARCH_FLAGS: u8 = 0x0E;
/// `SRVCAP_UDP_NEWTAGS_LARGEFILES` (aMule `ClientTags.h`): the one capability
/// value aMule announces in that tag.
const SRVCAP_UDP_NEWTAGS_LARGEFILES: u8 = 0x01;

/// The `OP_GLOBSEARCHREQ` family (ADR-0051): the TCP `OP_SEARCHREQUEST` query
/// tree — byte-identical, one encoder — wrapped per variant. `0x98`/`0x92`
/// carry the bare tree under their opcode; `0x90` prepends a one-entry tag
/// set (`[tag_count u32 = 1][CT_SERVER_UDPSEARCH_FLAGS = NEWTAGS_LARGEFILES]`,
/// the tag in aMule's compact `WriteNewEd2kTag` form `[0x89][0x0E][0x01]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobSearchReq {
    request: SearchRequest,
}

impl GlobSearchReq {
    /// Wrap a TCP-form search request for UDP.
    #[must_use]
    pub const fn new(request: SearchRequest) -> Self {
        Self { request }
    }

    /// The wrapped TCP-form request — the sweep reads
    /// [`SearchRequest::uses_64bit`] off it to decide which servers can be
    /// asked at all (aMule's `m_64bitSearchPacket`).
    #[must_use]
    pub const fn request(&self) -> &SearchRequest {
        &self.request
    }

    /// The packet form for one variant: the bare query tree, or the tree
    /// behind the capability tag the large-file variant prepends.
    #[must_use]
    pub fn encode_packet(&self, variant: GlobSearchVariant) -> Packet {
        let tree = self.request.encode_packet().payload().to_vec();
        let payload = match variant {
            GlobSearchVariant::Baseline | GlobSearchVariant::ExtGetFiles => tree,
            GlobSearchVariant::LargeFiles => {
                let mut payload = 1_u32.to_le_bytes().to_vec();
                payload.extend_from_slice(
                    &Tag::new(
                        TagName::compact_id(CT_SERVER_UDPSEARCH_FLAGS),
                        TagValue::U8(SRVCAP_UDP_NEWTAGS_LARGEFILES),
                    )
                    .encode(),
                );
                payload.extend_from_slice(&tree);
                payload
            }
        };
        Packet::new(PacketProtocol::Edonkey, variant.opcode().as_u8(), payload)
    }
}

/// `OP_GLOBSEARCHRES` (0x99): a server's UDP search answer. Unlike the TCP
/// `OP_SEARCHRESULT` (a `u32` count then rows), each `0x99` packet carries
/// **exactly one** result row, and a multi-result answer packs several
/// packets in one datagram — walked per aMule `ServerUDPSocket.cpp`: after
/// each row, while at least 3 bytes remain, the next `[protocol][opcode]`
/// header must repeat `[0xE3][0x99]` or the walk stops ("additional bogus
/// bytes"); fewer than 3 remaining bytes end it silently. Rows already
/// decoded survive a bogus tail, matching aMule's already-added results. The
/// row bytes are the TCP row's (`search_result::decode_row_prefix` — one
/// decoder); strings stay raw [`rmule_primitives::Ed2kText`] bytes, read as
/// UTF-8 at projection (aMule consumes with `optUTF8 = true`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobSearchRes {
    results: Vec<SearchResult>,
}

impl GlobSearchRes {
    #[must_use]
    /// The rows this datagram carried.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Decode a whole `0x99` datagram (every packed packet). Errors only
    /// when the datagram yields nothing — a bad header or an undecodable
    /// first row; a failure after the first row returns what was walked.
    pub fn decode_udp(bytes: &[u8]) -> Result<Self> {
        let opcode = Opcode::GlobSearchRes.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBSEARCHRES datagram missing header",
            });
        };
        let mut remaining = body;
        if *protocol != PacketProtocol::Edonkey.as_byte() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if *op != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_GLOBSEARCHRES",
            });
        }
        let mut results = Vec::new();
        let mut first_skip = None;
        loop {
            match decode_row_prefix(remaining) {
                Ok((row, consumed)) => {
                    match row {
                        Ok(result) => results.push(result),
                        // A row read whole that does not stand is dropped
                        // alone, as aMule's `AddToList` drops it.
                        Err(reason) => {
                            first_skip.get_or_insert(reason);
                        }
                    }
                    remaining = &remaining[consumed..];
                }
                Err(reason) if results.is_empty() => {
                    return Err(Ed2kError::InvalidPayload {
                        opcode,
                        reason: skip_reason_str(first_skip.unwrap_or(reason)),
                    });
                }
                // aMule keeps the results already added when a later row
                // throws; the walked prefix is the answer.
                Err(_) => break,
            }
            // The continuation check: another packet needs at least a 2-byte
            // header and one body byte; anything shorter ends the walk.
            if remaining.len() < 3 {
                break;
            }
            if remaining[0] != PacketProtocol::Edonkey.as_byte() || remaining[1] != opcode {
                // "Server search reply got additional bogus bytes."
                break;
            }
            remaining = &remaining[2..];
        }
        match first_skip {
            Some(reason) if results.is_empty() => Err(Ed2kError::InvalidPayload {
                opcode,
                reason: skip_reason_str(reason),
            }),
            _ => Ok(Self { results }),
        }
    }
}

const fn skip_reason_str(reason: SearchResultSkipReason) -> &'static str {
    reason.as_static_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_udp::sources::glob_found_sources_datagram;
    use rmule_primitives::FileHash;

    /// The query tree for a bare "abba" phrase: `[EXPR_PHRASE][len u16 LE]
    /// [bytes]` — the TCP `OP_SEARCHREQUEST` payload, byte-identical inside
    /// every UDP variant.
    const ABBA_TREE: [u8; 7] = [0x01, 0x04, 0x00, b'a', b'b', b'b', b'a'];

    fn abba_search() -> GlobSearchReq {
        GlobSearchReq::new(SearchRequest::from_query(
            rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("abba"))
                .expect("valid phrase"),
        ))
    }

    /// One `0x99` packet (`[0xE3][0x99]` + one result row): hash filled with
    /// `hash`, one source, two tags (filename "a.bin", size 4096).
    fn glob_search_res_packet(hash: u8) -> Vec<u8> {
        let mut out = vec![
            PacketProtocol::Edonkey.as_byte(),
            Opcode::GlobSearchRes.as_u8(),
        ];
        out.extend_from_slice(&[hash; FileHash::BYTE_LEN]);
        out.extend_from_slice(&0x0100_007F_u32.to_le_bytes()); // High-ID source
        out.extend_from_slice(&4662_u16.to_le_bytes());
        out.extend_from_slice(&2_u32.to_le_bytes()); // tag count
        // FT_FILENAME (0x01) string tag, length-prefixed name form.
        out.extend_from_slice(&[0x02, 0x01, 0x00, 0x01, 0x05, 0x00]);
        out.extend_from_slice(b"a.bin");
        // FT_FILESIZE (0x02) u32 tag.
        out.extend_from_slice(&[0x03, 0x01, 0x00, 0x02]);
        out.extend_from_slice(&4096_u32.to_le_bytes());
        out
    }

    #[test]
    fn glob_search_req_wraps_one_tree_under_three_opcodes() {
        let search = abba_search();

        let baseline = search
            .encode_packet(GlobSearchVariant::Baseline)
            .encode_udp();
        let mut expected = vec![0xE3, 0x98];
        expected.extend_from_slice(&ABBA_TREE);
        assert_eq!(baseline, expected);

        let ext = search
            .encode_packet(GlobSearchVariant::ExtGetFiles)
            .encode_udp();
        let mut expected = vec![0xE3, 0x92];
        expected.extend_from_slice(&ABBA_TREE);
        assert_eq!(ext, expected);

        let large = search
            .encode_packet(GlobSearchVariant::LargeFiles)
            .encode_udp();
        // The 0x90 prefix: `[tag_count u32 = 1]` then the compact
        // CT_SERVER_UDPSEARCH_FLAGS tag — aMule's `WriteNewEd2kTag` bytes
        // `[TAGTYPE_UINT8|0x80][0x0E][SRVCAP_UDP_NEWTAGS_LARGEFILES]`.
        let mut expected = vec![0xE3, 0x90, 0x01, 0x00, 0x00, 0x00, 0x89, 0x0E, 0x01];
        expected.extend_from_slice(&ABBA_TREE);
        assert_eq!(large, expected);
    }

    #[test]
    fn glob_search_res_walks_every_packed_packet() {
        let mut datagram = glob_search_res_packet(0xAA);
        datagram.extend_from_slice(&glob_search_res_packet(0xBB));

        let decoded = GlobSearchRes::decode_udp(&datagram).expect("decodes");
        assert_eq!(decoded.results().len(), 2);
        assert_eq!(
            decoded.results()[0].file_hash(),
            FileHash::from_bytes([0xAA; FileHash::BYTE_LEN])
        );
        assert_eq!(
            decoded.results()[1].file_hash(),
            FileHash::from_bytes([0xBB; FileHash::BYTE_LEN])
        );
        assert_eq!(decoded.results()[0].file_size(), 4096);
        assert_eq!(decoded.results()[0].names().len(), 1);
    }

    #[test]
    fn glob_search_res_stops_at_bogus_continuation_bytes_keeping_the_prefix() {
        // A valid row followed by a non-0x99 header: aMule logs "additional
        // bogus bytes" and keeps what it already added.
        let mut datagram = glob_search_res_packet(0xAA);
        datagram.extend_from_slice(&glob_found_sources_datagram(0xCC));

        let decoded = GlobSearchRes::decode_udp(&datagram).expect("prefix survives");
        assert_eq!(decoded.results().len(), 1);
        assert_eq!(
            decoded.results()[0].file_hash(),
            FileHash::from_bytes([0xAA; FileHash::BYTE_LEN])
        );

        // A short (< 3 byte) tail ends the walk silently, same as aMule's
        // `position + 2 < size` loop bound.
        let mut datagram = glob_search_res_packet(0xAA);
        datagram.extend_from_slice(&[0xE3, 0x99]);
        let decoded = GlobSearchRes::decode_udp(&datagram).expect("short tail ignored");
        assert_eq!(decoded.results().len(), 1);
    }

    #[test]
    fn glob_search_res_rejects_a_datagram_with_no_decodable_row() {
        // Wrong opcode outright.
        assert!(GlobSearchRes::decode_udp(&glob_found_sources_datagram(0xAA)).is_err());
        // Right opcode, truncated first row.
        let datagram = glob_search_res_packet(0xAA);
        assert!(GlobSearchRes::decode_udp(&datagram[..10]).is_err());
    }
}
