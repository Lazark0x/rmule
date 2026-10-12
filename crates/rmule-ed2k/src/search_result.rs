//! `OP_SEARCHRESULT` (0x33): the rows a server answers a search with, and the
//! reasons an undecodable row is skipped rather than fatal.
//!
//! Row tags are capture-backed: what rmule reads is what genuine servers were
//! observed to emit, not what a spec allows.

use rmule_primitives::{
    ClientId, FileHash, Packet, PacketProtocol, PeerSource, PrimitiveError, SearchResult, Tag,
    TagValue, WireReader,
};

use crate::{Ed2kError, Opcode, Result};

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_FILEFORMAT: u8 = 0x04;
const FT_SOURCES: u8 = 0x15;
/// `FT_COMPLETE_SOURCES` — how many of the reported sources hold the whole
/// file. Capture-backed twice over: the genuine `0x99` in
/// `tests/fixtures/server/captured/ed2ksrv-glob-search-20260802` ends
/// `83 30 01 00 00 00`, and the captured Lugdunum `0x33` replayed in
/// `tests/search_packets.rs` carries `89 30 01`. Both servers emit it beside
/// `FT_SOURCES` on every row of both the TCP answer (`0x16`→`0x33`) and the
/// UDP one (`0x98`→`0x99`).
const FT_COMPLETE_SOURCES: u8 = 0x30;
const FT_FILESIZE_HI: u8 = 0x3A;

/// `OP_SEARCHRESULT`: one batch of search rows, and whether the server holds
/// more for `OP_QUERY_MORE_RESULT` to fetch.
///
/// The more-results byte follows the rows: `0x01` more, `0x00` none (eMule
/// `SearchList.cpp:266-277`; ed2k-server `search.rs:186-187`). Every captured
/// answer, Lugdunum's and ed2k-server's, ends in it (`0x00` in all 586 of runs
/// 1790602217–1790605441). eMule reads a lone byte of any other value, or a
/// longer tail, as "no more" and keeps every row (`SearchList.cpp:268-282`);
/// aMule reads no tail on a server's answer (stock 2.3.3
/// `SearchList.cpp:541-548`), only on a peer's shared-file list
/// (`SearchList.cpp:526-535`). rmule reads it as eMule does.
///
/// A row that does not stand is skipped, never the batch. A row whose bytes
/// were read whole but name no file, no size or a size eD2k cannot address,
/// or carry a known tag of the wrong type, is skipped alone and the rows after
/// it are read; aMule drops a row with no usable size alone
/// (`SearchList.cpp:561-570` at stock 2.3.3). A row whose bytes do not decode
/// leaves no way to find the next one, so the rows before it are kept and the
/// batch ends there, as aMule keeps the rows it already added when a row
/// throws (`ServerSocket.cpp:608-611`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResults {
    results: Vec<SearchResult>,
    skipped: Vec<SearchResultSkipReason>,
    more_available: bool,
}

/// Why a search answer was not surfaced as results.
///
/// Skipping is a diagnosis, not a session failure: a server that sends one
/// unreadable row is still a server worth talking to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchResultSkipReason {
    /// The payload is not a readable result batch at all.
    MalformedPayload,
    /// A row carried no name, leaving nothing to display.
    MissingFileName,
    /// A row carried no size, leaving the file unidentifiable.
    MissingFileSize,
    /// A row's descriptor tags did not decode.
    TagDecodeFailed,
    /// A row named a file larger than eD2k addresses (256 GiB).
    FileSizeAboveLimit,
    /// A row named a file of zero bytes: no part to fetch.
    FileSizeZero,
}

impl SearchResults {
    /// A batch from already-decoded rows, the last page.
    #[must_use]
    pub const fn new(results: Vec<SearchResult>) -> Self {
        Self {
            results,
            skipped: Vec::new(),
            more_available: false,
        }
    }

    /// The same batch, saying whether the server holds more.
    #[must_use]
    pub const fn with_more_available(mut self, more_available: bool) -> Self {
        self.more_available = more_available;
        self
    }

    /// The rows, in the order the server sent them.
    #[must_use]
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Why each row the batch did not yield was skipped, in the order the
    /// server sent them. A row whose bytes did not decode ends the batch, so
    /// it is the last one named.
    #[must_use]
    pub fn skipped(&self) -> &[SearchResultSkipReason] {
        &self.skipped
    }

    /// The server said it holds more rows for this search.
    #[must_use]
    pub const fn more_available(&self) -> bool {
        self.more_available
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        Self::try_decode_packet(packet).map_err(|reason| Ed2kError::InvalidPayload {
            opcode: Opcode::SearchResult.as_u8(),
            reason: reason.as_static_str(),
        })
    }

    /// Decode the batch, reporting *why* it was unreadable rather than
    /// flattening the reason into a payload error — what the session needs to
    /// emit a skip diagnostic. A row that does not stand is named in
    /// [`Self::skipped`], not an error.
    ///
    /// # Errors
    /// [`SearchResultSkipReason::MalformedPayload`] when the packet is not a
    /// result batch at all: another opcode, or no row count.
    pub fn try_decode_packet(packet: &Packet) -> std::result::Result<Self, SearchResultSkipReason> {
        if packet.protocol() != PacketProtocol::Edonkey
            || packet.opcode() != Opcode::SearchResult.as_u8()
        {
            return Err(SearchResultSkipReason::MalformedPayload);
        }

        let mut reader = WireReader::new(packet.payload());
        let count = reader
            .read_u32_le("result count")
            .map_err(|_| SearchResultSkipReason::MalformedPayload)?;
        let mut results = Vec::new();
        let mut skipped = Vec::new();
        let mut framed = true;
        for _ in 0..count {
            match decode_row(&mut reader) {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(reason)) => skipped.push(reason),
                Err(reason) => {
                    skipped.push(reason);
                    framed = false;
                    break;
                }
            }
        }
        // The more-results byte, eMule's reading: a lone `0x01` is more, and
        // any other tail says none without costing the rows. After a row that
        // did not decode, what follows is not a tail.
        let more_available = framed
            && reader.remaining() == 1
            && reader
                .take(1, "more-results byte")
                .map_err(|_| SearchResultSkipReason::MalformedPayload)?
                == [0x01];

        Ok(Self {
            results,
            skipped,
            more_available,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(self.results.len() as u32).to_le_bytes());
        for result in &self.results {
            let source = result
                .sources()
                .first()
                .copied()
                .unwrap_or_else(|| PeerSource::new(ClientId::from_u32(0), 0));
            payload.extend_from_slice(result.file_hash().as_bytes());
            payload.extend_from_slice(&source.wire_id().to_le_bytes());
            payload.extend_from_slice(&source.tcp_port().to_le_bytes());

            let mut tags = Vec::new();
            for name in result.names() {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_FILENAME),
                    TagValue::String(name.clone()),
                ));
            }
            tags.push(Tag::new(
                rmule_primitives::TagName::compact_id(FT_FILESIZE),
                TagValue::U32(result.file_size() as u32),
            ));
            if result.file_size() > u64::from(u32::MAX) {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_FILESIZE_HI),
                    TagValue::U16((result.file_size() >> 32) as u16),
                ));
            }
            if let Some(file_type) = result.file_type() {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_FILETYPE),
                    TagValue::String(file_type.clone()),
                ));
            }
            if let Some(file_format) = result.file_format() {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_FILEFORMAT),
                    TagValue::String(file_format.clone()),
                ));
            }
            if let Some(availability) = result.reported_availability() {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_SOURCES),
                    TagValue::U32(availability),
                ));
            }
            if let Some(complete) = result.complete_sources() {
                tags.push(Tag::new(
                    rmule_primitives::TagName::compact_id(FT_COMPLETE_SOURCES),
                    TagValue::U32(complete),
                ));
            }
            tags.extend(result.extra_tags().iter().cloned());

            payload.extend_from_slice(&(tags.len() as u32).to_le_bytes());
            for tag in tags {
                payload.extend_from_slice(&tag.encode());
            }
        }
        payload.push(u8::from(self.more_available));
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::SearchResult.as_u8(),
            payload,
        )
    }
}

impl SearchResultSkipReason {
    /// The reason as the fixed text a payload error carries.
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::MalformedPayload => "malformed OP_SEARCHRESULT payload",
            Self::MissingFileName => "OP_SEARCHRESULT row missing filename",
            Self::MissingFileSize => "OP_SEARCHRESULT row missing file size",
            Self::TagDecodeFailed => "OP_SEARCHRESULT descriptor tag decode failed",
            Self::FileSizeAboveLimit => "OP_SEARCHRESULT row file size above the eD2k limit",
            Self::FileSizeZero => "OP_SEARCHRESULT row file size zero",
        }
    }
}

/// Decode one result row (`[hash 16][client_id u32][port u16][tag_count u32]
/// [tags]`) from the front of `bytes`, returning it — or why it does not
/// stand, when its bytes were read whole — with its consumed length. An error
/// means the row's bytes did not decode, so its length is unknown.
/// The row is the shared server-search vocabulary: the TCP `OP_SEARCHRESULT`
/// packs `count` of them behind a `u32`, and the UDP `OP_GLOBSEARCHRES`
/// (ADR-0051) carries exactly one per packet — one decoder, no drift.
pub(crate) fn decode_row_prefix(
    bytes: &[u8],
) -> std::result::Result<(Row, usize), SearchResultSkipReason> {
    let mut reader = WireReader::new(bytes);
    let row = decode_row(&mut reader)?;
    Ok((row, reader.position()))
}

/// A row whose bytes were read whole: the result, or why it does not stand.
pub(crate) type Row = std::result::Result<SearchResult, SearchResultSkipReason>;

/// One row from the reader. The outer error is a row whose bytes did not
/// decode, leaving the reader with no way to the next row; the inner one a
/// row read whole that does not stand, with the reader past it.
fn decode_row(reader: &mut WireReader<'_>) -> std::result::Result<Row, SearchResultSkipReason> {
    let hash_bytes = reader
        .read_array::<{ FileHash::BYTE_LEN }>("file hash")
        .map_err(|_| SearchResultSkipReason::MalformedPayload)?;
    let file_hash = FileHash::from_bytes(hash_bytes);
    let client_id = ClientId::from_u32(
        reader
            .read_u32_le("client id")
            .map_err(|_| SearchResultSkipReason::MalformedPayload)?,
    );
    let tcp_port = reader
        .read_u16_le("tcp port")
        .map_err(|_| SearchResultSkipReason::MalformedPayload)?;
    let tag_count = reader
        .read_u32_le("tag count")
        .map_err(|_| SearchResultSkipReason::MalformedPayload)?;

    let mut names = Vec::new();
    let mut size_low = None;
    let mut size_high = None;
    let mut file_type = None;
    let mut file_format = None;
    let mut reported_availability = None;
    let mut complete_sources = None;
    let mut extra_tags = Vec::new();
    let mut wrong_type = false;

    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes())
            .map_err(|_| SearchResultSkipReason::TagDecodeFailed)?;
        reader
            .skip(consumed, "tag")
            .map_err(|_| SearchResultSkipReason::MalformedPayload)?;

        match (tag.name().id(), tag.value()) {
            (Some(FT_FILENAME), TagValue::String(name)) if !name.as_bytes().is_empty() => {
                names.push(name.clone());
            }
            (Some(FT_FILENAME), TagValue::String(_)) => {}
            (Some(FT_FILENAME), _) => wrong_type = true,
            (Some(FT_FILESIZE), value) => {
                size_low = uint_tag(value);
                wrong_type |= size_low.is_none();
            }
            (Some(FT_FILESIZE_HI), value) => {
                size_high = uint_tag(value).map(u64::from);
                wrong_type |= size_high.is_none();
            }
            (Some(FT_FILETYPE), TagValue::String(value)) => file_type = Some(value.clone()),
            (Some(FT_FILEFORMAT), TagValue::String(value)) => file_format = Some(value.clone()),
            (Some(FT_SOURCES), value) => {
                reported_availability = uint_tag(value);
                wrong_type |= reported_availability.is_none();
            }
            (Some(FT_COMPLETE_SOURCES), value) => {
                complete_sources = uint_tag(value);
                wrong_type |= complete_sources.is_none();
            }
            // A type or format that is not a string — ed2k-server sends
            // `FT_FILETYPE` as an integer (`search-wire-20260928` capture) —
            // is kept as a tag the row carries, as aMule keeps it
            // (`SearchFile.cpp`, the switch's default) and eMule's string read
            // skips it (`AbstractFile.cpp:286-294`); neither drops the row.
            _ => extra_tags.push(tag),
        }
    }

    Ok(row_of(
        wrong_type,
        file_hash,
        client_id,
        tcp_port,
        RowTags {
            names,
            size_low,
            size_high,
            file_type,
            file_format,
            reported_availability,
            complete_sources,
            extra_tags,
        },
    ))
}

/// The descriptor tags a row's bytes carried.
struct RowTags {
    names: Vec<rmule_primitives::Ed2kText>,
    size_low: Option<u32>,
    size_high: Option<u64>,
    file_type: Option<rmule_primitives::Ed2kText>,
    file_format: Option<rmule_primitives::Ed2kText>,
    reported_availability: Option<u32>,
    complete_sources: Option<u32>,
    extra_tags: Vec<Tag>,
}

/// The row a whole row's bytes stand for, or why it does not stand.
fn row_of(
    wrong_type: bool,
    file_hash: FileHash,
    client_id: ClientId,
    tcp_port: u16,
    tags: RowTags,
) -> Row {
    let RowTags {
        names,
        size_low,
        size_high,
        file_type,
        file_format,
        reported_availability,
        complete_sources,
        extra_tags,
    } = tags;
    if wrong_type {
        return Err(SearchResultSkipReason::TagDecodeFailed);
    }
    let low = size_low.ok_or(SearchResultSkipReason::MissingFileSize)?;
    if names.is_empty() {
        return Err(SearchResultSkipReason::MissingFileName);
    }
    let file_size = (size_high.unwrap_or(0) << 32) | u64::from(low);
    let result = SearchResult::new(
        file_hash,
        file_size,
        names,
        // The sentinel id names no address here: `0x33`/`0x99` rows define no
        // IPv6 form (ADR-0087), so such a row keeps its file and loses its
        // source rather than surfacing `255.255.255.255`.
        PeerSource::from_record(client_id, tcp_port)
            .into_iter()
            .collect(),
    )
    .map_err(|error| match error {
        PrimitiveError::FileSizeAboveLimit { .. } => SearchResultSkipReason::FileSizeAboveLimit,
        PrimitiveError::FileSizeZero => SearchResultSkipReason::FileSizeZero,
        _ => SearchResultSkipReason::MissingFileName,
    })?;

    let result = if let Some(value) = file_type {
        result.with_file_type(value)
    } else {
        result
    };
    let result = if let Some(value) = file_format {
        result.with_file_format(value)
    } else {
        result
    };
    let result = if let Some(value) = reported_availability {
        result.with_reported_availability(value)
    } else {
        result
    };
    let result = if let Some(value) = complete_sources {
        result.with_complete_sources(value)
    } else {
        result
    };

    Ok(result.with_extra_tags(extra_tags))
}

/// Read any integer tag as a `u32`, the way aMule reads every numeric search
/// descriptor (`CSearchFile`'s constructor calls `CTag::GetInt()` for
/// `FT_FILESIZE`, `FT_FILESIZE_HI`, `FT_SOURCES` and `FT_COMPLETE_SOURCES`
/// alike — `SearchFile.cpp:70-84`).
///
/// The width is not fixed on the wire: every *Mule writer narrows an integer
/// tag to the smallest type that holds it (`TagValue::compact_uint`), so the
/// same field arrives as `TAGTYPE_UINT8` from one server and `TAGTYPE_UINT16`
/// or `_UINT32` from the next. Pinning a single width here would not merely
/// lose the field — a mismatch fails the row, and one failed row skips the
/// whole `OP_SEARCHRESULT` packet.
const fn uint_tag(value: &TagValue) -> Option<u32> {
    match value {
        TagValue::U32(value) => Some(*value),
        TagValue::U16(value) => Some(*value as u32),
        TagValue::U8(value) => Some(*value as u32),
        TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}
