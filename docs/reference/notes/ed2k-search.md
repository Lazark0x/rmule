# ED2K server search

**Status:** planned
**Scope:** TCP connected-server search only: `OP_SEARCHREQUEST` sent to the current server session and `OP_SEARCHRESULT` rows received back on that same session.

This note covers the first rmule **eD2k Server Search** slice. It deliberately excludes Kad, UDP global server fanout, durable search history, result ranking, and automatic download start policy.

## Packet roster

| Opcode | Direction | Name | Scope |
| --- | --- | --- | --- |
| `0x16` | C->S | `OP_SEARCHREQUEST` | Submit one search query to the connected TCP server |
| `0x33` | S->C | `OP_SEARCHRESULT` | Receive one count-prefixed batch of matching file descriptors |

The eMule PDF section 6.2.10 labels the `OP_SEARCHRESULT` type byte as `0x16`, but the opcode table and current aMule constants use `0x33`. rmule follows the opcode table in `docs/reference/notes/ed2k-server-protocol.md` and the pinned aMule `Client2Server/TCP.h` constants.

## OP_SEARCHREQUEST (`0x16`)

**Direction:** C->S. Client asks the currently connected server for files matching a user-facing **Search Query**.

The first slice exposes only:

- required text phrase;
- optional file type;
- optional minimum file size;
- optional maximum file size;
- optional minimum availability;
- optional filename extension.

It does not expose a public arbitrary boolean-expression builder. The packet encoder may still use the historical search-expression wire form internally.

### Text phrase

The eMule PDF section 6.2.9 describes a pre-order boolean expression tree with string operands and `AND`, `OR`, and `NOT` operators. It also documents the later compatible short form for all-AND searches: encode the phrase as one string with terms separated by spaces and let the server parse it as an AND phrase.

rmule's first slice encodes one required text phrase using that compatible AND phrase form. This keeps the public query vocabulary small while matching the behavior aMule uses for local eD2k searches when the parsed expression contains no `OR` or `NOT`.

### Optional filters

Filters are appended as AND constraints after the phrase. The first-slice filter vocabulary is:

| Query field | Wire tag / descriptor | Value kind | Notes |
| --- | --- | --- | --- |
| file type | `FT_FILETYPE` (`0x03`) | string | One of `Audio`, `Video`, `Pro`, `Image`; `Program` maps to historical wire label `Pro` |
| minimum size | `FT_FILESIZE` (`0x02`) | integer constraint | Lower bound |
| maximum size | `FT_FILESIZE` (`0x02`) | integer constraint | Upper bound |
| minimum availability | `FT_SOURCES` (`0x15`) | integer constraint | Advisory source-count lower bound |
| filename extension | `FT_FILEFORMAT` (`0x04`) | string | Extension filter, separate from file type |

The eMule PDF describes search-size constraints as megabytes. aMule's current search builder passes byte-sized `uint64_t` values into the metadata-search parameter writer; rmule's public primitive stores sizes as bytes. Packet fixtures decide the exact first-slice wire encoding before broadening compatibility behavior.

## OP_SEARCHRESULT (`0x33`)

**Direction:** S->C. Server returns one batch of result rows. The message is often sent in a compressed packet frame; packet framing and zlib behavior remain the same as other server packets.

| Offset | Size | Field | Endianness | Notes |
| --- | ---: | --- | --- | --- |
| 0 | 4 | result count | little-endian integer | Number of following rows |
| 4 | varies | result rows | mixed | Count repetitions of the row layout below |

### Result row

| Offset | Size | Field | Endianness | Notes |
| --- | ---: | --- | --- | --- |
| 0 | 16 | file hash | bytes | **ED2K File Hash** for the candidate file |
| 16 | 4 | client ID | little-endian integer | Reporting peer's **Client ID** |
| 20 | 2 | TCP port | little-endian integer | Reporting peer's TCP port |
| 22 | 4 | tag count | little-endian integer | Number of descriptor tags |
| 26 | varies | descriptor tags | per `tags.md` | File metadata and additional evidence |

The reporting peer is evidence attached to the search row. Core search may preserve it as metadata, but selecting a result still starts normal download orchestration with a fresh source lookup.

## Descriptor tags

Type these descriptor tags in the first implementation slice:

| Tag | Value kind | Projection |
| --- | --- | --- |
| `FT_FILENAME` (`0x01`) | string | Required for app-facing result; collected as advertised names |
| `FT_FILESIZE` (`0x02`) | u32 low bits | Required for app-facing result |
| `FT_FILETYPE` (`0x03`) | string | Optional result metadata |
| `FT_FILEFORMAT` (`0x04`) | string | Optional result metadata |
| `FT_SOURCES` (`0x15`) | u32 | Optional advisory availability |
| `FT_FILESIZE_HI` (`0x3A`) | u16 or u32 high bits | Optional large-file extension, combined with `FT_FILESIZE` |

`FT_FILESIZE_HI` follows the same high/low file-size family used by file descriptors such as `OP_OFFERFILES`. If present, combine the size as `(high << 32) | low`. If absent, the low 32-bit `FT_FILESIZE` is the full size.

Unknown well-formed descriptor tags are preserved as `extra_tags`. They are evidence for later typed projection, not decode failures.

## Acceptance rules

- Decode `OP_SEARCHRESULT` as a `u32` count followed by exactly that many rows.
- Rows missing a usable `FT_FILENAME` are unprojectable and skipped.
- Rows missing a usable `FT_FILESIZE` are unprojectable and skipped.
- Rows with malformed descriptor tags make that framed search-result payload unprojectable.
- Malformed framed `OP_SEARCHRESULT` payloads emit a visible non-terminal `SearchResultSkipped` event and keep the session alive.
- Malformed packet frames outside the `OP_SEARCHRESULT` payload remain strict frame errors.
- Preserve every unknown well-formed tag.
- Emit every well-formed search-result packet from `rmule-ed2k`; core decides whether it belongs to an active **Search Activity**.

## Sources

Cached:

- `docs/reference/emule-spec/emule_protocol_specification.pdf`, section 2.3: search flow; search results may be compressed; users choose results before source lookup.
- `docs/reference/emule-spec/emule_protocol_specification.pdf`, section 6.2.9: TCP search request and optional constraints.
- `docs/reference/emule-spec/emule_protocol_specification.pdf`, section 6.2.10: TCP search result row and descriptor tag layout.
- `docs/reference/notes/ed2k-server-protocol.md`: corrected TCP opcode table.
- `docs/reference/notes/tags.md`: descriptor tag encoding and unknown-tag preservation policy.

Link-only:

- aMule source, pinned commit `377ec8d9`: `src/include/protocol/ed2k/Client2Server/TCP.h:34,47` records `OP_SEARCHREQUEST` and `OP_SEARCHRESULT`: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/include/protocol/ed2k/Client2Server/TCP.h#L34-L47>
- aMule source, pinned commit `377ec8d9`: `src/SearchList.cpp:309-384` builds and sends connected-server eD2k search packets on the current server connection: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/SearchList.cpp#L309-L384>
- aMule source, pinned commit `377ec8d9`: `src/SearchList.cpp:677-792` builds the text phrase and first-slice filter constraints used by local eD2k search: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/SearchList.cpp#L677-L792>
- aMule source, pinned commit `377ec8d9`: `src/SearchList.cpp:541-548` reads TCP search-result count and rows before adding them to the search result list: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/SearchList.cpp#L541-L548>
- aMule source, pinned commit `377ec8d9`: `src/SearchList.cpp:587-608` dedupes by file hash plus file size while preserving stable result order: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/SearchList.cpp#L587-L608>
- aMule source, pinned commit `377ec8d9`: `src/ServerSocket.cpp:356-368` dispatches `OP_SEARCHRESULT` to the search-list consumer: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/ServerSocket.cpp#L356-L368>
- aMule source, pinned commit `377ec8d9`: `src/ServerSocket.cpp:526-537` treats bad search-result processing as non-terminal: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/ServerSocket.cpp#L526-L537>
- aMule source, pinned commit `377ec8d9`: `src/include/tags/FileTags.h:29-42` records the file descriptor tag IDs used by search results: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/include/tags/FileTags.h#L29-L42>

## Open questions

- Whether current public servers consistently send `FT_FILESIZE_HI` as `u16` or `u32` in search results. aMule's tag header labels it `uint32`; first rmule fixtures should accept the well-formed tag values supported by the shared tag codec.
- Whether any current servers send multiple filename tags for the same result row. rmule's primitive model supports aliases either way.
- Whether captured result rows carry additional media descriptor tags often enough to promote them beyond `extra_tags`.
