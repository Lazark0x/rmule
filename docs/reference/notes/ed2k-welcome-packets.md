# ED2K welcome packets

**Status:** implemented
**Scope:** the post-login server-protocol exchange that delivers identity, status, and server-list metadata to a freshly connected client, plus the single client-initiated request that triggers the list refresh.

This note tightens the wire layout, accept/reject conditions, and tag taxonomy for every packet rmule needs to model for the server's welcome burst. It supersedes the opcode table in `ed2k-server-protocol.md` for the six packets listed below; the broader server-protocol index keeps its open-questions on search and source lookup, which stay deferred.

Frame layer per `packet-framing.md`. Every wire offset below is relative to the **payload after opcode** (i.e. after the 6-byte header `0xE3 | u32 size | u8 opcode`); `size` in citations refers to that post-opcode payload length, matching aMule's `ProcessPacket(packet, size, opcode)` convention.

## Packet roster

| Opcode | Direction | Name | Section |
| --- | --- | --- | --- |
| `0x05` | S→C | `OP_REJECT` | [Reject](#op_reject-0x05) |
| `0x14` | C→S | `OP_GETSERVERLIST` | [GetServerList](#op_getserverlist-0x14) |
| `0x32` | S→C | `OP_SERVERLIST` | [ServerList](#op_serverlist-0x32) |
| `0x34` | S→C | `OP_SERVERSTATUS` | [ServerStatus](#op_serverstatus-0x34) |
| `0x35` | S→C | `OP_CALLBACKREQUESTED` | [CallbackRequested](#op_callbackrequested-0x35) — callback notification: server tells us a peer is asking to be called back |
| `0x38` | S→C | `OP_SERVERMESSAGE` | [ServerMessage](#op_servermessage-0x38) |
| `0x41` | S→C | `OP_SERVERIDENT` | [ServerIdent](#op_serverident-0x41) |

The values above come from `src/include/protocol/ed2k/Client2Server/TCP.h` lines 31-58 at pinned commit `377ec8d9`. They correct two errors carried in earlier rmule notes that swapped `OP_SERVERSTATUS` (`0x34`, not `0x41`) and `OP_SERVERIDENT` (`0x41`, not `0xA2`).

## OP_REJECT (`0x05`)

**Direction:** S→C. Server emits this when it discards the client's last command (most often a login that violated server policy — banned hash, capacity limit, version too old).

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| — | 0 | (no payload) | — | header.size = `1` (opcode byte only); total frame on wire = `6` bytes |

### Accept / reject conditions

- Accept any frame with opcode `0x05` and zero payload bytes.
- Reject if `size != 1` at the frame layer (i.e. any trailing bytes after the opcode).

### Tag list expectations

None. There is no tag area.

### Source citations

- aMule `src/ServerSocket.cpp` lines 518-522 — handler does not read a payload; only logs the rejection.
- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 32 — `OP_REJECT 0x05`.
- eMule PDF spec section 6.2.16 "Message rejected" (p40) — "The size of the message is 6 bytes. The receiving client logs the message and discards it."

### Open research gaps

- The accepted design carries an `Ed2kText` reason on `LoginResponse::Reject`. Neither cited source describes such a reason field; aMule's handler discards the payload unconditionally. Real-world `OP_REJECT` packets observed against modern lugdunum servers should be captured before introducing a reason field, otherwise rmule should model `Reject` as a unit type (no payload). **Action:** settle this before authoring the fixtures.

## OP_GETSERVERLIST (`0x14`)

**Direction:** C→S. Client asks the connected server to push its known peer servers (extends the client's `server.met`).

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| — | 0 | (no payload) | — | header.size = `1`; total frame on wire = `6` bytes |

### Accept / reject conditions

- Accept any frame with opcode `0x14` and zero payload bytes.
- Reject if `size != 1`.

### Tag list expectations

None.

### Source citations

- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 33 — `OP_GETSERVERLIST 0x14`.
- eMule PDF spec section 6.2.5 "Get list of servers" (p34) — "The message size is 6 bytes." (NB: the PDF mis-labels the type field's comment as `OP_SERVERSTATUS opcode`; the type byte `0x14` and aMule constant agree.)
- aMule wiki `ed2k_protocol.wikitext` does not cover this opcode directly; behavior inferred from the spec and confirmed against the aMule constant.

### Open research gaps

- None for this packet. The empty-payload contract is unambiguous in both cited sources.

## OP_SERVERLIST (`0x32`)

**Direction:** S→C. Server pushes a list of peer servers in response to `OP_GETSERVERLIST` (or proactively after login on some servers).

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | `count` | — | unsigned 8-bit count of entries that follow |
| 1 | `count * 6` | server entries | — | repeated `count` times; one entry below |

Each server entry (6 bytes):

| Offset (in entry) | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 4 | IPv4 address | little-endian u32 | byte 0 is the leftmost dotted octet; aMule renders via `Uint32toStringIP(ip)` from a LE-read u32, so wire bytes `C0 A8 00 01` decode to `192.168.0.1` |
| 4 | 2 | TCP port | little-endian u16 | server's listening port |

### Accept / reject conditions

- Accept when `size >= 1 + count * 6` and the entry block consumes exactly `count * 6` bytes.
- aMule's behavior (line 447-449) is to **silently truncate** to zero entries when `count * 6 + 1 > size`, rather than reject. rmule's stricter posture (per `packet-framing.md`'s round-trip discipline) is to **reject** the frame; document the divergence in the decoder's error mapping. Tighter than aMule is acceptable here because we never produce these packets, only consume them, and a corrupt count is a wire violation.
- Reject if trailing bytes remain after the declared count is consumed.

### Tag list expectations

None. Each entry is a fixed 6-byte tuple.

### Source citations

- aMule `src/ServerSocket.cpp` lines 442-472 — `count = ReadUInt8()`, then `count` × (`ReadUInt32()` IP, `ReadUInt16()` port).
- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 47 — `OP_SERVERLIST 0x32`.
- eMule PDF spec section 6.2.7 "List of servers" (p35) — entry size 6 bytes; "4 bytes IP address and then 2 byte TCP port".

### Open research gaps

- None for the wire shape.

## OP_SERVERSTATUS (`0x34`)

**Direction:** S→C. Server reports current user count and indexed file count. Typically pushed shortly after login and refreshed periodically.

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 4 | `user_count` | little-endian u32 | currently connected clients |
| 4 | 4 | `file_count` | little-endian u32 | files the server indexes |

### Accept / reject conditions

- Accept when `size == 8`.
- aMule (line 387) accepts any `size >= 8` and ignores trailing bytes. The handler carries a `FIXME` comment ("some statuspackets have a different size — why? structure?"), which is the strongest available evidence that **some servers emit additional trailing bytes**. rmule's posture: reject trailing bytes for strict round-trip; if a fixture surfaces with extras, model the extension explicitly rather than silently dropping bytes.
- Reject if `size < 8`.

### Tag list expectations

None. This packet predates the tag-bag pattern.

### Source citations

- aMule `src/ServerSocket.cpp` lines 384-399 — reads two `uint32` fields; `FIXME` note about variable sizes.
- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 49 — `OP_SERVERSTATUS 0x34`.
- eMule PDF spec section 6.2.6 "Server status" (p34) — confirms two `u32` counts; lists message size as 14 bytes (header inclusive).

### Open research gaps

- Capture a `OP_SERVERSTATUS` packet from a current lugdunum server to confirm whether the "different size" the aMule FIXME notes is still observed. If present, identify the extra fields before deciding whether rmule's strict 8-byte rule needs to relax into a tag-bag tail or a typed extension struct.

## OP_CALLBACKREQUESTED (`0x35`)

**Direction:** S→C. Server emits this when a High ID peer asks the server to relay a callback to us (we are Low ID and cannot accept inbound peer TCP); the receiving Low ID client is expected to dial out to the carried `PeerEndpoint`. Documented here even though it is not part of the welcome burst — same opcode table family, same server-protocol direction.

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 4 | IPv4 address | little-endian u32 | dialable peer IP; LE u32 read identical to other eD2k IPv4 fields |
| 4 | 2 | TCP port | little-endian u16 | dialable peer port |
| 6 | 1 | (optional) `crypt_options` | u8 | present only when `size >= 23`; decoded into `PeerCallbackCrypt`, the dial-back's crypt stance (ADR-0049) |
| 7 | 16 | (optional) `user_hash` | byte-order opaque | present only when `size >= 23`; the key an obfuscated dial-back is keyed toward |

### Accept / reject conditions

- Accept when `size >= 6` and the first 6 bytes form an IPv4 + TCP port pair; the optional 17-byte crypt extension at `size >= 23` is decoded, and bytes between 6 and 23 are ignored, as aMule reads exactly its fields.
- Reject if `size < 6` — aMule's handler short-circuits the same way (`size >= 6` guard).

### Tag list expectations

None. Fixed-width payload.

### Source citations

- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` — `OP_CALLBACKREQUESTED 0x35` at pinned commit `377ec8d9`.
- aMule `src/ServerSocket.cpp` lines 365-395 — `size >= 6` guard, `ReadUInt32()` IP + `ReadUInt16()` port; extended `size >= 23` form reads `ReadUInt8()` crypt options and `ReadHash()` user hash for AICH SUI.

### Open research gaps

- The extended 23-byte form (`crypt_options` + `user_hash`) belongs to the secure-identification / obfuscation capability set and is deferred until those slices land; until then the trailing bytes are tolerated at decode time but not exposed.

## OP_SERVERMESSAGE (`0x38`)

**Direction:** S→C. Server pushes a free-form text payload — MOTD, login notice, error/warning lines, embedded `[emDynIP: ...]` directives, version banner.

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 2 | `text_length` | little-endian u16 | declared count of text bytes that follow |
| 2 | `text_length` | text bytes | — | raw bytes; **not guaranteed to be UTF-8** (per ADR-0019, model as `Ed2kText`); aMule then splits on `\r` / `\n` |

### Accept / reject conditions

- Accept when `size >= 3` (the minimum that holds a 2-byte length plus one text byte) **and** `text_length == size - 2`.
- aMule (line 148) only enforces `size >= 3` and reads `size - 2` bytes regardless of the declared `text_length`. rmule should enforce the equality and reject the mismatch — that is the byte-for-byte round-trip rule. Servers in the wild appear to set `text_length` equal to the trailing byte count, so the stricter rule should hold in practice.
- Reject if `size < 3` or if `text_length + 2 != size`.

### Tag list expectations

None. The text body is opaque.

### Application-layer parsing (informational, not wire)

aMule splits the text on `\r\n` tokens and recognizes these line prefixes for special handling. They are application semantics, not wire format — rmule preserves the raw `Ed2kText` and surfaces the line set to the service layer:

- `server version <ver>` — version banner.
- `ERROR <msg>` — server-side error notice.
- `WARNING <msg>` — server-side warning notice.
- `[emDynIP: <host>]` — server's preferred dynamic-IP address (embeddable mid-message).

### Source citations

- aMule `src/ServerSocket.cpp` lines 144-227 — `size >= 3` guard, `memcpy(buffer, &packet[2], size-2)`; tokenizes on `\r\n`; line-prefix dispatch for version / ERROR / WARNING / `[emDynIP: ...]`.
- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 52 — `OP_SERVERMESSAGE 0x38`.
- eMule PDF spec section 6.2.2 "Server message" (p31) — "Size 2 bytes — The number of bytes in the remainder of the message"; lists `version`, `error`, `warning`, `emDynIP` as special messages.
- aMule wiki `ed2k_protocol.wikitext` — mentions `OP_SERVERMESSAGE` as part of the post-login flow without giving exact byte layout.

### Open research gaps

- Confirm whether the 16.40 lugdunum-era servers ever send `text_length != size - 2`. If so, rmule's strict equality check needs to relax to "trust `text_length`, ignore trailing bytes" with a documented deviation.

## OP_SERVERIDENT (`0x41`)

**Direction:** S→C. Server publishes its own identity: a 16-byte GUID hash, the address it advertises (often the server's own IP and TCP port, sometimes used for proxy/NAT introspection), and a tag list carrying name/description and assorted capability metadata.

### Wire layout

| Offset | Size | Field | Endianness | Notes |
| --- | --- | --- | --- | --- |
| 0 | 16 | `server_hash` | byte-order opaque | MD4-shaped 128-bit GUID; modeled as `ServerHash` per ADR-0017; aMule treats `0x2A2A2A2A` at the hash start as the "eFarm" sentinel |
| 16 | 4 | advertised IPv4 | little-endian u32 | server's own IP (aMule reads and discards) |
| 20 | 2 | advertised TCP port | little-endian u16 | server's own port (aMule reads and discards) |
| 22 | 4 | `tag_count` | little-endian u32 | number of tags that follow |
| 26 | varies | `tag_count` tags | — | each tag per `tags.md`; minimum byte budget per tag is checked by aMule via the `size >= 38` guard (16 + 4 + 2 + 4 + 12 = 38) |

### Accept / reject conditions

- Accept when `size >= 38` and the tag block consumes exactly `tag_count` well-formed tags with no trailing bytes.
- aMule (line 405) treats `size < 38` as "Unknown server info received! - too short" and **silently breaks out** without rejecting the connection. rmule's stricter posture rejects the frame at the decoder boundary.
- Reject malformed tags per `tags.md`. Reject if declared `tag_count` does not match consumable tags. Reject trailing bytes.

### Tag list expectations

Tag IDs are sourced from `src/include/tags/ServerTags.h` lines 31-52 at pinned commit `377ec8d9`. Two are typed by aMule's `OP_SERVERIDENT` handler (`src/ServerSocket.cpp` lines 429-433); the rest are documented in the enum but ignored on this code path. rmule's policy (ADR-0018) is to **type the two aMule consumes** and **preserve every other well-formed tag** in `extra_tags`.

| Tag ID | Constant | Wire kind | rmule treatment |
| --- | --- | --- | --- |
| `0x01` | `ST_SERVERNAME` | String | Typed: maps to `ServerIdentity::name: Ed2kText` |
| `0x0B` | `ST_DESCRIPTION` | String | Typed: maps to `ServerIdentity::description: Ed2kText` |
| `0x0C` | `ST_PING` | u32 | Preserved as unknown (aMule ignores in this packet) |
| `0x0D` | `ST_FAIL` | u32 | Preserved as unknown |
| `0x0E` | `ST_PREFERENCE` | u32 | Preserved as unknown |
| `0x85` | `ST_DYNIP` | String | Preserved as unknown |
| `0x87` | `ST_MAXUSERS` | u32 | Preserved as unknown |
| `0x88` | `ST_SOFTFILES` | u32 | Preserved as unknown |
| `0x89` | `ST_HARDFILES` | u32 | Preserved as unknown |
| `0x90` | `ST_LASTPING` | u32 | Preserved as unknown |
| `0x91` | `ST_VERSION` | String | Preserved as unknown (candidate for promotion if a fixture confirms presence) |
| `0x92` | `ST_UDPFLAGS` | u32 | Preserved as unknown |
| `0x93` | `ST_AUXPORTSLIST` | String | Preserved as unknown |
| `0x94` | `ST_LOWIDUSERS` | u32 | Preserved as unknown |
| `0x95` | `ST_UDPKEY` | u32 | Preserved as unknown |
| `0x96` | `ST_UDPKEYIP` | u32 | Preserved as unknown |
| `0x97` | `ST_TCPPORTOBFUSCATION` | u16 | Preserved as unknown |
| `0x98` | `ST_UDPPORTOBFUSCATION` | u16 | Preserved as unknown |

Any tag whose ID is not in `ServerTags.h` is still preserved per ADR-0018 — rmule does not gate on aMule's enum membership.

### Source citations

- aMule `src/ServerSocket.cpp` lines 401-440 — `size >= 38` guard, 16-byte hash + u32 IP (discarded) + u16 port (discarded) + u32 tag count + tag loop; only `ST_SERVERNAME` and `ST_DESCRIPTION` are dispatched.
- aMule `src/include/protocol/ed2k/Client2Server/TCP.h` line 58 — `OP_SERVERIDENT 0x41`.
- aMule `src/include/tags/ServerTags.h` lines 31-52 — full server-tag enum.
- eMule PDF spec section 6.2.8 "Server identification" (p35) — hash (16) + IP (4) + port (`"4 bytes"` — spec error: aMule uses 2 bytes, matching every other port field in the protocol; trust aMule) + tag count + Server-Name tag (`0x01`) + Server-Description tag (`0xB`).

### Open research gaps

- The eMule PDF spec lists the advertised port as a 4-byte field, but aMule's handler reads a 2-byte `uint16`. aMule is authoritative here; the spec is wrong. Note this in the decoder comments so a future reader trusting the spec catches the discrepancy.
- `ST_VERSION` (`0x91`) is observed on real servers but not in aMule's `OP_SERVERIDENT` typed-tag list. Promote to a typed field on `ServerIdentity::version` once a captured fixture confirms presence; until then it lives in `extra_tags`.
- The hash-prefix sentinel `0x2A2A2A2A` ("eFarm" marker) is application metadata, not wire shape. rmule's decoder does not interpret it; it merely preserves the 16 raw bytes inside `ServerHash`.

## Cross-packet invariants

- Every welcome-packet payload integer is little-endian (consistent with the rest of the eD2k protocol, per `packet-framing.md`).
- Server-sourced text fields (`OP_SERVERMESSAGE` body, `ST_SERVERNAME`, `ST_DESCRIPTION`) are bytes-not-strings: model as `Ed2kText` and never reject on non-UTF-8 input (ADR-0019).
- Unknown well-formed packets at frame level are preserved per ADR-0018 (umbrella `ServerPacket::Unknown`). Unknown well-formed tags inside `OP_SERVERIDENT` are preserved per ADR-0018.

## Sources

Cached:

- `docs/reference/emule-spec/emule_protocol_specification.pdf` — sections 6.1 (general encoding), 6.2.2 (server message), 6.2.5 (get list of servers), 6.2.6 (server status), 6.2.7 (list of servers), 6.2.8 (server identification), 6.2.16 (message rejected). Local-only PDF; cite by section.
- `docs/reference/amule-wiki/ed2k_protocol.wikitext` — login walkthrough and tag worked example (lines 31-74); does not deepen the welcome-packet coverage itself, used here for tag-form orientation.

Link-only (GPLv2, no in-tree copy; pinned commit SHA in `docs/protocol/source-map.md`):

- `src/ServerSocket.cpp` — packet dispatch for every welcome opcode, line numbers cited per section above.
- `src/include/protocol/ed2k/Client2Server/TCP.h` — `OP_*` opcode constants for the welcome packets.
- `src/include/tags/ServerTags.h` — `ST_*` server-tag enum.

## Forward references

The wire definitions above fed the welcome-packet implementation. The "Open research gaps" subsections call out the two places where its accepted design may need revision (`OP_REJECT` reason field; potential `ST_VERSION` promotion).
