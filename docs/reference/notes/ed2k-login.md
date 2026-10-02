# ED2K login

**Status:** implemented
**Scope:** the eD2k server login request (client → server) and the minimal set of server responses the offline login work chose to model.

The login request is the first packet a client sends after opening a TCP connection to a server. It declares the client's `UserHash`, current `ClientID` (zero on first connect), TCP listening port, and a small bag of tags describing the client.

## Login request wire layout

Wrapped in a standard `Packet Frame` (see `packet-framing.md`):

| Offset (inside payload) | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 16 | UserHash | per `user-hash.md` |
| 16 | 4 | ClientID | little-endian u32; `0x00000000` on first connect |
| 20 | 2 | TCP port | little-endian u16; the port the client is listening on for incoming peer connections (default `4662` = `0x36 0x12`) |
| 22 | 4 | TagCount | little-endian u32; number of tags that follow; despite the name this is **not** itself a tag |
| 26 | varies | TagCount tags | each tag per `tags.md` |

Opcode for login: `OP_LOGINREQUEST` = `0x01`. Protocol byte: `0xE3` (eDonkey).

## Expected login tags (request)

The login request carries a small set of well-known tags. The minimum set rmule emits for synthetic fixtures (per `docs/protocol/fixtures.md`):

| Tag name (numeric) | Kind | Meaning |
| --- | --- | --- |
| `0x01` | String | client nickname |
| `0x11` | U32 | protocol version (eMule-family observed value: `60`) |
| `0x0F` | U32 | TCP port (redundant with header field, but historically sent) |
| `0x20` | U32 | server flags / compression and capability bitmask |
| `0xFB` | U32 | extended client metadata (purpose not fully documented; preserved verbatim per ADR-0018) |

aMule-generated login requests in the wild include additional well-known tags (client version, UDP port, etc.). rmule preserves any **well-formed unknown tag**; only malformed bytes reject the request. This protects forward-compatibility.

## Login responses (server → client) — first scope

The offline login work modelled only response packets with strong fixture evidence. Initial in-scope responses (per ADR-0018):

- **OP_IDCHANGE** (`0x40`): server assigns or refreshes a `ClientID`. The payload is
  progressive (aMule `ServerSocket.cpp` `case OP_IDCHANGE`, `size >=` ladder), all
  fields `u32 LE`, and rmule models it fully (ADR-0047):

  | offset | field | present when |
  |---|---|---|
  | 0 | `client_id` | always (size ≥ 4) |
  | 4 | `tcp_flags` | size ≥ 8 (a bare 4-byte reply zeroes aMule's stored flags: `SetTCPFlags(0)`) |
  | 8 | `standard_tcp_port` | size ≥ 12 ("aux port login" — aMule `SetPort(ConnPort)` and remembers the dialed port in the aux list) |
  | 12 | `public_ip` + `obfuscation_tcp_port` | size ≥ 20, the pair lands together (a 13–19-byte payload yields neither) |

  Bytes past offset 20 (and the 12..20 residue of a between-thresholds payload) are
  preserved verbatim (ADR-0018). Consume rules (`ServerAssignedFacts` projection):
  a LowID-valued reported IP is discarded (`IsLowID → 0`, `wxFAIL` debug-only); a
  zero obfuscation port is "not offered" (`SetObfuscationPortTCP` gated on `!= 0`);
  ports narrow to `u16` as aMule's setters do. aMule applies the reported IP
  globally only while LowID (`IsLowID(new_id) && reported != 0 → SetPublicIP`) —
  that gate belongs to the consumers (callback / Kad self-check / buddy / crypt-ping).
  Emit `Ed2kEvent::LoginAccepted { client_id, tcp_flags, facts }`.

  **Re-assignment, not violation**: aMule re-runs the whole handler on every
  `OP_IDCHANGE` (mid-session LowID↔HighID transitions re-assign; `SetClientID`
  unconditional, connected-transition only when not already connected). rmule
  re-projects grants + facts and re-emits `LoginAccepted`; the former
  `DoubleIdChange` protocol violation is removed. A **zero id** is aMule's
  smart-id bookkeeping case: flags/ports still apply, no id assignment, no
  connected transition — rmule applies facts silently, no event. Not transplanted:
  the SmartID LowID retry policy (`thePrefs::GetSmartIdCheck`, a connectivity policy
  outside this decoder) and `ResetLocalServerRequests` (rmule's discovery re-asks per sweep,
  ADR-0051).

  **Capture evidence**: `tests/fixtures/login/id_change_lugdunum_extended.bin` — a
  real 20-byte extended reply (id 936 LowID, flags `0x05DD`, standard port 936,
  reported IP `171.25.158.106`, obfuscation port 4661) — is the ADR-0047
  capture-tier golden vector; the capture writer records the projected facts in
  `events.toml` for future runs.
- **OP_SERVERMESSAGE** (`0x38`): server pushes a text message (MOTD, login notice). Payload: u16 length + UTF-8 string. Emit `eD2k Event::ServerMessage`.

Server TCP flags are eD2k server-session capability bits, not shared protocol
primitives. `rmule-ed2k` models them as a transparent `ServerTcpFlags` newtype
(`bits()` preserves unknown bits) plus the typed `ServerGrants` projection the
session holds from `OP_IDCHANGE` on (ADR-0047) — consumers read their
own grant field, never raw bits.

### `SRV_TCPFLG_*` (aMule `src/include/protocol/ed2k/Client2Server/TCP.h`) — full set + consumers

| bit | flag | aMule consumer (pinned) |
|---|---|---|
| `0x00000001` | `COMPRESSION` | packed `0xD4` frames toward the server + the compressed-capable offer-id magic (`KnownFile.cpp` `CreateOfferedFilePacket`: complete → id `0xFBFBFBFB` port `0xFBFB`, incomplete → `0xFCFCFCFC`/`0xFCFC`); rmule consumer = packed-frames slice |
| `0x00000008` | `NEWTAGS` | compact new-eD2k tag form in offers (`KnownFile.cpp`: `new_ed2k → WriteNewEd2kTag`) |
| `0x00000010` | `UNICODE` | UTF-8 strings toward the server (`Server.h` `GetUnicodeSupport()` → `utf8strRaw` in `CreateOfferedFilePacket`) |
| `0x00000040` | `RELATEDSEARCH` | related-search queries (`Server.h` `GetRelatedSearchSupport()`); no rmule feature — modelled for parity completeness |
| `0x00000080` | `TYPETAGINTEGER` | integer `FT_FILETYPE` tag in offers (`KnownFile.cpp`) |
| `0x00000100` | `LARGEFILES` | 64-bit sizes in offers/get-sources (`Server.h` `SupportsLargeFilesTCP()`); rmule's session large-file command gates |
| `0x00000400` | `TCPOBFUSCATION` | server-crypt dial (`Server.h` `SupportsObfuscationTCP()`: non-zero obfuscation TCP port **and** (UDP-flag `0x400` **or** this bit); dial gate `ServerSocket.cpp` adds the crypt pref) — feeds ADR-0042 through the port the IDCHANGE extension supplies |

Out of that first scope (per ADR-0018):

- Search results.
- Source lookup responses.
- Server status / version packets (modeled when fixture-backed).
- `server.met` server-list exchange.

## Decode error mapping

Login decoder rejects:

- Wrong opcode for login: not `0x01`.
- Truncated body: cannot read the 26 fixed bytes or any declared tag.
- Tag count mismatch: declared `TagCount` larger than tags actually present.
- Malformed tag bytes: kind/name/length cannot be parsed.
- Trailing bytes after the declared `TagCount` tags consumed.

Unknown well-formed tags are **preserved**, not rejected (see `tags.md` and ADR-0018).

## Service events (draft)

The offline login work introduced draft `eD2k Event` shapes validated by these response models without opening sockets:

- `eD2k Event::Connecting { server_endpoint }`
- `eD2k Event::LoginAccepted { client_id, server_message }`
- `eD2k Event::LoginRejected { reason }` — only when a captured rejection fixture is available
- `eD2k Event::Disconnected { reason }`

These stayed a type-level draft until the live server session wired a socket.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_protocol.wikitext` lines 31-74 — the worked login example (HEADER + USERHASH + CLIENTID + TCPPORT + TAGCOUNT + tags) and the example tag set (nickname, protocol version, compression, unknown `0xFB`).
- `docs/reference/amule-wiki/userhash.wikitext` — the `UserHash` field semantics.
- `docs/reference/emule-spec/emule_protocol_specification.pdf` section "Connection startup message exchange" describes login plus initial server messages. Local-only PDF.

Link-only:

- aMule source (GPLv2): `src/ListenSocket.cpp` and `src/ServerSocketHandler.cpp` are the behavioral oracles for login handling. Pinned commit SHA in `docs/protocol/source-map.md`.

## Open questions

- Confirm the exact set of tags an aMule release in 2026 emits in its login request against a fresh loopback capture. The offline login fixtures use a synthetic baseline; an aMule-generated baseline (per `docs/protocol/amule-login-fixtures.md`) is the authority once captured.
- Decide the offline login coverage for `OP_GETSERVERLIST` (`0x14`) and `OP_SERVERLIST` (`0x32`): these are commonly observed right after login but ADR-0018 keeps them out of the first login scope. Notes here mention them only for context.
- Capture or synthesize an `OP_REJECT` (`0x05`) fixture before adding `Event::LoginRejected` modelling.
