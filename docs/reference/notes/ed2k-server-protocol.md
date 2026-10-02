# ED2K server protocol

**Status:** next
**Scope:** the post-login server-protocol surface — search, source lookup, server-list exchange, and server status — beyond what `ed2k-login.md` already covers.

This note is the research index for the live server work that followed the offline login work. Depth is sources + observed opcodes + open questions; wire tables are filled in as the implementing work produces fixtures.

## Known opcodes (server → client and client → server)

| Opcode | Direction | Name | Topic |
| --- | --- | --- | --- |
| `0x05` | S→C | `OP_REJECT` | server rejects last command (covered in welcome-packets notes) |
| `0x14` | C→S | `OP_GETSERVERLIST` | server-list exchange (covered in welcome-packets notes) |
| `0x15` | C→S | `OP_OFFERFILES` | announce shared files |
| `0x16` | C→S | `OP_SEARCHREQUEST` | TCP search |
| `0x19` | C→S | `OP_GETSOURCES` | source lookup |
| `0x1C` | C→S | `OP_CALLBACKREQUEST` | callback to a low-ID peer |
| `0x32` | S→C | `OP_SERVERLIST` | server-list payload (covered in welcome-packets notes) |
| `0x33` | S→C | `OP_SEARCHRESULT` | TCP search reply |
| `0x34` | S→C | `OP_SERVERSTATUS` | reported user / file counts (covered in welcome-packets notes) |
| `0x38` | S→C | `OP_SERVERMESSAGE` | server push text (covered in welcome-packets notes) |
| `0x40` | S→C | `OP_IDCHANGE` | covered in login notes |
| `0x41` | S→C | `OP_SERVERIDENT` | server name, description, capability tags (covered in welcome-packets notes) |
| `0x42` | S→C | `OP_FOUNDSOURCES` | source lookup reply |

Opcodes are little-endian single bytes; protocol byte is `0xE3` for plain eDonkey messages and `0xC5` for eMule extensions. Authoritative values come from `src/include/protocol/ed2k/Client2Server/TCP.h` at pinned commit `377ec8d9` (see `docs/protocol/source-map.md`). Earlier revisions of this table swapped `OP_SERVERSTATUS` and `OP_SERVERIDENT` with values from the eMule PDF spec (which carries internal inconsistencies on those two type bytes); the table above is the corrected one. UDP-side keep-alive/status opcodes live on a separate dispatch table inside `ServerUDPSocket.cpp` and are not enumerated here.

## Topics that fan out from here

- **Search** — query language is a mix of full-text plus typed filters; replies are tag-bearing file descriptors. Detailed first-slice TCP search notes live in `ed2k-search.md`.
- **Source lookup** — given a file hash, the server returns **Peer Sources** (`Client ID` plus TCP port). Source lookup feeds peer transfer. Detailed wire notes live in `ed2k-source-lookup.md`.
- **Server list exchange** — `server.met` is the on-disk binary form, also exchanged over the wire as a payload.
- **Server status / identity** — server-pushed metadata that populates the `Server Identity` distinct from the `Server Endpoint`.
- **Runtime** — connection lifecycle, timeouts, welcome-burst arrival ordering, and disconnect causes. Broken out into `ed2k-runtime.md` and consumed by the sans-I/O **Ed2k Session** and the **Driver** in `rmule-ed2k-net`.

Each topic gets its own note when its implementing work begins; this index points future research at the right cached sources. The welcome-packet topic (`OP_REJECT`, `OP_SERVERMESSAGE`, `OP_SERVERSTATUS`, `OP_SERVERLIST`, `OP_SERVERIDENT`, `OP_GETSERVERLIST`) is broken out into `ed2k-welcome-packets.md` with full wire tables and source citations.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_protocol.wikitext` — primary medium-confidence walkthrough; admits the page may have errors so verify against source and fixtures.
- `docs/reference/emule-spec/emule_protocol_specification.pdf` — sections 2 ("Client server TCP Communication") and 3 ("Client server UDP Communication"). Local-only PDF.

Link-only:

- aMule source (GPLv2): `src/ServerSocketHandler.cpp`, `src/ServerList.cpp`, `src/ServerConnect.cpp`, `src/SearchList.cpp`. Pinned commit SHA in `docs/protocol/source-map.md`.
- eMule project corruption-handling help (proprietary site): covers some of the same semantics.

## Open questions

- Server-protocol search query encoding: how do the various filter operators (`AND`, `NOT`, `>=`, codec match) wire-format? Defer until a captured search fixture is available.
- Server-list payload format on the wire vs the on-disk `server.met` form: are they the same byte layout, or is there a framing difference?
- UDP server-status keep-alive: which opcodes does aMule emit and accept on the UDP path, and are they identical to their TCP counterparts or distinct?
