# Packet framing

**Status:** implemented; compression notes tightened after a live welcome-burst capture
**Scope:** the eD2k wire frame that wraps every server-protocol and peer-protocol packet.

A **Packet Frame** is the unit of byte-level protocol I/O. The frame is the same shape on the server protocol and the peer protocol; the protocol byte distinguishes which dialect is inside.

## Wire layout

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | protocol byte | `0xE3` = eDonkey, `0xC5` = eMule extension, `0xD4` = packed eD2k/eMule payload, `0xE4`/`0xE5` = Kad / packed Kad |
| 1 | 4 | length (little-endian u32) | counts the opcode byte plus payload bytes; does **not** include the protocol byte or the length field itself |
| 5 | 1 | opcode | which message this frame carries |
| 6 | length-1 | payload | opcode-specific bytes |

Total framed bytes on wire: `1 + 4 + length`.

## Compressed packet frames

`0xD4` is `OP_PACKEDPROT` in aMule's protocol constants. The frame still has the same length and opcode fields as a plain eD2k/eMule frame; only the opcode-specific payload bytes are zlib-compressed. After successful inflation aMule treats the unpacked packet as an eMule/eD2k protocol packet and dispatches the original opcode.

Compression is bidirectional in the eD2k server protocol:

- Servers may send compressed packets to clients. A live server capture proves this in a real welcome burst, and aMule's server socket explicitly unpacks `OP_PACKEDPROT` before server-packet dispatch.
- Clients may send compressed packets to servers for specific modeled commands. aMule compresses `OP_OFFERFILES` when the connected server advertises `SRV_TCPFLG_COMPRESSION`; keep-alive `OP_OFFERFILES` with zero files is normally left uncompressed because compression is not useful for that tiny payload.
- Peer-transfer compressed file parts (`OP_COMPRESSEDPART`, `OP_COMPRESSEDPART_I64`) are a separate message family, not the server-protocol **Compressed Packet Frame** slice.

For rmule this means the byte-level frame parser should recognize and preserve `0xD4` without silently inflating. The protocol-specific packet layer decides when to inflate inbound frames or emit outbound compressed frames so fixture round trips remain byte-exact and Kad / peer transfer do not inherit server-protocol assumptions.

There are two round-trip surfaces:

- Raw **Packet Frame** tests must preserve the original compressed bytes exactly, including protocol byte `0xD4`.
- Logical **Server Packet** decoding inflates inbound compressed payloads and returns the uncompressed opcode-specific packet. `ServerPacket::encode()` emits the logical uncompressed packet until outbound compression is explicitly modeled.

Inbound eD2k server compressed frames use a 250,000-byte decompressed-size ceiling. This mirrors aMule's server TCP unpack path and is a compatibility limit for this protocol surface, not a general zlib policy for peer transfer or future Kad work.

If inflation fails for one inbound eD2k server compressed frame, rmule should skip that frame and keep the session alive. aMule logs the failed unpack and returns success from the server socket packet handler rather than disconnecting. In rmule this surfaces as `Ed2kEvent::CompressedFrameSkipped { opcode, compressed_len, reason }`, a non-terminal event distinct from `UnknownServerPacket` and `Disconnected`. `reason` is a typed `CompressedFrameSkipReason` such as `InflateFailed` or `DecompressedSizeLimitExceeded { limit }`; it is not a raw zlib error string and not a `SessionError`. The event should not carry the compressed payload bytes; capture artifacts already preserve bytes for replay.

Capture `events.toml` records skipped compressed frames with summary fields:

```toml
[[event]]
type = "CompressedFrameSkipped"
opcode = 56
compressed_len = 123
reason = "InflateFailed"
```

For `DecompressedSizeLimitExceeded`, include `limit = 250000`. The raw bytes remain in `s2c.bin` / per-packet fixture files, not in `events.toml`.

The first captured compressed server frame (`welcome-burst-2026-05-17/04_undecoded_tail.bin`) has opcode `0x38` and inflates to an `OP_SERVERMESSAGE` payload. This is the first implementation oracle because the logical packet type is already modeled: after compressed-frame support lands, replaying the captured `s2c.bin` should emit a second `ServerMessageReceived` event instead of ending in `ProtocolViolation`.

Implementation note: `rmule-ed2k` may use `flate2` privately for zlib inflation. Keep it behind an internal helper so public API and event reasons remain independent of the chosen compression crate or backend.

## Length semantics

The frame length is one of the two recurring boundary traps:

- `length` counts opcode + payload bytes.
- `length` does **not** count the protocol byte or the length field.
- A frame with no payload still has `length = 1` (the opcode byte alone).

This is asserted as a domain rule in `/CONTEXT.md` ("A `Packet Frame` length counts the opcode byte plus payload bytes, while the protocol byte and length field are outside the count.") and is the boundary every decoder must respect.

## Decode error taxonomy

Per `docs/protocol/fixtures.md`, packet decoders must distinguish:

1. **Truncated frame prefix** — fewer than 6 bytes of input; cannot read protocol + length + opcode.
2. **Truncated payload** — `length` declares N bytes after the opcode, fewer than `N - 1` payload bytes are available.
3. **Invalid length** — `length == 0` (impossible because opcode is inside length).
4. **Unsupported protocol byte** — byte 0 is not a recognized protocol byte for this codec.
5. **Trailing bytes** — input has data left over after the declared frame ends and the caller asked for exact-frame decode.

These categories are explicit so callers can tell "need more bytes" apart from "stream is corrupt".

## Round-trip discipline

Packet fixtures are strict: `decode -> re-encode -> bytes` must equal the original raw bytes. This guards against silent normalization that could break compatibility with aMule on the wire.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_protocol.wikitext` — "All messages have a 6 bytes header with: protocol (1 byte: 0xE3 indicates edonkey while 0xC5 indicates emule); size (4 bytes: The message size not including this header); type (1 byte: A unique message ID)."
- `docs/reference/emule-spec/emule_protocol_specification.pdf` — section "Client server TCP Communication" describes the header layout; sections on search results, file offers, found sources, and compressed file parts document where compression appears. Local-only PDF; cite by section and page.
- `docs/reference/rhash/ed2k.c` — not protocol-framing material; included only for hash work. Do not import framing patterns from this file.

Link-only:

- aMule source (GPLv2, no in-tree copy): `src/include/protocol/Protocols.h:32-38` defines `OP_PACKEDPROT = 0xD4`; `src/Packet.cpp:247-306` shows zlib pack/unpack behavior; `src/ServerSocket.cpp:592-608` unpacks inbound server TCP packets before dispatch; `src/SharedFileList.cpp:740-854` compresses outbound `OP_OFFERFILES` when the server advertises compression. Read upstream by pinned commit SHA from `docs/protocol/source-map.md`. Behavioral findings rewritten here; do not paste source.

## Open questions

- Which outbound eD2k server commands should rmule ever compress beyond future `OP_OFFERFILES`? Defer until those commands are modeled.
