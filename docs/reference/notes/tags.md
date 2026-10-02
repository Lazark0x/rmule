# ED2K tags

**Status:** implemented
**Scope:** the TLV-like attribute carrier used across server-protocol and peer-protocol packets.

eD2k tags are optional named values attached to messages (login, file announce, search reply, etc.). Each tag is a (type, name, value) triple, with two name-encoding styles and several value kinds.

## Wire layout (per tag)

| Field | Size | Notes |
| --- | --- | --- |
| type | 1 byte | low bits = value kind; high bit chooses name encoding |
| name | variable | either length-prefixed string or one-byte numeric |
| value | variable | depends on value kind |

### Name encoding: two styles

The single-byte tag type splits the name encoding:

- **Length-prefixed name** (legacy / long form): name is a `u16` length followed by that many bytes of name. Used when the tag name is a string (e.g. user-set metadata key) or a one-byte numeric name padded into the long form.
- **Compact numeric name** (short form): name is a single byte; no length prefix. Used when both ends agree the tag has a well-known numeric ID.

The high bit of the type byte selects compact form. The same numeric name can appear in either form depending on how the encoder built it. Round-trip fidelity requires preserving the encoding the original packet used.

This is the second recurring boundary trap (after frame length). aMule-generated login requests historically use the **length-prefixed** form even for one-byte numeric names; newly built rmule login requests should match until a captured aMule packet proves otherwise (locked in `docs/protocol/fixtures.md`).

### Value kinds

Per `docs/reference/amule-wiki/ed2k_protocol.wikitext` and the Kulbak/Bickson PDF (section "Tags"), the early-scope value kinds are:

| Kind code | Name | Wire shape |
| --- | --- | --- |
| `0x02` | String | u16 length + bytes |
| `0x03` | U32 | 4 bytes little-endian |
| `0x04` | Float | 4 bytes IEEE-754 |
| `0x05` | Bool | 1 byte (rare) |
| `0x06` | Hash | 16 bytes (used for AICH / file ident) |
| `0x07` | String list | varies |
| `0x08` | U16 | 2 bytes |
| `0x09` | U8 | 1 byte |
| `0x0A` | BSOB | binary string of bytes, length-prefixed |
| `0x0B` | U64 | 8 bytes |

The first implementation covered String + U32 only (per ADR-0018 and `docs/protocol/fixtures.md`). The offline login work added whatever the login request needs. Other kinds waited for the message types that use them.

## Round-trip discipline

A decoded tag must re-encode to byte-exact original bytes, including:

- the name-encoding style used (compact vs length-prefixed).
- the declared length bytes (no normalization to "minimum length").
- the byte order of the value.

If a tag fails to round-trip, the fixture is wrong or the decoder is wrong; never normalize silently.

## Unknown tags

Unknown well-formed tags are **preserved**, not rejected, for login requests (ADR-0018 wording: "model only the response packets that have enough fixture evidence; leave weak cases as open tasks"). Decoders separate "unknown well-formed tag" from "malformed bytes": preserve the first, reject the second.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_protocol.wikitext` lines 14-30 (tag layout) and 54-74 (worked example of login tags).
- `docs/reference/emule-spec/emule_protocol_specification.pdf` section on tags. Local-only PDF; cite by section.

Link-only:

- aMule source (GPLv2, no in-tree copy): `src/Tag.cpp` is the implementation reference for value kinds and name encoding. Pinned commit SHA in `docs/protocol/source-map.md`.

## Open questions

- Confirm aMule's exact preference between compact vs length-prefixed names for each numeric login tag against a captured request. The current rmule decision (length-prefixed for newly built tags) is provisional.
- Behavior of `BSOB` value kind for AICH tags was deferred to the server protocol work or later.
