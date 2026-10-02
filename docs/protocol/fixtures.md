# Protocol Fixtures

Protocol fixtures are compatibility evidence. They should explain where each case came from and what behavior it protects.

## Provenance Labels

- `handwritten`: created for edge-case coverage from documented protocol rules.
- `documentation`: derived from a protocol reference example.
- `amule-generated`: produced by aMule behavior without copying implementation code.
- `captured`: taken from packet capture or live interoperability testing.

## Link Fixtures

Link fixtures should be stored as TOML near `rmule-primitives` tests and include:

- input link text
- expected typed fields
- expected canonical output
- whether the input is accepted or rejected
- provenance label
- source note when derived from documentation or observed behavior

The first link parser accepted file links with required identity fields and the modeled `p=` part-hash-set and `h=` AICH-root metadata. It rejected unmodeled optional fields such as `s=`, source-list suffixes, unknown keys, and duplicate `p=` or `h=` fields until those semantics were explicitly modeled.

Canonical link formatting should normalize only the modeled value:

- use lowercase ED2K scheme and link type names
- render ED2K file and part hashes as uppercase hexadecimal
- render AICH root hashes as uppercase unpadded base32
- render decimal file sizes and ports without leading zeroes
- percent-encode file names with `%20` for spaces, not `+`
- decode safe incoming percent escapes before re-encoding canonically
- order file-link optional fields as `p=` before `h=`
- emit no extra separators beyond the final `|/`
- lowercase DNS server host names while preserving IP literals
- preserve server-list address payloads without aggressive URL normalization

Link parsing should remain explicit and fixture-driven. Parser-combinator dependencies are deferred until a later grammar becomes complex enough to justify them.

## Hash Fixtures

Hash compatibility cases are fixtures. They should cover empty input, one-part input, exact ED2K part-size boundary input, multi-part input, and boundary-plus-one input before the ED2K hash implementation is accepted.

ED2K part-hash-set fixtures should use a part size of 9,728,000 bytes. A present part hash set is valid only when it contains exactly the expected aMule ED2K hashset count for the file size; invalid counts should be rejection fixtures.

Exact part-size boundary fixtures must assert the eMule/aMule-compatible ED2K file hash variant. The `ed2k` crate exposes this as `Ed2kRed`; its default `Ed2k`/`Ed2kBlue` behavior must not be used for rmule's canonical file hash.

Expected ED2K part-hash-set counts:

- `file_size == 0`: no part hash set
- `0 < file_size < 9,728,000`: no part hash set
- `file_size >= 9,728,000`: `floor(file_size / 9,728,000) + 1` hashes
- exact nonzero part-size multiples include the special trailing empty-part hash `31D6CFE0D16AE931B73C59D7E0C089C0`

Hash fixtures should avoid storing large fixture files. Use deterministic synthetic input descriptions, such as a repeated byte and length, when testing ED2K part boundaries.

## Fixture Layout

Use one TOML file per behavior case:

```text
crates/rmule-primitives/tests/fixtures/
  hashes/
    empty.toml
    one_part.toml
    exact_part_size_emule_variant.toml
    two_exact_parts_emule_variant.toml
    boundary_plus_one.toml
  links/
    file_minimal.toml
    file_with_part_hash_set.toml
    file_with_aich_root.toml
    server_ipv4.toml
    server_dns.toml
    serverlist_http.toml
    reject_unknown_file_field.toml
    reject_duplicate_part_hash_set.toml
  packets/
    tag_string.bin
    tag_string.toml
```

Common TOML fields:

- `name`
- `provenance`
- `source_note`
- `accepted`
- behavior-specific `[input]`
- behavior-specific `[expected]`
- optional `reject_reason`

## Packet Fixtures

Packet fixtures should pair raw bytes with expected decoded fields. When exact bytes matter, keep the raw data in a `.bin` file and the expected model in a neighboring `.toml` file.

The first packet and tag foundations were kept minimal:

- packet fixtures assert strict decode and exact re-encode behavior
- packet frames include a protocol byte, little-endian length, opcode byte, and payload bytes
- frame length counts the opcode byte plus payload bytes; the protocol byte and length field are outside the count
- decode errors distinguish truncated frame prefixes, truncated payloads, invalid lengths, unsupported protocol bytes, and trailing fixture bytes
- tag fixtures start with only the value kinds needed by early server-protocol fixtures, expected to be `String` and `U32` first
- full server login, search, Kad, transfer, and networking packet models are out of scope

The offline login work then moved packet fixtures into the first eD2k server-protocol scope:

- add fixture-backed packet models in `rmule-ed2k`
- start with offline eD2k server login encode/decode
- model the login request as a typed value with stable fields and a preserved tag list
- reject malformed packets and malformed tags, but preserve unknown well-formed login tags
- add minimal login response packet models only when fixtures are strong enough to support them
- use login response models to validate draft events such as accepted login and rejected login, without implementing a running service
- preserve tag name encoding style during decode/re-encode, including compact numeric names and length-prefixed one-byte numeric names
- use length-prefixed one-byte numeric tag names for newly built login requests unless captured aMule evidence proves a different canonical choice
- keep search, source lookup, `server.met` parsing, server-list exchange, and live sockets out of the first slice
- promote packet/tag helpers out of `rmule-primitives` only when multiple protocol crates need the same codec surface or the primitive crate becomes the wrong ownership boundary

`rmule-tools` may support this work with offline packet inspection commands that read local bytes and print decoded packet or login-request summaries. Inspection tooling must not perform network login, search, source lookup, server-list fetching, Kad, or transfers.

First `rmule-ed2k` slice fixture coverage:

- handwritten minimal login request with deterministic synthetic `UserHash`, `ClientId = 0`, client TCP port, nickname tag, protocol version tag, port tag, and flags tag
- aMule-generated loopback login request when the local fake-listener harness is available
- rejection fixtures for truncated frame prefix, truncated login body, wrong opcode for login decoding, tag count mismatch, malformed tag, and trailing bytes
- tag fixtures proving compact numeric tag names and length-prefixed one-byte numeric names round-trip exactly
- response fixtures only for login responses with enough source or capture evidence to model confidently

## Safety

Use synthetic filenames, hashes, hosts, and packet data unless a real capture is necessary. Do not include copyrighted content names or links to real copyrighted files.

For login fixtures, prefer aMule-generated loopback captures over public-network captures:

- configure aMule with synthetic nickname and no real shared content
- point aMule at a local fake TCP listener rather than a public eD2k server
- capture only the first client-to-server login packet bytes needed for the fixture
- store the raw packet plus TOML metadata with `provenance = "amule-generated"`
- reserve `provenance = "captured"` for real interoperability captures that have been redacted and justified
- do not commit pcap files unless the fixture needs packet-container metadata and the redaction rule is documented

Reject fixture candidates that include public IPs, real server lists, content names, or user-identifying data.

The detailed loopback capture procedure lives in `docs/protocol/amule-login-fixtures.md`.
