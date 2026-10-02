# A server is three separate primitives: where it is, who it is, and how busy it is

## Context

The eD2k wire describes a server in separate pieces. Where to reach it comes from
links, server lists and configuration. Who it is comes from `OP_SERVERIDENT` (`0x41`),
which carries static identity: the server hash, name, description and further tags.
How busy it is comes from `OP_SERVERSTATUS` (`0x34`), dynamic user and file counts
refreshed while the session runs. The opcode values are pinned to aMule
`src/include/protocol/ed2k/Client2Server/TCP.h` lines 31-58 at commit
`377ec8d9d56618f1059d8705ae53a70fa4ffbe87`; the table lives in
`docs/reference/notes/ed2k-welcome-packets.md`. A single type for all three fights the
wire, forces partial mutation on every status refresh, and leaves no clean way to
combine sources that each know a different subset.

## Decision

`rmule-primitives` models a server with three orthogonal types plus a typed hash:

- **`ServerEndpoint`** (`identity.rs`) is where: host-or-IP plus port (ADR-0016).
- **`ServerIdentity`** (`server.rs`) is who. Every typed field is an `Option`, because
  no single source carries all of them, and tags rmule does not type are kept in an
  `extra_tags` tail. It is built from an `OP_SERVERIDENT`-shaped source through the
  `ServerIdentSource` trait, which the eD2k `ServerIdent` packet implements, so the
  primitives crate never depends on the protocol crate. Combining sources is an
  explicit `merge(other)` with documented precedence: the newer value wins on every
  typed field it states, and the unknown-tag tail is unioned without duplicates.
- **`ServerStatusReport`** (`server.rs`) is how busy: the user and file counts a
  status packet reports, as the server's own unverifiable claim.
- **`ServerHash`** is a typed 16-byte identity, parallel to `UserHash`, `FileHash` and
  `AichRootHash`, so server-hash bytes cannot be confused with other 16-byte values.

## Consequences

- Each wire packet maps onto one type, and a status refresh replaces one small value
  without touching identity.
- A partly known server stays representable, and enrichment from several sources is a
  real operation rather than implicit mutation.
- Unknown identity tags survive decoding and merging.
