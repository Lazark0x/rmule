# server.met and nodes.dat codecs live with their domain types and replicate aMule's readers

## Context

A cold-start node learns its first eD2k servers from a `server.met` file and its
first Kad contacts from a `nodes.dat` file. Both arrive through the acquisition
pipelines of ADR-0065 and both are aMule formats with quirks that change what a
node can do with a file: a v1 `nodes.dat` carries no verified bits, a v3
bootstrap-edition file is meant to be dialled and never merged, and a truncated
file still yields the rows before the cut.

The readers this ADR mirrors are aMule's, pinned at
`4e8f2b3c3f90cda23765730546b04c684a92e4f5`:

- `server.met`: `CServerList::LoadServerMet`
  ([ServerList.cpp#L86](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerList.cpp#L86)).
- `nodes.dat`: `CRoutingZone::ReadFile`
  ([RoutingZone.cpp#L135](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L135))
  and `ReadBootstrapNodesDat`
  ([RoutingZone.cpp#L228](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L228)).

Evidence, per ADR-0045: aMule-written `server.met` files (the full `SaveServerMet`
ST_ tag set) under `crates/rmule-ed2k/tests/fixtures/server_met/captured/`, and an
aMule-written v2 `nodes.dat` under
`crates/rmule-kad/tests/fixtures/nodes_dat/captured/amule-2.3.3-routing-zone-v2/`.
aMule 2.3.3 has no living v1 or v3 writer (the v3 writer is `#if 0` dead code), so
those branches rest on a machinery-shared capture: their rows are byte-identical to
the captured v2 rows minus the extensions, and the version-specific branches close on
hand-built vectors cited to the reader source. Real-world bootstrap files are
public-network data and are not used as evidence.

## Decision

**Placement: format near domain.** `server.met` is eD2k tag encoding onto the
`rmule_primitives::Server` shape, so its codec (`ServerMet::decode` / `encode`)
lives in `rmule-ed2k`. `nodes.dat` needs `KadId`, XOR distance, contact types and
the verified seam of ADR-0064, so its codec (`NodesDat::decode` / `encode_v2`, plus
the bootstrap-edition reader) lives in `rmule-kad`. `rmule-bootstrap` depends on
both and only fetches. File I/O stays in the runtime and core: `rmule-net` writes
`nodes.dat` (`write_nodes_dat`, on shutdown and on a periodic flush), and
`rmule-core` reads and writes `clients.met` for the credit ring of ADR-0041
(119-byte records, version `0x12`).

**server.met reader.**

- **Unwrap first.** aMule runs `UnpackArchive` before parsing. rmule accepts gzip
  and plain payloads, with a 16 MiB ceiling on the inflated size because the
  download is untrusted. A zip payload is rejected with its own error: a zip
  dependency is not earned, and an operator whose mirror serves zip picks another.
- **Header.** `0xE0` (aMule's own write) or `MET_HEADER 0x0E`
  ([#L117](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerList.cpp#L117),
  [DataFileVersion.h#L44](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/common/DataFileVersion.h#L44)).
  Anything else rejects the file, including `0x0F` (`MET_HEADER_WITH_LARGEFILES`),
  which is the `known.met` header.
- **Per-server stream**
  ([#L128](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerList.cpp#L128)):
  `ip4 / port2 / tagcount4` plus an ST_ tag list. Recognised tags project onto
  `Server` fields, unknown tags are skipped, an out-of-range priority normalises to
  Normal (aMule's explicit quirk check), and an empty name becomes
  `"Server <ip:port>"`.
- **Truncation keeps the rows parsed so far.** aMule's whole-file catch keeps partial
  loads; rmule decodes row by row, a row error ends the parse, and earlier rows stand.
- **Merge posture.** A new `(ip, port)` is added. A duplicate updates the list name
  and a non-empty description only; every other field is kept. This is aMule's
  behaviour, not an overwrite.

**nodes.dat reader.**

- **Version matrix, as aMule branches it.** A non-zero first u32 is v0 and is refused
  as too old, because contact Kad versions are unknowable
  ([#L170](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L170)).
  A zero first u32 is followed by the version
  ([#L153](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L153)).
  Version 3 with bootstrap edition 1 goes to the bootstrap reader
  ([#L156](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L156));
  versions 1–3 otherwise go to the normal reader, and a normal v3 file falls through
  to the v2 layout
  ([#L165](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L165)).
- **Normal reader.** 25-byte rows `id16 / ip4 / udp2 / tcp2 / ver1`
  ([#L177](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L177));
  v2 and later append the 8-byte UDP key and a verified u8
  ([#L185](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L185)).
  Truncation keeps the contacts parsed so far. aMule's loose `count × 25` pre-check
  ([#L175](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L175))
  is replaced by exact per-version row bounds with the same observable outcome.
- **Per-contact filters, in aMule's order**
  ([#L193](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L193)):
  Kad2 only (`ver > 1`; Kad1 rows are counted and skipped), an `IsGoodIPPort`
  equivalent, and port 53 dropped for contact version 5 or lower (crypt-capable v6+
  contacts on port 53 are kept; this is finer than the datagram gate of ADR-0064 and
  sits at a different layer). aMule's ipfilter step has no rmule equivalent.
- **Verified seam.** A v2 or v3 verified bit makes the contact enter the table
  pre-verified, with its UDP key kept for the checks of ADR-0046. A v1 file carries
  no bits, so every contact it loads is marked verified — aMule's explicit heuristic
  ([#L215](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L215)).
  Without it a v1 file yields no servable contacts until the 0x22 handshakes finish.

**nodes.dat v3 bootstrap edition.** v1-style 25-byte rows (500–1000 expected), an
exact `count × 25 == remaining` check (aMule has it here,
[#L242](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L242)),
the same filters, and the 50 contacts closest to the own Kad ID by XOR distance,
insertion-sorted
([#L257](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L257)).
Those contacts feed the bootstrap-dial list one at a time and are never merged into
the routing table, which is aMule's anti-DDoS reason for the format. The reader
refuses when a bootstrap list is already loaded
([#L237](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L237)).

**Writers.** rmule writes the formats it needs for its own persistence, with the same
placement. The `nodes.dat` v2 writer is byte-exact against aMule's
`RoutingZone::WriteFile` and skips the write below `MIN_CONTACTS_TO_WRITE` (25), as
aMule does. The `server.met` writer re-encodes field for field; tags the decoder
drops are lost. v1 and v3 `nodes.dat` have no writer, because no living aMule writer
exists to mirror.

## Consequences

- A local-file load path reuses the same codecs as the HTTP fetch; the domain crates
  carry the formats and `rmule-bootstrap` carries no Kad or eD2k types of its own.
- Files aMule loads partially, rmule loads partially; a strict reader would reject
  files aMule uses.
- A zip-serving mirror fails cleanly with a named error instead of silently.
- The deterministic test matrix covers header rejection including the `0x0F`
  `known.met` trap, v0 refusal, truncation in both formats, the Kad1 skip count, the
  port-53 × version-5/6 boundary, gzip / zip / plain, priority normalisation,
  empty-name synthesis, the duplicate merge, the v1 all-verified flip, v2 verified bit
  and UDP key passthrough, closest-50 determinism, and the already-loaded guard. The
  cold-start scenario of ADR-0065 exercises the decoders end to end.

## Considered options

- **All decoders inside `rmule-bootstrap`.** Rejected: it drags Kad types into an
  HTTP crate, inverts the dependency direction, and orphans the formats from any
  local-file load.
- **zip support.** Rejected: a dependency not earned; gzip covers the live mirrors.
- **Strict all-or-nothing parses.** Rejected: aMule's observable outcome is a partial
  load on truncation.
- **Skipping the v1 all-verified heuristic** and letting ADR-0064 verification earn
  trust. Rejected: a parity break with a real effectiveness cliff, against aMule's own
  considered trade-off.
