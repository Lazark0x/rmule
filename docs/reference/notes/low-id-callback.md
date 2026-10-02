# Low-ID callback — wire pins + correlation (spike, ADR-0039)

Pinned from aMule (`amule-project/amule`; opcode constants are canonical eD2k and
stable across the tree — the working copy carries refactor/"eMule ref:" comments, but
`src/include/protocol/ed2k/Client2Server/TCP.h` is upstream). Cite-and-rewrite only
(ADR-0004); never port GPLv2.

## Server opcodes (under `OP_EDONKEYPROT` = `0xE3`)

`src/include/protocol/ed2k/Client2Server/TCP.h`:

| Opcode | Byte | Body | Direction |
| --- | --- | --- | --- |
| `OP_CALLBACKREQUEST` | `0x1C` | `[id 4]` | client → server |
| `OP_CALLBACKREQUESTED` | `0x35` | `[ip 4][port 2]` | server → client |
| `OP_CALLBACK_FAIL` | `0x36` | none | server → client |

**Send (`BaseClient.cpp`):** the requester writes the *source's* low id and asks its
server to relay: the body is the LOW-ID source's id as a `u32`, sent as an
`OP_CALLBACKREQUEST` over the server connection. The client then moves that source's
download state to "waiting for callback", i.e. the source now awaits the inbound dial.

So `OP_CALLBACKREQUEST` payload = `[low_id u32]` (the source we want to reach).
`OP_CALLBACKREQUESTED` carries the *requester's* `[ip u32][port u16]` — the **peer**
acts on it (dials the requester); rmule-the-requester ignores the body.
`OP_CALLBACK_FAIL` has no payload ("null notverified") — the server could not route the
callback (source gone / unknown low id).

## Correlation linchpin — GATE: PASSED

The requester must match the inbound dial-back to the source it called. rmule never
learns the Low-ID peer's real IP (that is the point of Low-ID), so the only link is the
**server-assigned low id**, namespaced by the server (low ids are unique per server).

Confirmed already present in rmule's decoded hello (`crates/rmule-peer/src/hello.rs`,
`PeerHelloBody`): both correlation fields exist and are byte-faithful —

- `client_id: ClientId` — a firewalled (Low-ID) peer advertises its server-assigned low
  id here, so `client_id` of the inbound hello == the low id we passed to
  `OP_CALLBACKREQUEST`.
- `connected_server: Ipv4Endpoint` — the server the peer is connected to; rmule matches
  this against its own connected server to namespace the low id.

**Correlation key = `(connected_server, client_id)`** from the inbound `OP_HELLO`. For
the spike every callbackable Low-ID source came from rmule's connected server's
`OP_FOUNDSOURCES`, so the source's server == rmule's connected server == the inbound
peer's `connected_server`.

**Residual risk** (a client advertising `0` instead of its low id) is verified at the
real-aMule interop cycle, not assumed away; the documented-but-deferred *opportunistic*
fallback (ADR-0039) is the contingency. The loopback (cycle 9) controls both ends, so
session-B sets its hello `client_id` to the low id and exercises precise correlation
end-to-end regardless.

## Low id == 0 has no callback semantics

A low id of `0` is not routable (server assignments start at `1`); never emit
`OP_CALLBACKREQUEST` for id `0`. `ClientId::LOW_ID_THRESHOLD` (`0x1000000`) already
gates Low-ID; add the `> 0` guard at the callback emit site.

## The Kad-buddy callback route's 128-bit fields

The other callback route — ADR-0061's route 4, a downloader reaching a
firewalled Kad source through that source's buddy — moves two 128-bit fields
across a namespace boundary, and the two families agree byte for byte on how.

**Emit, `KADEMLIA_CALLBACK_REQ 0x52`.** Both senders build the body with
`WriteUInt128`, which emits a `CUInt128` as four little-endian 32-bit chunks
(`src/SafeFile.cpp:285-291`), and both 128-bit values enter that type
big-endian:

| Sender (aMule source) | Field 1 | Field 2 | Field 3 |
| --- | --- | --- | --- |
| `BaseClient.cpp:2136-2138`, the buddy endpoint is already known | the buddy ID, built from raw bytes by the big-endian constructor | the requested file hash, built the same way | our TCP port, `u16` |
| `Search.cpp:1092-1100`, a FINDSOURCE search at convergence toward the buddy ID | the ID the source used to find a buddy (the search target) | the first requested file ID | our TCP port, `u16` |

So both fields are on the wire with each 32-bit word's bytes reversed relative
to the eD2k hash they came from.

**Relay, `0x52` → `OP_CALLBACK 0x99`.** The buddy rewrites nothing. It reads
both fields into `CUInt128`s and writes them straight back out
(`src/kademlia/net/KademliaUDPListener.cpp:1783-1794`, aMule at the pinned
`amule-kno` tree `ab483654`; eMule 0.70b `kademlia/net/KademliaUDPListener.cpp`
`Process_KADEMLIA_CALLBACK_REQ` is line-for-line the same), then appends the
datagram source IP and the body's TCP port. The relayed body is therefore
`[check 16][file 16][ip u32][tcp u16]` under the eMule protocol byte and opcode `0x99`;
reading a field into a `CUInt128` and writing it back is the identity on the bytes.

**Consume, the firewalled end.** Here the two fields part company
(`src/ClientTCPSocket.cpp:1749-1766`; eMule `ListenSocket.cpp:1373-1391`):

| Step | Field | What the reader does |
| --- | --- | --- |
| 1 | check (buddy ID) | read as a 128-bit value, XOR with the all-ones value, compare against our own Kad ID as a value; a mismatch drops the packet. The word order never leaves the 128-bit type, so it is never observable. |
| 2 | file | read as a 128-bit value, then converted to a 16-byte array; that read-then-convert pair is the per-word swap that yields a true file hash. |
| 3 | lookup | the swapped bytes form the file hash; if it names neither a shared file nor a download-queue file, the packet is dropped. |

The buddy ID never becomes a hash, so its word order is invisible to everyone.
The file hash does become one, and the un-swap that makes it one happens at the
*reader*, not at the relay. An implementation that keeps the field raw all the
way through relays correct bytes and still fails its own file lookup — a defect
rmule had and fixed: rmule normalises at the `0x52` decode and denormalises
at the `0x99` framing, a composition that reproduces the byte-for-byte
pass-through while holding a true file hash in between.

Capture-backed since 2026-09-23. A first harness run drew rmule's own `0x52` and
aMule's relay of a walk's; a second (run `1790185890`) drew **aMule's own**
`BaseClient.cpp` emit — a stock requester reading the firewalled aMule's
type-3 row — whose 36 bytes carry `kad_wire_id(TAG_BUDDYHASH)` and
`kad_wire_id(file MD4)` exactly as read above, equal rmule's emit for the same
file byte for byte, and crossed rmule's buddy unchanged into a `0x99` the
firewalled aMule consumed (fixtures `rmule-kad/.../amule-233-callback-req-20260923`,
`rmule-peer/.../amule-233-callback-req-relay-20260923`). A third (run `1790190646`)
drew the `Search.cpp` FINDSOURCE emit: toward an rmule-published
row naming its buddy by ID alone, the requester walked a `KADEMLIA2_REQ` to the
buddy and sent the search's `0x52`, byte-identical to the `BaseClient.cpp` one
(fixture `rmule-kad/.../amule-233-callback-req-findsource-20260923`). A fourth (run `1790206695`)
ran the same requester with its crypt layer on: the search's
`0x52` crossed keyed on the buddy's Kad ID (`SendPacket(…, &clientID)`,
receiver verify key `0`), rmule's buddy opened it under its own ID and relayed
it (fixture `rmule-kad/.../amule-233-callback-req-findsource-keyed-20260923`).
