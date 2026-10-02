# Kad Packet Framing

**Status:** initial research note for Kad dependency spike
**Scope:** eMule Kad UDP datagram envelope, Kad2 opcode evidence, compression boundary, and open packet-layout gaps.

Kad uses its own UDP packet family. It is not the eD2k TCP/server frame from `docs/reference/notes/packet-framing.md`, even though aMule's `CPacket` helper can construct both.

## Evidence Sources

Cached:

- `docs/reference/emule-web-wiki/introduction_kad.wikitext` says Kad uses UDP to find sources for ED2K hashes, keyword/file lookups, comments/ratings, buddy services, and publishing. It also notes that Kad does not transfer file bytes.
- `docs/reference/notes/packet-framing.md` already records aMule protocol constants for `0xE4` / `0xE5` as Kad / packed Kad.

Link-only:

- Pinned aMule source at commit `377ec8d9d56618f1059d8705ae53a70fa4ffbe87`, read as reference only:
  - `src/include/protocol/Protocols.h:32-45`
  - `src/include/protocol/kad2/Client2Client/UDP.h:33-53`
  - `src/include/protocol/kad/Client2Client/UDP.h:29-58`
  - `src/include/protocol/kad/Constants.h:33-47`
  - `src/ClientUDPSocket.cpp:88-118`
  - `src/kademlia/net/KademliaUDPListener.cpp:187-211,213-231,237-288,931-939,978-987,1088-1201,1228-1247,1583-1599`
  - `src/Packet.cpp:247-272`
  - `src/kademlia/kademlia/Search.cpp:464-485,570-660,870-927`
  - `src/kademlia/kademlia/Indexed.cpp:563-636,815-863`
  - `src/include/tags/FileTags.h:81-124`

## Datagram Envelope

Confirmed:

| Offset | Size | Field | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| 0 | 1 | Kad protocol byte | aMule names `0xE4` as Kad and `0xE5` as packed Kad. | high |
| 1 | 1 | Kad opcode | aMule UDP receive path reads opcode from byte 1 and passes bytes after byte 1 to Kad opcode handlers. | high |
| 2 | rest | opcode-specific payload | aMule Kad listener computes payload as `lenData - 2` after protocol byte and opcode. | high |

Unlike the eD2k TCP/server frame, this Kad UDP envelope has no four-byte length field between protocol and opcode in the decrypted datagram passed to Kad dispatch.

Open:

- ~~rmule has not yet captured an actual eMule Kad datagram.~~ Resolved: the
  committed captured fixtures under `crates/rmule-kad/tests/fixtures/`
  (`routing/captured/…-distance-20260707`, `node/captured/…-node-messages-20260707`)
  hold genuine plain-`0xE4` aMule datagrams for `0x21`/`0x29` and the
  node-maintenance family below.
- Obfuscated/encrypted UDP wrapper behavior is out of scope for this first note. The first fixture may use unobfuscated Kad bytes if the provenance proves the inner Kad envelope.

## Protocol Bytes

Confirmed:

- `0xE4` is the Kad protocol byte for plain Kad UDP packets.
- `0xE5` is the packed Kad protocol byte.

Compression boundary:

- aMule creates outbound Kad packets as `0xE4` plus opcode and opcode-specific payload. When packet size is above its compression threshold and compression wins, the helper changes the protocol byte to `0xE5` and zlib-compresses only the opcode-specific payload bytes.
- aMule's UDP receive path treats packed Kad as `0xE5`, inflates the bytes after protocol/opcode, restores the logical protocol byte to `0xE4`, and dispatches the original opcode.

Resolved (2026-07-07):

- aMule uses an expansion budget of `packetLen * 10 + 300` for packed Kad receive, which scales with attacker-controlled input. rmule instead caps the inflated payload at a fixed `MAX_INFLATED_KAD_PAYLOAD = 64 KiB` (`rmule-kad/src/envelope.rs`): a packed datagram is a compressed form of a plain datagram, and a plain Kad datagram can never exceed one UDP payload, so any stream inflating past the cap cannot be legitimate. Trade-off: a hypothetical client packing a >64 KiB logical payload would be rejected — but such a datagram could not exist unpacked either. rmule also requires the payload to be exactly one zlib stream (no trailing bytes), stricter than aMule; malformed and oversized streams are typed decode errors.

## Kad2 Opcode Evidence

Confirmed Kad2 opcodes relevant to the first source-lookup slice:

| Opcode | Name | First-slice role | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| `0x01` | `KADEMLIA2_BOOTSTRAP_REQ` | bootstrap request | aMule Kad2 UDP header and listener dispatch. | high |
| `0x09` | `KADEMLIA2_BOOTSTRAP_RES` | bootstrap result | aMule Kad2 UDP header and listener dispatch. | high |
| `0x11` | `KADEMLIA2_HELLO_REQ` | node contact validation | aMule Kad2 UDP header and listener dispatch. | high |
| `0x19` | `KADEMLIA2_HELLO_RES` | node contact validation | aMule Kad2 UDP header and listener dispatch. | high |
| `0x21` | `KADEMLIA2_REQ` | lookup next-hop request | aMule Kad2 UDP header and routing-response code. | high |
| `0x29` | `KADEMLIA2_RES` | lookup next-hop response | aMule Kad2 UDP header and routing-response code. | high |
| `0x34` | `KADEMLIA2_SEARCH_SOURCE_REQ` | source-lookup request | aMule Kad2 UDP header and source request handler. | high |
| `0x3B` | `KADEMLIA2_SEARCH_RES` | source/search result response | aMule Kad2 UDP header and result handler. | high |

Kad1 compatibility is reference-only for this spike. Its source result opcode `0x38` exists in the Kad1 header, but rmule's first evidence target is Kad2 because current aMule source sends Kad2 source lookups to version 3+ contacts.

## Source-Lookup Packet Facts

Confirmed request fields for `KADEMLIA2_SEARCH_SOURCE_REQ`:

- target: 16-byte Kad key for the known file;
- start position: 15-bit result offset; the top bit is masked away by the receiver;
- file size: 64-bit size used to filter source results;
- destination: a Kad node endpoint chosen by the lookup walk.

Confirmed result shape for `KADEMLIA2_SEARCH_RES`:

- sender Kad ID;
- target key;
- result count;
- repeated result rows: source ID plus tag list.

For source results, the tag set can contain source type, source IP, TCP source port, UDP source port, buddy/server callback fields, and encryption options. The first rmule slice accepts only direct-connectable High ID results and treats Low ID, buddy, firewalled, and callback-mediated result forms as diagnostics.

## 2026-07-07 KADEMLIA2_REQ / KADEMLIA2_RES wire layout (from genuine capture)

Decoded from the retained `.scratch/evidence/kad-source-lookup-0x34-0x21-0x29.pcap`
(genuine plain-`0xE4` datagrams between harness-owned aMule nodes; provenance
`captured`). This is the routing-lookup packet pair that the distance-ordering proof
(ADR-0043) uses.

`KADEMLIA2_REQ` (`0x21`) — a lookup next-hop request. Captured `.6 → .4`, UDP payload
length 35:

```
e4 21 | 02 | b52d308e 5ca206b8 23fc8593 d26210f2 | 9cc39abc 15ec1dd9 a0e20c66 d142bd49
 ^pb   ^op   ^count(1)  ^target Kad key (16)                ^check / receiver Kad ID (16)
```

- byte 2 is a 1-byte **contact count** the requester wants back (`0x02` here);
- bytes 3..19 are the 16-byte **target** key (here the file-hash target, matching the
  `0x34` capture exactly — same word-swap byte order, so `KadEvidence::KadIdByteOrder`
  is re-confirmed by a second opcode);
- bytes 19..35 are a 16-byte **check** value = the *receiver's own* Kad ID, an
  anti-misdelivery guard the responder validates against its own identity.

`KADEMLIA2_RES` (`0x29`) — the response. Captured `.4 → .6`, UDP payload length 19:

```
e4 29 | b52d308e 5ca206b8 23fc8593 d26210f2 | 00
 ^pb   ^op  ^target Kad key echoed (16)        ^contact count (1) = ZERO
```

- bytes 2..18 echo the 16-byte **target**;
- byte 18 is the **contact count**; when non-zero it is followed by that many
  **25-byte contacts**, each `[16B Kad ID][4B IPv4][2B UDP port LE][2B TCP port LE]
  [1B version]` — the same 25-byte contact record the bootstrap-edition `nodes.dat`
  uses (`tools/interop-harness/src/kad_seed.rs`).

**Load-bearing finding for the distance-ordering proof:** every captured `0x29` in this pcap carries
**count = 0** — the queried nodes had no closer contacts to return. A zero-contact
response contains no ordering information, so these existing pcaps *cannot* prove
distance ordering; the "promote existing pcaps" fallback for that proof is therefore weak
by construction. The seeded-table capture is the real instrument: seed one responder's
routing table with harness-authored contacts so its `0x29` returns them *ranked by XOR
distance*, then read the ordering off the wire.

## 2026-07-07 Node-maintenance layouts (from genuine captures)

Decoded from the retained private-mesh pcaps of the 2026-06-19 and 2026-07-07
capture sessions and committed as
`crates/rmule-kad/tests/fixtures/node/captured/private-amule-kad-node-messages-20260707/`
(provenance `captured`; see its `metadata.toml`). Every datagram is an aMule
2.3.3 emission to another aMule node. These are the layouts the
**Routing Responder** implements (`rmule-kad/src/messages.rs`).

`KADEMLIA2_BOOTSTRAP_REQ` (`0x01`): **empty payload** — it carries no sender
identity, so a responder cannot learn the requester from it.

`KADEMLIA2_BOOTSTRAP_RES` (`0x09`):

```
e4 09 | sender Kad ID (16) | TCP port (2 LE) | version (1) | count (2 LE) | count × 25-byte contact
```

`KADEMLIA2_HELLO_REQ` (`0x11`) / `KADEMLIA2_HELLO_RES` (`0x19`):

```
e4 11/19 | Kad ID (16) | TCP port (2 LE) | version (1) | tag count (1) | eD2k tags
```

Observed tags: `0xFC` (`TAG_SOURCEUPORT`, u16 — the sender's UDP port; when
absent the receiver falls back to the datagram source port) and `0xF2`
(`TAG_KADMISCOPTIONS`, u8 — not yet modeled; skipped tolerantly). Tags use the
explicit length-prefixed name form `[type][01 00][name byte][value]`.

`KADEMLIA2_PING` (`0x60`): empty payload.
`KADEMLIA2_PONG` (`0x61`): `u16 LE` = the UDP source port the responder
*observed* the ping arrive from (external-port discovery).

Contact rows everywhere (`0x09`, `0x29`, and the nodes.dat editions) are the
same 25 bytes: `[Kad ID (16)][IPv4 (4, low octet first)][UDP port (2 LE)]
[TCP port (2 LE)][version (1)]`. aMule 2.3.3 emits version byte `8`.

Documentation-backed only (link-only aMule listener source, not capturable —
no real client sets the masked bits): the `KADEMLIA2_REQ` requested-contact
count is the **low 5 bits** of the first payload byte; aMule masks with `0x1F`
and drops a request whose masked count is zero.

## 2026-07-07 Source-publish layouts (documentation provenance)

**Provenance: `documentation`, NOT captured.** Derived from the pinned link-only
aMule sources above (`SendPublishSourcePacket`, `Process2PublishSourceRequest`,
`Process2PublishResponse`, `CIndexed::AddSources`, `CIndexed::SendValidSourceResult`,
`Search.cpp` `STOREFILE`, `Constants.h`, `FileTags.h`). Running rmule as publisher
against a real aMule storer captures the genuine bytes and upgrades these rows the
same way the `0x3B` fixture is slated to upgrade.

`KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`) — publisher → storer, Kad2 (contact
version ≥ 4):

```
e4 44 | file key (16) | source ID (16) | tag count (1) | eD2k tags
```

- **file key**: the published file's Kad key (same word-swap byte order as every
  other Kad ID field);
- **source ID**: the publisher's **eD2k User Hash** (aMule writes
  `CKademlia::GetPrefs()->GetClientHash()`, *not* the Kad ID) — this is the
  documentation-backed answer to the `SourceIdMeaning` open question, still
  pending capture proof;
- **tags** (HighID, non-firewalled publisher; `Search.cpp` `STOREFILE`):
  `TAG_SOURCETYPE` (`0xFF`, u8: 1, or 4 for >4 GiB), `TAG_SOURCEPORT` (`0xFD`,
  u16 TCP), `TAG_SOURCEUPORT` (`0xFC`, u16, sent when an internal Kad UDP port
  is in use), `TAG_FILESIZE` (`0x02`, int for <4 GiB / BSOB-8 for larger, sent to
  version ≥ 2 contacts), `TAG_ENCRYPTION` (`0xF3`, u8 crypt options).
  **No `TAG_SOURCEIP` is ever sent** — the storer records the datagram's
  observed sender IP, which is what makes a stored entry evidence-grade
  (parse → store → re-serialize with substitution, never an echo).
  Firewalled publishers send type 3/5 + buddy tags or type 6 (direct callback)
  instead; out of rmule's v1 roles.

Storer acceptance (`Process2PublishSourceRequest` + `AddSources`):

- tolerance gate: drop unless the **most-significant 32-bit word** of
  `own ID XOR file key` ≤ `SEARCHTOLERANCE` (`0x0100_0000`) **or** the sender IP
  is LAN (RFC1918-style);
- entry IP = observed datagram sender IP (a `TAG_SOURCEIP` synthesized from it);
  entry UDP port = `TAG_SOURCEUPORT` when present, else the observed datagram
  source port (tag synthesized); `TAG_FILESIZE` moves into the entry's size
  field (not kept as a row tag); rejected outright: zero TCP port, no tags, no
  `TAG_SOURCETYPE`;
- entry lifetime = now + `KADEMLIAREPUBLISHTIMES` (**5 h**);
- dedupe: same IP and (same TCP **or** same UDP port) replaces the stored entry;
- per-key cap `KADEMLIAMAXSOURCEPERFILE` (**1000**): a publish past the cap
  evicts the **oldest** entry for that key (`load = 100`); otherwise
  `load = stored_count × 100 / 1000` (first entry for a key reports 1). aMule
  has **no total-index cap for sources** (`KADEMLIAMAXINDEX` 50000 bounds
  keywords only) — rmule adds a deliberate total cap as anti-flood policy.

`KADEMLIA2_PUBLISH_RES` (`0x4B`) — storer → publisher, sent **only** when the
entry was actually indexed (a rejected publish gets silence, not a NAK):

```
e4 4b | file key (16) | load (1)
```

An optional trailing options byte exists in the receive path ("for future
use": bit 0 requests a `KADEMLIA2_PUBLISH_RES_ACK` `0x4C`, honored only under
an obfuscation sender key) — aMule 2.3.3 **never emits it**, so its `0x4B` is
exactly 17 payload bytes and `0x4C` never fires on the version-8 plain path.
rmule therefore models `0x44`/`0x4B` only and tolerates (ignores) a trailing
options byte on decode; `0x4C` stays out of scope.

Publisher consumption (`Process2PublishResponse` + `Search.cpp`): a `0x4B` is
accepted only from an endpoint with an outstanding publish (out-track list);
a store search ends after `SEARCHSTOREFILE_TOTAL` (10) acked stores or
`SEARCHSTOREFILE_LIFETIME` (140 s); a published source is republished every
`KADEMLIAREPUBLISHTIMES` (5 h).

Storer answer to `KADEMLIA2_SEARCH_SOURCE_REQ` (`CIndexed::SendValidSourceResult`)
— the `0x3B` shape the requester already decodes, **re-encoded from the parsed
stored entries** (`WriteTagList` of the entry's tag objects), never echoed
request bytes:

- header `[own Kad ID (16)][file key (16)][row count (2 LE)]`, then rows of
  `[stored source ID (16)][tag count (1)][stored tags]`;
- rows go out in batches of **50 per datagram** (the count field of the final
  partial batch is patched in place); at most **300** rows per request; the
  requester's `start position` skips that many rows; a row is returned when
  `request size == 0`, `entry size == 0`, or they are equal.

## Open Questions

- Exact byte order for Kad IDs in source lookup request/result fixtures.
- Exact byte order for source IP tags in Kad result tag lists.
- Whether source IDs in Kad source results correspond to client user hashes, Kad IDs, or another eMule identity value for each source type. Documentation-backed answer (2026-07-07, publish-layout section above): the publisher writes its **User Hash**; capture proof still pending.
- Whether a captured source result with direct-connectable High ID sources is available from a local interop harness.
- Whether `KADEMLIA2_SEARCH_RES` source rows use only normal eD2k tag encoding or any Kad-specific tag edge cases not yet covered by rmule tag fixtures.
