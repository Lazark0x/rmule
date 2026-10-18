# Speak the emule-qt IPv6 dialect end to end, with kno's seven hardenings

## Context

The eD2k IPv6 dialect has three client implementations — emule-qt, eMuleAI, and aMule on
kno's fork — and two servers, eNode-go and ed2k-server. Its core never widens a 32-bit
field: IPv6 rides as tags in the hello, the login and the ExtSX record, as a Sentinel
Source record's inline address in source lists (ADR-0085), as two string tags in Kad
publishes, and as one new client↔client opcode. Kad itself stays IPv4 end to end.

Normative text is `ModderMule/emule-qt` `docs/protocol/ipv6-spec.md`, read under the
reference discipline of ADR-0082. Hardenings come from `amule-org/amule` master
(`PeerAddressing.h`, `PublicIPv6Corroboration.h`, `ClientTags.h`) and kno's fork. Citations
below are to emule-qt at `73fff714`, kno's aMule Fork Pin at `ab483654` (ADR-0045), eMuleAI
at `a2f05dc8` and stock aMule 2.3.3, as each line says.

Stock aMule 2.3.3 ignores every tag and opcode of the dialect: `HASH` is a known tag type,
`0xAC` and `0x26` travel under `0xE3`, and a server sends a sentinel only to a session that
advertised `SRVCAP_IPV6`.

**Evidence, per surface.** aMule implements none of the dialect, so by ADR-0082's rule —
parity is measured against aMule, and against the eMule-family counterparty for behaviour
aMule does not implement — the client surfaces are scored on emule-qt, beside kno's aMule
Fork Pin where it ports the surface (ADR-0045), and the server surfaces on the servers that
speak them. Each surface states its oracles, and a surface with one says so:

| Surface | Oracles |
|---|---|
| Hello tags, `0xAC`, UDP key, buddy v6 tag | emule-qt + kno |
| ExtSX | emule-qt alone — kno writes none |
| Kad `ip6` / `bi6` | emule-qt + kno (kno writes `ip6`, stores and reads both, writes no `bi6`) |
| Sentinel sources, `0x4000`, `0xAB` / `0xAF`, login tags | ed2k-server + eNode-go |
| `0x26`, the `OP_SERVERLIST` v6 block | eNode-go alone |
| Legacy ignore | aMule 2.3.3 |

Captures: emule-qt's `OP_ANSWERSOURCES2` carrying `CT_MOD_IP_V6`
(`crates/rmule-peer/tests/fixtures/source_exchange/captured/emule-qt-73fff714-extsx-ipv6-20260923/`,
and `…-extsx-lowid-server-ipv6-20260924/`); kno's documented absence on ExtSX — it claims no
`EXTXS` and its source writer `CKnownFile::CreateSrcInfoPacket` (`KnownFile.cpp:1139-1330`)
writes classic records only, skipping a source with no IPv4 wire form (`:1219`)
(`…/source_exchange/captured/amule-kno-ab483654-sx1-no-ipv6-20260923/`); kno's Kad `ip6` both
ways and rmule's `bi6` re-served byte for byte by kno's storer
(`crates/rmule-kad/tests/fixtures/ipv6/captured/amule-kno-ab483654-kad-ip6-20260923/`,
`…-kad-bi6-20260924/`); kno's callback request to a buddy row's IPv4 trio
(`crates/rmule-kad/tests/fixtures/buddy/captured/amule-kno-ab483654-callback-req-20260924/`);
emule-qt's lower-case Kad `ip6` publish, re-served by an rmule storer and followed by a
byte-equal transfer over IPv6
(`crates/rmule-kad/tests/fixtures/ipv6/captured/emule-qt-73fff714-kad-ip6-20260924/`).

kno's verified-IPv6 `OP_HELLOANSWER` counts `CT_MOD_IP_V6` (`BaseClient.cpp:1447-1449`) and
then writes it through `CTag::WriteTagToFile`'s `restrictive = true` default (`Tag.h:80-82`),
whose type test drops a `TAGTYPE_HASH16` tag (`Tag.cpp:398`): the answer declares ten tags
and carries nine
(`crates/rmule-peer/tests/fixtures/hello_refusal/captured/amule-kno-ab483654-short-count-20260924/`).
No kno commit changes that writer. So a file off kno's own Kad row cannot arrive at this
pin, and the transfer off a Kad row carrying `ip6` is drawn from emule-qt as publisher and
server.

## Decision

**Speak the emule-qt IPv6 dialect exactly as written, with kno's seven hardenings, on the
foundation of ADR-0085 (types, Family Pairs, sentinel readers) and ADR-0084 (the Known IPv6
verdict and the Advertised Endpoints chooser).**

### Capability posture

- `CT_MOD_MISCOPTIONS 0xAA` is sent in every hello as a **static claim** of what rmule can
  speak: `EXTXS | IPV6 | EXTXS_SKIPTAGS` (bits 0, 2, 5) plus the uTP NAT-traversal bit 1 of
  ADR-0091; the QUIC bit 4 and the buddy-pull bit 3 stay off. Received bits are masked to the
  known set (`0x3F`: aMule's `0x1F` plus the spec's bit 5). This extends the registry of
  ADR-0047.
- **The fact is the tag:** `CT_MOD_IP_V6 0xAE` (old-format `TAGTYPE_HASH`, 16 raw bytes) is
  written only when the chooser reports a Known IPv6 that is not probed-unreachable. Peers
  treat its presence, never the bit, as "reachable IPv6" — Honest Capability Advertisement
  (ADR-0047): the bit says what rmule can do, the tag what is true now.
- **ExtSX** (version byte pinned at 1) is the IPv6 carrier in source exchange and nothing
  more. It is parsed from any peer with bounds-checked reads, unknown tags skipped by type —
  never abandoning the packet, which is eMuleAI's bug — and emitted only to peers that
  advertised `EXTXS`; `USERHASH` / `CONOPTS` tags go only to `SKIPTAGS` peers and are accepted
  from anyone.
- **A dual-stack source is one source with two addresses.** On consume, the two families
  are judged independently, through admission too: a record whose classic half is a Low ID
  no route reaches still yields its usable IPv6 (emule-qt writes `htonl(userIDHybrid)`, so
  every server-less peer it hands out is Low ID `0` beside its IPv6). Admission keeps the
  **IPv6 Half** on the source it admits, so a dual-stack record reaches core as one
  `SourceSighting` — never two candidates, which would dial one peer twice into two worker
  slots. On emit, a source carries its IPv6 Half (its hello's `CT_MOD_IP_V6`, past
  `IsUsableTagIdentity`) beside a High ID, and the ExtSX writer emits `CT_MOD_IP_V6` beside
  the IPv4 id, as emule-qt's writer does for any source with a public open IPv6
  (`KnownFile.cpp:937`, `:849`, `:854`). A Low-ID client with a usable IPv6 queued on a
  complete file is written for an `EXTXS` asker under the **Placeholder Low ID** `1` —
  emule-qt's own IPv6-only marker (`kNoIPv4SourceId`) — and omitted from a classic answer,
  whose fixed stride has no field for the half.
- `OP_CHANGE_CLIENT_IP 0xAC` (`0xE3`, 16 raw bytes) is sent when the Advertised IPv6 moves
  to a new address, once, on every identified session whose peer's hello claims
  `MODMISC_IPV6`, and never on any other (emule-qt `CoreSession.cpp:1510-1520`,
  `UpDownClient.cpp:4670-4697`). A move before identification rides our hello, or follows it
  when the peer identifies. A move to no address sends nothing: there is nothing to name. `CT_EMULE_SERVINGBUDDYIPV6 0xA0` carries the buddy's IPv6 where
  ADR-0061 carries its IPv4, from the held buddy link under emule-qt's gate (firewalled and
  a buddy, `UpDownClient.cpp:1197-1210`), read per hello so it drops with the link.

### kno's hardenings (all seven)

1. `CT_MOD_SVR_IP_V6 0xAF` is refused in a peer hello — it is a server tag.
2. `CT_MOD_YOUR_IP 0xAD`'s integer form is refused; the hash form is a vote (ADR-0084).
3. Corroboration needs three observers within 30 minutes, eight remembered (ADR-0084).
4. IPv6 rate limits and per-address caps count per `/64`, never per `/128` — accounting
   only, never identity, ban, index or routing.
5. No resolver family preference: servers resolve A first with one AAAA fallback, because a
   High ID is the packed public IPv4 and preferring AAAA costs one for nothing.
6. `IsUsableTagIdentity`: a tag address that is not global unicast is refused, since a
   16-byte tag carries no scope id.
7. `HasEd2kWireForm`: a native-IPv6 peer is omitted from every 32-bit wire field (`.part.met`
   seeds, classic SX, source lists), never written as `0`; `0.0.0.0` and `::ffff:0.0.0.0` are
   refused.

**Unmapping at every claim boundary.** The Family Pairs bind `IPV6_V6ONLY`, so a mapped
`::ffff:a.b.c.d` address never arrives as a socket source; but a peer's *claim* can be
written mapped. So `AccountingKey::of` unmaps first (kno's `RateLimitScope` calls
`Unmapped()` before keying, `PeerAddressing.h:227-231`), and so do
`IpFilter::is_filtered_peer` (an `ipfilter.dat` IPv4 range cannot be dodged by spelling the
host mapped) and `BanStore::ban` / `is_banned` (a flood-banned IPv4 cannot redial as a mapped
claim). `IsUsableTagIdentity` already refuses a mapped address, so every 16-byte-tag reader
— the hello, `0xAC`, ExtSX, a Kad source row, the Kad publish reader
(`decode_published_source`) — refuses a mapped claim outright.

### Dial policy

- **One Dial Chooser** beside `advertised_endpoints()` owns family policy: dial IPv6 when the
  peer has a usable IPv6 **and** we hold a Known IPv6. The route tree of ADR-0061 gains
  **rung 0** — that direct IPv6 dial — ahead of the Low-ID→Low-ID drop and every callback,
  and a download's Low-ID candidate takes it before its callback roads. The "Low ID ⇒
  callback" rule applies to the IPv4 identity only. An IPv6 source this node cannot dial is
  dropped and counted (ADR-0085).
- **A dual-stack High-ID source** is settled at ingest on the family the chooser picks,
  before the endpoint-keyed pool sees it; a Low-ID source keeps its half as its candidate's
  rung 0. emule-qt always dials the IPv4 of a High-ID source (`UpDownClient.cpp:88-89`,
  `:1623-1627`); both reach the same peer.
- **A failed first-family dial falls to the other family once.** A dial that ends short of a
  completed handshake (no route, refused, timed out, closed before the hello answer, or a
  worker that could not start) is retried once in the other family, if that family is
  dialable from here at that moment. The pool holds the other half beside the endpoint it
  dials (`dual_stack_fallbacks`), and a later sighting naming a half the pool lacks merges
  into the record it already holds (`pool_high_id`). A `CryptIncompatible` retirement is not a
  family failure and does not fall. The IP filter judges each half at ingest
  (`judge_halves`), including a Low ID's rung-0 half.
- Reask `0x90` / `0x91` are byte-identical over IPv6; upload-side sender attribution compares
  the full 128 bits.
- **SUI** uses v1 for any dial where either side is native IPv6 (v1 signs no address); v2's
  4-byte `ChallengeIP` stays IPv4-only. Credits stay keyed by User Hash.

### The client-UDP surface, per opcode

| Opcode | Body | Family |
|---|---|---|
| `0x90` `OP_REASKFILEPING` | `<hash 16>[part status][complete sources]` | both |
| `0x91` `OP_REASKACK` | `[part status]<rank u16>` | both |
| `0x92` `OP_FILENOTFOUND` | empty | both |
| `0x93` `OP_QUEUEFULL` | empty | both |
| `0x94` `OP_REASKCALLBACKUDP` | `<buddyID 16><forwarded…>` | IPv4 only |
| `0x95` `OP_DIRECTCALLBACKREQ` | `<tcp port u16><userhash 16><connect opts u8>` | both |
| `0xE4` / `0xE5` Kad | a Kad2 datagram | IPv4 only |

What widens names no address: the sender is the datagram's source and the answer goes back
to it, and `0x95`'s rate limit buckets by `AccountingKey`. **`0x94` stays IPv4** for what the
relay becomes: a verified `0x94` is rewritten into `OP_REASKCALLBACKTCP` (`0x9A`) over the
buddy's TCP link with the requester as `WriteUInt32(ip)` + `WriteUInt16(port)`, and the far
reader is a stock firewalled client that would read a sentinel as the broadcast address. An
IPv6 `0x94` is dropped and counted (`unanswerable_family_datagrams_total`). The `0x9A` codec
reads and writes the sentinel form both counterparties use, `<FFFFFFFF><ipv6 16><port 2>`
then the forwarded tail (emule-qt `CoreSession.cpp:962-964`, `UpDownClient.cpp:3572-3583`;
eMuleAI `ClientUDPSocket.cpp:1225-1228`, `ListenSocket.cpp:4050-4059`), refusing a requester
`IsUsableTagIdentity` refuses; the relay never writes it, because a stock firewalled client
negotiates no capability for it.

**The UDP obfuscation key** (ADR-0046) takes its layout from the datagram's actual family,
never probed: IPv4 23 bytes (`hash ‖ ip as host-order u32 ‖ 0x5B ‖ rand2`), IPv6 35 bytes
(`hash ‖ 16 network-order bytes ‖ 0x5B ‖ rand2`), magic at offset 32
(`EncryptedDatagramSocket.cpp:129-134` receive, `:241-246` send). On send the key is our own
external address in the family the datagram leaves by, read from the store's stale-tolerant
verdict, not the Advertised IPv6; holding none in that family means plaintext, aMule's
`GetPublicIP() != 0` gate generalised. eMuleAI's layout differs in one byte: it never writes
offset 32 of an uninitialised buffer (`srchybrid/EncryptedDatagramSocket.cpp` receive
`:227-234`, send `:338-346`), so an obfuscated IPv6 datagram between rmule and eMuleAI opens
only when that stack byte happens to be `0x5B`. rmule keeps emule-qt's derivation both ways
and counts the miss (`ipv6_undecryptable_datagrams_total`); a 256-candidate search would cost
256 setups per miss, raise false-sync odds from 2⁻³² to about 2⁻²⁴, and still leave rmule's
sends unreadable to eMuleAI. Pinned by `datagram_obfuscation::ipv6_key_kat`.
rmule does not work around it by sending eMuleAI plaintext on the IPv6 half, although
eMuleAI passes a plain `0xC5` through (`EncryptedDatagramSocket.cpp:181-188`): client-UDP
stays obfuscated toward every peer that asks for it. The cost is a recorded **divergence**:
over IPv6, an eMuleAI peer and rmule cannot exchange an obfuscated reask, Kad or NAT-T
datagram in either direction, so IPv6 client-UDP reachability with eMuleAI is lost until
eMuleAI writes offset 32.

### The server-UDP surface

Every server-UDP body is IPv4 on this surface. Most name no address at all; what fixes the
family is rmule's own ask: the surface is request/response, rmule is always the requester,
servers resolve A first, the transport reaches only an IPv4 literal, and a `0x9B` answer is
attributed by its source port minus four. A datagram from an IPv6 source answers nothing
rmule asked and is dropped and traced in `recv`. `0x9B`'s sentinel records carry IPv6 sources
inside the body; a server must never put one in a chained datagram, which a legacy reader
walks at `count × 6`. `0x99`'s rows name third-party sources in 32 bits with no sentinel form,
so an IPv6-only source is the server's to omit. **`0x9C` `OP_GLOBCALLBACKREQUEST` is refused
for its own body, permanently:** it carries rmule's own contact as `WriteUInt32(ip)`, and for
a request whose content is that address, omitting is dropping — a v6-only rmule has no global
callback. A v6-only server in the list is usable over TCP (login, search, source lookup, the
sentinel sources it publishes there) and gets no UDP status sweep, so it holds no proven
capabilities and never enters the global-source rotation, as a DNS-named server.

### Kad `ip6` and `bi6`

- String tags of exactly 32 ASCII hex characters, MSB first, parsed case-insensitively, any
  other length ignored, written **upper-case** (kno writes upper-case with
  `CMD4Hash::Encode`; emule-qt lower-case with `QByteArray::toHex`, `KadSearch.cpp:1391`).
  No Kad opcode, version or contact format changes.
- **`ip6`** is emitted on source publishes only while the chooser reports a Known IPv6. It is
  consumed from search results as the source's IPv6 Half, as an ExtSX record's: a High-ID row
  is dialed in the family the chooser picks, a buddy or type-6 row keeps its callback road with
  the half beside it for rung 0, and only a known source type (1, 3–6) whose 32-bit projection
  found no road becomes an IPv6-only `PeerSource::Ipv6`. A deprecated type 2 or an unknown type
  is no source, `ip6` or not (eMuleAI's `KademliaSearchFile`, `DownloadQueue.cpp:4924-4926`).
- **`bi6`** closes a firewalled type-3/5 row whenever the held buddy link knows the buddy's
  IPv6: the link's own remote address when it runs over a usable IPv6 (verified; eMuleAI's
  rule, `Search.cpp:920-923`), otherwise the `CT_MOD_IP_V6` the buddy's hello carried on that
  link (claimed; emule-qt's rule, `KadSearch.cpp:1419-1421`). The link is held only after its
  user hash matched the `0x5A`, so the claim is the recruited buddy's. No held link, no `bi6`.
  A `bi6` is consumed into the row's buddy contact, never into a source, and decides no road:
  every implementation measured drops or ignores it (kno `Search.cpp:1205-1224`; emule-qt stores
  it at `DownloadQueue.cpp:484-485` and reads it nowhere).
- **rmule's storer re-serves** a stored row's `ip6` and `bi6` verbatim, last and in that order
  (eMuleAI's publisher order, `Search.cpp:913-923`; kno's verbatim index keeps arrival order,
  `KademliaUDPListener.cpp:1402`). A `bi6` is gated by `IsUsableTagIdentity` at store time;
  only a type-3/5 row indexes a buddy contact.
- **The buddy's IPv4 gate** on both readers (`0x44`, `0x3B`): a `TAG_SERVERIP` that cannot name
  one remote host (`0.0.0.0`, loopback, link-local, multicast, `240/4`) gives the contact no
  IPv4 endpoint, so the road is the Callback Walk toward the buddy ID; private ranges stay
  admitted. `TAG_SOURCEIP` refuses only `0.0.0.0` and `224/3`. eMuleAI's IPv6-buddy row writes
  `TAG_SERVERIP` as a `UINT_MAX` stand-in (`Search.cpp:886`, `Address.cpp:91-92`) and pairs
  `bi6` with `TAG_SERVERPORT`; rmule keeps that pair as the contact's `buddy_udp_ipv6`, which no
  road dials, and re-serves the port beside `bi6` without the stand-in.

### The server half

The login carries `CT_SERVER_FLAGS` bit `0x1000` (`SRVCAP_IPV6`) and `CT_MOD_IP_V6`.
`OP_IDCHANGE` and UDP-ping flag bit `0x4000` are read, deliberately asymmetric.
`OP_SERVERIDENT`'s `ST_IPV6_STATUS 0xAB` feeds Reachability's IPv6 probe verdict (`PROBED`
without `REACHABLE` suppresses the tag; cleared on disconnect), and the server's own IPv6 is
read id-tolerantly (`0xAF` per spec). Sentinel sources are dialed. `OP_SERVERLIST`'s trailing
IPv6 block is read. `OP_CALLBACKREQUESTED_IPV6 0x26` (16 bytes and a little-endian port) is
consumed. The `s6=` link token (§6.2) and `ST_IPV6 0x99` in `server.met` are parsed and
written.

A `server.met` row that carries `ST_IPV6` beside a non-zero header IP is kept whole: one row
with two endpoints at the header's port, and the dialer takes the IPv4 half, because a High ID
is the packed public IPv4 and dialing a dual-stack server over IPv6 would cost it. This is a
recorded **divergence** from emule-qt, whose reader applies the tag only while the entry holds
no address (`Server.cpp:190-196`) and whose writer writes it only for an IPv6-only entry
(`Server.cpp:295-298`); it drops the IPv6 half of such a row, rmule keeps it and writes it back.

## Consequences

- A dual-stack rmule exchanges IPv6 sources with emule-qt and kno, dials them under the AND,
  publishes and re-serves Kad `ip6` / `bi6`, and takes a capable server's sentinel sources —
  while stock aMule sees nothing new.
- A client that can parse IPv6 sources but holds no confident IPv6 cannot tell a server so —
  the spec's asymmetry stands.
- Per-`/64` accounting reaches the flood limiter (ADR-0064), the `0x95` window and the
  upload-queue cap (ADR-0088).
- An eMuleAI peer's obfuscated IPv6 datagrams mostly fail, both ways, until eMuleAI writes
  offset 32; the misses are counted, and no plaintext fallback hides them.
- The kno transfer row turns from documented absence to measured on the first kno pin whose
  hello answer carries the tag it counts, admissible under ADR-0045's Fork Pin rule.

## Considered options

- **Advertise the IPv6 bit only when an IPv6 exists.** Rejected: it breaks the spec's
  static-claim model, and peers read an absent bit as "no support".
- **No ExtSX.** Rejected: rmule would never receive an IPv6 source from a peer.
- **eMuleAI's posture** (accept `YOUR_IP`'s integer form and `0xAF` in hellos). Rejected: one
  unverified peer would set our public IPv4.
- **Prefer IPv6 whenever the peer has one.** Rejected: dialing from an address we cannot
  corroborate breaks reply attribution and dial-back; the AND is deliberate.
- **Family decisions at each dial site.** Rejected: three copies of the rule ADR-0061 collapsed.
- **Two candidates for a dual-stack source.** Rejected: one peer dialed twice, one queue place
  and credit record described twice.
- **Gate `0x26` and the `SERVERLIST` block on a second server oracle.** Rejected: an 18-byte
  consume that, ungated, would leave an IPv6-only rmule unable to take its one server's
  callback; the evidence table is the honest form of the gate.
- **A reader tolerant of kno's short tag count, or a locally patched kno.** Rejected: the
  first accepts a count the bytes do not back; the second makes the surface partly
  self-authored (ADR-0045).
- **A verification dial before writing `bi6`.** Rejected: the publisher is the firewalled
  party, often IPv4-only, and its failure says nothing about a searcher's.
