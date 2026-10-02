# Server-UDP wire pins (ADR-0051 source discovery, ADR-0052 status chain, ADR-0068 desc pair)

Pinned from aMule (`amule-project/amule`). Opcode constants are canonical eD2k.
Cite-and-rewrite only (ADR-0004); never port GPLv2.

## Opcodes (UDP, protocol byte `0xE3`)

`src/include/protocol/ed2k/Client2Server/UDP.h`:

| Opcode | Byte | Direction | Meaning |
| --- | --- | --- | --- |
| `OP_GLOBSEARCHREQ3` | `0x90` | client → server | search, caps-tag prefix (ADR-0051) |
| `OP_GLOBSEARCHREQ2` | `0x92` | client → server | search, bare tree (ADR-0051) |
| `OP_GLOBGETSOURCES2` | `0x94` | client → server | size-extended source query (gated on `EXT_GETSOURCES2`) |
| `OP_GLOBSERVSTATREQ` | `0x96` | client → server | status ping, `[challenge 4]` (ADR-0052) |
| `OP_GLOBSERVSTATRES` | `0x97` | server → client | progressive status reply (ADR-0052) |
| `OP_GLOBSEARCHREQ` | `0x98` | client → server | search, baseline (ADR-0051) |
| `OP_GLOBSEARCHRES` | `0x99` | server → client | one result row per packet (ADR-0051) |
| `OP_GLOBGETSOURCES` | `0x9A` | client → server | basic source query |
| `OP_GLOBFOUNDSOURCES` | `0x9B` | server → client | sources answer |
| `OP_GLOBCALLBACKREQ` | `0x9C` | client → server | per-server callback (payload below) |
| `OP_INVALID_LOWID` | `0x9E` | server → client | UDP callback-fail, `[id 4]` (deferred) |
| `OP_SERVER_DESC_REQ` | `0xA2` | client → server | description request, `[challenge 4]` (ADR-0068) |
| `OP_SERVER_DESC_RES` | `0xA3` | server → client | description reply, two formats (ADR-0068) |

E1 uses **`OP_GLOBGETSOURCES` (0x9A)** + **`OP_GLOBFOUNDSOURCES` (0x9B)** only.

## Global search: `OP_GLOBSEARCHREQ` family (0x98/0x92/0x90) / `OP_GLOBSEARCHRES` (0x99) — ADR-0051

**One query, three opcodes** (`src/SearchList.cpp` — the sender rewrites the opcode per
server; the tree bytes are the TCP `OP_SEARCHREQUEST` payload, one encoder):

| Server advertises | Opcode sent | Payload |
| --- | --- | --- |
| large-file UDP support **and** `EXT_GETFILES` | `0x90` | one-entry tag set announcing our own caps, then the search tree |
| `EXT_GETFILES` only | `0x92` | bare search tree |
| neither | `0x98` | bare search tree |

Both bare-tree rows are skipped for a server entirely when the search packet carries a
64-bit size term and the server lacks large-file UDP support (aMule logs "Skipped UDP
search ... No large file support").

`CT_SERVER_UDPSEARCH_FLAGS = 0x0E`, `SRVCAP_UDP_NEWTAGS_LARGEFILES = 0x01`
(`src/include/tags/ClientTags.h`). The compact tag bytes are
`[TAGTYPE_UINT8|0x80][0x0E][0x01]` = `89 0E 01`, so the full `0x90` payload prefix is
`01 00 00 00 89 0E 01`. Variant selection reads the capability store (ADR-0052);
the connected server is skipped (it got the TCP search); one server per timer tick.

**`OP_GLOBSEARCHRES` (0x99)** — unlike the TCP `OP_SEARCHRESULT` (0x33: `[count u32]`
then rows), each `0x99` packet carries **exactly one** result row (decoded by aMule's
`CSearchFile` constructor with UTF-8 strings). A multi-result answer packs several
packets in one datagram; `src/ServerUDPSocket.cpp` walks them. The walk is: decode one row; if more than 2 bytes remain, read the next
`[protocol][opcode]` pair; if that pair is not `0xE3` + `0x99`, log "Server search reply got
additional bogus bytes." and stop, keeping the rows already decoded; otherwise decode the
next row and repeat. The loop also ends when 2 or fewer bytes remain.

Row body = the TCP result row (`[hash 16][client_id u32][port u16][tag_count u32][tags]`);
rmule reuses one row decoder for both paths. A tail shorter than 3 bytes ends the walk
silently; a bogus continuation keeps the rows already decoded (aMule's already-added
results). Results merge into the active search session beside TCP results.

### Capture recipe (ADR-0051 capture tier — pending, needs an operator present)

rmule-stimulus search against the local eserver (`tools/interop-harness`): TCP-login,
then fire a `0x98` (Lugdunum baseline; `0x92`/`0x90` attempted per its advertised flags —
inability to advertise ExtGetFiles goes down the documented-attempt path). Record the
`0x99` reply datagram as the acceptance evidence and the golden multi-result packing
vector, pinned beside the synthetic vectors in `rmule-ed2k::server_udp` tests. Runs
on the global-search send path; do not run unattended.

## Status chain: `OP_GLOBSERVSTATREQ` (0x96) / `OP_GLOBSERVSTATRES` (0x97) — ADR-0052

**Ping** (`src/ServerList.cpp`, plain variant; the crypt-ping is ADR-0046's): a 4-byte
`0xE3`-protocol packet, opcode `0x96`, whose challenge is stored on the server record
before the send.

**Payload (`0x96`)** = `[challenge u32 LE]`, challenge = `0x55AA0000 + rand16`. The
challenge is per-server anti-spoof state: the reply must echo it or be dropped.

**Reply (`0x97`)** — `src/ServerUDPSocket.cpp` `ProcessPacket`. NOTE the threshold base:
`OnPacketReceived` hands `ProcessPacket` a memory file that starts 2 bytes into the
datagram (past the protocol byte and opcode), so every size threshold below measures the
**body** (header already stripped). The body is
progressive — each threshold adds fields, all `u32/u16 LE`:

| Body size | Fields added |
| --- | --- |
| ≥ 12 (required) | `[challenge u32][users u32][files u32]` |
| ≥ 16 | `[max_users u32]` |
| ≥ 24 | `[soft_files u32][hard_files u32]` |
| ≥ 28 | `[udp_flags u32]` |
| ≥ 32 | `[low_id_users u32]` |
| ≥ 40 | `[obf_udp_port u16][obf_tcp_port u16][server_udp_key u32]` |

Between-boundary lengths yield the thresholds they clear; bytes past 40 are ignored.
Acceptance gates (both throw-and-drop in aMule): the source must map to a known server
(`GetServerByIPUDP(ip, port, true)` — reply arrives from TCP port + 4) and
the echoed challenge must equal the one stored on that server record. On acceptance
aMule zeroes the stored challenge — one answer per ping. On a valid `0x97` aMule then
auto-fires `OP_SERVER_DESC_REQ` (0xA2) — the trigger + desc pair pinned below.

**UDP flags** (`src/include/protocol/ed2k/Client2Server/UDP.h`):

| Flag | Bit mask |
| --- | --- |
| `SRV_UDPFLG_EXT_GETSOURCES` | `0x00000001` |
| `SRV_UDPFLG_EXT_GETFILES` | `0x00000002` |
| `SRV_UDPFLG_NEWTAGS` | `0x00000008` |
| `SRV_UDPFLG_UNICODE` | `0x00000010` |
| `SRV_UDPFLG_EXT_GETSOURCES2` | `0x00000020` |
| `SRV_UDPFLG_LARGEFILES` | `0x00000100` |
| `SRV_UDPFLG_UDPOBFUSCATION` | `0x00000200` |
| `SRV_UDPFLG_TCPOBFUSCATION` | `0x00000400` |

`EXT_GETSOURCES2` gates the `0x94` get-sources upgrade; `EXT_GETFILES` +
`LARGEFILES` gate the global-search variant (ADR-0051); `UDPOBFUSCATION` + the
`server_udp_key` feed datagram crypt (ADR-0046).

### Capture recipe (ADR-0052 capture tier — pending, needs an operator present)

The acceptance evidence is a real `0x97` from the local eserver image
(`tools/interop-harness`, `rmule/interop-eserver:local` — Lugdunum answers status
pings): send one `0x96` with a logged challenge at the container's UDP port
(TCP + 4), record the reply datagram, and pin it as the golden progressive-body
vector beside the synthetic ones in `rmule-ed2k::server_udp` tests. The status-ping
sweep is the send path (a valid reply also auto-fires `0xA2`, so the same run
can capture the `0xA3` desc reply); do not run unattended.

## Status-ping sweep pacing — ADR-0052 breakdown 3

`CServerList::ServerStats()` (`src/ServerList.cpp`), called from
`CDownloadQueue::Process` (`src/DownloadQueue.cpp`) behind two gates: the UDP
socket exists and at most once per `UDPSERVERSTATTIME` = `SEC2MS(5)`
(`src/include/protocol/ed2k/Constants.h`; all constants below from there).
Each call pings **at most one server**:

The steps of one tick:

1. Take the next server from a persistent list cursor.
2. While that server was pinged less than the re-ask window ago, advance the cursor; if
   the cursor wraps back to where it started, the tick is idle and nothing is sent.
3. Mint the `0x55AA0000 + rand16` challenge and register it on the server record
   **before** the send.
4. Stamp the server's last-pinged times (one of the two stamps has a random jitter
   of up to an hour subtracted, see below) and increment its failed count.
5. Send the `0x96` packet.

- **Per-server re-ask window**: `UDPSERVSTATREASKTIME` = `HR2MS(4.5)` — a server
  pinged within 4.5 h is walked past without consuming the tick.
- **Fire-and-forget**: the failed count a non-answer leaves behind only matters
  to aMule's dead-server removal (failed count at or above the `DeadserverRetries` preference),
  which rmule does **not** transplant — its list has no health-based eviction
  (ADR-0052: a non-answer just leaves the server capability-less, retried next
  pass). Any accepted UDP reply resets the failed count.
- **Not transplanted**: the "connected to an eD2k server" gate (rmule's capability store
  feeds UDP-only consumers), and the random ping jitter (an hour's worth of
  seconds mixed into a millisecond clock — a ≤ 3.6 s no-op as aMule computes it).

rmule: `rmule-core::server_udp::StatusPingSweep` — `status_ping_tick` = 5 s,
`status_ping_reask` = 4.5 h (`CoreConfig`), challenge minted from caller-supplied
entropy (`GlobServStatReq::mint`), registered via `StatusChallenges::expect`
**before** the send, DNS-named servers walked past (no `Ipv4Endpoint` key).

## Crypt-ping arm — ADR-0046 breakdown 4

**Transplanted** (was "not transplanted" above): the obfuscation branch of
`CServerList::ServerStats` (`src/ServerList.cpp`, plain-arm cite above; obf arm
here). When server-UDP crypt is on and our public IP is known, a due server is
probed with an **obfuscated crypt-ping** before the plain fallback.

The obfuscation arm runs only when all four hold: no crypt-ping reply is already pending
for the server, the server is stale, our public IP is known, and server-UDP crypt is
enabled. Then:

| Field | Value |
| --- | --- |
| Pending flag | set on the server record |
| Packet length | `4 + rand % 16` bytes, i.e. 4 to 19 (at most 15 padding bytes) |
| Challenge | a random 32-bit value assembled from three `rand()` calls, bumped to 1 if it comes out 0 |
| Body | `[challenge u32 LE]` then random fill |
| Last-pinged time | `now - re-ask window + 20`, so the server is due again after the grace |
| Send | raw (no encryption), to the server's TCP port + 12 |

- **Raw, unencrypted**: the crypt-ping is a **raw** packet (the send is flagged raw,
  so the socket skips its server-encrypt step) — literally `[challenge u32 LE]` +
  up to 15 random padding bytes, sent to **TCP + 12** (contrast the plain `0x96` at
  TCP + 4). The challenge doubles as the RC4 **base key** the server encrypts
  its `0x97` reply under, and the value the reply's body must echo.
- **20 s grace / fallback**: the pending flag marks the probe outstanding.
  A valid `0x97` within the grace clears it; a timeout with the flag still set falls
  to the plain arm, which sends a plain `0x96`. aMule's `+ 20` on its **millisecond**
  tick clock is a unit slip (the comment says "20 seconds"); rmule models the intended
  **20 s** (`CoreConfig::crypt_ping_grace`), an ADR-0045 cite-and-correct beside
  the jitter one.
- **Reply mapping** (`GetServerByIPUDP(ip, port, bObfuscationPorts=true)`,
  `src/ServerList.cpp#L639`): a `0x97` maps back to its server three ways —
  the datagram's source port equals the server's TCP port + 4 (plain), equals its
  advertised obfuscation UDP port (encrypted data reply), or equals its TCP port + 12
  (crypt-ping reply).
- **Decrypt key** (`OnPacketReceived`, `src/ServerUDPSocket.cpp#L69`): decrypt is
  attempted when the server has a learned UDP key **and** supports UDP obfuscation,
  **or** a crypt-ping reply is pending with a non-zero stored challenge; the key is the
  crypt-ping challenge while pending, else the learned server UDP key. The plaintext
  discriminator is "first byte equals the eD2k protocol marker `0xE3`" — the server
  socket's gate, **not** the peer/Kad `is_udp_plaintext_marker` bypass set. The IP
  argument to `DecryptReceivedServer` is a debug-only parameter and goes **unused**;
  the server family key is `MD5(base_key_LE ‖ 0xA5 ‖ random_key)`, no IP (confirms the
  datagram primitive).

rmule: `StatusPingSweep::send_crypt_ping` (raw `[challenge LE][padding]` via the
transport's `SERVER_UDP_OBFUSCATION_PORT_OFFSET = 12`), `SweepState::CryptPending`
(grace) → `Pinged` (answered) or plain fallback (timeout); `ServerUdpEngine`
dual-path `receive` (`resolve_source` three-way map + `decrypt_datagram_server`
keyed on `StatusChallenges::crypt_base_key` or the store's `ServerUDPKey`, gated on
`ServerUdpFlags::supports_udp_obfuscation`). Consumes the datagram primitive
(`datagram_key_server` / `decrypt_datagram_server`) — not re-derived. Capture-gated:
`CoreConfig::server_udp_crypt()` derives from `peer_crypt` (ADR-0046;
aMule's server-UDP-crypt-enabled check reads the one crypt preference too) and is
**off by default** since `peer_crypt` is `None`; `public_ip_known` (aMule's
public-IP getter) is a shared flag the session raises on a High-ID login (the
IDCHANGE `public_ip`), wired at capture-run enablement.

### Capture recipe (ADR-0046 capture tier — pending, needs an operator present)

The crypt-ping and its encrypted `0x97` are **`[pending]`** — the server-family
byte facts (sync wire endianness, `base_key`/`random_key` hash order, the
`0x6B`/`0xA5` direction magics) are ratified only by a live capture against an
**obfuscation-capable eserver**. Recipe (beside the wire pins,
`tools/interop-harness`): run a High-ID-connected rmule with `--peer-crypt` set,
send one crypt-ping with a logged challenge to the container's TCP + 12, record the
encrypted reply datagram, and confirm it decrypts under the challenge to the golden
progressive `0x97` body — pinned beside the datagram primitive KATs. **Blocked**:
Lugdunum 17.15 crypt support is **unverified** (ADR-0046); the documented-attempt
path (image configuration, alternative build, eNode) applies if it can't advertise
`SRV_UDPFLG_UDPOBFUSCATION`. Do not run unattended.

## Server description pair: `OP_SERVER_DESC_REQ` (0xA2) / `OP_SERVER_DESC_RES` (0xA3) — ADR-0068

**Trigger + emit** (`src/ServerUDPSocket.cpp`, inside the valid-`0x97` handler):

On each valid `0x97` the handler first increments the server's desc-ping counter
(`src/Server.cpp`, the setter's boolean argument selects increment vs reset). While the
counter is below 2 it mints the challenge, stores it on the server record and sends a
4-byte `0xA2` packet; otherwise it resets the counter to 0 and sends nothing.

- **Payload (`0xA2`)** = `[challenge u32 LE]`, challenge = `(rand16 << 16) |
  0xF0FF`. `INV_SERV_DESC_LEN` `0xF0FF` sits in the **low half**, so the wire's
  first two body bytes read as the `u16 LE` `0xF0FF` — never a valid legacy
  string length, which is the reply-format discriminator.
- **Cadence**: `lastdescpingedcout` (sic) increments per valid `0x97`, the
  desc-req fires while it stays `< 2`, and the reply that reaches 2 resets it —
  so the request rides the 1st, 3rd, 5th… valid `0x97`, alternating.

**Reply (`0xA3`)** — two formats under one opcode, disambiguated by the body
being at least 8 bytes **and** its first `u16` (peeked, not consumed) equalling
`INV_SERV_DESC_LEN` = `0xF0FF` (body sizes, header stripped):

- **eserver 16.45+ tagged**: `[challenge u32][tag_count u32][tags…]` — accepted
  only when the challenge echoes the outstanding desc-request challenge, which
  is then zeroed (one answer per ask; aMule's comment pins the benign mismatch
  case: a multi-homed eserver answering twice from one IP — dropped, challenge
  kept). Tags: `ST_SERVERNAME 0x01`, `ST_DESCRIPTION 0x0B`, `ST_DYNIP 0x85`,
  `ST_VERSION 0x91` (string, or int rendered `hi16.lo16`), `ST_AUXPORTSLIST
  0x93` (`src/include/tags/ServerTags.h`); unknown tags skipped.
- **Legacy two-string**: `[len u16 LE][bytes] × 2`. aMule 2.3.3 assigns the
  **first** string via `SetDescription` and the **second** via `SetListName` —
  the reverse of the opcode comment (`<name_len 2><name …><desc_len 2 desc…>`)
  and of eMule's read order; rmule mirrors the pinned code path. No challenge
  gate in aMule beyond the known-server lookup; rmule's known set is the
  `0x97`-proven capability store, so an unproven source's legacy reply drops.

Parsed strings land as display fields on the same `ServerCapabilities` record
the `0x97` populates (one per-server store; a status re-ping preserves them).
rmule: codec `rmule-ed2k::server_udp::{ServerDescReq, ServerDescRes}`, consume
in `rmule-core::server_udp` (engine demux row `0xA3`).

## Send: `OP_GLOBGETSOURCES` (0x9A)

`src/DownloadQueue.cpp` `CDownloadQueue::SendNextUDPPacket` packs **multiple 16-byte
file hashes into one packet payload**, then sends it to a server over UDP:

| Packet | Per-file entry | Notes |
| --- | --- | --- |
| `0x9A` (basic) | `[file_hash 16]` | what E1 sends |
| `0x94` (server has `EXT_GETSOURCES2`) | `[file_hash 16][size u32]`, or `[file_hash 16][0 u32][size u64]` for a large file | E1 does **not** use this |

The packet holds at most `MAX_FILES_PER_UDP_PACKET` = 31 entries, to stay under 512 bytes.

**E1 payload (`0x9A`)** = `[file_hash 16] × N`, `N ≤ 31`. No count prefix — `payload.len() / 16`
is the count.

### The `0x94` upgrade (ADR-0052)

`SendNextUDPPacket` + `SendGlobGetSourcesUDPPacket` (`src/DownloadQueue.cpp`) pin the rules:

- **Opcode**: `0x94` when the server's UDP flags include `EXT_GETSOURCES2`, otherwise
  `0x9A` — per server, from the `0x97`-populated capability store.
- **`0x94` entry** = hash + size: the size as a `u32` for a file that fits, or the
  large-file escape — a `u32` zero followed by the size as a `u64` — for a file over
  4 GiB.
- **Large-file skip**: a large file is skipped for a server that lacks large-file UDP
  support, under either opcode (aMule logs "UDP Request for sources on a large file
  ignored").
- **Packing** (`GetMaxFilesPerUDPServerPacket`): `SRV_UDPFLG_EXT_GETSOURCES` → up to
  `MAX_FILES_PER_UDP_PACKET` (31); without it → **1 file per datagram**. (aMule additionally
  caps lifetime requests per server via `MAX_REQUESTS_PER_SERVER`; rmule's sweep cadence is
  ADR-0051's — re-ask per sweep — so that cap does not transplant.)

## Receive: `OP_GLOBFOUNDSOURCES` (0x9B)

`src/ServerUDPSocket.cpp` (`CServerUDPSocket::OnPacketReceived` → per-file parse):

For each packet aMule reads the 16-byte file hash, then looks it up in the download queue.
A known file gets the rest of the body (`[count u8]` plus `count` six-byte entries) handed
to its source-adder, tagged as a remote-server source from the datagram's origin with the
port reduced by 4. An unknown file's body is skipped: read `count`, then step over
`count × 6` bytes.

**Payload** = `[file_hash 16][count u8]` then `count × ([ip u32 LE][port u16 LE])`.
**Identical to the TCP `OP_FOUNDSOURCES` (0x42)** body — the existing `FoundSources` codec
(`crates/rmule-ed2k/src/found_sources.rs`) can be mirrored, only the opcode changes.

**Multiple files per datagram:** the receive loop continues parsing further
`[protocol byte][opcode][body]` packets while bytes remain — so one UDP datagram may carry
several `0x9B` packets (one per file). rmule decodes them with a `Packet::decode` loop over
the datagram buffer (the datagram-level analogue of the TCP `next_packet` loop).

**A Sentinel Source body must be the last in its datagram.** emule-qt
`docs/protocol/ipv6-spec.md` §4.4 says so outright: a **Sentinel Source** (ADR-0085) carries
sixteen address bytes *inline, as its record's last field*, so a legacy reader that walks a
chained datagram at the classic `count × 6` stride lands inside the address and loses every
packet behind it. rmule's reader consumes the sixteen bytes in place and stays in step either
way; the constraint is on any emitter.

The harness measured the same loss against stock aMule 2.3.3, 2026-09-16
(harness flow
`sentinel-sources-legacy --drive-legacy`, run `1789576224`), but with rmule's **earlier trailing
layout** — the sixteen bytes appended after the body's declared records, where the next packed
packet's `[0xE3][0x9B]` header would begin — so aMule read `0x3f` (the first byte of a
`3fff::/20` address) as a protocol byte, stopped, and logged:

```
!2026-09-16 16:37:15: ServerUDP: Server sources reply got additional bogus bytes.
```

The control run — the same two-packet datagram with no sentinel — had **both** bodies read.
That run's TCP `OP_FOUNDSOURCES` leg (aMule read every record) was also taken on the trailing
layout and says nothing about the inline one, which *does* shift a stock reader's records —
the reason the spec lets a server send sentinels only to a session that advertised
`SRVCAP_IPV6`. rmule has no `0x9B` **encoder** (`GlobFoundSources` decodes only), so this is
a constraint on any future emitter and on the harness's stimulus, not a bug in shipped code.

## Source IP == client_id

Each 6-byte source is `[u32 LE][u16 LE]`. For a High-ID source the `u32` is its IPv4
(High-ID *is* the IP); for Low-ID it is `< ClientId::LOW_ID_THRESHOLD`. So `PeerSource::new
(ClientId::from_u32(u32), port)` + `as_peer_endpoint()` (Some ⇔ High-ID) classifies them
exactly as `FoundSources` does. The first global-source step pooled the High-ID ones and
dropped the Low-ID ones (no per-server callback until the send below).

## Send: `OP_GLOBCALLBACKREQ` (0x9C)

rmule (High-ID, with a bound inbound listener) asks a Low-ID global source's **own
source-server**, over UDP, to relay a callback so that Low-ID peer dials rmule back. The
source-server is one rmule is *not* logged into (global source discovery found the source there), so unlike
the connected-server TCP `OP_CALLBACKREQUEST` (0x1C, `<low_id u32>` only), the global UDP
request must **self-report rmule's own contact** — the server has no TCP session to learn it
from.

**Payload** = `[ip u32][port u16 LE][client_id u32 LE]` — pinned three ways:

- aMule `src/include/protocol/ed2k/Client2Server/UDP.h`: the header's own comment on
  the `0x9C` opcode gives the layout as a 4-byte IP, a 2-byte port and a 4-byte client
  id. aMule *defines* the opcode but has **no send site** — it is not in
  `DownloadQueue.cpp`, `ServerSocket.cpp`, or `amule.cpp`; eMule originates these, aMule
  only receives the inbound side. Cite-and-rewrite only (ADR-0004).
- Wireshark `epan/dissectors/packet-edonkey.c`: the UDP callback-request case reads an
  "Address" (4-byte IP plus 2-byte LE port, via `dissect_edonkey_address`) and then the
  4-byte client ID.
- The IP-plus-port Address is the same shape as the `0xA0` `OP_SERVER_LIST_REQ` payload in
  the same header, and matches rmule's `Ipv4Endpoint` (`[oct0..3][port_lo][port_hi]`,
  `WIRE_LEN = 6`).

So the wire body is exactly `Ipv4Endpoint::encode(rmule's own ip+listen-port)` ++
`target_low_id.as_u32().to_le_bytes()`:

- `[ip u32]` — rmule's **own** public IP. For a High-ID client this equals its connected-
  server-assigned client-id rendered as the 4 IP octets in order (the same ip-as-u32 the
  `OP_GLOBFOUNDSOURCES` decoder reads back); on the wire it is the 4 octets `a.b.c.d`.
- `[port u16 LE]` — rmule's **own** advertised TCP listen port (the bound inbound listener).
- `[client_id u32 LE]` — the **target** Low-ID source's server-assigned id (the one E1 decoded
  from this server's `OP_GLOBFOUNDSOURCES`).

**Loopback fidelity:** because the port rides in the payload (not inferred from the datagram
source), a deterministic fake source-server learns rmule's exact listener endpoint and triggers
the Low-ID peer to dial it — no port guessing, high fidelity (the Correctness-Tier loopback).
The runner enacting the send must therefore thread rmule's own `(ip, listen_port)` into the
request (the Low-ID callback spike's connected-server callback never needed this — the server filled it from the
TCP session).

**Failure path:** the UDP callback-fail is `OP_INVALID_LOWID` (`0x9E`, body `[id 4]`) — it *carries*
the failed low-id (unlike the TCP `OP_CALLBACK_FAIL` 0x36, which is id-less). Decoding `0x9E`
for precise slot release is available but **deferred**: as in the Low-ID callback spike, the per-callback timeout
(ADR-0039) is the slot-release workhorse; the request is fire-and-forget.

## Deferred

The `OP_INVALID_LOWID` (0x9E) precise callback-fail decode (timeout suffices). The
status-ping pair (0x96/0x97), the `0x94` get-sources upgrade, and the
status sweep pacing + desc pair are no longer deferred — pinned above.
