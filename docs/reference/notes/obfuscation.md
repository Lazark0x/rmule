# Protocol obfuscation

**Status:** active (2026-07-06 decision, ADR-0042) — unparked from the evidence wall
([ADR-0041](../../adr/0041-secure-user-identification-and-credit.md)).
The park reason was "no obfuscated-handshake capture and no capture pipeline"; the
`amule-direct-sui` interop harness plus the raw-socket capture sidecar
(`tools/interop-harness/images/capture`) now make one reachable, and a source read of
aMule `EncryptedStreamSocket.cpp` @`377ec8d9` gives the full byte layout — the same
"source beats the spec PDF" move that corrected four SUI facts. Phase-2 ring of
[ADR-0047](../../adr/0047-honest-capability-advertisement.md),
sequenced after SUI/credit.

**Scope:** the eMule crypt layer that RC4-streams TCP packet bytes after a
byte-0-discriminated handshake, hiding the eD2k protocol byte from middleboxes that
throttle or block eD2k. **In scope:** client↔client (peer) TCP and client↔server TCP.
**The UDP surfaces** — server-UDP and Kad-UDP — use a different **stateless
per-datagram** scheme, once out of scope here and now specced by
[ADR-0046](../../adr/0046-per-datagram-udp-obfuscation-layer.md); its facts are
pinned in "Per-datagram UDP obfuscation" below. It is not confidentiality — it defeats
protocol fingerprinting only — and is independent of Secure User Identification (a new
capability word, not the SUI nibble).

Each fact is tagged by source confidence, matching `secure-ident.md`:
- **[aMule]** — read from aMule source @`377ec8d9` (behavioral oracle; rewritten, never
  ported — ADR-0004).
- **[pending]** — byte layout is source-read but **not yet confirmed byte-for-byte**
  against a capture. The peer decrypt-vector and the server live-interop are the gates
  (see Evidence ladder). Treat every magic value / offset / prime below as `[pending]`.

## The two forms

Both forms share an RC4 stream (RC4-drop1024), a `MAGICVALUE_SYNC` confirmation, random
padding, and byte-0 discrimination. They differ only in the **handshake** and the **RC4
key basis**:

- **Peer (client↔client)** — the key basis is the *target client's* **User Hash**, a
  secret both ends already hold (the initiator learned it from the source; the receiver
  uses its own). One-shot: keys are derivable from the first 5 plaintext bytes.
- **Server (client↔server)** — client and server share no prior secret, so they agree
  one by **768-bit Diffie-Hellman**. Two-shot: keys are derivable only after both public
  values are exchanged.

## Magic constants [aMule `EncryptedStreamSocket.h`] [captured — peer, 2026-07-07]

| Constant | Value | Role |
|---|---|---|
| `MAGICVALUE_REQUESTER` | `34` (`0x22`) | key-derivation magic, initiator/client→peer/server direction |
| `MAGICVALUE_SERVER` | `203` (`0xCB`) | key-derivation magic, responder/server→client direction |
| `MAGICVALUE_SYNC` | `0x835E6FC4` | RC4-encrypted in the handshake to confirm both ends derived matching keys |
| `ENM_OBFUSCATION` | `0` | the only defined encryption method |

The **peer** values are `[captured]`: a live rmule↔aMule 2.3.3 obfuscated handshake
completed under `--obfuscation required` (both directions), and aMule's real reply
decrypts to `MAGICVALUE_SYNC` under `MD5(user_hash ‖ 203 ‖ random_key)` — see
"Capture confirmations" below. The server (DH) form stays `[pending]`.

## Byte-0 discrimination [aMule `EncryptedStreamSocket.cpp`, `ClientTCPSocket.cpp`] [captured — peer, 2026-07-07]

On an accepted TCP connection, the first byte classifies the stream:

- `0xE3` (`OP_EDONKEYPROT`), `0xC5` (`OP_EMULEPROT`), `0xD4` (`OP_PACKEDPROT`) → **plaintext**
  (existing path, untouched).
- anything else → **obfuscated handshake**.

The initiator's `SemiRandomNotProtocolMarker` byte is drawn (up to 128 tries via
`GetRandomUint8()`) to avoid those three values, so the classification never collides.
Every legitimate eD2k/eMule *TCP* frame starts with one of the three, so plaintext stays
a pure superset.

## Peer handshake (client↔client) [aMule `EncryptedStreamSocket.cpp`] [captured 2026-07-07]

Initiator (A) → responder (B):

```
[SemiRandomMarker      1  plain]
[RandomKeyPart         4  plain]
[MAGICVALUE_SYNC       4  encrypted]
[MethodsSupported      1  encrypted]   // bitmask, ENM_OBFUSCATION=0
[MethodPreferred       1  encrypted]   // 0
[PaddingLen            1  encrypted]
[Padding      PaddingLen  encrypted]   // random, discarded
```

Responder (B) → initiator (A):

```
[MAGICVALUE_SYNC       4  encrypted]
[MethodsSelected       1  encrypted]
[PaddingLen            1  encrypted]
[Padding      PaddingLen  encrypted]
```

**RC4 keys** — `UserHashB` is the responder's (target's) 16-byte **User Hash**;
`RandomKeyPart` is the 4 plaintext bytes A sent. Each key discards the first 1024 RC4
keystream bytes (RC4-drop1024).

```
outgoing (A):  send = RC4(MD5(UserHashB[16] ‖ 34  ‖ RandomKeyPart[4]))
               recv = RC4(MD5(UserHashB[16] ‖ 203 ‖ RandomKeyPart[4]))
incoming (B):  send = RC4(MD5(UserHashB[16] ‖ 203 ‖ RandomKeyPart[4]))   // magics swapped
               recv = RC4(MD5(UserHashB[16] ‖ 34  ‖ RandomKeyPart[4]))
```

The initiator needs `UserHashB` **before dialing** → outbound obfuscation is gated on
source provenance (see below). The responder uses its own User Hash → inbound accept
needs no external data.

## Server handshake (client↔server) [aMule `EncryptedStreamSocket.cpp`, `ServerConnect.cpp`] [pending]

768-bit Diffie–Hellman, `g = 2`, hardcoded prime `dh768_p`, `PRIMESIZE_BYTES = 96`. `A =
g^a mod p`, `B = g^b mod p`, shared secret `S = B^a mod p = g^(ab) mod p` (96 bytes).

Client → server:

```
[SemiRandomMarker      1   plain]
[G^A                  96   plain]
[RandomBytes        0-15   plain]
```

Server → client:

```
[G^B                  96   plain]
[MAGICVALUE_SYNC       4   encrypted]
[MethodsSupported      1   encrypted]
[MethodPreferred       1   encrypted]
[PaddingLen            1   encrypted]
[Padding      PaddingLen   encrypted]
```

Client → server:

```
[MAGICVALUE_SYNC       4   encrypted]
[MethodsSelected       1   encrypted]
[PaddingLen            1   encrypted]
[Padding      PaddingLen   encrypted]
```

**RC4 keys** — same magics, keyed on the 96-byte DH secret `S` instead of a User Hash:

```
client:  send = RC4(MD5(S[96] ‖ 34)),   recv = RC4(MD5(S[96] ‖ 203))
server:  send = RC4(MD5(S[96] ‖ 203)),  recv = RC4(MD5(S[96] ‖ 34))    // swapped
```

Because `S` is a DH secret, a **passive** third-party capture cannot recompute the key —
the server byte-compat proof must have rmule as a live participant (contrast the peer
form, whose vector is passively verifiable).

## Policy and config [aMule `ServerConnect.cpp`] [pending]

eMule exposes three cumulative flags — `IsClientCryptLayerSupported` /
`…Requested` / `…Required` — advertised to servers as `SRVCAP_SUPPORTCRYPT` /
`SRVCAP_REQUESTCRYPT` / `SRVCAP_REQUIRECRYPT`. rmule models the ladder as a four-state
**Obfuscation Policy**:

| State | Accept obfuscated inbound | Initiate obfuscated | Accept plaintext inbound |
|---|---|---|---|
| `Disabled` | no (undecodable → violation) | no | yes |
| `Supported` | yes | no | yes |
| `Requested` | yes | yes; a server connect **falls back to plaintext** on failure, a peer dial does not (ADR-0049) | yes |
| `Required` | yes | yes, no fallback | **no** |

Server-connection fallback is source-confirmed: on a failed obfuscated connect when the
policy is not `Required`, eMule retries the same server with `bNoCrypt = true`.

## Source-provenance gate (outbound peer)

`PeerSource` carries only `{client_id, tcp_port}` today — no User Hash. So:

- Server-lookup sources (`OP_FOUNDSOURCES`, IP+port only) can **never** be
  obfuscate-dialed — plaintext by protocol necessity, in eMule too.
- Source-exchange (`OP_ANSWERSOURCES` v≥2) and Kad sources carry a User Hash + a
  crypt-options byte → those can be obfuscate-dialed once threaded onto the candidate.
  Kad is parked, so rmule's obfuscate-dial coverage is source-exchange only.

## rmule realization (ADR-0042)

Three layers, no new crate:

- **`rmule-primitives`** (wrapped per ADR-0012): `Rc4` (keystream + drop-1024), MD5 wrap
  (`md-5`), `ObfuscationDhKeypair` over `dh768_p` (`crypto-bigint` `U768`), peer key
  derivation (binds **User Hash** → sits next to it and the SUI keypair), magic
  constants. No RustCrypto type in a public API.
- **`rmule-net-runtime`**: `CryptStream<S, H: ObfuscationTransport>` — byte-0 sniff +
  buffer + drive `H` + per-chunk transform. Protocol- and cipher-agnostic, so it stays
  a tokio-only leaf and plugs into the existing `spawn<S: AsyncRead + AsyncWrite>` seam.
- **`rmule-peer` / `rmule-ed2k`**: the two `ObfuscationTransport` impls (peer one-shot /
  server DH two-shot), each owning its `Rc4` pair.
- **Config**: `ConnectOptions.obfuscation: Option<ObfuscationConfig>` in each `-net`
  crate (mirrors `secure_ident`). Crypt support advertised in a new `MiscOptions2` word
  (bits `[pending]`), lit only once inbound-accept is real (ADR-0047 honest
  advertisement). The crypt handshake runs below the session, so it needs its own short
  deadline lest it eat the hello budget.

Slice order: inbound-accept (tracer) → server obfs → source-exchange crypt plumbing →
outbound peer initiate.

## Evidence ladder and the two direction traps

1. **Primitive vectors** — RC4 KAT + drop-1024, MD5, DH round-trip, and the peer keys
   asserted as *distinct exact bytes* for magic 34 vs 203.
2. **Handshake state machines** (sans-I/O) — byte-0 both ways; adversarial paths (wrong
   User Hash → `SYNC` mismatch; `Required` + plaintext inbound → reject; `Disabled` +
   obfuscated → violation).
3. **CryptStream transport** — two wrappers over a `tokio::io::duplex`, **opposite
   roles**, real handshake, app bytes cross intact.
4. **Captured decrypt-vector** (peer, `[pending]→[captured]` gate) — a real aMule
   handshake `(RandomKeyPart, ciphertext, known UserHash)` that rmule decrypts to
   `MAGICVALUE_SYNC`; committed fixture + byte-flip vacuity guard.
5. **Real-aMule interop** — peer: `amule-direct-obfs` scenario (aMule crypt keys on, raw
   tcpdump sidecar for pre-framing bytes). Server: a live rmule handshake against an
   obfuscation-capable eserver (no static vector — DH is not passively recomputable).

The ladder exists to defeat two traps (the SUI "self-consistent ≠ aMule-compatible"
lesson generalized):

- **Relative-direction trap** — a symmetric loopback with one shared key round-trips even
  with send/recv flipped. Rungs 1+3 defeat it: derive with the real 34/203 split and
  assert cross decryption **and** intra-side key distinctness.
- **Absolute-direction trap** — even a correct asymmetric rmule↔rmule loopback only
  proves self-consistency; flipping 34↔203 on both sides still passes while rmule↔aMule
  fails. Only rungs 4/5 pin the absolute magic assignment against aMule's real bytes.

## Per-datagram UDP obfuscation (ADR-0046) [aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`] [pending]

A **stateless** scheme, unrelated to the stream handshake above: each datagram carries
its own 2-byte random key seed in the clear and derives a fresh RC4 key per packet.
Source-read from aMule `src/EncryptedDatagramSocket.cpp`
@`4e8f2b3c3f90cda23765730546b04c684a92e4f5` (cite-and-rewrite, ADR-0004); every value is
`[pending]` until an ADR-0046 capture confirms it byte-for-byte. Two crucial differences
from the stream form:

- **No RC4-drop1024.** aMule skips the 1024-byte keystream discard on UDP keys "to save
  CPU time" — the datagram key uses `Rc4::new` (undropped), not `with_drop_1024`.
- **Per-packet key seed.** A `RandomKeyPart` (`uint16`, `GetRandomUint16()`) rides in the
  clear at bytes `[1..3]` and is mixed into every key derivation, so no two packets share
  a key even under one family.

### On-wire layout

Client (peer/Kad) datagram (`EncryptSendClient` / `DecryptReceivedClient`):

```
[0]        SemiRandomNotProtocolMarker   1  plain   // low 2 bits = key family
[1..3]     RandomKeyPart                 2  plain   // uint16 LE
--- RC4(key) from here ---
[3..7]     MAGICVALUE_UDP_SYNC_CLIENT     4  enc
[7]        PaddingLen                     1  enc
[8..]      Padding                 PadLen  enc
(Kad only) ReceiverVerifyKey              4  enc
(Kad only) SenderVerifyKey                4  enc
[..]       Payload                        *  enc
```

Server datagram (`EncryptSendServer` / `DecryptReceivedServer`) is identical minus the
verify-key trailer, and uses `MAGICVALUE_UDP_SYNC_SERVER`. `CRYPT_HEADER_WITHOUTPADDING =
8` (marker 1 + key 2 + sync 4 + padlen 1).

### Four key families — RC4 key = `RC4(MD5(…))`, no discard

| Family | MD5 input (concatenation order) | marker bits |
|---|---|---|
| ed2k client | `user_hash[16] ‖ sender_ip[4] ‖ MAGICVALUE_UDP ‖ random_key[2]` (IPv4, 23 bytes); `user_hash[16] ‖ sender_ip6[16] ‖ MAGICVALUE_UDP ‖ random_key[2]` (IPv6, 35 bytes, ADR-0087) | `1` |
| Kad NodeID | `kad_id[16] ‖ random_key[2]` | `0` |
| Kad verify key | `receiver_verify_key[4] ‖ random_key[2]` | `2` |
| server | `base_key[4] ‖ direction_magic ‖ random_key[2]` | — (socket-dispatched) |

`base_key` is the `ServerUDPKey` learned from `OP_GLOBSERVSTATRES` (server-udp.md), or the
crypt-ping challenge for a status-ping reply. `direction_magic` is
`MAGICVALUE_UDP_CLIENTSERVER` for client→server, `MAGICVALUE_UDP_SERVERCLIENT` for
server→client. The ed2k `sender_ip` is the sender's own public IP (the receiver recomputes
with the datagram's source IP). Integers are hashed little-endian (`[pending]` — the wire
byte order is a capture gate).

**IPv6 ed2k key — eMuleAI diverges** [source-read, eMuleAI `a2f05dc8`, emule-qt `73fff714`].
The 35-byte layout is emule-qt's (`src/core/net/EncryptedDatagramSocket.cpp:129-134` receive,
`:241-246` send): magic at offset 32, after the sixteen address bytes. eMuleAI
(`srchybrid/EncryptedDatagramSocket.cpp:227-234` receive, `:338-346` send) keeps the IPv4
statement order — `achKeyData[20] = MAGICVALUE_UDP`, then a 16-byte address `memcpy` at 16 that
overwrites it — and never writes offset 32 of its uninitialised `achKeyData[35]`. Its key
equals emule-qt's everywhere but offset 32, which holds whatever the stack did; the two agree
only when that byte is `0x5B`. rmule derives emule-qt's key only (no receiver can match an
unwritten byte), and counts an obfuscated IPv6 datagram its key did not open
(`ipv6_undecryptable_datagrams_total`). Upstream fix: write offset 32.
Pinned by `datagram_obfuscation::ipv6_key_kat`.

### Magic constants

| Constant | Value | Role |
|---|---|---|
| `MAGICVALUE_UDP` | `0x5B` | ed2k client key magic |
| `MAGICVALUE_UDP_CLIENTSERVER` | `0x6B` | server key magic, client→server |
| `MAGICVALUE_UDP_SERVERCLIENT` | `0xA5` | server key magic, server→client |
| `MAGICVALUE_UDP_SYNC_CLIENT` | `0x395F2EC1` | encrypted header sync, peer/Kad datagrams |
| `MAGICVALUE_UDP_SYNC_SERVER` | `0x13EF24D5` | encrypted header sync, server datagrams |

The sync word identifies the crypt scheme (client vs server); the key magic distinguishes
direction. Decryption succeeds only when the decrypted header word equals the expected
sync (a ≈2⁻³² false-accept guard against wrong-key / garbage datagrams).

### Marker bits and the plaintext-bypass set

- **Family select (receive):** `bufIn[0] & 0x03` picks the first key family to try —
  `0`=Kad NodeID, `1`=ed2k, `2`=Kad receiver-verify-key, with `3` folding onto ed2k (1).
  The dual-path receive then tries the remaining held keys in order (sync-word gated).
- **Plaintext bypass (receive):** a first byte in `{0xC5, 0xE4, 0xE5, 0xD4, 0xA3, 0xB2}`
  (`OP_EMULEPROT`, `OP_KADEMLIAHEADER`, `OP_KADEMLIAPACKEDPROT`, `OP_PACKEDPROT`,
  `OP_UDPRESERVEDPROT1`, `OP_UDPRESERVEDPROT2`) is passed through untouched at any policy —
  note this differs from the *TCP* set (no `0xE3`; adds the two Kad + two reserved
  markers). Send draws the marker clear of this set, then OR's the family bits.

### The `+12` server obfuscation UDP port offset

An obfuscated status ping targets the server's **TCP port + 12** (contrast the plain
`0x96` ping at TCP + 4). `[aMule ServerList.cpp#L314, matched via #L646]`. Part of the
server family; consumed by the crypt-ping arm of `StatusPingSweep`, not the
primitive.

### rmule realization: the datagram primitive [pending]

`rmule-primitives::datagram_obfuscation` (beside the stream `obfuscation` module, no new
crate — ADR-0046's "socket-agnostic wrapper" home): the four `datagram_key_*` derivations
(reusing the undropped `Rc4::new`), `encrypt_datagram_client` / `decrypt_datagram_client`
(dual-path, marker-bit try order, verify-key trailer), `encrypt_datagram_server` /
`decrypt_datagram_server`, `is_udp_plaintext_marker`, and `marker_family`. Randomness
(marker byte, key seed, padding) is injected via `DatagramNonce` for deterministic tests
(the `fn() -> u16` entropy-seam pattern). Deterministic tier only: per-family KATs
(MD5-order oracles), crossed-role loopbacks, plaintext-bypass, key-try-order,
garbage-datagram, and the two direction traps (symmetric-key + derivation-flip). The
`[pending]` byte facts (sync wire endianness, IP/key hash order, the 34/203-analogue
absolute direction) are ratified by the ADR-0046 captures — Kad-UDP, peer-UDP,
and server-UDP (an obfuscation-capable eserver, still unproven) — not by these tests.

### Kad-UDP surface [pending]

`rmule_kad::KadNode` consumes the datagram primitive at its sans-I/O seam — the driver
(`rmule-kad-net`) stays a pure byte-mover (its `CONTEXT.md` contract; the crypt-ping precedent
put server-UDP crypt in the protocol engine, not the socket loop). Receive is dual-path in
`handle_datagram`, always on like aMule's `DecryptReceivedClient`: a datagram is
trial-decrypted keyed on this node's **own Kad ID** (the KadNodeId family, marker bits `0`),
a plaintext `0xE4`/`0xE5` first byte bypasses, a miss falls through to plaintext decode.
Send-encrypt (`enable_datagram_obfuscation`) keys on the **recipient contact's Kad ID** —
aMule's `SendPacket` keys on the target's client ID and the recipient decrypts with its own
— and is **capture-gated off by default** (the crypt-ping posture): production stays plaintext until
the byte facts are ratified and per-contact crypt-support tracking (ADR-0058 verify-key
state) lands. The Kad verify-key family (marker bits `2`) and the ed2k user-hash family are
deliberately absent on this socket (own verify-key state is ADR-0058; the user-hash family
is the peer-UDP socket's). The per-packet `DatagramNonce` is injected — the driver supplies
OS entropy, tests a fixed nonce. Deterministic tier only (`tests/kad_udp_crypt.rs`):
dual-path dispatch parity (a crypt ping/bootstrap drives the same response as its plaintext
twin), not-for-us / garbage rejection, and send-encrypt keyed on the recipient Kad ID
round-tripping to the exact plaintext with a wrong-key trap.

**ADR-0062 — `0x4C` dormant emit hook.** `on_publish_res` models aMule's
`Process2PublishResponse` ack: a null-payload `KADEMLIA2_PUBLISH_RES_ACK` (`0x4C`) iff the
storer's `0x4B` set options bit 0 **and** a crypt sender key is held. `crypt_sender_key`
returns `None` — the dual-path receive decrypts but drops the recovered crypt provenance
before dispatch — so the ack provably never emits on the plain path (byte-identical to aMule
2.3.3's empty `senderKey`). The later slice that threads received crypt provenance
implements `crypt_sender_key` and activates the emit.

### Kad-UDP crypt capture recipe (ADR-0046 capture tier — pending, needs an operator present)

The Kad datagram byte facts stay **`[pending]`**: the deterministic tests lock rmule's
scheme as internally consistent (crossed-role loopbacks, wrong-key traps) but a mesh-sim /
`FakeKadPeer` vector is rmule-authored and can never prove the gate (`rmule-kad CONTEXT.md`,
"Private Kad Transcript"). The ratifying capture is a **real aMule 2.3.3 with Kad crypt
enabled** emitting an encrypted Kad datagram to a seeded rmule **Kad Stimulus Node** (the
ADR-0043 counterparty machinery): pin its bytes and confirm they decrypt under
`MD5(our_kad_id ‖ random_key)` with no drop-1024, and that its verify-key trailer is echoed
back. Not offline/deterministic (needs a live aMule plus Kad seeding), so it is not run
here — the deterministic integration KATs ship and this recipe records the remaining step.

### Peer-UDP surface [pending]

`rmule_core::client_udp::PeerUdpCrypt` consumes the datagram primitive at the shared client-UDP
demux front (ADR-0057), the peer-UDP sibling of the Kad-UDP crypt — same dual-path
discipline, different key family. It keys the **ed2k user-hash family** (`MAGICVALUE_UDP`,
marker bits `1`) — `MD5(user_hash ‖ sender_ip ‖ MAGICVALUE_UDP ‖ random_key)` — this surface's
own; the Kad NodeID / verify-key families are the Kad socket's and are deliberately absent
here, exactly as the ed2k family is absent there. Receive is dual-path in
`ClientUdpEngine::demux`, always on when armed like aMule's `DecryptReceivedClient`: a
datagram is trial-decrypted keyed on **our own user hash + the datagram's UDP source IP** (a
counterparty encrypts its reply to us on our hash + its own sender IP, so we decrypt with our
hash + the IP it arrived from), a plaintext-marker first byte bypasses, and a miss (garbage /
another peer's hash) falls through to the plaintext demux which diagnoses it — the recovered
inner packet re-demuxes by its own `0xC5` protocol + opcode. Send-encrypt
(`encrypt_client_udp_reply`) keys on the **target peer's user hash + our own public IP**, and
send-gates per ADR-0046: encrypt only when armed **and** the target's hash is known,
otherwise plaintext. Capture-gated **off by default** (the crypt-ping and Kad-UDP posture): the engine
holds `None`, so production stays plaintext until the byte facts are ratified; the live arming
and the `SendClientUdp` send-gate wiring (the ServeState reask resolver supplies the resolved
waiter's user hash as the target) ride the same socket-unification step as the front's live
spawn. The per-packet `DatagramNonce` is injected — a live send draws OS entropy, tests a
fixed one. Deterministic tier only (`client_udp.rs` tests): dual-path dispatch (a crypt reask
ping/reply decrypts and re-demuxes to the same inbox as its plaintext twin, plaintext still
bypasses), wrong-hash / garbage rejection, and the send-gate's arm/known-target round-trip to
the exact plaintext.

### Peer-UDP crypt capture recipe (ADR-0046 capture tier — pending, needs an operator present)

The peer-UDP datagram byte facts stay **`[pending]`**: the deterministic tests lock rmule's
scheme as internally consistent (crossed-role round-trip, wrong-key trap) but a self-authored
vector can never prove aMule compatibility. The ratifying capture is the ADR-0046 evidence
line: a **real aMule 2.3.3** peer, a TCP session first so the user hash + crypt advert are
exchanged, then a **UDP reask** — aMule's encrypted reply datagram is the evidence. Pin its
bytes and confirm they decrypt under `MD5(our_user_hash ‖ its_sender_ip ‖ 0x5B ‖ random_key)`
with no drop-1024, guarded by a byte-flip vacuity check. Not offline/deterministic (needs a
live aMule peer plus a hash/crypt-advert TCP handshake), so it is not run here — the
deterministic integration KATs ship and this recipe records the remaining step.

## Sources

- aMule GPLv2 @`4e8f2b3c` (link-only, ADR-0013): `src/EncryptedDatagramSocket.cpp`
  (per-datagram RC4, four key families, marker bits, bypass set, sync magics, verify-key
  trailer), `src/ServerList.cpp` (`+12` obfuscated-ping port offset).
- aMule GPLv2 @`377ec8d9` (link-only, ADR-0013): `src/EncryptedStreamSocket.cpp` /
  `.h` (handshake layouts, key derivation, magics, byte-0, DH), `src/ServerConnect.cpp`
  (crypt-flag gating + plaintext retry), `src/ClientTCPSocket.cpp` (peer accept path).
  The `dh768_p` prime bytes are a public constant reproduced under the same `[pending]`
  gate as every other byte fact.
- `docs/reference/emule-spec/emule_protocol_specification.pdf` — **predates obfuscation
  entirely**; not a reference for this topic (recorded in the source map).

## Implementation status (2026-07-07)

The obfuscation **code** is complete and the **peer** form is `[captured]` — a live
rmule↔aMule 2.3.3 interop passed. What ships:

- **Peer + server crypto/transport**: RC4 primitives, both handshakes,
  `CryptStream`, byte-0 discrimination, the four-state policy, inbound accept, server
  obfuscated-connect.
- **Outbound peer initiate + source crypt plumbing**: `AnswerSources` decodes
  the per-source User Hash (v≥2) + crypt-options byte (v4) via a version-parameterized
  entry codec, aMule-exact-validated against the cross-check version rather than inferred
  from geometry alone (ADR-0055); `ExchangedSource`/`SourceCryptOptions` carry them;
  `DownloadState` remembers the dial target; `Connection::connect` obfuscate-dials via the
  initiator (its plaintext fallback retired, ADR-0049). Still `[pending]`: aMule's v3+ `dwID` hybrid byte-swap
  is now implemented (source-read) but not exercised by the peer-handshake capture; the
  advertised source-exchange version stays **v1** until that and the wider strides are
  capture-confirmed.
- **`MiscOptions2` crypt advert**: `MiscOptions2` (rmule-peer) packs the crypt
  bits; the policy is threaded → session → hello. Still `[pending]` — the peer capture had
  rmule *dial* aMule, so aMule never read rmule's advert; confirming it needs aMule to
  obfuscate-dial rmule based on the advert.
- **`amule-direct-obfs` interop + responder vector**: `rmule-tools ed2k peer transfer
  capture` gained `--obfuscation`/`--obfuscation-target-hash`; the `amule-direct-sui`
  scenario grew `--obfuscation <policy>` (learn-then-dial). The captured decrypt-vector is
  `crates/rmule-peer/tests/fixtures/amule_obfs_responder_reply.bin` +
  `tests/obfuscation_capture.rs`.

## Capture confirmations (2026-07-07) — peer form `[pending]→[captured]`

A live rmule↔aMule 2.3.3 obfuscated handshake **completed** under `--obfuscation required`
(no plaintext fallback), proving rmule's *absolute* 34/203 derivation is aMule-compatible —
the anchor a rmule↔rmule loopback cannot provide. Evidence, both directions:

- **Initiator (rmule→aMule, magic 34)**: aMule accepted rmule's obfuscated opening and the
  full session (hello + SUI) completed through the crypt layer (`peer identity_verified`).
- **Responder (aMule→rmule, magic 203)**: aMule's real encrypted reply decrypts to
  `MAGICVALUE_SYNC` under `MD5(user_hash ‖ 203 ‖ random_key)` + RC4-drop1024 — the committed
  responder fixture, verified in `cargo test` with no live aMule.

Every peer fact — the 34/203 split, `MD5(user_hash ‖ magic ‖ random_key)` key order,
`MAGICVALUE_SYNC = 0x835E6FC4` little-endian, RC4-drop1024, and the handshake structure —
matched aMule byte-for-byte; **no corrections needed** (contrast the SUI capture's four).

**Harness finding:** aMule 2.3.3 **ignores a pre-set `amule.conf` `UserHash`** and generates
its own at runtime, so the obfuscation target hash cannot be pinned. The scenario learns it
from a plaintext hello first (`--obfuscation <policy>` on `amule-direct-sui` does this), then
obfuscate-dials. The plaintext probe runs *without* SUI so it binds no key that would trip
aMule's SUI anti-theft on the real obfuscated dial.

**Still to capture:** the server (DH) form (needs an obfuscation-capable eserver); the
`MiscOptions2` advert (needs aMule to obfuscate-dial rmule); the source-exchange v4 stride.

## Open questions ([pending] facts to lock at capture)

- Peer: confirm the exact byte order, `MAGICVALUE_SYNC`, the 34/203 assignment, and the
  drop-1024 against a captured aMule handshake (the peer decrypt-vector, rung 4). The
  handshake state machine + keygen are implemented; the capture ratifies the absolute
  direction the rmule↔rmule loopback cannot.
- Server: confirm `dh768_p`, `PRIMESIZE_BYTES = 96`, and the DH key derivation against a
  live handshake with an obfuscation-capable eserver (rung 5) — the evidence source still
  to be stood up.
- **`MiscOptions2` crypt advertisement** [aMule `BaseClient.cpp` @`377ec8d9`, source-read
  2026-07-06, byte-compat `[pending]`]: **implemented** in `MiscOptions2` (crypt bits 7/8/9,
  tag `0x55`, dependency rule `requests &= supports; requires &= requests`) and threaded
  policy → session → hello. Still `[pending]`: the tag id `0x55` and the bit offsets — a
  wrong id/bit just means a real aMule does not obfuscate-dial rmule, which the capture
  observes directly.
- The source-exchange crypt-options byte layout (v4 stride 29, crypt bits 0/1/2 =
  supports/requests/requires) and the v3+ `dwID` hybrid byte-swap are **implemented** in
  the version-parameterized `AnswerSources`/`AnswerSources2` codec (ADR-0055),
  `[pending]` until the capture confirms both against a real SX2 exchange.
