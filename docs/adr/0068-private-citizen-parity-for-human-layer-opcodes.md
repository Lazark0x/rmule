# Human-layer opcodes answer as aMule at its most private setting (Private-Citizen Parity)

## Context

eD2k carries a human layer that rmule has no feature for: server descriptions, chat,
chat captchas, file comments, shared-file and shared-directory browsing, the public-IP
request, and the client-ID change notice. The catalog:

- server UDP: `OP_SERVER_DESC_REQ 0xA2` / `OP_SERVER_DESC_RES 0xA3`;
- peer TCP: `OP_MESSAGE 0x4E`, `OP_CHATCAPTCHAREQ 0xA5` / `RES 0xA6`, `OP_FILEDESC
  0x61` (`0xC5`), shared-files browse `0x4A` / `0x4B`, shared-dirs browse
  `0x5D` / `0x5E` / `0x5F` / `0x60` / `0x61` (`0xE3`), `OP_PUBLICIP_REQ 0x97` /
  `ANSWER 0x98`, `OP_CHANGE_CLIENT_ID 0x4D`.

Decoding these as unknown packets (ADR-0018) is graceful by accident, cannot be named
in tests or counters, and is silent where aMule answers. ADR-0063's Empty-Storer
Parity sets the doctrine for Kad notes: send only bytes that a legitimate aMule in a
legitimate degenerate state sends. This ADR applies the same doctrine to the human
layer.

Upstream citations are aMule at `4e8f2b3c3f90cda23765730546b04c684a92e4f5`. Evidence,
per ADR-0045's graceful tier: deterministic decode, emit and silence vectors, plus a
genuine eserver tagged description reply at
`crates/rmule-ed2k/tests/fixtures/server/captured/lugdunum-server-udp-20260726/desc_res_0xA3.bin`.

## Decision

rmule handles the human-layer catalog under **Private-Citizen Parity**: it behaves
byte-exact as an aMule 2.3.3 client with every human-layer feature at its most private
setting — `CanSeeShares = nobody`, no comments or ratings, chat received but never
answered. Every byte rmule sends, and every silence, is one some legitimate aMule
client produces, so invented bytes are impossible by construction. Each row's response
comes from the pinned source's code path for that configuration, which yields three
classes.

**Respond by parity** (aMule answers even at maximum privacy):

- **Browse requests** `OP_ASKSHAREDFILES 0x4A`, `OP_ASKSHAREDDIRS 0x5D`,
  `OP_ASKSHAREDFILESDIR 0x5E` → `OP_ASKSHAREDDENIEDANS 0x61` (`0xE3`), the
  `CanSeeShares == nobody` path of each browse handler
  ([ClientTCPSocket.cpp#L829](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L829),
  [#L883](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L883),
  [#L912](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L912)).
  The most private aMule refuses explicitly; it does not go silent.
- **`OP_PUBLICIP_REQ 0x97`** → `OP_PUBLICIP_ANSWER 0x98` carrying the peer's IPv4 as
  rmule observes it. aMule answers ungated
  ([ClientTCPSocket.cpp#L1578](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1578)).
  The answer has room only for IPv4, so a request from an IPv6 peer is dropped with a
  counter (`PublicIpRequestUnanswerable`, ADR-0085).
- **Server description pair.** `0xA2` is sent only by the server-UDP engine's trigger
  of ADR-0052, after a valid `0x97` status reply; the codec lives here. Its `u32 LE`
  challenge has a random high half and `INV_SERV_DESC_LEN` (`0xF0FF`) in the low 16
  bits — the first two bytes on the wire, where a legacy `0xA3` carries its first
  string length
  ([ServerUDPSocket.cpp#L242](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerUDPSocket.cpp#L242)).
  `0xA3` is read in both formats as aMule tells them apart
  ([#L256](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerUDPSocket.cpp#L256)):
  legacy `<name_len2><name><desc_len2><desc>`
  ([#L315](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerUDPSocket.cpp#L315))
  and eserver 16.45+ `<challenge4><taglist>`
  ([#L278](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerUDPSocket.cpp#L278)).
  The engine holds the outstanding per-server description challenge beside the status
  challenge, and a mismatched echo drops the packet. Name, description, version,
  dynamic IP and auxiliary ports land as display fields on the per-server
  `ServerCapabilities` record of ADR-0052 — one store, no second map.

**Surface as an event** (silent on the wire; the payload goes up the session spine of
ADR-0044):

- **`OP_MESSAGE 0x4E`** — parse `<len2><text>`, cap at aMule's 450-character inbound
  limit
  ([ClientTCPSocket.cpp#L800](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L800)),
  and emit `ChatMessageReceived`. No reply, no state, and no spam gate: the captcha
  machinery protects a chat feature rmule does not have.
- **`OP_FILEDESC 0x61` (`0xC5`)** — parse `<rating1><len4><comment>`
  ([BaseClient.cpp#L1176](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1176))
  and emit `FileCommentReceived`. Its collision with `OP_ASKSHAREDDENIEDANS 0x61`
  (`0xE3`) is resolved by keying on protocol and opcode together.
- **`OP_CHANGE_CLIENT_ID 0x4D`** — parse `<newID4><newServerIP4>` and emit a
  source-ID change; core applies it to the matching candidate-pool entry (ADR-0030),
  refreshing its ID and server endpoint the way aMule updates `UserIDHybrid`
  ([ClientTCPSocket.cpp#L765](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L765)).
  Ignoring it would leave source records stale and break later dials.

**Drop with a counter** (never solicited, no display value):

- the captcha pair `0xA5` / `0xA6`, which rides on outbound chat
  ([BaseClient.cpp#L2727](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L2727))
  that rmule never sends;
- browse answers `0x4B` / `0x5F` / `0x60` / denied `0x61`, because rmule never browses;
- `OP_PUBLICIP_ANSWER 0x98`, because rmule never asks;
- a `0xA3` with a wrong challenge echo or an unreadable format, with no store change.

**Never sent:** `0x4E`, `0xA5` / `0xA6`, `OP_FILEDESC`, browse requests, browse answers
other than denied, `OP_PUBLICIP_REQ`, and `OP_CHANGE_CLIENT_ID` (aMule marks it "Unused
for sending").

Every row has an explicit handler in its surface's opcode enum and each gate is
counted (`browse-denied`, `publicip-answered`, `chat-surfaced`,
`captcha-unsolicited`, …). Peer rows live in the `rmule-peer` sans-I/O session; the
description pair lives in the server-UDP engine of ADR-0051. No new state exists: the
only writes are the `ServerCapabilities` display fields and the candidate-pool refresh,
both owned by existing stores.

## Consequences

- The three must-answer rows answer as aMule does; the rest stay silent on the wire
  and are nameable in tests and counters.
- Chat and comments reach the front end as typed events at the cost of one enum
  variant each.
- Each class changes at one point if a feature arrives: a real list builder replaces
  the always-denied browse branch, a chat feature replaces the never-reply branch, a
  comments store replaces the event-only sink.
- The test matrix holds decode vectors per row (well-formed, truncated, oversize, and
  the `0x60` / `0x61` collisions under `0xE3` vs `0xC5`), golden emit vectors for
  `OP_ASKSHAREDDENIEDANS`, `OP_PUBLICIP_ANSWER` and `OP_SERVER_DESC_REQ`, silence
  assertions on every drop row, per-gate counter tests, and a session-level check that
  a full human-layer volley mid-transfer leaves the transfer unbroken.

## Considered options

- **Silence for browse and public-IP requests.** Rejected: no aMule configuration is
  silent on those paths.
- **An empty browse answer (`0x4B` with zero files).** Rejected: that is the
  `CanSeeShares == everybody` path of a client sharing nothing, which is false for
  rmule, which shares and uploads. Denied is the truthful private path.
- **Counter-only for chat and file comments.** Rejected: the payload is already parsed
  for validity, and dropping it buys nothing.
- **Ignoring `OP_CHANGE_CLIENT_ID`.** Rejected: aMule applies it, it costs nothing on
  the wire, and ignoring it leaves stale sources.
- **Leaving everything as unknown packets.** Rejected: wrong on the three must-answer
  rows and unnamable in tests and counters.
