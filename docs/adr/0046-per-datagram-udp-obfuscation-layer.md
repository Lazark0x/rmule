# One per-datagram obfuscation layer serves peer, Kad and server UDP under one policy

## Context

ADR-0042 covers TCP stream obfuscation. The UDP surfaces (peer-UDP, Kad-UDP and
server-UDP) use a different, stateless scheme, read from aMule's
`EncryptedDatagramSocket.cpp` @`4e8f2b3c`. Each datagram carries a 2-byte random key
seed in the clear and derives a fresh RC4 key per packet, without the 1024-byte discard
the stream form uses. Four key families cover the surfaces, and on the wire the client
families multiplex through the low two bits of the marker byte. aMule shares one
`EncryptedDatagramSocket` between peer and Kad, apart from its stream socket.

The obfuscation-aware server source pair `OP_GETSOURCES_OBFU` (`0x23`) and
`OP_FOUNDSOURCES_OBFU` (`0x44`) carries each source's crypt options and, optionally,
its User Hash, which is what an obfuscated outbound dial needs.

Both references run every crypt surface off one preference: aMule obfuscates a Kad
datagram only while `IsClientCryptLayerSupported()` (`MuleUDPSocket.cpp:282-284`), and
`IsServerCryptLayerUDPEnabled()` is defined as that same call (`Preferences.h:883`, kno
fork `ab483654`).

The evidence is captured: Kad crypt in
`crates/rmule-kad/tests/fixtures/kad_crypt/captured/amule-233-kad-crypt-20260726`,
peer-UDP crypt in
`crates/rmule-peer/tests/fixtures/peer_udp_reask/captured/amule-233-crypt-reask-20260728`,
server-UDP crypt in
`crates/rmule-ed2k/tests/fixtures/server/captured/enode-server-udp-crypt-20260727` and
`ed2ksrv-crypt-ping-20260802`. The Kad capture exposed a direction trap: the sync word is
written little-endian. A big-endian frame was self-consistent and every known-answer
test round-tripped, but only the little-endian form decodes aMule's bytes.

## Decision

**One layer in `rmule-primitives`.** The `datagram_obfuscation` module holds per-datagram
RC4, the marker-bit key-try order (`byte0 & 0x03`), the plaintext whitelist and all four
key families:

- **ed2k client**: `MD5(user_hash ‖ sender address ‖ MAGICVALUE_UDP ‖ random_key)`, with
  the address width following the datagram's actual family (a 23-byte key for IPv4, 35
  for IPv6; ADR-0087).
- **Kad NodeID**: `MD5(kad_id ‖ random_key)`.
- **Kad verify key**: `MD5(receiver_verify_key ‖ random_key)`.
- **Server**: `MD5(base_key ‖ direction_magic ‖ random_key)`, keyed on the server's
  `ServerUDPKey` or a pending crypt-ping's challenge.

It is a set of socket-agnostic functions over `&[u8]` (encrypt on send, dual-path on
receive), not a tokio adapter: a datagram has no handshake state. Each runtime calls it
at its socket boundary.

**The whitelist is a plaintext form, not a ban.** The six bytes `0xC5`, `0xE4`, `0xE5`,
`0xD4`, `0xA3` and `0xB2` mean:

- On receive, a datagram whose first byte is one of them passes through untouched at any
  policy. This read is identical across aMule, eMule and eMuleAI, which is why `0xB2`
  can share the client-UDP port: a client that knows nothing of NAT-T drops the frame
  instead of misreading a decrypt.
- On send, the random marker is never one of them, so an encrypted datagram never looks
  whitelisted.
- So an obfuscated `0xB2` frame is legal: its plaintext begins `0xB2` only after the
  dual-path decrypt. `0xB2` is carried in both families, and the ed2k key selects the
  layout by the family the datagram leaves by; with no own address in that family, the
  frame goes plaintext.

**NAT-T keys and signalling** (ADR-0091). An endpoint reached only through NAT-T has no
identified User Hash, so a **KEY frame** (`0xB2 0xFF`, body = the sender's own User Hash)
supplies one. It is sent in the clear, at most once per `(ip, port)` per 10 s, on a uTP
`ST_SYN` or a QUIC long-header packet, and a learned `(ip, port) → User Hash` mapping
expires after 10 minutes. `0xC5` NAT-T signalling (rendezvous, punch, endpoint hints)
always goes plaintext, even under `Required`: its target is usually unidentified, and a
punch that fails to deobfuscate looks the same as one that never arrived.

**One policy, one knob.** The `ObfuscationPolicy` of ADR-0042 governs datagrams too, and
`CoreSettings::obfuscation` is the only setting. Any set policy arms peer-UDP crypt, Kad-UDP
crypt together with Kad verify keys (the keys ride inside the crypt header), and the
server-UDP crypt-ping and dual-path decrypt. Unset, every UDP surface stays plaintext. Per
transport:

- **Receive** is always dual-path, whatever the policy: bypass the whitelist, otherwise
  try to decrypt in marker-bit key order. Dropping plaintext would break reask and Kad
  with legacy peers.
- **Send** encrypts whenever key material for the target exists (User Hash, Kad ID,
  verify key, `ServerUDPKey`), otherwise sends plaintext.
- **`Required`** reads as `Requested` on the datagram side.

**The policy changes live, on every surface at once.** A running core holds the policy in
one shared cell, and Core Settings answers `TakesEffect::Now` for it (ADR-0069). No surface
keeps a copy: each reads the cell at the moment it decides, so the change reaches the next
outbound peer dial, the next inbound accept, the next server login (its link and crypt flags,
ADR-0042), the next peer-UDP and NAT-T datagram (send gate,
dual-path receive, KEY frame and CAPS crypt bits), and the server-UDP crypt-ping sweep and
decrypt. The Kad node is the one surface that caches its obfuscation: its **Kad Node Start**
installs it, and the Kad pump's reconciler installs it anew before the pump takes another
input — `KadCommand::SetObfuscation` runs the start's own install, obfuscation and verify keys
together or neither — and states the publish byte's crypt ladder from the same read. That
install is asynchronous, and stays so: the setter writes the cell and returns, and the node,
which runs on its own task and timers, takes the new obfuscation when the pump next wakes,
after the step it is in. A datagram the node sends inside that window leaves under the old
obfuscation. Installing from the setter would not close the window, because the node takes
commands through its own queue; only a node that read the cell per datagram could, and the
node is a sans-I/O state machine over the obfuscation installed in it.
The window is one pump step (under a second in the live flip). A connection that has already negotiated keeps what it agreed: an
obfuscated link stays obfuscated and a plain one stays plain, and a dial or accept past its
crypt decision finishes under the policy it read. A datagram negotiates nothing, so the next
one follows the new policy. What the layers learned stays put across a change: learned Kad
contact keys, NAT-T key-frame hashes and a pending crypt-ping's challenge are kept, so
a new install finds them.

**The Kad UDP Key** is a private per-install seed, minted once from OS entropy and
persisted (`AppConfigStore::ensure_kad_udp_key`, read by core at build into
`KadNodeIdentity::kad_udp_key`, a core key per ADR-0069), where aMule persists `/Obfuscation/CryptoKadUDPKey`.
Own verify keys derive from it per target IP, so our own address never enters them. A
*learned* contact key binds to our public IP, as aMule's `CKadUDPKey` does: the Kad
pump's reconciler sends `KadCommand::SetOwnPublicIp` from Address Learning's IPv4
verdict (ADR-0084), at Kad start and whenever the verdict moves, which retires keys
learned under the old address. With no verdict the node binds `0.0.0.0`, aMule's
`GetPublicIP() == 0`.

**Source crypt provenance.** `OP_FOUNDSOURCES_OBFU` threads `(crypt_options, user_hash)`
onto each candidate source, and source exchange's v2/v4 entries (ADR-0055) use the same
model. A source that carries a User Hash can be obfuscate-dialed.

**Server crypt-ping.** While our public IP is known and the policy is set, rmule
crypt-pings a server at TCP + 12: the challenge (little-endian) and padding, raw. It is
not gated on the server advertising obfuscation, it has a 20 s grace, and an unanswered
crypt-ping counts no failure (the plain fallback does). A reply is matched to its server
by the three port relations both references use (aMule `CServerList::GetServerByIPUDP`,
eMule `ServerList.cpp:563-575`): TCP + 4, the advertised obfuscation port and TCP + 12.
While a crypt-ping is pending, its challenge keys the decrypt whichever relation matched;
otherwise the obfuscation port's `ServerUDPKey` does. A leading `0xE3` skips the decrypt,
and a datagram that fails to decrypt passes through to be dropped.

**Server datagram seal.** Every other server datagram leaves through one gate, the
Server-UDP Seal (aMule `CServerUDPSocket::SendPacket`, `ServerUDPSocket.cpp:366-374`):
the status ping, the description ask, global search, get-sources and the callback
request. While the policy is set and the server's UDP crypt facts offer a key — non-zero,
UDP obfuscation advertised, learned under the public IPv4 we hold now — the frame is
sealed under that `ServerUDPKey` in the client-to-server direction, its marker never
`0xE3`, and sent to the server's advertised obfuscation UDP port; otherwise it goes plain
to TCP + 4. The facts come from this run's `0x97` first, else from the row's saved ones,
the order the receive side finds a server by its obfuscation port in. No sender knows a
port offset or a key, and the transport sends to the address the seal names. The engine
hands each consumer its datagrams tagged with the answering server's standard endpoint,
because a sealed answer comes from the obfuscation port.

**What `Required` still accepts plain: Test Connections.** On TCP, `Required` refuses
every plaintext opener, but the two parties that test whether rmule is reachable may
dial plain. Refusing them would guarantee a Low ID and a firewalled Kad, so both
references carve them out (aMule `EncryptedStreamSocket.cpp:377-397`), and so does rmule:

- The **Awaited Testers** are the server whose login answer is awaited (from the moment
  the TCP link is up and the login sent, until the answer or failure) and each Kad helper
  sent a `KADEMLIA_FIREWALLED(2)_REQ`, for 180 s (strict `<`), dropped when a recheck
  starts or Kad stops.
- A plain dial from one of them is admitted as a **Test Connection**. It meets the IP
  filter and ban gate, its hello is answered, an `OP_KAD_FWTCPCHECK_ACK` on it is counted,
  and it ends on its first request to be served (a file, hash set, slot, parts, sources,
  AICH) or after 30 s. Being identified, Secure User Identification and other statements
  ask for nothing and do not end it. It never reaches inbound triage: no upload queue,
  source exchange, callback adoption, buddy link, Kad handoff or address vote sees it.
  The references serve it as any peer; rmule does not, because the exception is keyed
  on a source address that anyone sharing it inside the window could use.
- `rmule_net::peer::AwaitedTesters` is the seam, asked only for a plain dial under
  `Required`. Core's `SharedAwaitedTesters` is the level: login establishment writes the
  server half, the Kad pump the helper half, and the accept pump reads it synchronously.

**The Kad firewall checks under `Required`.** rmule's TCP check states the crypt bits of
its publish connect-options byte (never its direct-callback or NAT-T bits), with the User
Hash written in aMule's `WriteUInt128` order, so a crypt-enabled helper dials back
obfuscated as an ordinary connection; the Test Connection carries legacy and
crypt-disabled helpers. The UDP check asks its helper over an outbound Test Connection,
dialed plain under every policy: our hello states our true crypt stance, the link carries
one request, serves nothing and is dropped after. aMule refuses that dial under
`Required` (`ClientList.cpp:1213-1215`), which leaves its UDP verdict unverifiable; rmule
departs on purpose.

## Consequences

- The deterministic tier holds known-answer tests per key family, crossed-role datagram
  loopbacks, plaintext-bypass, key-try-order and garbage-datagram tests, and both
  crypto-direction traps of ADR-0042 generalized to datagrams. Only captures pin the
  absolute magic and byte-order assignments.
- A Kad datagram that fails to decode is counted
  (`SessionCounters::kad_undecodable_envelopes_total`) and logged, never dropped silently.
- `crates/rmule-net/tests/fixtures/kad_fwcheck/captured/amule-233-required-dialback-20260929`
  holds aMule helpers' obfuscated dial-backs under `Required` and `Requested`, replayed
  against the `Required` listener.
- Lugdunum answers a crypt-ping from TCP + 12 (`tools/interop-harness` `crypt-ping-port`,
  run `1790791973`); its answer, opened under the ping's challenge, carries obfuscation UDP
  port 4675 and a `ServerUDPKey` (run `1791422886`), while its plain `0x97` carries neither.
  The other two relations follow both references.
- Lugdunum's answers to sealed datagrams: `crypt-ping-port --sealed`, run `1791811231`.
- The Run Log states the policy as every Core starts and at every live change, as core
  events whose records the lean level holds: it is our own posture (ADR-0075). The
  Settings row is a four-way choice: off, supported, requested, required, and its receipt
  says the change took effect at once.

## Considered options

- **Per-surface RC4 datagram code.** Rejected: ADR-0042 rejected the same shape for TCP,
  and aMule shares one datagram socket between peer and Kad.
- **A dedicated obfuscation crate, or a tokio `CryptDatagram` adapter in `rmule-net`.**
  Rejected: the primitives already have a home, and a pure byte transform with no
  handshake needs no runtime adapter.
- **A separate datagram, Kad or server-UDP policy.** Rejected: both references read one
  crypt preference across TCP and UDP; a second knob invents a setting users never had.
- **Dropping plaintext datagrams under `Required`.** Rejected: it breaks reask and Kad
  interop with legacy peers.
- **Obfuscating `0xC5` NAT-T signalling.** Rejected: there is usually no key, and it turns
  a diagnosable NAT failure into a silent one.
- **A per-run Kad UDP seed.** Rejected for a Core: a seed that changes across a restart
  makes every key the network learned for us a mismatch. Single-run tools keep one.
- **A strict `Required` that refuses tests too.** Not offered: neither reference has it
  (`IsClientCryptLayerRequiredStrict` returns `false` in both), and its only effect is a
  guaranteed Low ID and firewalled Kad.
