# Protocol obfuscation is an RC4 crypt layer, wrapped generically below the packet codec

## Context

**Protocol obfuscation** is eMule's RC4 stream wrapper over TCP. It hides the eD2k/eMule
protocol byte from middleboxes that throttle or block the protocol. It is not
confidentiality: it defeats protocol fingerprinting and nothing else. It is independent
of Secure User Identification (ADR-0041) and is advertised in its own capability bits,
not the SUI nibble.

aMule's `EncryptedStreamSocket.cpp` @`377ec8d9` gives the full byte layout. Two
handshake forms share one RC4 core:

- **Peer** (client↔client): a one-shot keyed by the *target's* **User Hash**,
  `MD5(target_user_hash ‖ magic ‖ random_key)`, RC4 with the first 1024 keystream bytes
  dropped.
- **Server** (client↔server): a two-shot 768-bit Diffie-Hellman exchange over the
  `dh768_p` prime, keyed `MD5(shared_secret ‖ magic)`.

The peer form has a deterministic, verifiable core: given a captured random key and the
known User Hash, rmule recomputes the RC4 key and the reply must decrypt to the sync
magic. `crates/rmule-peer/tests/fixtures/amule_obfs_responder_reply.bin` is that vector,
captured from aMule 2.3.3 in the `amule-direct-obfs` harness scenario. The server form
has no static vector, because its DH secret cannot be recomputed passively.

## Decision

Obfuscation is a **byte-0-discriminated RC4 stream wrapper below the packet codec**,
split across the existing crates with no crate of its own:

- **`rmule-primitives`** holds the crypto primitives, wrapped per ADR-0012: `Rc4`
  (keystream plus drop-1024), an MD5 wrap over `md-5`, `ObfuscationDhKeypair` over
  `crypto-bigint`'s `U768`, the peer key derivation, and the magic constants. The peer
  key binds to User Hash, so it sits next to User Hash and the SUI RSA keypair. No
  RustCrypto type crosses a public API.
- **`rmule-peer` and `rmule-ed2k`** hold the two sans-I/O handshake state machines,
  `PeerObfuscation` and `ServerObfuscation`. Each owns its `Rc4` pair.
- **`rmule-net`** holds `CryptStream<S, H: ObfuscationTransport>`: sniff byte 0, buffer,
  drive `H` through the handshake, then apply `H`'s per-chunk transform. It never names
  RC4 or a protocol, so it plugs into the `spawn<S: AsyncRead + AsyncWrite>` seam and the
  session above it sees only decrypted bytes. `PeerObfuscationTransport` and
  `ServerObfuscationTransport` adapt the two state machines to the trait and draw
  per-connection entropy (marker, random key, padding) from the OS CSPRNG, so the
  protocol crates stay deterministic.

**Byte-0 discrimination keeps plaintext a pure superset.** An accepted TCP connection
whose first byte is `0xE3`, `0xC5` or `0xD4` takes the plaintext path untouched; any
other first byte starts an obfuscated handshake.

**An Obfuscation Policy governs each connection.** `ConnectOptions.obfuscation:
Option<ObfuscationConfig>`; `None` is disabled. The active states are `Supported`
(accept obfuscated inbound, never initiate), `Requested` (initiate when possible) and
`Required` (refuse plaintext). A failed peer dial does not fall back to plaintext. Under
`Required`, the listener still accepts a plain connection from a party rmule is awaiting
a reachability test from (ADR-0046). The crypt handshake runs below the session, so it
has its own deadline and does not eat the hello budget: the connect timeout for a server,
and for a peer dial aMule's socket timeout, `CONNECTION_TIMEOUT` (40 s,
`protocol/ed2k/Constants.h:34`), which covers a socket from its connect through the
handshake (`ClientTCPSocket.cpp:201-222`). A peer that takes the connection and never
answers the handshake ends the dial as a connect failure, its Run Log cause
`crypt_unanswered`, as aMule's socket times out and the connect fails.

**A server login opens its link by aMule's gate** (`ServerSocket.cpp:786-795`). Each
dial reads the policy: under `Requested` or `Required`, a server whose row says it takes
obfuscated TCP (an obfuscation TCP port from its status answer, and `TCPOBFUSCATION` in
its UDP flags or its last login's TCP flags, aMule's `SupportsObfuscationTCP()`) is
dialed at that port with the server-form handshake before the login. Any other dial
goes plain to the server's own port. The login's `CT_SERVER_FLAGS` states the policy
whatever the link, as aMule's does (`ServerConnect.cpp:273-288`). A failed obfuscated
attempt (dial, handshake, or a link that closes or times out before the answer) earns
one plain dial under `Requested` and none under `Required` (`ServerConnect.cpp:465-470`).
Like aMule, `Required` does not refuse a server that has said nothing about
obfuscation: it dials it plain. Each dial states its **Login Link** in the Run Log
(ADR-0075).

**Outbound peer obfuscation needs the target's User Hash.** A candidate source without
it is dialed plaintext. Plain `OP_FOUNDSOURCES` sources carry only id and port, so they
are always dialed plaintext. `OP_FOUNDSOURCES_OBFU`, source exchange and Kad sources
carry a crypt-options byte and the User Hash, so they can be obfuscate-dialed. Accepting
obfuscated inbound needs none of this, because rmule keys from its own User Hash.

Crypt support is advertised in the peer hello's `MiscOptions2` word and the server
login flags, from the one policy-to-stance ladder in ADR-0049.

## Consequences

- New dependencies `rc4`, `md-5` and `crypto-bigint`, all wrapped in `rmule-primitives`.
  `crypto-bigint` rather than `num-bigint` keeps the RustCrypto family and gives
  constant-time modexp, which is not needed against passive DPI but costs nothing.
- Byte facts carry evidence tags in `docs/reference/notes/obfuscation.md`. The peer
  form is captured. The server form is live-proven: stock Lugdunum and ed2k-server
  answer rmule's obfuscated login (interop-harness `server-login-crypt`), once the
  opening carries the plain padding-length byte aMule writes after `G^A`.
- The evidence ladder must defeat two crypto-direction traps. A symmetric loopback where
  both ends use one key round-trips even with send and receive flipped; deriving with
  the real 34/203 magic split and asserting cross-decryption plus intra-side key
  distinctness defeats it. A correct asymmetric rmule↔rmule loopback still passes if
  rmule swaps the two magics on both sides; only the captured peer vector and live
  server interop pin the absolute assignment against aMule's bytes.
- The Correctness Tier covers primitive vectors (RC4 KAT plus drop-1024, MD5, DH round
  trip, the 34/203 peer keys), handshake state machines with adversarial paths, and a
  `CryptStream` duplex test with opposite roles so the keys are crossed.

## Considered options

- **A dedicated `rmule-obfuscation` crate** holding RC4, DH, both handshakes and the
  wrapper. Rejected: the wrapper is an `AsyncRead + AsyncWrite` adapter and would
  duplicate `rmule-net`'s transport role, and it would pull the primitive out of
  `rmule-primitives`, where User Hash and the SUI keypair live. The two consumers (peer
  and server) are served by homes that already exist.
- **A feature flag duplicating the RC4 core in each protocol's runtime module.**
  Rejected: it duplicates the shared byte-0 sniff, RC4, drop-1024 and sync magic that the
  split exists to share once.
- **Peer obfuscation only.** Rejected: the RC4 core is shared, so leaving the server form
  out would reopen the same transport seam later.
- **Blocking the build until a capture lands.** Rejected: the source read gives the full
  layout, and the capture gates only the byte-compat claim. The rmule↔rmule path ships
  regardless.
- **Per-datagram UDP obfuscation in this layer.** Rejected: server-UDP and Kad-UDP use a
  different, stateless per-datagram scheme, decided in ADR-0046.
