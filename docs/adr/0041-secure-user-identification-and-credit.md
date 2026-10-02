# Secure User Identification and credit, honoring eMule's weak key

## Context

eMule-family clients reward peers that upload to them: an upload-credit ledger per
User Hash weights the upload queue, so a peer that has given more waits less. A bare
User Hash is spoofable — any peer can claim another's hash and inherit its credit — and
credit that ranks nothing is inert. Secure User Identification (SUI) is eMule's RSA
challenge/response that proves a peer owns the key bound to its hash.

eMule's SUI is deliberately weak by modern standards: 384-bit RSA. eMule stores a
peer's public key in an 80-byte buffer (`MAXPUBKEYSIZE`); a stronger key overflows it
and SUI silently fails — no signature verifies, no credit accrues. What SUI protects is
upload-queue priority, not confidentiality.

A captured real-aMule exchange settled the details the specification notes had wrong:
the signature scheme is RSASSA-PKCS1v15 with SHA-1 (CryptoPP
`RSASSA_PKCS1v15_SHA_Signer`), and the wire public key is an X.509
SubjectPublicKeyInfo (76 bytes for a 384-bit key), not bare PKCS#1. The captured key and
signature are golden vectors in `crates/rmule-primitives/tests/fixtures/`
(`amule_sui_public_key_spki.bin`, `rmule_sui_public_key_spki.bin`,
`amule_sui_signature.bin`), asserted by
`crates/rmule-primitives/tests/primitives/sui_captured_key.rs`; the scheme is pinned in
`docs/reference/notes/secure-ident.md`.

## Decision

rmule implements SUI and credit-weighted queueing exactly as eMule does, honouring the
weak key rather than strengthening it.

- **Three layers, as with AICH (ADR-0038).**
  - The crypto primitive — `SecureIdentKey` and its public key, `sign` and `verify` —
    lives in `rmule-primitives` beside the User Hash it binds to, with RustCrypto `rsa`
    and `sha1` wrapped behind rmule types (ADR-0012). eMule's 384-bit keys are below
    `ring`'s floor.
  - The SUI protocol — `OP_PUBLICKEY` (`0x85`), `OP_SIGNATURE` (`0x86`) and
    `OP_SECIDENTSTATE` (`0x87`) under `OP_EMULEPROT` (`0xC5`), the challenge/response
    state machine and the signing input — lives in `rmule-peer`.
  - Key storage and credit policy live in `rmule-core`.
- **Key material.** `SUI_RSA_KEY_BITS` is 384; signing is RSASSA-PKCS1v15 with SHA-1.
  rmule's keypair is generated once, on first run, and kept unencrypted in the typed
  store's app config (ADR-0083), as eMule keeps `cryptkey.dat` unencrypted; only the
  wire form of the public key is an interoperability constraint.
- **Both versions.** V1 signs `verifier_public_key ‖ challenge_u32_le`. V2 also binds an
  IP address and a `byIPUsed` kind byte that stays honest under Low-ID and NAT. The
  exchange uses V1 whenever the peer advertises it and V2 only for a peer that advertises
  V2 alone; a native-IPv6 session never uses V2 (ADR-0087). The
  exchange is order-independent, and a failed exchange costs the peer its secured credit,
  never the connection.
- **Honest advertisement.** The `MiscOptions1` secure-identification field (bits
  `[16..20)`) carries the version bitmask `3` (V1 and V2), exactly what eMule and aMule
  send, and only when a keypair is present (ADR-0047).
- **Credit binding.** The first successful SUI binds the peer's ledger row to its public
  key (a Secured Identity) through the store's atomic `bind_public_key`, which answers
  `Adopted`, `AlreadyBound` or `Mismatch`. A later peer presenting the same User Hash with
  a different key is denied the secured credit and never overwrites it (eMule's
  `IS_IDFAILED`). Peers without SUI still accrue unsecured credit and are never gated out;
  unsecured credit is first-come and spoofable by design, which is the reason SUI exists.
- **Credit ranks the queue.** The upload queue's score is wait time weighted by the
  credit modifier, aMule's `GetScoreRatio` (ADR-0031), so a verified peer with upload
  history earns real priority. Per-file upload priority is fixed.
- **Durability.** The credit ring lives in the typed store (ADR-0083). When a
  `clients.met` directory is configured, the ring is seeded from aMule's `clients.met` at
  start (only peers the store has never met) and written back to it at shutdown, in
  aMule's byte format.

## Consequences

- rmule interoperates with the whole SUI-speaking network and earns and grants credit as
  its peers expect.
- SUI's wire bytes are additive: they are gated by the advertised field, and the session
  already tolerates opcodes it does not model.
- Deterministic RSASSA-PKCS1v15 makes a captured `(key, challenge, signature)` triple a
  reproducible byte-compat assertion in ordinary `cargo test`; adversarial paths (bad
  signature, wrong key, replayed challenge, IP mismatch) run against `FakePeer`
  (ADR-0040).
- Protocol obfuscation is a separate decision (ADR-0042), unrelated to the SUI field.

## Considered options

- **A stronger RSA key.** Rejected: it overflows eMule's 80-byte key buffer and silently
  breaks SUI with every eMule peer.
- **V1 only.** Rejected: deterministic signing makes V2's layout testable from vectors,
  so both ship.
- **SUI with a FIFO queue.** Rejected: identity proof guarding a number that ranks nothing
  is dangling; eMule's queue is credit-weighted.
- **A separate `rmule-crypto` crate.** Rejected: SUI has one consumer, the peer protocol;
  Kad uses a non-RSA scheme.
