# Secure User Identification

**Status:** pinning in progress (2026-07-06) for SUI and credit (ADR-0041,
phase-2 ring of ADR-0047). The asymmetric-key challenge/response that proves a peer owns
the **User Hash** it claims, so **Credit** cannot be spoofed.

Each fact below is tagged by source confidence:
- **[aMule]** — read from aMule source at pinned commit `377ec8d9` (behavioral oracle;
  rewritten, never ported — ADR-0004).
- **[spec]** — eMule Protocol Specification (Kulbak & Bickson, 2005), local PDF
  `docs/reference/emule-spec/`, §4.2 / §4.2.1 / §6.5.8–6.5.10.
- **[pending]** — strongly established but not yet confirmed byte-for-byte; the
  captured aMule vector is the deterministic backstop.

## Handshake flow [spec §4.2, aMule `BaseClient.cpp`]

Immediately after the initial hello, if a peer's **Capability Block** advertises secure
identification (`MiscOptions1` SecIdent nibble > 0):

1. Each side sends `OP_SECIDENTSTATE` telling the other whether it needs the peer's public
   key, and a fresh challenge for the peer to sign.
2. If the peer asked for our key, we send `OP_PUBLICKEY`.
3. We send `OP_SIGNATURE` over the peer's challenge (+ IP for V2).

Bidirectional — each side both challenges and signs. It is the credit-protecting proof,
not encryption.

## Opcodes [aMule `src/include/protocol/ed2k/Client2Client/TCP.h`]

All under `OP_EMULEPROT = 0xC5` (the extended-protocol byte), in `ED2KExtendedClientTCP`:

| Opcode | Byte | Payload |
|---|---|---|
| `OP_SECIDENTSTATE` | `0x87` | `[state:u8][challenge:u32-le]` |
| `OP_PUBLICKEY` | `0x85` | `[len:u8][der_public_key:len]` |
| `OP_SIGNATURE` | `0x86` | `[len:u8][signature:len]` — V2 appends `[ip_kind:u8]` |

## SecIdentState values + send logic [aMule `BaseClient.cpp::SendSecIdentStatePacket`]

Wire state byte: `IS_UNAVAILABLE = 0`, `IS_SIGNATURENEEDED = 1`, `IS_KEYANDSIGNEEDED = 2`.

| Condition (checked in order) | State byte sent |
| --- | --- |
| we hold no public key for the peer | `IS_KEYANDSIGNEEDED` (2) |
| the peer's IP differs from the one its last signature was made for | `IS_SIGNATURENEEDED` (1) |
| otherwise | `IS_UNAVAILABLE` (0) |

(Note the peer-side `EIdentState` enum — `IS_NOTAVAILABLE / IS_IDNEEDED / IS_IDENTIFIED /
IS_IDFAILED / IS_IDBADGUY` — is the *stored* credit ident-state, distinct from the wire
state byte above.)

## Challenge [aMule `BaseClient.cpp`]

`uint32 dwRandom = rand()+1;` — a non-zero `u32`, written little-endian (`WriteUInt32`) and
stored as `m_dwCryptRndChallengeFor`. Verification rejects a stored challenge of 0, so the
`+1` guarantees a usable value. rmule generates its challenge from a real CSPRNG (not C
`rand()`); the wire shape (non-zero `u32-le`) is what matters for interop.

## Signature / signing input [spec §4.2 step 4; aMule `BaseClient.cpp::SendSignaturePacket`; layout **[pending]** capture confirm]

The signer signs: `signer's-copy-of-the-verifier's-public-key ‖ challenge(u32-le)` and, for
V2, `‖ challenge_ip(u32-le) ‖ ip_kind(u8)`.

**V2 IP + kind selection** (resolves the "whose IP under NAT?" question from source):

| Our own ID | `challenge_ip` signed | `ip_kind` byte |
| --- | --- | --- |
| Low-ID | the REMOTE peer's IP | `CRYPT_CIP_REMOTECLIENT` |
| High-ID | OUR OWN public ID | `CRYPT_CIP_LOCALCLIENT` |

Kind constants [aMule `ClientCredits.h`]: `CRYPT_CIP_REMOTECLIENT = 10`,
`CRYPT_CIP_LOCALCLIENT = 20`, `CRYPT_CIP_NONECLIENT = 30`. Verification uses the observed
remote IP (`GetIP()`) and the received kind byte. So under NAT rmule (Low-ID) signs the
remote peer's IP with kind 10; High-ID rmule signs its own assigned ID with kind 20 — no
guessing, the kind byte disambiguates on the wire.

## Key material [**[pending]** — the two facts the captured vector locks]

- **Key size: 384-bit RSA** (eMule `RSAKEYSIZE`). Not stated in the spec; the aMule crypto
  function bodies were unreachable via source fetch (long-file truncation). Corroborated by
  `MAXPUBKEYSIZE = 80` [aMule `ClientCredits.h`] — an 80-byte peer public-key buffer
  (`uint8 m_abyPublicKey[80]`) fits a DER RSA public key only up to ~512-bit, and 384 is the
  long-established eMule default. Pin `SUI_RSA_KEY_BITS = 384`; the captured verify-vector
  locks it (an rmule verify of a real aMule signature only succeeds against the right key).
- **Scheme: RSASSA-PKCS1v15 with MD5** (eMule CryptoPP `RSASSA<PKCS1v15, MD5>`). Deterministic
  (no PSS randomness) — the property that makes a captured `(key, challenge, signature)`
  triple a reproducible fixture. Confirm against the captured vector.
- **The 80-byte buffer is the hard interop cap** — a stronger key overflows the peer's
  buffer and SUI silently fails (ADR-0041). Honor 384; do not strengthen.
- The public key is a *stored, associative* binding to **User Hash** — there is **no**
  cryptographic derivation of User Hash from the key (User Hash stays random). The credit
  ledger stores both and SUI proves the sender holds the private key for the stored public
  key.

## Credit modifier — `GetScoreRatio` [aMule `ClientCredits.cpp`; spec §4.2.1]

aMule's rule, in prose (naming is from *our* perspective — `Downloaded` = bytes the peer
served **us**, `Uploaded` = bytes we served the **peer**):

1. If the peer has served us fewer than 1,000,000 bytes, the modifier is 1.0 (no bonus).
2. Otherwise take the ratio `2 × downloaded / uploaded` (the spec says a peer we never
   uploaded to gets 10).
3. Take the cap `sqrt(downloaded / 1,048,576 + 2)`, with `downloaded` in bytes.
4. The modifier is the smaller of the ratio and the cap, clamped to the range 1.0 to 10.0.

**rmule mapping (critical — the field names line up, do not invert):** rmule
`CreditTotals.downloaded` == aMule `GetDownloadedTotal()` (peer→us);
`CreditTotals.uploaded` == aMule `GetUploadedTotal()` (us→peer). So in rmule terms:

```
if downloaded < 1_000_000 { 1.0 }
else {
    let ratio = if uploaded == 0 { 10.0 } else { downloaded as f32 * 2.0 / uploaded as f32 };
    let cap   = ((downloaded as f32 / 1_048_576.0) + 2.0).sqrt();
    ratio.min(cap).clamp(1.0, 10.0)
}
```

A peer earns queue priority by having **uploaded a lot to us** (rmule `downloaded` high)
relative to what **we uploaded to it** (rmule `uploaded`). Credit is per-uploader and local,
never global [spec §4.2.1].

## rmule realization (ADR-0041)

- Crypto **primitive** (384-bit keypair, sign/verify PKCS1v15+MD5, DER public key) in
  `rmule-primitives` (wraps RustCrypto `rsa`; `ring` rejects sub-2048-bit keys).
- SUI **protocol** (the three codecs, challenge state machine, signing-input assembly,
  capability nibble at `MiscOptions1` bits [16..20)) in `rmule-peer`, V1 and V2.
- Our keypair in the app-config seam (`DurableAppConfig`, ADR-0083), plaintext; peers'
  keys in the credit ledger (atomic `bind_public_key`).
- Credit-weighted `UploadSlotQueue.rerank` via the modifier above.
- Captured golden vectors + two-peer interop.

## Sources

- `docs/reference/emule-spec/emule_protocol_specification.pdf` §4.2, §4.2.1, §6.5.8–6.5.10
  (local, citable).
- aMule GPLv2 @ `377ec8d9`: `src/include/protocol/ed2k/Client2Client/TCP.h` (opcodes),
  `src/ClientCredits.h` (`MAXPUBKEYSIZE`, `EIdentState`, `CRYPT_CIP_*`), `src/ClientCredits.cpp`
  (`GetScoreRatio`, 80-byte buffer), `src/BaseClient.cpp` (state/challenge/signature send +
  verify). Crypto function bodies (`CreateKeyPair`/`CreateSignature`/`VerifyIdent`) not
  extractable via fetch — key size + scheme confirmed by the captured vector.

## Capture corrections — 2026-07-06 `amule-direct-sui` run [captured]

The first real-aMule exchange (Ubuntu `amule-daemon` in the `amule-direct-sui` harness scenario,
run `1783343233`) corrected four spec-derived assumptions. Everything below is
**[captured]** — the strongest confidence tier — with the source-read backstop quoted
from `BaseClient.cpp` where behavior (not bytes) is the fact.

- **Wire public key is X.509 `SubjectPublicKeyInfo`, not bare PKCS#1.** CryptoPP's
  `DEREncode` emits SPKI: the captured `OP_PUBLICKEY` body is 76 bytes —
  `SEQUENCE { AlgorithmIdentifier { rsaEncryption, NULL }, BIT STRING { RSAPublicKey } }`
  — still within `MAXPUBKEYSIZE = 80`. (aMule's throwaway key used exponent 17.)
  Fixture: `crates/rmule-primitives/tests/fixtures/amule_sui_public_key_spki.bin`.
- **The SecIdent nibble is a bitmask, not a version number.** Bit 0 = V1, bit 1 = V2.
  Real aMule advertises **3** (`CryptoAvailable() ? 3 : 0`); rmule now advertises 3 too.
- **Version selection** [aMule `SendSignaturePacket`]:
  `bUseV2 = (peer_nibble & 1) == 0` — V2 is used only against a peer that does *not*
  claim V1. eMule↔eMule (3 vs 3) therefore runs **V1**; V2 fires only against a
  bit0-clear advertiser. On receive, a V2-shaped signature (trailing kind byte) is
  accepted only if the sender advertised bit 1 (`m_bySupportSecIdent & 2`).
- **eMule initiates SUI only for "mule" peers.** `InfoPacketsReceived()` (which calls
  `SendSecIdentStatePacket`) requires both info packets, and the eMule half is only
  flagged when the hello carried `CT_EMULE_VERSION 0xFB` (`dwEmuleTags & 0x04`). A hello
  without 0xFB gets *no challenge* from aMule — observed directly. rmule's hello now
  always carries 0xFB (the aMule 2.3.3 parity word `0x0304_0D80`).
- **V2 kind-10 verification uses the verifier's own public address**
  (eMule `VerifyIdent`, `CRYPT_CIP_REMOTECLIENT` → `theApp->GetPublicIP()`); under the
  harness NAT topology neither side can know the address its peer observes, which is a
  second reason real clients effectively run V1 with each other.
