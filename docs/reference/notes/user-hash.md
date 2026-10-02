# User hash

**Status:** implemented
**Scope:** the 16-byte client identity reused across server and peer flows.

`UserHash` is a per-installation client identity, not an account identity. It is generated once on first run and persisted (aMule keeps it in `preferences.dat`). It identifies the client to servers and peers; it is used as the input to credit accounting and to Secure User Identification.

## Wire shape

- 16 bytes (128 bits), random.
- Two bytes are conventionally fixed by eMule-derived clients:
  - byte index 5 (zero-based, "6th position" in 1-based aMule wiki text) = `0x0E` (decimal 14)
  - byte index 14 (zero-based, "15th position" in 1-based aMule wiki text) = `0x6F` (decimal 111)
- Other 14 bytes are random.

These fixed bytes are a historical eMule client fingerprint, useful for distinguishing eMule-family clients from rogue clients on the wire. rmule generates user hashes with these positions set to match aMule behavior.

## Lifecycle

- Generated once on first run.
- Persisted (rmule stores it in its own application state under ADR-0083 storage boundary).
- Sent to every server during eD2k login (see `ed2k-login.md`).
- Sent to peers during peer handshake (deferred topic).
- Used as input to Secure User Identification asymmetric key derivation (see `secure-ident.md`).

Changing the user hash means the user starts over with credits on every server and peer, so the value is treated as long-lived.

## Identity vs account

`UserHash` is **not**:

- A user account.
- A login credential.
- A username (the nickname tag in the login request carries the display name).

The eD2k server protocol does not authenticate users in the account-management sense; it only correlates traffic by `UserHash` for session and quota purposes.

## Sources

Cached:

- `docs/reference/amule-wiki/userhash.wikitext` — establishes that `UserHash` is reused across protocol flows and ties to credits / Secure User Identification.
- `docs/reference/amule-wiki/ed2k_protocol.wikitext` lines 42-43 — the "6th and 15th positions are not randomly generated, and their values are 14 and 111" rule.

Link-only:

- aMule source (GPLv2): `src/Preferences.cpp` is where the user hash is generated and persisted. Pinned commit SHA in `docs/protocol/source-map.md`.

## Open questions

- Confirm the byte indices for the fixed bytes against an actual aMule-generated login request fixture. The aMule wiki uses 1-based positions; rmule's tests should assert the zero-based byte indices directly.
- Document the exact RNG and any history of "weak" user hashes (some early eDonkey clients used predictable seeds). Deferred to the secure-ident notes.
