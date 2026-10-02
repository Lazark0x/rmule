# AICH (Advanced Intelligent Corruption Handling)

**Status:** deferred
**Scope:** the optional ED2K integrity layer that hashes each `ED2K Part` into a tree of 180 KiB block hashes so corruption can be detected and recovered at sub-part granularity.

The first implementation preserved the `AICH Root Hash` carried by `h=` in file links (per `ed2k-link.md`) without verification or recovery. This note is the research index for full AICH support.

## Concepts

- **AICH Root Hash**: 20-byte SHA-1 over the root of the per-file AICH hash tree. Identifies the file's AICH state independent of the `ED2K File Hash`.
- **AICH Part Hash Tree**: a binary tree of SHA-1 hashes where leaves are blocks of 180 KiB inside each 9,728,000-byte ED2K part.
- **Trusted set**: AICH only commits a root hash when enough peers have reported the same root (per the eMule "secure" AICH propagation rule).

## Why deferred

- AICH adds a second hash algorithm (SHA-1) and a tree shape orthogonal to ED2K parts. Implementing it before the basic ED2K part hash set is solid risks tangling the two.
- Real-world AICH coverage in the network is partial; many files have no published AICH root. Practical interop is mostly the ED2K side.
- Per ADR-0014 reasoning, the first scope intentionally kept the AICH root hash as opaque metadata.

## What the link parser already does

- Parses `h=AICH_ROOT_HASH` from a file link, validates uppercase unpadded base32 shape (32 chars).
- Preserves the value on round-trip without computing it.
- Rejects malformed AICH root values (wrong length, invalid base32).

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_link.wikitext` line 39 — AICH root hash as an optional `h=` field on file links.
- `docs/reference/emule-spec/emule_protocol_specification.pdf` mentions root hash in the file-ID context. Local-only PDF.

Link-only:

- aMule source (GPLv2): `src/AICHSyncThread.cpp`, `src/AICHHash.cpp` are the implementation references.
- eMule project corruption-handling help (proprietary site): the highest-level rationale for AICH and the trusted-set propagation rule.

## Open questions

- Full AICH support needs to define an AICH-tree value object distinct from `AICHRootHash`; the boundary between "verify file" and "request recovery hashset" decides where the AICH state machine lives.
- Confirm the block size (180 KiB) and the tree shape against aMule code before writing fixtures.
- Decide whether to wrap a SHA-1 crate or hand-roll; ADR-0012 ("wrap ed2k hash crate") suggests wrapping.
