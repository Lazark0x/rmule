# ED2K hash

**Status:** implemented
**Scope:** the `ED2K File Hash` content identity, the per-part `ED2K Part Hash`, and the `ED2K Part Hash Set` carried by file links.

ED2K hashing is MD4-derived but is **not** plain MD4 of the file. It is a tree of MD4 hashes over fixed-size parts.

## Constants

- **Part size**: `9,728,000` bytes (`9500 * 1024`). The size never changes; it is the protocol's only configuration constant for hashing.
- **Special empty-part hash**: `31D6CFE0D16AE931B73C59D7E0C089C0` — MD4 of the empty input.

## Algorithm

Per `docs/reference/amule-wiki/md4_hash.wikitext`:

1. Split the file into parts of 9,728,000 bytes (last part may be shorter or zero-length depending on file size).
2. Compute MD4 of each part separately → `ED2K Part Hash`.
3. Concatenate the per-part hashes into one byte array.
4. Compute MD4 of that concatenated array → `ED2K File Hash`.

The subtlety is at **exact part-size boundaries**.

## The exact-multiple boundary case

When `file_size` is an exact non-zero multiple of `9,728,000`, two ED2K hash variants exist in the wild:

- **Fixed-boundary variant**: hash only the existing parts, then hash the concatenation.
- **eMule/aMule variant (rmule's choice)**: append the MD4 of empty input (`31D6CFE0…`) as a "trailing empty part" before computing the file hash.

rmule targets the eMule/aMule variant. See ADR-0014 ("eMule-compatible ED2K boundary hash"). The reasoning: matching the variant that actual eMule and aMule clients produce is the only way to interoperate with them.

The `ed2k` crate exposes both variants. rmule's canonical file hash uses `Ed2kRed` (eMule/aMule); `Ed2k`/`Ed2kBlue` is the fixed-boundary variant and must not be used.

## ED2K Part Hash Set count

The part hash set carried by `p=` in a file link follows aMule's rules:

| File size | Part hash set count |
| --- | --- |
| `file_size == 0` | no part hash set (zero parts) |
| `0 < file_size < 9,728,000` | no part hash set (sub-part file) |
| `file_size >= 9,728,000`, not an exact multiple | `floor(file_size / 9,728,000) + 1` hashes (last part shorter) |
| `file_size >= 9,728,000`, exact multiple | `file_size / 9,728,000 + 1` hashes (last hash is the special empty-part hash) |

The "+1 with trailing empty hash" at exact multiples is the part-hash-set tracker for the same eMule/aMule variant that the file-hash algorithm uses. The set must match the size; mismatches are rejected as invalid links.

## Implementation notes

- Fixture coverage required: empty input, one-part input, exact-part-size boundary input, multi-part input, boundary-plus-one input.
- rmule wraps the `ed2k` crate behind `rmule-primitives` types (ADR-0012) so a future swap to a hand-rolled implementation does not change the public API.

## Sources

Cached:

- `docs/reference/amule-wiki/md4_hash.wikitext` — the four-step algorithm; the canonical short statement of "not plain MD4".
- `docs/reference/wikipedia/ed2k_uri_scheme.wikitext` — cross-check on hash shape and part size.
- `docs/reference/rhash/ed2k.c` — independent implementation; useful for confirming the eMule/aMule variant exists in third-party tools. **Reference only, do not port** (ADR-0004).
- `docs/reference/emule-spec/emule_protocol_specification.pdf` section "File ID" / "File hash". Local-only PDF.

Link-only:

- aMule source (GPLv2): `src/KnownFile.cpp` is the behavioral oracle for part counts, part hash sets, and the exact-multiple case. Pinned commit SHA in `docs/protocol/source-map.md`.
- AniDB wiki Ed2k-hash (license unconfirmed, Cloudflare-gated): documents the variant split, supporting the choice in ADR-0014.

## Open questions

- None outstanding. The variant decision is locked, fixtures cover the boundary cases, and the part hash set count rules are exhaustive.
