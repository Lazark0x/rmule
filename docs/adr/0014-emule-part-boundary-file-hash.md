# The canonical eD2k file hash uses eMule's exact-part-size boundary

## Context

eD2k-compatible tools disagree on the file hash when a file's size is an exact nonzero
multiple of the 9,728,000-byte part size. eMule and aMule append the hash of an empty
part after the last full part and hash the resulting part-hash list; other tools hash
only the full parts. The `ed2k` crate offers both: its default `Ed2k`/`Ed2kBlue` type
follows the fixed-boundary variant, and `Ed2kRed` follows eMule. eMule and aMule are
rmule's compatibility targets, and a file hash that differs from theirs is a different
file on the network.

## Decision

rmule's canonical eD2k file hash is the eMule/aMule variant. On an exact multiple of
the part size, the part-hash set carries one extra entry, the hash of the empty part
(`crates/rmule-primitives/src/hash.rs`). File hashes are computed with `Ed2kRed`, never
the crate default, and part hashes with `Ed2kBlue`.

## Consequences

- Exact part-size hash fixtures name the eMule/aMule variant explicitly.
- `rmule-tools` prints the canonical eMule/aMule hash.
- Any future inspection of the fixed-boundary variant is an explicit non-canonical
  mode, never part of file identity.

## Considered options

- **Support both exact-multiple variants in the public hash APIs.** Rejected: two
  identities for one file split the network view of it.
- **Use the `ed2k` crate's default fixed-boundary type.** Rejected: it disagrees with
  eMule and aMule on every exact-multiple file.
