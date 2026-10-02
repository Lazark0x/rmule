# The `ed2k` hash crate is used behind rmule-owned hash types

## Context

The `ed2k` crate computes the MD4-based eD2k file and part hashes. Reusing it saves
writing and maintaining a hash implementation, but ADR-0002 accepts a
protocol-specific crate only on compatibility evidence, and a dependency's types in
public APIs would make the protocol model depend on that one choice.

## Decision

rmule computes eD2k hashes with the `ed2k` crate, which passes rmule's hash
compatibility fixtures. Public APIs expose only rmule-owned types: `FileHash`,
`PartHash` and `PartHashSet` in `rmule-primitives`. The crate is used internally by
`rmule-primitives` (`hash.rs`), by `rmule-core` for incremental file hashing, and by
`rmule-testkit`; no public signature names an `ed2k` type.

## Consequences

- Hash compatibility tests cover single-part and multi-part files, the exact
  part-size boundary (ADR-0014), the empty file, and canonical hex formatting.
- If the `ed2k` crate ever fails a compatibility test, the implementation changes
  without breaking any public API.
- eD2k link parsing and formatting stay in `rmule-primitives`, independent of the
  hash crate.

## Considered options

- **Expose the `ed2k` crate directly in public APIs.** Rejected: it leaks a dependency
  choice into the protocol model.
- **Implement eD2k hashing in-house.** Rejected: fixtures prove the existing crate
  correct, so rewriting it buys nothing.
