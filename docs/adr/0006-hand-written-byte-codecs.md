# Explicit hand-written byte codecs for eMule wire formats

## Context

eMule packet and tag formats are full of quirks: mixed endianness, length prefixes of
different widths, optional trailing fields, and tag encodings that differ by
direction. Compatibility work depends on seeing exactly which byte goes where. A
serialization framework that derives the layout from type definitions hides those
quirks behind generated code, and a round trip through it can be self-consistent while
disagreeing with aMule.

## Decision

Every eMule wire format is decoded and encoded by an explicit, hand-written codec that
works directly on byte slices, with small cursor helpers in each crate and typed errors
for every rejection. The higher-level grammars are hand-parsed the same way: eD2k links
(`crates/rmule-primitives/src/link.rs`) and search expressions
(`crates/rmule-ed2k/src/search_request.rs`, `crates/rmule-kad/src/search_tree.rs`).

A parser crate may be adopted for a higher-level text grammar only if its output can be
tested against protocol examples and it does not hide byte-level packet layout. None is
in use.

## Consequences

- Packet compatibility tests assert both the decoded values and the re-encoded bytes.
- Protocol quirks stay visible in the code that handles them, next to the upstream
  citation that explains them.
- Each codec carries some boilerplate that a derive-based framework would generate.

## Considered options

- **A parser/serializer framework for the whole wire format.** Rejected: it hides the
  byte layout that compatibility work has to see.
