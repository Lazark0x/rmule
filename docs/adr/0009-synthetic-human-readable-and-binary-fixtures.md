# Protocol fixtures are human-readable plus binary, and their content is synthetic

## Context

Compatibility claims need executable evidence that a reader can check: what input
went in, what typed value came out, and which exact bytes go back on the wire. Inline
test literals hide that evidence inside Rust code. A fixture corpus also has to stay
publishable: real server lists, real eD2k links and real file names would turn a
protocol test suite into a content index.

## Decision

Fixtures live next to the crate that uses them, under `crates/*/tests/fixtures/`.
Expected protocol models are human-readable TOML; exact bytes, where they matter, are
binary golden files. A link fixture records the input, the normalized and canonical
output, and whether it is accepted or rejected. A packet fixture pairs raw bytes with
the expected decoded fields and round-trip behaviour.

Every fixture records its provenance: `handwritten`, `documentation`,
`amule-generated` or `captured` (`docs/protocol/fixtures.md`). Captured fixtures sit in
a `captured/` directory with a `meta.toml` naming the counterparty and how the bytes
were taken; they come from live runs against counterparties on the local interop
bench (ADR-0033). Values read from upstream source are never a fixture (ADR-0082).

Fixture content is synthetic: synthetic file names, hashes, hosts and packets. The
repository bundles no real server lists, content indexes or real eD2k links. This rule
covers the repository's contents only; the shipped client's default bootstrap sources
are ADR-0065's decision.

## Consequences

- Protocol tests double as protocol documentation, readable without running them.
- Fixture quality comes from controlled synthetic cases and explicit captures, never
  from real content links.
- A capture is stored only when its bytes carry nothing but bench-generated content.

## Considered options

- **Keep protocol cases inline inside Rust tests.** Rejected: the evidence is hard to
  review and cannot be shared across crates or tools.
- **Use real network examples for higher fidelity.** Rejected: it puts real content
  and real hosts into the repository; the bench gives the same fidelity with synthetic
  content.
