# Library crates return typed errors; anyhow only at tool and CLI edges

## Context

Library consumers act on what went wrong: an invalid link, an invalid hash, an
unsupported variant, a malformed or truncated packet, an invalid tag, an incompatible
fixture, a failed dependency. An opaque error type throws those categories away.
Tools and command handlers, by contrast, mostly report an error and stop, where
`anyhow`'s context chaining is the ergonomic choice.

## Decision

Library crates under `crates/` expose typed domain errors, defined with `thiserror` or
an equivalent hand-written enum, and never put `anyhow` in a public API. `anyhow` is
used only at the edges: `rmule-cli`, the tools under `tools/`, examples and build
scripts.

## Consequences

- Public errors carry useful context without dumping untrusted packet payloads by
  default.
- Edge crates convert library errors into their own reporting types.
- Error categories are part of each crate's API and change with the same care as
  other public types.

## Considered options

- **`anyhow` throughout all crates.** Rejected: consumers cannot match on the failure.
- **Highly granular error types for every module from the start.** Rejected: the
  categories grow with the protocol model rather than ahead of it.
