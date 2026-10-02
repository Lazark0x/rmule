# Protocol behaviour lives in reusable libraries; front-ends only consume them

## Context

rmule speaks the eMule-family protocols: eD2k server and peer TCP, server and peer
UDP, and Kad. Long-term compatibility with aMule and eMule depends on parsing,
hashing, session, transfer and storage-coordination logic that can be tested on its
own, without a user interface in the loop. The same stack is driven from more than one
place: the `rmule` terminal UI (`apps/rmule`), the headless `rmule-cli`
(`apps/rmule-cli`), the developer tools under `tools/`, and integration tests.

## Decision

Protocol behaviour lives in library crates under `crates/`. Every front-end is a
consumer of those libraries and owns no protocol behaviour of its own. The front-ends
today are the `rmule` terminal UI, attached to an in-process core (ADR-0069), and the
headless `rmule-cli`.

## Consequences

- Public crate APIs are designed deliberately rather than treated as app internals.
- Protocol conformance tests run without any front-end.
- A front-end cannot paper over a protocol-model mistake; the mistake shows in the
  libraries and is fixed there.
- Tools and tests reuse the same stack the shipped binaries use.

## Considered options

- **Front-end first, with protocol behaviour behind app services.** Rejected: it
  shows visible progress sooner, but it buries the protocol model inside one
  application, where it cannot be tested or reused on its own.
