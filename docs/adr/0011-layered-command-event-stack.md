# A layered protocol stack: commands flow down, events flow up

## Context

rmule combines stateless primitives (hashes, links, identifiers, packet conventions,
tags), stateful protocol behaviour (eD2k server sessions, Kad, peer transfer), and
application concerns (what the user asked for, what to show). Without fixed layers,
socket handling and protocol state leak into the front-ends, and application policy
leaks into the protocol crates.

## Decision

rmule is a layered stack driven by commands and events:

- **Primitives** (`rmule-primitives`) provide hashes, links, identifiers, packet
  conventions, tags and fixtures, with no orchestration and no async runtime.
- **Protocol services** own the state machines for eD2k, Kad and peer transfer, as
  sans-I/O sessions in the protocol crates driven by the runtime in `rmule-net`.
- **The core** (`rmule-core`) coordinates the services, storage, bandwidth policy and
  the application-facing flow. It accepts `CoreCommand`s and emits `CoreEvent`s.
- **Apps and tools** consume the layer they need. The front-ends talk to the core
  only through commands and events (ADR-0069).

## Consequences

- Stateful networking belongs in protocol services, never in a front-end.
- Applications send commands down and observe events coming up; they do not call into
  protocol sessions directly.
- Primitives stay free of orchestration and runtime concerns (ADR-0007).

## Considered options

- **An actor system throughout the protocol stack.** Rejected: it spreads concurrency
  through every layer, including the ones that should stay sans-I/O.
- **Service objects with direct method calls.** Rejected: it couples callers to
  service internals and gives front-ends a path around the core.
