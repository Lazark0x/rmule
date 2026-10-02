# Local interop harness uses real server, aMule, and rmule CLI

## Context

In-process loopbacks and fakes prove rmule's own logic deterministically, but they
cannot prove that rmule interoperates with the software it must live beside: a real
eD2k server, aMule/amuled and the other clients on the network. The server is itself
part of the compatibility surface, so a rmule-authored stand-in cannot answer the
question. And the production-facing CLI — source lookup, peer transfer, durable state,
final file write — is part of the operator contract and needs exercising end to end.

## Decision

`tools/interop-harness` is an opt-in Compatibility Tier that stands real, unmodified
counterparties up in containers and drives rmule against them.

- It is a separate workspace member, not part of `rmule-tools`. The harness owns
  external-process lifecycle, networks, artifact directories, timeouts and environment
  checks; `rmule-tools` stays the rmule-side operator CLI that the harness invokes
  (for example `ed2k download start`) or packages into the rmule node image.
- Each end-to-end exchange is a named Flow, reachable from its own subcommand (such as
  `amule-serves-rmule-downloads`), never a generic `run`. A Flow builds its images,
  creates its network, starts every container, drives the exchange, collects logs,
  writes its verdict and tears down.
- Images come from checked-in Dockerfile recipes under `tools/interop-harness/images/`.
  Recipes may fetch pinned external artifacts at build time; archives, binaries,
  built images and run artifacts are never vendored, and binaries of uncertain licence
  never enter the repository. Callers may override images and build contexts.
- The container runtime is a Docker-compatible CLI chosen by `--container-runtime`
  (default `docker`); there is no deeper runtime abstraction.
- Each run writes its resolved configuration, logs and verdict into a run directory as
  Interop Run Artifacts.
- The main download path discovers its source through the real server's source
  lookup, not by injecting a peer endpoint.
- Readiness is event-driven where a counterparty exposes a signal, otherwise bounded by
  explicit polling timeouts, keeping the latest logs.
- A transfer succeeds on verified parts plus a byte-for-byte final file.

## Consequences

- The harness builds in ordinary workspace checks but starts no container unless
  invoked. Its acceptance tests run only with `RMULE_BENCH=1`; plain `cargo test` never
  touches the network, and a missing container runtime or artifact fails clearly.
- The harness is best-effort evidence, not the correctness gate: the deterministic
  Correctness Tier beneath it runs in ordinary `cargo test` (ADR-0040). Only a run
  against the stock counterparty counts as interop proof.
- What a Flow proves is recorded under the evidence standard (ADR-0045).

## Considered options

- **rmule-authored mock server and peer only.** Rejected: they cannot prove real
  server-session or aMule interoperability; that is the Correctness Tier's job, not
  this one's.
- **A minimal rmule-authored rendezvous server.** Rejected: the server is part of the
  surface under test.
- **Linking `rmule-core` directly from a Rust integration test.** Rejected: the CLI
  boundary is part of the operator contract.
- **Folding the harness into `rmule-tools`.** Rejected: container lifecycle, artifact
  fetching and counterparty profile generation are test-environment work, not operator
  commands.
- **A shell script.** Rejected: structured process control, timeouts, retained run
  metadata and eD2k parsing are less brittle in Rust.
