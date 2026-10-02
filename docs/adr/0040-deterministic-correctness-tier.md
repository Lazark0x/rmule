# Deterministic correctness tier: in-process fake counterparties in rmule-testkit

## Context

Interop against real counterparties (ADR-0033) catches bugs no loopback reaches, but
it is a poor correctness gate. The Lugdunum eserver is a closed, decades-old x86
binary run under emulation; it drops a client's login once a Low-ID client is
connected, and its multi-client states have a history of dropped connections that
nobody can fix. A real-aMule run against it once caught four Low-ID callback bugs —
the listener bound after login (so the reachability back-connect found nothing and
rmule got Low-ID), a serve-start failure swallowed into a hang, a hostname server
encoded as `0.0.0.0:0` in the callback correlation key, and the server relay between
two client sessions — that the in-process fake of the time missed, because it faked
away the probe, the relay and the correlation.

Separately, counterparty scaffolding was duplicated and crate-locked: hand-scripted
fake peers re-rolled per test, and a fake server in one crate's `tests/common/` that
CLI tests, runtime loopbacks and identity tests elsewhere could not reach.

## Decision

Interop testing has two tiers, and the deterministic one lives in a dev-only crate.

- **Correctness Tier.** Deterministic, in-process fakes over real localhost sockets, run
  by ordinary `cargo test`. They are faithful to behaviour, not to bytes, and a seam is
  added only when a test demands it.
- **Compatibility Tier.** The container harness against real counterparties
  (ADR-0033): opt-in and best-effort. It proves real-wire compatibility when it runs; it
  is not the correctness gate.
- **`crates/rmule-testkit`** holds the Correctness Tier. It is `publish = false`,
  consumed only as a `[dev-dependencies]` entry, never in a production dependency graph,
  and never wired into the container harness. It provides:
  - `FakeEd2kServer`, which models exactly the seams the callback bugs lived in: a
    High-ID back-connect probe (the captured `OP_HELLO` → `OP_HELLOANSWER` port check;
    reachable means High-ID, refused means Low-ID), Low-ID assignment, and the callback
    relay across two client sessions — plus an obfuscated-accept option for the
    connect-crypt seams (ADR-0042). Because High-ID is gated on a real probe, binding the
    listener before login is a precondition for the positive callback loopback to pass.
  - `FakePeer`, a scriptable peer that also misbehaves on command in ways a real peer
    will not: stall after the slot, queue forever, drop mid-part, never finish the
    handshake.
  - Scenario wiring: core spawn, temporary directories, config plumbing, a real serving
    core as counterparty, and per-protocol fixture vocabularies (Kad mesh, node, keyword
    and source; peer session; wire).
- **Both fakes, by test class.** Happy paths run against a real serving rmule core, so
  every download test exercises the serve side too; adversarial paths use `FakePeer`.
  Protocol-Counterparty Tests — a subject speaking eD2k, peer or Kad protocol to a faked
  other side — use the testkit. Transport Probes — raw scripted sockets exercising driver
  pipe invariants such as duplex, write-error convergence and synthesised disconnect —
  stay raw, because they have no protocol counterparty to fake.
- **Hermetic CLI tests keep the process boundary real.** `assert_cmd` spawns the actual
  binary against fakes running in the test process.

## Consequences

- Callback correctness — probe, relay and correlation — regresses in ordinary
  `cargo test`, independent of the eserver's behaviour.
- The testkit introduces dev-dependency cycles: `rmule-net` dev-depends on
  `rmule-testkit`, which depends on `rmule-core`, which depends on `rmule-net`. Cargo
  supports them; it is the usual testkit shape.
- Tests that bind `:0` must set `identity.tcp_port` to the bound port, because the login
  advertises the configured port, not the bound one; in production the two coincide.
- A fake passing is never interop proof; only a run against the stock counterparty is.

## Considered options

- **One tier with an enriched fake.** Rejected: it leaves the flaky real server as the
  only real-wire check and conflates catching logic bugs with proving byte
  compatibility — two jobs with opposite reliability needs.
- **A faithful-to-bytes in-process eserver, or building every fake seam up front.**
  Rejected: it re-implements the closed eserver, which is the Compatibility Tier's job
  and a maintenance sink.
- **Sharing the in-process server with the container harness.** Rejected: they are
  different tools; the harness orchestrates processes.
- **Keeping the fakes in `rmule-core/tests/common/`.** Rejected: a test module cannot
  cross the crate boundary, and the consumers span the workspace.
- **Only `FakePeer`, or only a real counterparty.** Rejected: the first turns happy paths
  into byte scripts that re-implement the peer protocol; the second cannot express the
  stall, timeout and race cases.
- **Relying on the real server for correctness.** Rejected: non-deterministic, emulated,
  and broken in exactly the topology under test.
