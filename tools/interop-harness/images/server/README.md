# Server Interop Image

This directory contains the default local eD2k server image build context.

The image downloads the Lugdunum `eserver` 17.15 x86_64 Linux binary at build time
and runs it under Docker's amd64 emulation on ARM hosts. The binary is intentionally
not vendored in this repository.

This is the **Compatibility Tier** server (ADR-0033): it proves real-wire compatibility,
not correctness.

## Known limitation — Low-ID multi-client topology is flaky

The configless Lugdunum 17.15 build (a ~20-year-old closed x86 binary under emulation)
**drops a client's login (`reason=ServerClosed`, no `OP_IDCHANGE`) once a Low-ID client is
connected**; a second client is also dropped. Found while building the
`amule-low-id-callback` scenario, and reproducible independently of UDP (the `donkey.ini`
fixed that separately), hostname-vs-IP, in-container-vs-local, and the High-ID back-connect.
It is a **server-image problem**, not a rmule bug — rmule logs in, serves, and gets High-ID
fine here in isolation; the eserver has a documented history of dropping client connections
in multi-client states (fixable only by its now-absent author), and the Low-ID multi-client
path was never exercised before cycle-11 (`amule_low_id` defaults false).

**Consequence (ADR-0040):** the Low-ID callback **correctness** bar lives in the deterministic
in-process `FakeEd2kServer` (`crates/rmule-core/tests/common/fake_ed2k_server.rs`), which
models the back-connect probe, Low-ID assignment, and the callback relay faithfully. This
Docker scenario stays an **opt-in, best-effort smoke** (`#[ignore]`); do not treat its
flakiness on the Low-ID topology as a rmule regression. A native open-source eD2k server
(eNode, Node.js) is filed as a follow-up for a greener real smoke — see the first-class-peer
issue tracker.
