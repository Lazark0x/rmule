# A parity gap closes on the evidence its disposition demands

## Context

The parity matrix in `docs/protocol/parity/` scores every wire row against aMule and
the wider eMule family. A row's disposition is `full` (it affects transfers, source
discovery, upload fairness, connectivity, network health or obfuscation), `graceful`
(human-layer semantics or optional operations: parse, answer safely, never break the
protocol) or `n-a`. A **gap** is derived: disposition `full` or `graceful` × status
`missing` or `partial`.

Closing a gap needs a rule for what counts as proof. Two failure modes bound it. A
loopback that fakes away the real seams misses real-wire bugs, which is why the
Compatibility Tier exists (ADR-0033, ADR-0040). And a rule with no principled exit
forces capturing a known-defective binary's failure, which has no decision value. The
Kad work (ADR-0043) showed that apparent elicitation walls fall to better approaches,
such as rmule as stimulus and harness-authored counterparty state.

## Decision

**Every gap, `full` or `graceful`, needs a deterministic regression** that gates CI in
ordinary `cargo test`. The tier is named by role, not crate: `rmule-testkit` fakes
(`FakeEd2kServer`, `FakePeer`) for the server and peer surfaces, the sans-I/O `KadNode`
with the mesh simulation for Kad, a local HTTP fixture for bootstrap acquisition.
`graceful` rows are exercised with misbehaviour scripts (malformed body, unexpected
opcode): parse, answer safely, never break the protocol. Fakes stay faithful to
behaviour, never drifting into byte-faithful reimplementations (ADR-0040).

**A `full` gap also needs capture evidence:**

1. **The counterparty is a pinned real implementation, hosted locally**: aMule 2.3.3,
   amuled or a server, in the interop harness. Not protocol documents and not rmule.
2. **Only counterparty bytes are evidence.** rmule's own emissions never self-certify.
   For an emit row the evidence is the counterparty's observable reaction (the expected
   reply opcode, a state change): acceptance, not transmission.
3. **No public-network bytes are committed as evidence.** A run against the public
   network, a live IPv6 server or a maintainer's live node is gated on `RMULE_BENCH`,
   writes the verdict `SMOKE` with observed bytes summarised in the run directory, and
   promotes nothing.
4. **Provenance is reproducible**: a checked-in harness scenario or a documented recipe
   (seeded counterparty state, image, exact command). Re-runnable in principle, never
   CI-gating.

**Capture feeds the deterministic tier.** When a capture yields counterparty bytes for
a consume row, at least one golden vector is committed beside the deterministic test,
with a provenance note naming the scenario. Raw pcaps and run directories stay out of
the repo.

**The sole exemption is a counterparty defect.** A `full` gap closes without capture
only when the counterparty demonstrably cannot produce the behaviour (its own bug or
absence), proven by the approaches attempted and recorded in the matrix row's Notes.
Difficulty alone never exempts. The toolbox is wide: stimulus elicitation, authored
counterparty state (seeded `nodes.dat`, config, fake-public topology), aMule↔aMule wire
observation with rmule absent, remote control as a test instrument (`amulecmd`
cancelling a transfer to elicit `OP_CANCELTRANSFER`), amuled as an HTTP stimulus, an
alternative server build.

**Who counts as a counterparty.**

- Any **independent, maintained third-party implementation** pinned at an exact upstream
  commit is admissible. Independent means not authored, forked or steered by this
  project. rmule-authored servers (testkit fakes, emulated-server shims) never are.
- **Maturity gates interpretation, not admissibility.** A young server's bytes prove
  what that implementation does. Rows scored against ecosystem behaviour keep the
  aMule and Lugdunum forms as the parity reference, and a divergence is recorded in the
  row's Notes without overwriting it.
- **A locally patched counterparty is inadmissible for the patched surface.**
  Admissibility returns once the upstream maintainer merges the change and the bench
  re-pins a commit that contains it.
- **rmule's own upstream contributions keep independence** once the maintainer has
  reviewed and merged them; the fixture provenance for that surface is tagged
  `rmule-contributed`. Spec corrections and bug reports taint nothing.
- **A fork-branch pin is admissible** (kno's aMule fork at `ab483654` is the first). The
  image recipe records the SHA, the fork owner and the upstream base; fixtures carry a
  body-specific prefix (`amule-kno-*`); rebuilding the image re-verifies the pin and
  fails loudly if the commit is gone. A pin that can no longer be rebuilt is downgraded
  to stimulus for the rows it supported.
- **A debug build of a pinned body is the same body.** The pin names the commit, not
  the compile mode. aMule's release build compiles its debug logger away
  (`Logger.h`: `CLogger::IsEnabled` is `false` outside `__DEBUG__`), so a log-silence
  argument from the release image is never load-bearing.
- The **Reference Source** (pinned upstream eMule source) specifies behaviour and is
  never evidence; a row supported only by a source reading stays open. The emule-qt
  **Stimulus Counterparty** never scores a row, except for IPv6 and port mapping, where
  it is the reference implementation of the dialect (ADR-0082). A Wine-hosted GUI
  client with no script surface never counts.

**NAT flows prove the NAT they build.** Every flow behind a gateway container writes the
gateway's self-proof (the `nft` ruleset and a `conntrack` dump) and a `nat-type.toml`
naming the RFC 4787 mapping and filtering behaviour it claims (ADR-0092). A negative
verdict (a failed punch, a refused mapping) also needs an RFC 5780 reflector probe in
the same run. The reflector proves the bench, never a counterparty.

**Three row classes cover surfaces with thin external evidence:**

- **`single-oracle`**: counterparty bytes exist from exactly one implementation. The row
  is captured and flagged, never proven at parity, and upgrades when a second pinned
  body produces the bytes.
- **`rmule-only`**: no external bytes exist because both ends are rmule. The row is
  covered by the deterministic tier plus bench observation behind a proven NAT, scored
  exercised and never captured, and upgrades when a third party adopts the pairing.
- **`unprovable`**: the counterparty behaviour lives only in a protocol generation no
  pinned body speaks (Kad below v7, Kad1), so no counterparty can emit it toward rmule or
  answer rmule's form of it. rmule records a deliberate divergence in the surface's ADR
  instead of code it could never prove; the row is `exempt`, with `—` evidence and a
  Note naming that ADR, and the deterministic tier pins what rmule does in its place. It
  reopens only when a pinned body produces the behaviour.

## Consequences

- `docs/protocol/parity/README.md` cites this standard as the definition of a closed
  gap.
- Exemption claims live in the matrix row's Notes, listing the approaches attempted,
  the same way an `n-a` row carries its justification.
- Capture recipes and scenarios live in the interop harness; golden vectors land beside
  the deterministic tests they feed.
- Fixtures captured against a third-party server carry a body prefix (`ed2ksrv-*`,
  `enode-*`, `amule-kno-*`) and a provenance note naming the pinned commit.
- The Compatibility Tier stays opt-in and outside CI. This standard makes its evidence
  required when a gap closes, not continuously green.

## Considered options

- **Capture for every gap.** Rejected: `graceful` rows are malformed input and exotic
  opcodes that a real counterparty cannot emit on command; misbehaviour scripts exist
  because real clients cannot express them.
- **Deterministic tests only.** Rejected: a loopback that fakes the seams away misses
  real-wire bugs; compatibility evidence against a real counterparty is what the
  Compatibility Tier is for.
- **Waivers granted when the gap is specified.** Rejected: they erode into
  capture-when-convenient. Exemptions are earned by documented attempts, and only a
  counterparty defect qualifies.
- **No exemption at all.** Rejected: it forces capturing a defective binary's failure,
  which has no decision value.
