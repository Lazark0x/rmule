# A shared sans-I/O session spine in rmule-primitives owns the paired-Disconnected close

## Context

`Ed2kSession` and `PeerSession` share their session scaffolding: the output enum shape
(`Write`, `Event`, `Close`), the input buffer and output queue, the loop that drives
`Packet::decode` over incoming bytes, and the close discipline. ADR-0023 made
`Disconnected` the last word about a session, so the close discipline is the
load-bearing part: every close must queue exactly one `Disconnected` event immediately
before `Close`, and the driver harness relies on it.

When the generation of that event was split between the session and the harness, it
drifted. The sessions emitted the pair only for local closes and left the harness to
synthesize `Disconnected` for every other reason, behind a discriminant and a
"already pushed" flag. The stated reason, avoiding a `Clone` bound on wrapped errors,
does not hold: `CloseReason`, `PeerCloseReason` and `SessionError` are all `Clone`, and
the only stored I/O value is `io::ErrorKind`, which is `Copy`. Two copies of the
invariant, edited in lockstep, had already diverged once.

## Decision

`rmule-primitives` has a `session` module that both TCP sessions embed by composition:

- `SessionOutput<E, C>`, the output enum.
- `SessionCore<E, C>`, which owns the buffer loop (`feed`, generic over per-protocol
  packet dispatch and frame-error mapping), output queueing and polling, and `close`.
- `drain`, the helper tests use to collect a session's output.

**The session owns the paired `Disconnected` on every close path.**
`SessionCore::close` emits `Event(Disconnected { reason })` immediately before
`Close(reason)`, whatever the reason. The harness does not compensate. The `rmule-net`
driver synthesizes a `Disconnected` (through `DrivenSession::disconnected_event`) only
for closes the sans-I/O session cannot observe: clean EOF and socket I/O errors.

Protocol dispatch, states, commands, events and close-reason vocabularies stay in each
protocol crate. The spine shares plumbing, not vocabulary, so the rule that close-reason
variant names never unify across protocols (ADR-0081) is untouched. `KadNode` stays
outside: it is connectionless, takes explicit time and has no close (ADR-0043).

## Consequences

- The close invariant is correct by construction in one place, and the harness contract
  is smaller: its `Close` arm records the label and ends.
- `rmule-ed2k` and `rmule-peer` embed `SessionCore` with no change to either session's
  public interface.
- Hand-rolled test drain loops use `session::drain`.
- A future TCP protocol session embeds the same spine rather than re-copying the close
  discipline.
- A shared datagram spine for Kad would need its own case; this module does not cover it.

## Considered options

- **Keep the duplication.** Rejected: the close invariant lives in two copies and every
  new TCP session copies it again.
- **Wait for a third TCP protocol session**, per the rule to promote a shared
  abstraction only when a third protocol crate needs the same shape. Rejected: that rule
  governs shared vocabulary, which the spine does not unify, and the invariant is
  load-bearing with two sessions.
- **A new leaf crate (`rmule-sansio`).** Rejected: `rmule-primitives` already owns
  `Packet` framing, and the buffer loop is a framing-adjacent concern.
- **A `DrivenSession`-style trait over sans-I/O sessions.** Rejected as over-abstract;
  composition keeps each session's interface unchanged.
- **Having `close` return a typed `Result`.** Rejected: the paired emission is
  unconditional, so there is nothing for a caller to handle.
