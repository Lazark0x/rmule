# A dial that ends before the hello says why, and the cause outlives the slot

## Context

A worker that ends before the peer's hello — refused, never dialed, timed out, closed — leaves
its slot to the next peer within a second, so a cause kept on the slot is never seen, and an
operator cannot tell a dead source from one rmule refused.

## Decision

A worker that ends before the peer's hello names its cause — refused for an unknown or unmeetable
crypt stance or a missing key, never dialed (IP filter, ban), the connect refused, timed out or reset,
the link closed, broken or silent before the hello — as `DialEnded`, written to the Run Log with the
peer's address at the full level only. The download's diagnostics row keeps a **Dial End** per source:
the peer, the cause, when, and whether it was a seed; a later end for the same peer replaces it, a new
dial to that peer removes it, it survives the slot moving on and the run ending, it clears when a run
starts or the row is reset, and the newest 64 per download are kept. The Sources pane lists every slot
and, below them, one row per Dial End whose peer no slot holds.

## Consequences

- The Sources pane shows why each peer a download dialed never answered, including seeds
  (ADR-0109).
- A peer's address reaches the Run Log only at its full level (ADR-0075).

## Considered options

- **Keeping a dial's end cause on the worker slot.** Rejected: the slot took its next peer within a second,
  so the cause was never seen.
