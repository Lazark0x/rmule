# What a panic costs: the process in a dist build, the task elsewhere, and always a record

## Context

A panic in rmule is rmule's own defect: no panic is known to be reachable from a peer or from
the disk, and the fuzz targets keep it that way. What a defect costs was left to whatever each
task happened to do. Search reads its panic from the join handle, Kad's watchdog and serve's
liveness cell turn theirs into a stop (ADR-0093), and every other long task died silently: a
download's row kept saying it ran, the fronts' handles were dropped, and nothing wrote the
Run Log. `ratatui::init` restored the terminal on a panic on any thread, so one task's panic left
the UI drawing onto the shell's screen. A lock poisoned by that panic took down each later task
that took it, the bridge among them, and the bridge's end said nothing to the UI.

A half-dead node with a plausible screen is the worst outcome: the operator trusts rows no task
stands behind, and nobody learns why.

## Decision

**A panic always leaves a record. In a dist build it then ends the process. In every build that
unwinds it ends the one task it happened on, and that task's activity dies as any activity does.**

### The record

`rmule` and `rmule-cli` call `run_log::panic_record` first in their panic hooks. It writes a `panic` record and drains the log before anything else happens, so a panic's last
lines reach the file even when the process ends on the next instruction. The record holds the
thread and the source location at every level; the panic's message holds arbitrary values, so it
is a free-text field the full level admits alone.

### The dist build

`[profile.dist]` sets `panic = "abort"`, so the build an operator installs has no half-dead
state to reach: no task outlives a broken invariant, and no lock is ever seen poisoned. What
stands behind that is the Durable Store: a restart resumes every download from its transaction
and loses at most the credit minute (ADR-0083). The price is taken knowingly: a panic a peer
could reach would end the node rather than one session. The fuzz targets guard that door, and a
node that restarts is an honest failure where a node that limps is not.

### Builds that unwind

The bench's release binary, `cargo install`, tests and dev builds unwind, and there the
supervisor (`crate::supervisor`) is the one reader of a long task's panic:

- `watched` runs a future and answers `Err(Panicked)` when polling it panicked. It adds no task,
  so an abort still cancels the run itself and a join still means the run has ended.
- A download run, a search and the actor are read this way; a panicked run takes the failure
  `TaskPanicked`, so the row, its store record and the finish notice all say it ended
  (ADR-0093, "a death is a stop").
- `spawn_told` runs a front or a pump no ledger owns and tells `CoreEvent::TaskDied` with the
  [`LongTask`] that stopped. The actor's own death is told the same way; a front end treats that
  one as the core's end, since the rest of the node goes on holding the Outbox open.
- The bridge is watched from outside its own task, and a panic in it reaches the UI as
  `CoreClosed`. The input pump's end before the run's is a Quit, since it leaves no key to
  press.

Kad's watchdog and serve's liveness cell keep their shape: both already reach their retire.

### The terminal

`rmule` enters the terminal by hand, with no hook of ratatui's. A hook of its own decides by what
the panic costs. A worker's panic leaves the terminal alone and prints nothing onto the frame: it
is a Run Log record and a note on the action bus. A panic on the UI thread, or any panic in a dist
build, restores the terminal first and then says on the normal screen what happened, where, and
where the record is.

### Locks

Every blocking lock is `parking_lot`'s, which has no poison. A panic is the supervisor's to read,
once. A second panic in every later task that takes the lock is a cascade with no information in
it.

### Quit's reach

Every way out of a run is a Quit: `q`, SIGTERM, SIGHUP, SIGINT, the Windows Ctrl-C, Ctrl-Break and
console close, a failed draw, and the same signals around `rmule-cli`'s wait for a download.
`CORE_SHUTDOWN_GRACE` covers the sum of quit's own bounds, 33 s with nothing wedged, so a quit
that is merely slow is not cut off.

What the grace can still cut short is written first: quit opens with a credit checkpoint and the
`clients.met` snapshot, ahead of every step that can be slow, and closes with them again for what
the stops themselves accrued. Past the grace the runtime is shut down within a short bound, so a
blocking walk cannot keep the process alive after the terminal is back.

### After the core stops

A stopped core claims nothing. The connection dots, the rates and the row speeds read
`core_alive`, and the status bar tells the operator to quit and start rmule again.

## Consequences

- A dist build's panic is a restart with a record; there is no degraded mode to explain.
- The bench and the tests run the unwinding path, so the supervisor is proved where it runs, and
  a bench run keeps its other activities' evidence past one task's panic.
- `DownloadFailure::TaskPanicked` is appended, so rows already stored decode as they did.

## Considered options

- **Abort everywhere.** Throws the bench's evidence away with the process, and leaves the
  supervisor proved by nothing.
- **Unwind everywhere.** Keeps a node running past a broken invariant, with locks read
  through poison; the half-dead node this decision exists to end.
- **A second task per watched future** (the shape `run_watched` had). Aborting the watcher then
  leaves the real run ending some time later, so a join stops meaning the run ended.
