# Front ends are thin shells over the core: headless rmule-cli and the in-process rmule TUI behind a CoreClient seam

## Context

The core (`rmule-core`) runs the whole client: server sessions, search, source
discovery, downloads, serving, Kad. A front end has to own a process — arguments, the
data directory, logging, the terminal — and present what the core reports. Two shapes
of front end were possible: one that keeps its own state (a config file, its own
server list) beside the core, and one that keeps none and speaks to the core only
through commands and events.

The core's observable surface is deliberately narrow: a single-consumer `CoreEvent`
stream (`Core::next_event()`) and a poll-style `DiagnosticsSnapshot`. One owner drains
events; there is no broadcast. rmule has no daemon binary, so a detached front end
would need an IPC surface invented for it alone.

## Decision

### The front-end layer

- **Durable application state lives in the core**, in the one store of ADR-0083:
  identity, the managed server list (ADR-0080), and preferences. A front end edits them
  through core commands and reads them through queries. No front end keeps a config
  file of its own as a source of truth.
- **`apps/rmule-cli` is the headless client**: a thin command router. Each subcommand
  opens the store in the data directory, issues one core command and prints what the
  core reports (`add <ed2k link>`, `server add|list`, `config`); the Kad node runner is
  its one long-lived command. It owns only process concerns: argument parsing, the data
  directory, the diagnostic `tracing` subscriber, and presentation.
- **`apps/rmule` is the product front end.** Its binary is named **`rmule`**,
  mirroring aMule, where `amule` is the UI app with the embedded core; `rmuled` stays
  free for a daemon.
- **`rmule-tools` stays a diagnostic tool**, never the product CLI.
- **No middle crate** between the core and the front ends. While the core owns the
  durable state, front ends share only the core API, and a middle crate would be a
  pass-through. One is extracted only when a second consumer proves shared non-core
  logic.

### The TUI's attachment

- **In process, behind a seam.** `rmule` embeds the core through `CoreBuilder`, and UI
  code speaks only to the `CoreClient` trait. The in-process binding, the **bridge**,
  owns the sole `Core` handle: it drains `next_event()`, issues commands and serves
  snapshots. UI components never hold `Core`, which keeps the single-consumer event
  rule honest. The seam is a module in the TUI crate and graduates to a crate only when
  a second consumer, such as a remote transport, exists.
- **One multi-thread tokio runtime.** The UI loop is an async task selecting over the
  terminal's input, a tick and the `Action` channel; core tasks and the bridge run on
  the same runtime. No render thread.
- **Hybrid sync.** The bridge folds lifecycle edges from the event stream into
  `UiState` at once and marks it dirty. A 1 Hz tick polls `diagnostics_snapshot()` for
  byte-level levels; rates are derived at the edge by differencing the monotonic
  counters of ADR-0077.
- **Render policy.** Dirty-flag coalescing capped at about 30 fps, each frame in
  synchronized output (mode 2026). Input redraws at once; bursts of core events between
  frames collapse into one draw. Backpressure is coalescing — bounded channels,
  latest state wins, a snapshot poll skips while one is in flight — so no queue can
  grow.
- **State model.** The bridge owns a single-writer `UiState`; components hold view
  state only (selection, scroll). `UiState` evolves purely —
  `fold(state, event)` and `apply_snapshot(state, snapshot, now)` with time injected —
  so the UI core is testable without a terminal, tokio or a live core, and renders are
  golden-tested on ratatui's `TestBackend`. Tables keep full row vectors and render the
  visible window; sorted and filtered projections recompute on dirty, not per frame.
- **Closing the UI stops the transfers**, as in stock aMule. Quit is `Core::quit`, the
  one retire sequence of ADR-0093; the status bar redraws on each
  `CoreEvent::Quitting { step }`, and if the bridge's `CORE_SHUTDOWN_GRACE` elapses
  before the flush confirms, it says so rather than reporting a clean drain.

## Consequences

- Front ends share one source of truth, the core's store; adding a front end adds no
  second persistence path.
- A remote transport — a future daemon's — implements `CoreClient`, and the UI runs
  unchanged against it. No bespoke IPC exists in the meantime.
- The bridge is the home for UI-side derived state the core does not hold, such as rates
  and ETA.
- The UI core is pure and tested without a terminal.

## Considered options

- **A detached daemon for the TUI.** Rejected: it needs an IPC surface invented for it
  alone, against the single-consumer event stream.
- **A front-end config file (TOML) as the source of truth.** Rejected: a second
  persistence path every other front end would have to share or duplicate.
- **Growing `rmule-tools` into the product CLI.** Rejected: the diagnostic tool and the
  product stay separate members.
