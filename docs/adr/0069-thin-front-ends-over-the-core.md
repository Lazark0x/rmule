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
  identity, the managed server list (ADR-0080), and preferences. A front end changes a
  preference through **Core Settings** (below) and the rest through core commands, and
  reads them back the same way. No front end keeps a config file of its own as a
  source of truth.
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

### Core Settings

Core owns every preference that changes what core does, and one door reaches them:
the `CoreSettings` value and a synchronous handle on it — `Core::settings()` on a
running core, or opened on the store alone where no core runs (the CLI's `config`
subcommands).

- **The key split.** Core's keys are the download directory, the Temp Directory,
  obfuscation, port mapping (with the learned method and the PCP secret), the Kad UDP
  Key, `Remember peers`, the Dead Server Limit, the Announce Policy, both mirror URLs
  with their fetch switches, the server.met auto-update switch and its URL list
  (ADR-0065), the nickname and both ports. The nickname and the ports stay
  in the identity rows; the handle hides where each value is kept. `CoreSettings::credentials` turns the
  nickname and the TCP port into what every login, hello and Kad dial presents. Core
  reads them itself, so no command carries credentials and a front end never composes
  them from the rows; `StartServing` names only where to listen. A test or a tool
  injects its own `CoreSettings` per core, where a TCP port of `0` takes one the OS
  assigns and presents the port bound — each hello reads the listener's port as it is
  sent, so a download begun before the bind, or before the listener restarted on another
  port, presents the one bound now, and a Kad start
  binds the listener first (ADR-0095); the store refuses `0`. The Kad UDP Key and the
  Kad ID are read from core's store at build, so `EnableKad` carries neither. Likewise
  `StartDownload` names the file only: core places it in the download directory its
  settings name, judged by the share guards at the start (ADR-0101), and refuses the
  start when there is none or the guards refuse it, so no front end composes a path and
  no download finishes where core would not share it. `DownloadCompleted` names the
  final path core placed the file at, so a front end shows where it landed without
  composing one. `DownloadQueued` and `DownloadRecovered` name where a download's bytes
  lie now (ADR-0114). Six keys are the front end's: the theme, the table sorts, the Run
  Log level, connect at start and the last server — those two because connecting is the
  operator's act (ADR-0095) — and the Player Command, because core never runs a player
  (ADR-0114). They stay in the one
  `preferences` table under the same key strings. Core keeps them through a raw
  key/value surface that refuses a key of core's own, and never interprets one; each
  front end names its keys in an enum of its own.
- **The change path.** `set(Setting)` validates the value, persists it, and answers
  when it takes effect: `Now` or `NextStart`. A download directory is validated against
  the Shared Directory List's guards too (ADR-0101) — the running core's, or those the
  front end names on a handle opened on the store alone — and a refusal carries the
  guard's reason, so a refused directory is never stored. A handle taken from a running core
  applies a live key itself; one opened on the store alone answers `NextStart`. No core
  command changes a preference, and the store seam reads core's keys but writes none,
  so no front end can go around the handle.
- **One queue.** A live key travels to the actor on the same inbox as the commands, so
  the actor takes both in the order they were sent: a command sent after `Now` runs
  under the change. The handle stays synchronous — the queue is unbounded, and commands
  alone wait for room.
- **The build.** `Core::builder(config, store)` reads `CoreSettings` from the store it
  is given, so every front end starts its core under the operator's choices without
  copying them. A test and `rmule-tools` inject one with `.settings(…)`, so nothing
  reads the store behind them. `CoreConfig` keeps only engineering knobs: timeouts,
  concurrency, cadences.

| Setting | Takes effect |
| --- | --- |
| `Remember peers` | now: the next seed write keeps that many |
| Dead Server Limit, Announce Policy | now: every server is judged again, and the live session follows |
| Download directory | now: core starts its scan, with the answer the front end's confirm gave (ADR-0101); a core scans the one its settings name from attach, asking from the answer recorded for it |
| Temp Directory | now: downloads started after the change place their part files there; every stored download keeps its own (ADR-0115) |
| Obfuscation | now: every surface reads the one policy as it decides, and the Kad node is re-armed (ADR-0046) |
| every other key | at the next start |

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
  frames collapse into one draw.

### Core never waits on the front end

A reader that stops reading — a full pty, a stalled ssh, a remote transport's dead link —
costs the front end its view and costs the node nothing. Peers do not wait for a
terminal, so nothing that serves them waits for one.

- **The Outbox.** Every core task reports through the Outbox, whose send is synchronous
  and never waits. `Core::next_event()` and `Core::quit()`'s stream read it. It holds
  three weights, named for each `CoreEvent` in one exhaustive match, so a new event does
  not compile until it is placed:
  - An **Edge** is a change the front end's state folds and cannot rebuild: a download's
    or a search's lifecycle, a verified part, a session's transitions, a refusal. An Edge
    is never dropped. Edges grow with what the operator and the library do, not with
    peer traffic.
  - A **Level** is a value a later one of the same subject replaces: a queue rank, a
    search's legs, a reconnect countdown. A new value takes the old one's place out of
    the queue and joins the tail, so what the reader sees is always what core said, in
    the order core said it, less the values already superseded.
  - A **Note** is a peer-driven fact with no successor: a source found, a dial's end, a
    slot granted. Notes are delivered in order while the reader keeps up.
- **The room.** The Outbox holds a fixed room of events. Past it, Levels and Notes are
  dropped together and one `EventsShed` Edge takes their place with their count, so peer
  traffic never grows the queue and the reader learns what it missed. A shed loses a
  front end some per-peer detail, never a row's lifecycle.
- **The Run Log is written in core** (ADR-0075), at the send, before any weight is read.
  It holds every event a stalled front end missed, and it does not stop with the bridge.
  The level handle is the builder's, shared with the front end that changes it.
- **The bridge is two tasks.** One forwards commands and may wait for the inbox's room;
  the other reads events and may wait for the `Action` bus. Neither wait holds the
  other. `CoreClient::send` hands a command over and returns, so the UI loop never waits
  on the bridge. The forwarding queue is unbounded because the operator is its only
  writer; the inbox's room is the bound.
- **Stops do not join in a command arm.** A stop tells the run and goes on. The actor
  retires the run when its task has ended, finishes the operator's act there, and holds
  later commands for that download until then, so they run in the order they were sent.
- **Inner cycles follow the same rule.** The Kad pump holds what discovery has not read,
  as it holds what the node's inbox has no room for, and a sweep's asks wait for room
  outside the task that reads the answers (ADR-0093).
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
- **Front ends write preferences and apply them.** A front end wrote the store, copied
  start-time values into `CoreConfig` and sent a command per live key. Rejected: two
  doors, and a front end that copied nothing started its core under defaults the
  operator had changed.
- **Growing `rmule-tools` into the product CLI.** Rejected: the diagnostic tool and the
  product stay separate members.
- **Bounded channels with awaited edges.** The first shape: every event awaited a
  32-slot channel and the bridge awaited the bus. Rejected: a stalled terminal stopped
  every run, and the bridge, the actor and the UI formed two cycles of bounded awaits
  that about 66 commands could close for good.
- **A plain unbounded event channel.** Rejected: a stalled front end would grow it with
  peer traffic for as long as the stall lasted.
- **Dropping any event past the room.** Rejected: a lost lifecycle edge leaves a row
  wrong for the rest of the session, and no later event repairs it.
