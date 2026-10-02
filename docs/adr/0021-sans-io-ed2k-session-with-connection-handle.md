# Sans-I/O Ed2kSession with Connection handle

## Context

A server connection has a lifecycle: TCP connect, write the login, read framed bytes,
decode the welcome burst into `Ed2kEvent`s, accept `Ed2kCommand`s, and tear down
cleanly. The idiomatic Tokio shape is an actor task per connection that owns the
socket and the state, with channels for commands and events. That shape fuses the
protocol state machine to a running runtime: unit tests must spin one, fixture replay
needs an extra tap, capture is bolted on rather than structural, and the Kad and peer
protocols would face the same problem with no template.

## Decision

The session is a sans-I/O state machine in `rmule-ed2k`; a thin Tokio driver in
`rmule-net` runs it.

- `Ed2kSession` exposes `new(endpoint, identity)`, `start()`, `handle_bytes(&[u8])`,
  `handle_command(Ed2kCommand)`, `login_deadline_elapsed()` and
  `poll_output() -> Option<Output>`. `Output` is the shared
  `SessionOutput<Ed2kEvent, CloseReason>` — `Write`, `Event` or `Close`
  (ADR-0044). The session owns its frame buffer, decodes packets, and never sees a
  socket or a clock.
- The driver in `rmule-net` is the only place that imports Tokio. It owns the socket,
  feeds inbound bytes into the session, drains outputs into writes, events and
  closes, and enforces the connect and login timeouts by telling the session when a
  deadline has passed.
- The public entry point is `rmule_net::ed2k::Connection` with `connect`,
  `connect_with_options`, `send`, `next_event` and `shutdown`. `connect` returns once
  TCP is up, before login completes, so the login outcome arrives as an event rather
  than inside the constructor's result.
- Teardown is shared with every other driven session: `shutdown` is cooperative with
  a grace period, and dropping the handle aborts the driver and capture tasks as the
  safety net.

## Consequences

- The whole protocol runs in unit tests over byte slices, with no runtime.
- Capture is structural: the driver already sees every byte in both directions
  (ADR-0022).
- The shape is the template for the Kad and peer sessions (ADR-0044).
- The cost is one extra layer and an explicit state machine instead of imperative
  async code — the same cost `rustls`, `quinn` and `http` pay for the same reasons.
