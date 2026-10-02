# Capture is a first-class library feature

## Context

The compatibility policy ranks `captured` fixtures as the strongest evidence rmule
can have: bytes nobody on the project typed, recorded from a real counterparty and
replayable forever (ADR-0003, ADR-0009). Recording them from outside the library —
a diagnostic tool wrapping the connection and observing the socket — would mean
either reimplementing the driver or adding a general observer trait whose only
consumer is one capture utility. Yet the sans-I/O driver already sees every byte in
both directions (ADR-0021), so capture is a structural property of the runtime,
not an afterthought.

## Decision

Capture is an option on every connection API in `rmule-net`, not a separate tool.

- Each driven session takes `capture_dir: Option<PathBuf>` in its options: the eD2k
  server connection (`ConnectOptions`), the peer connection, and the Kad driver.
- One capture engine in `rmule-net` (`driver/capture.rs`) runs a writer task per
  session. A per-protocol `CaptureFormat` adapter owns only the file layout and the
  frame, row and meta encoding; the engine owns the invariants.
- A server capture writes inbound bytes to `s2c.bin`, outbound bytes to `c2s.bin`,
  decoded events to `events.toml`, and a `meta.toml` with the endpoint, start time,
  duration, identity summary and final `CloseReason` label. Datagram
  taps (Kad) write `datagrams.bin` and `datagrams.toml`.
- Every file streams to `<name>.partial` and is renamed only on a clean finalize,
  so a crashed or killed session leaves obviously non-authoritative artifacts.
- Capture never stalls a datagram driver: datagram taps drop frames when the writer
  channel is full. Stream captures apply backpressure instead, so a stream capture
  is complete or visibly `.partial`.
- `rmule-tools` packages the server capture as `ed2k server welcome live`, and
  `ed2k server welcome slice` walks `events.toml` to cut `s2c.bin` into per-packet
  fixture files.

## Consequences

- Any live session is one option away from producing checked-in compatibility
  evidence, for every protocol, through the same engine.
- The `.partial` contract puts the burden on long-running processes to reach a clean
  stop. `ed2k serve start` handles `SIGTERM` and `SIGINT` by running the core's
  clean-stop path, which finalizes the Kad tap, and the interop harness stops such a
  process with a clean `docker stop`, never a kill, before reading its tap.
- The public cost is one optional field per options type and the engine module.
