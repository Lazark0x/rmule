# rmule-net

The live network runtime crate: every socket in the workspace lives here, one
module per wire surface. `driver` is the generic Tokio harness and capture
engine; `ed2k`, `peer`, and `kad` are the per-protocol runtime layers driving
their sans-I/O session crates (`rmule-ed2k`, `rmule-peer`, `rmule-kad`), which
stay runtime-agnostic and own all protocol knowledge. Consolidated from the
former `rmule-net-runtime` / `rmule-ed2k-net` / `rmule-peer-net` /
`rmule-kad-net` crates (ADR-0081); each module keeps that crate's public
surface, re-exported under `rmule_net::<module>::…`.

## `driver` — the shared harness

The generic Tokio **Driver** harness shared by the connection-shaped runtime modules. Owns the `select!` loop, the `drain` of session outputs, the **session-emits-paired-`Disconnected` invariant** (every session close path emits its own `Disconnected` before `Close`; the harness synthesizes one itself only for driver-originated EOF / I/O closes the sans-I/O session cannot observe), the capture-frame tap, `finalize`, and the one optional startup deadline. Also home to the **Capture Engine** and the crypt-layer `CryptStream`. It carries no protocol knowledge, no `Direction`, no concrete capture layout, and no `tracing` vocabulary of its own.

**Driven Session**:
The trait the harness drives. One impl per concrete session lives in that session's protocol module, on a local newtype around the sans-I/O session (`Ed2kDriven`, `PeerDriven`), keeping the runtime adaptation out of the sans-I/O crates. Supplies the session machinery (`start`/`handle_command`/`handle_bytes`/`poll_output`), the event/close vocabulary (`resolves_deadline`/`disconnected_event`/`close_label`/`eof_close_reason`/`io_close_reason`), the timeout hook (`deadline_elapsed`), and the tracing hooks.
_Avoid_: driver trait, session adapter, handler

**run_driver**:
The single async loop. `start`s the session, drains its outputs (writing bytes, forwarding events — including the session's own paired `Disconnected` — and synthesizing a `Disconnected` only for driver-originated EOF / I/O closes), reads the socket, applies the optional deadline by notifying the session, and finalizes capture on exit. Returns the terminating `io::Error`, if any; the caller maps it onto `DriverError::Io`.
_Avoid_: event loop, reactor, runtime

**Capture Engine**:
The one capture writer task, `run_capture` (or `spawn_capture` when the engine also owns the channels, returning a policy-aware `CaptureHandle`). Owns every capture invariant: `.partial` staging — each declared file streams to `<name>.partial` and is renamed only on a clean finalize, so a crashed run stays obviously non-authoritative — the ordered drain-then-finalize shutdown (drain frames and rows until the channels close, then read the finalize verdict; never a select against finalize, which once raced a clean shutdown into a lost capture), finalize-time row collection with the rows-file and `meta.toml` writes, and the `OverflowPolicy` knob (`Backpressure` for stream captures on the driver's own path, `Drop` for datagram taps — capture never stalls a driver).
_Avoid_: capture writer, recorder, tap

**Capture Format**:
The per-protocol adapter the **Capture Engine** drives (`CaptureFormat`): declares the file layout (`files`, `rows_file`) and encodes frames and meta (`encode_frame` — stateful, may transform bytes and emit a row — and `meta_toml`). Owns layout and encoding only; every invariant lives in the engine.
_Avoid_: capture schema, writer config

**spawn_connection**:
The connection factory each protocol module's `Connection::connect` reduces to: given the socket, the **Driven Session** newtype, channel capacities (`ChannelCaps`), an optional startup deadline, and optional capture wiring (`SpawnCapture` = a `CaptureSink` writer-task factory + the module's capture context), it creates the command/event channels, spawns the capture writer task, and spawns the driver task — returning the live `SpawnHandles`, which also owns the one teardown every connection shares (cooperative `shutdown` under `SHUTDOWN_GRACE`, abort-on-drop) and the shared runtime-failure type `DriverError` the per-protocol errors wrap. A caller-supplied `decorate` closure wraps the driver future before it is spawned: that is where each module maps the harness's `io::Error` onto its own error and attaches its `tracing` span, so the harness stays logging-free.
_Avoid_: connect, builder, client

## `ed2k` — eD2k server runtime

The live runtime layer for the **eD2k Server Protocol**: TCP sockets, the driver adapter, the public **Connection** handle, connect / login timeouts, the server-UDP and client-UDP sockets, and the **Capture** writer that produces checked-in fixtures from real sessions. Depends on `rmule-ed2k` for the sans-I/O **Ed2k Session** and for all packet decoding; carries no protocol knowledge of its own.

**Driver** (ed2k):
The thin loop that owns one connection's socket — the shared harness's `run_driver` over the `Ed2kDriven` newtype; this module provides the adapter and the capture format. It reads bytes from the socket into the **Ed2k Session**, accepts **eD2k Commands** from a bounded channel, drains the session's outputs as socket writes, **eD2k Events**, and tear-down signals. Carries no protocol knowledge — every protocol fact comes from the session, literally including the login timeout, which the **Ed2k Session** owns (`login_deadline_elapsed`) rather than the driver. One driver per connection, spawned by **Connection** and reaped on shutdown. The consumer always observes exactly one `Disconnected` as the final event: the session emits its own paired `Disconnected` on every close path, and the loop synthesizes one only on EOF (`ServerClosed`) / I/O error (`Io`).
_Avoid_: connection manager, runtime, protocol handler

**Connection** (ed2k):
The public handle for one live eD2k session. `connect(endpoint, identity)` opens a TCP socket and returns after TCP is established but *before* login completes (login outcome arrives as an **eD2k Event**). `send(`**eD2k Command**`)` queues a command; `next_event()` yields the next **eD2k Event** or `None` once the session has ended; `shutdown()` is the cooperative tear-down path with a small grace timeout. `Drop` is a best-effort safety net (send `Disconnect`, abort driver). Not `Clone`, and it hands out no command sender: one owner holds the handle and does all the sending. (The peer **Connection** is the surface with a second producer — a held buddy link — and ships `command_sender()` for it.)
_Avoid_: client, peer, ed2k session

**Capture** (ed2k):
A recorded session artifact produced by the **Driver** when `ConnectOptions::capture_dir` is set: `s2c.bin` (every inbound byte in arrival order), `c2s.bin` (every outbound byte), `meta.toml` (endpoint, ISO timestamp, rmule git sha, **Client Identity** summary, final **Close Reason**, durations), and `events.toml` (the decoded **eD2k Event** sequence). Files are written as `.partial` and renamed on clean shutdown so crashed sessions stay obviously non-authoritative; the writer body enforcing that contract is the shared **Capture Engine**, and this module contributes only `Ed2kCaptureFormat` — file layout plus TOML row encoding. A curated capture promotes directly into a `captured`-provenance **Compatibility Fixture**; `rmule-tools ed2k server welcome capture --slice` segments `s2c.bin` into numbered per-packet fixture files using `events.toml` as the boundary oracle.
_Avoid_: trace, log, recording, dump

## `peer` — eD2k peer runtime

The live runtime for the eD2k peer protocol: the dial-out `Connection`, the inbound `PeerListener`, the driver adapter, capture, and timeouts. Drives the sans-I/O `PeerSession` from `rmule-peer`.

**Connection** (peer):
One driven handle over one `PeerSession` over one TCP socket — single peer per connection (ADR-0026). Created two ways: `connect()` dials out (we send the hello first); `PeerListener` yields accepted connections built with `PeerSession::new_inbound` (we wait for the peer's hello and reply). Both feed the same bidirectional session, so an accepted connection can later download and a dialed one can later serve.
_Avoid_: socket, stream, peer manager

**PeerListener**:
Binds the local listen TCP port (the port already advertised to the eD2k server at login) as a **Family Pair** and runs one accept pump yielding inbound peer **Connection**s from either family. Owns sockets, not policy — it hands accepted connections up to the **Core Orchestrator**, which decides what to serve. Makes the advertised port real and is the prerequisite for High-ID reachability and `OP_CALLBACK` dial-back.
Under `Required` its one policy call is the plain opener: refused, or — when the caller's `AwaitedTesters` awaits a test from its address — yielded as `Admitted::TestConnection`, so core can serve it nothing (ADR-0046).
_Avoid_: server, acceptor pool, peer swarm (the swarm/registry lives in core)

**Family Pair**:
Two sockets for one role and one port — an IPv4 socket and an IPv6 socket bound `IPV6_V6ONLY` — behind one pump that merges them and yields family-tagged endpoints (ADR-0085). A family that is disabled or fails to bind is absent and reported on diagnostics, never fatal. Every listener and datagram socket in the crate is one. A TCP pair sets `SO_REUSEADDR` — never `SO_REUSEPORT` — so a restart rebinds a port its previous run's closed connections hold in `TIME_WAIT`, while a second listener on a held port is still refused.
_Avoid_: dual-stack socket (the one-socket strategy this replaces), listener pool

**Half-Bound Pair**:
A **Family Pair** that came up, but without a family it *selected* — the family's bind was refused while the other bound (`family::HalfBound`). Not a family that was never selected: an operator who configured one family has lost nothing, and only `FamilyBinds::refused` raises this. Carries the role, the missing family and its `io::ErrorKind`, and reads its own **Consequence** list off `PairRole::forfeits` — the one table saying what each role loses per family, so no consumer re-derives it and no front end words it differently. `Display` writes the sentence an operator reads. Permanent for the session: there is no re-bind (ADR-0057).
_Avoid_: partial bind (says nothing about what it costs), bind failure (that is the whole-pair refusal, `Client-UDP Bind Failure` in core)

**Receive-Error Budget**:
The consecutive-error counter (`family::ReceiveErrorBudget`) every UDP receive loop in the crate — and its `rmule-core` consumers, the client-UDP and server-UDP runtime transports — shares: a run of receive errors with no successful receive between them ends the pump (`Exhausted`, naming the last `io::ErrorKind` and the count), while any successful receive resets it and a lone error is merely tolerated (`Tolerated`, a short backoff before retrying). Keeps a permanently dead socket from hot-spinning (a closed or failed source ends its task, never busy-spins), without making one transient blip fatal.
_Avoid_: retry policy, circuit breaker (it counts consecutive failures only; it does not open/close or time-window)

**Inbound Source**:
The seam over the accept pump — the trait the **Family Pair** implements for TCP and a fake implements in tests — that yields inbound streams with a one-byte push-back for byte-0 protocol discrimination (ADR-0042), so nothing downstream needs a `TcpStream`.
_Avoid_: acceptor, socket factory

**Inverted hello timeout**:
A dialed **Connection** times out when *our* `OP_HELLO` goes unanswered; an accepted **Connection** times out when *the peer's* hello never arrives after accept. Same `PeerCloseReason::HelloTimeout`, opposite trigger.
_Avoid_: connect timeout (that is the TCP-establish timeout, dial-only)

## `kad` — Kad UDP runtime

The live tokio UDP runtime for Kad: one task per node that drives the sans-I/O `rmule_kad::KadNode` over a real socket. It owns no protocol logic — decode, routing, liveness, and role behavior all live in `rmule-kad`. This module only moves bytes and time.

**Kad Driver**:
The one-task-per-node `select!` loop that drives a `KadNode` over a **Kad Transport**: it maps real monotonic time onto the node's explicit `KadInstant` scale (driver start = epoch), feeds inbound datagrams and driver commands to the node, arms a single `sleep_until(next_wake())`, and flushes the node's outbound datagrams and events. It reads a clock and owns the transport so the node never has to. One loop whichever transport it runs on — the capture tap, the `nodes.dat` persistence, the summary counters and the self-check arming are the driver's either way.
_Avoid_: event loop, actor, session (a Kad node is connectionless — there is no session)

**Kad Transport**:
Where one driver's datagrams enter and leave, in two forms (ADR-0057). **Owned**: the driver binds a **Family Pair** of its own — the standalone node the `rmule-tools` drivers, the Kad Stimulus Node and the mesh sim run. **Shared**, through a **Kad Inlet**: a socket the caller owns feeds the driver and every answer leaves by that bind, which is how a node inside a core rides the one client-UDP port an eMule-family client listens on. IPv4 only in both forms — Kad packs a 32-bit address end to end, so the pair's `::` socket has no Kad dialect to feed.
_Avoid_: socket abstraction, channel, transport trait (it is a two-arm enum, deliberately closed)

**Kad Inlet**:
The shared transport's two halves: a deep queue of `(IPv4 endpoint, bytes)` the socket's owner fills with `try_send` — never awaited, so a Kad node that falls behind costs its own datagrams and not the reasks queued behind them — and the `ClientUdpSocket` every answer leaves by. Closing the queue ends the driver: the socket's owner is gone, so there is nothing left to receive and nothing to answer on.
_Avoid_: mailbox, pipe, kad channel (that is the core-side `KadSourceChannel`)

**Datagram Capture Tap**:
The first-class recording of every in/out datagram (ADR-0022), written to a run directory as length-prefixed raw frames (`datagrams.bin`) plus a decoded meta table (`datagrams.toml`: direction, remote endpoint, protocol/opcode) and `meta.toml`. Like the eD2k stream capture, an unclean exit leaves `.partial` files so a crashed run is obviously non-authoritative. Capture never back-pressures traffic: a lagging writer drops frame records rather than stalling the driver.
_Avoid_: logging, tracing, pcap (the OS-level pcap is a separate passive sidecar; this tap is the node's own view)

**Kad Net Handle**:
The caller's control surface for a running node: its bound `local_addr`, a command channel, an event stream, and a `shutdown()` that finalizes the capture and returns a `KadNetSummary` (datagram counts, non-IPv4 drops). Dropping the handle closes the command channel, which the driver treats as a shutdown request.
_Avoid_: client, connection, socket wrapper

### Why not `DrivenSession`

The `driver` module's `DrivenSession` is connection-shaped: a byte stream with a startup deadline and a close reason. A Kad node is connectionless with a rich timer set (per-lookup α-timeouts, bucket refresh, republish, expiry) and no close reason. Forcing it into `DrivenSession` would contort both sides, so this module implements the thin `select!` loop directly (ADR-0043, considered options). The *pattern* — sans-I/O machine + thin driver + capture tap — is shared; the trait is not. A shared datagram-driver harness is extracted only when a second datagram-driver consumer exists. (Sharing the *capture writer engine* with the stream modules is allowed — ADR-0043 rejected a shared driver contract, not shared capture plumbing.)

### The `rmule-cli kad join` exception

`rmule-cli kad join` drives `rmule_net::kad::spawn` directly rather than going through the **Core Orchestrator**. This is a deliberate, documented exception: it is the ADR-0043 live-smoke instrument (a join-only diagnostic with a routing census), and Core's Kad surface is download-coupled by design — a join-only command does not fit it. The `RoutingCensus` fold itself is domain observability and belongs in `rmule-kad` (unit-testable there); the CLI keeps rendering only. Any *product* Kad behavior still goes through Core.

## Relationships

- The `ed2k` and `peer` modules each provide one **Driven Session** newtype and call `spawn_connection` (which drives it through `run_driver`); neither owns a `select!` loop or its own channel/capture/driver-task spawning. The `kad` module owns its own datagram `select!` loop and shares only the **Capture Engine**.
- The harness owns the generic capture channels (created in `spawn_connection`) so it can await the sends (preserving backpressure); the writer-task body is the **Capture Engine**'s `run_capture`. The frame/meta *types*, `Direction`, each **Capture Format** (file layout + row encoding), and `event_to_toml` stay in the protocol modules.
- A **Connection** owns one **Driver**; one **Driver** owns one socket and one session. A **Driver** carries no protocol logic; every wire decision belongs to the session it feeds.
- A **Connection** (and `PeerListener` / `kad::spawn`) is the only entry point intended for `rmule-core`, `rmule-tools`, and integration tests. Direct construction of the driver adapters and sessions is for unit and replay tests only.
- `rmule-net` depends on the sans-I/O protocol crates (`rmule-ed2k`, `rmule-peer`, `rmule-kad`) and `tokio`; none of them depend back on it.

## Address seams (ADR-0084)

**Interface Source**:
The I/O seam behind which local interface enumeration lives — the trait a runtime implements with an enumeration crate and the testkit fakes — polled at startup, on every server connect, and on a five-minute tick, feeding core's **Address Learning** with `Interface` observations. The only place rmule asks the OS which addresses it holds.
_Avoid_: network watcher, ifconfig, address provider

**Peer Pin**:
`MappingBackend::pin_peer` — PCP `PEER` (RFC 6887 §12) for the five-tuple a **Punched Path** is using, turning an implicit NAT mapping into one with a lease the router agreed to (ADR-0091). Only PCP can name a remote peer, so NAT-PMP and UPnP answer `Unsupported` *without touching the network*. Reuses the deterministic nonce a map of the same port uses, which the RFC requires when an explicit mapping already covers it.
_Avoid_: peer mapping (it maps nothing new), keepalive (that is core's, and the two are independent)

**Mapping Backend**:
The trait one port-mapping protocol implements for the **Port Mapper** — probe, map, release — with three implementations (PCP and NAT-PMP over `crab_nat`, except PCP over IPv6, which is rmule's own `MAP` exchange from a socket bound to the address it maps; UPnP-IGD over `igd-next`). There is no separate renew: a renewal *is* a map that suggests the port already granted, which is what both RFCs and both crates do, and two methods would let the paths drift. This layer owns what the crates leave to the caller: epoch validation, a retransmit ladder bounded tighter than either RFC, IPv6 source-address pinning, and one socket per attempt.
_Avoid_: protocol driver, mapper (that is the core-side brain)

**Gateway Source**:
The seam that names the default gateway a **Mapping Backend** talks to — a route-table lookup in the runtime, a fixed address in the testkit and the harness.
_Avoid_: router discovery, SSDP (one protocol's discovery, not the gateway address)

## `natt` — the Tunnel (ADR-0091)

**Tunnel**:
The reliable stream raised over a punched UDP path — uTP (`0xB2/0x00`, `librqbit-utp` behind rmule's `Transport` impl) or QUIC (`0xB2/0x01`, `quinn-proto` with eMuleAI's pinned TLS parameters) — exposed as the same `AsyncRead + AsyncWrite` the harness already drives, so an unmodified **Peer Session**, `CryptStream` and capture tap run inside it. The engine never owns a socket: datagrams enter and leave through the client-UDP **Family Pair**'s pump.
_Avoid_: socket layer (eMuleAI's name for the same thing), VPN, circuit (the anonymous overlay's word)

**Tunnel Registry**:
Which endpoints hold, or are opening, a **Tunnel** — the table that lets the demux drop an unmatched non-SYN frame *before* an engine could answer it with an unsolicited `ST_RESET` (aMule's deferred item A2). Three states, and the difference between two of them is who chose to talk: a slot an **inbound** opening packet created ages out at `OPENING_TTL` (30 s), so a forged opener buys one window; a slot **our own dial** created lives exactly as long as that dial, held by a guard that releases it on drop — a bounded, retried dial ends by cancellation as often as by error, and a slot left behind would admit a stranger forever. A held slot never ages out; the **Tunnel** owns it and frees it on drop, in either family, so whatever ends the tunnel — or declines it — ends the admission, and two tunnels on one endpoint (a simultaneous open) keep it until the last one closes.
_Avoid_: connection table, allowlist, firewall (that is the IPv6 pinhole ADR-0086 opens)

**NAT-T Demux**:
The split of the client-UDP socket by protocol byte then `0xB2` frame type — uTP, QUIC, CAPS, CAPS-ACK, KEY. `0xB2` is on the never-obfuscated whitelist; transport frames are obfuscated once the **Key Frame** (`0xB2/0xFF`, the sender's user hash, once per endpoint per 10 s) has supplied the key; `0xC5` signalling is sent unobfuscated on purpose. Keeps a registry of which peers hold a **Tunnel** so an unmatched non-SYN frame is dropped, never answered with an RST. Its own user hash is a **NattOwnHash** it reads per frame and per QUIC handshake, never a value captured at `start` — the demux binds ahead of whichever credentialed activity would first identify the node, so a captured hash would be stale for the front's whole early life. A CAPS frame that arrives before identity exists is `CapsBeforeIdentity`, not `CapsNotOurs`, and draws no answer.
_Avoid_: dispatcher, router

**Prediction Fan**:
The endpoint-dependent side's half of **Port Prediction** (ADR-0091's amendment): N ephemeral IPv4 sockets the client-UDP socket opens for one attempt toward one peer address, each sending one empty `0xA1` to the punch target to open one fresh NAT mapping. A datagram from that peer on a Fan socket is a *hit*: it installs a **Prediction Route**, is answered with one `0xA1` from that socket, and joins the client-UDP `recv` as the peer's. Anything from another address is dropped.
_Avoid_: socket pool, port spray

**Prediction Route**:
Peer endpoint → the Fan socket a hit arrived on. Every client-UDP send path (`send_to_peer`, `try_`, `poll_`) consults it, so a Tunnel on a Fan socket is adopted as if it rode the advertised bind and nothing above the socket changes. It is released when its punched path closes, or with its Fan when no Tunnel rose.
_Avoid_: NAT binding, sticky socket
