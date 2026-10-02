# Persistent, multiplexed eD2k server session shared by source-lookup and serve

## Context

Several activities need the eD2k server at once: every download looks up sources,
the serve side announces the share set and needs the client id the login assigns,
searches go to the connected server, and Low-ID callbacks are relayed through it.
Opening a connection per need means logging in again for every download and twice
for a client that downloads and serves, and leaves no single owner of the live
connection. A real eMule client holds one persistent connection to one server.

## Decision

One logged-in server session, held in a shared slot, carries every request to the
server.

- **One multiplexer task per session.** `ServerSessionHandle` fronts a task in
  `rmule-core` that owns one logged-in `rmule-net` connection and `select!`s over a
  request channel and the connection's events. Requests are source lookups, the
  `OP_OFFERFILES` announce, searches, Low-ID callback relays and disconnect.
- **Answers are routed, never stolen.** Source lookups are demultiplexed by the file
  hash `OP_FOUNDSOURCES` carries: lookups for different files ride side by side, and
  a second lookup for a hash already asked joins that ask. The Source Ask Budget
  (ADR-0107) paces `OP_GETSOURCES` across the whole download set. Search answers are
  attributed by their place on the link (ADR-0034).
- **The link is a seam.** The loop runs over a `ServerLink` trait and is tested
  sans-I/O over a fake link; only establishment (connect and login) does real I/O.
- **The slot.** `SharedServerSession` holds `Arc<Mutex<Option<ServerSessionHandle>>>`
  plus the self-facts only a login can supply — the credentials presented and the
  client id and public IP the server reports in `OP_IDCHANGE` — and the Session
  Generation that followers wake on. Activities and adapters clone the cell, not
  the handle. The production source-lookup and serve adapters consult it behind the
  unchanged `SourceLookupService` and `ServeRuntimeService` traits, so tests keep
  injecting fakes.
- **The session is the operator's.** Only the operator's connect establishes a
  session (ADR-0095). Source lookup, search and the announce ride
  `SharedServerSession::live_session`, which waits out an operator connect in flight
  and never dials. No activity reconnects on its own.
- **Fail fast on close.** When the link closes or the server rejects a command, the
  loop fails every parked request — lookups with `ServerDisconnected` — and ends. The
  dead handle reports `!is_alive()` and stays in the slot until a connect replaces it.
- **Login timeout.** The login deadline is the eD2k session's own
  (`login_deadline_elapsed`, `CloseReason::LoginTimeout`), set from
  `CoreConfig::server_login_timeout` (default 15 s) and surfaced as
  `ServerConnectFailure::LoginTimedOut`; there is no second timer.
- **Serve restarts carry nothing from an old session.** A serve start rebuilds its
  handshake context at client id 0 and refreshes it when a login lands; it never
  answers inbound hellos with an id an earlier session was assigned (ADR-0031).

## Consequences

- One login serves every activity; the connection stays open between lookups, as an
  eMule client's does. Mock servers in tests abort their task at teardown instead of
  waiting for the client to close.
- The session task lives as long as its connection, even when idle. Its in-flight
  state is bounded by the per-hash waiter map and a bounded request channel.
- An activity that needs the server while none is connected waits or reports that no
  session exists; it never dials one.

## Considered options

- **A connection per lookup plus a separate serve login.** Rejected: two logins for a
  client that downloads and serves, a fresh login per download, and no single owner
  of the live connection.
- **The session as a field of the core actor's activity ledger.** Rejected: the
  handle would have to be routed into each download runner past the
  `SourceLookupService` seam the download tests fake; the shared slot reaches the
  same single owner without breaking that seam.
- **Background auto-reconnect.** Rejected: connecting is the operator's act
  (ADR-0095); an activity that redials hides a lost server from the operator.
