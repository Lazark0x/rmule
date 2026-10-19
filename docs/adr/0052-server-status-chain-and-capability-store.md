# A challenge-gated status chain fills a per-server capability store and judges server health

## Context

A server answers `OP_GLOBSERVSTATREQ` (`0x96`) with `OP_GLOBSERVSTATRES` (`0x97`), a
progressive body (12 to 40 bytes) carrying user and file counts, UDP flags
(ExtGetSources2, ExtGetFiles, LargeFiles, Obfuscation), the `ServerUDPKey` and the
obfuscation UDP and TCP ports. Global search's variant choice (ADR-0051), the `0x94`
get-sources upgrade and the server-UDP crypt (ADR-0046) all need those facts per server.

aMule's cadence pings one server per `UDPSERVERSTATTIME` (5 s, `DownloadQueue.cpp:580`),
spends a second tick on the plain fallback when a crypt-ping's 20 s grace lapses
(`ServerList.cpp:313`, `:329`), then waits out `UDPSERVSTATREASKTIME` (4.5 h less up to
1 h of jitter, `Constants.h:47`). aMule hides the slow start by persisting ping times in
`server.met`; a per-process schedule would pay it on every start and import.

aMule removes a non-static server whose failure tally reaches `/eMule/DeadServerRetry`
(default 3) at ping time and in `RemoveDeadServers` (`ServerList.cpp:280-281`,
`:828-837`). It counts a failure when a ping is sent (`ServerList.cpp:351`) and resets on
an answer (`ServerUDPSocket.cpp:383`), so its tally moves while the network is down.

aMule pings a server listed by host name, resolving it first and again once the last
answer is older than `DNS_SOLVE_TIME` = 30 min (`ServerUDPSocket.cpp:355-356`,
`:412-435`). It keeps a server's UDP crypt facts in `server.met` (`ST_UDPKEY` 0x95,
`ST_UDPKEYIP` 0x96, `ST_TCPPORTOBFUSCATION` 0x97, `ST_UDPPORTOBFUSCATION` 0x98;
`ServerList.cpp:784-796`), and hands the key out only while the public IP it was learned
under is still ours (`Server.cpp:300-314`), because the server derives the key from the
address it saw.

## Decision

**The status chain's output is a typed per-server capability record.**
`ServerCapabilities` holds the UDP flags, `ServerUDPKey`, obfuscation ports and counts,
populated by `0x97` inside the server-UDP engine (ADR-0051). It is the shared store that
search variant selection, the `0x94` upgrade and the crypt layer read.

**The challenge is an anti-spoof gate.** A plain ping carries `0x55AA0000 + rand16` to
TCP port + 4. A `0x97` is accepted only when its first `u32` equals the challenge rmule
sent that server and it comes from a known server; otherwise it is dropped without
touching any state. `StatusChallenges` holds each outstanding challenge until answered or
expired.

**The `0x94` get-sources upgrade rides the store.** Toward a server whose flags include
ExtGetSources2, global source discovery sends `OP_GLOBGETSOURCES2` (`0x94`: hash plus
`u32` size, or `u32(0)` plus `u64` for large files) instead of `0x9A`, which reaches files
over 4 GiB. `0x9A` stays the fallback.

**The description request is triggered here.** A valid `0x97` auto-fires
`OP_SERVER_DESC_REQ` (`0xA2`), as aMule does; its codec and handling are ADR-0068's. The
crypt-ping variant of the status ping is ADR-0046's.

**Cadence: a first-contact burst, then a slow refresh.** A server not yet probed this
run gets its first contact at one per 250 ms (eMuleAI's `UDPSEARCHSPEED`), its crypt
fallback on the same pace. Every later probe is a refresh, due once a 20-minute window
lapses (aMule's `UDPSERVSTATMINREASKTIME` floor) and paced at one per 5 s across the
list. Per server the load stays one `0x96` (plus one crypt-ping) per window. At attach
the sweep seeds its schedule from the durable status-answer date alone (ADR-0080's
`answered_at`): a server whose last challenge-matched `0x97` (or imported `ST_LASTPING`)
falls within the window counts as pinged then; a server with none, or an older one, joins
the burst. Counts a login reported carry their own date and never stand in for a ping, so
a server that was only logged into last run gets its first contact at once.

**The sweep reports each row's Ping State** (ADR-0080) to the level as a run-time fact: a
probe sent (awaiting, unless a round trip is already measured), a plain probe judged
silent (unanswered, dated by the first silence of the run), and a challenge-matched `0x97`
clears it. The offline guard gates the tally, not this fact.

**Dead servers are marked, never removed.** Removal is the operator's act; rmule departs
from aMule here on purpose.

- **Dead is derived, not stored.** A server is dead while its consecutive failure tally
  is at or above the Dead Server Limit, the `dead_server_retries` preference (default 3,
  at least 1): a Core Setting (ADR-0069) the actor starts under, changed live through
  the settings handle. The tally is the row's one stored fact; changing the
  limit re-derives every row.
- **Server Health**, ranked for sorting: `Answered` (tally 0, has answered at least
  once), `Unproven` (tally 0, never answered), `Failing` (below the limit), `Dead`.
- **The tally:** a failed connect or login counts one at once. A plain ping counts one
  when its verdict is silence, 20 s after it left; a crypt-ping is never judged alone,
  its plain fallback is. Any challenge-matched `0x97` or accepted login resets it to 0, so
  a dead server that answers lives again.
- **The offline guard.** A silence counts only when another ping to a living server
  sent within 60 s of it was answered. Two or more living servers silent within one window
  with no answer among them mean the network is down: the guard fires and nobody's tally
  moves. A lone living silence is inconclusive, so the sweep sends one **vouching ping**,
  a plain refresh to the living server that answered most recently. If it answers, the
  silence counts; if it is silent too, the guard fires. With nobody to vouch, the silence
  is dropped. A dead server's silence never fires the guard. A one-server list therefore
  never dies by pings alone.
- **What skips a dead server:** both global sweeps, whose swept list (ADR-0051) is
  published without dead servers and re-published on every health change. The status
  sweep keeps pinging a dead server at the refresh pace only, never in the burst, so it
  can come back. rmule dials no server on its own (ADR-0095), so the operator may always
  connect to a dead server, and an accepted login revives it. A static (pinned) server can
  be marked dead too.
- The moment a row turns dead is a run-time fact held beside it, never stored. A row
  already dead at start is "dead since before this run started".

**A server listed by name is resolved when the sweep reaches it.** The row's key stays
the listed name; the **Resolved Address** (`Resolved(ip)` or `DoesNotResolve`) is a
run-time fact on the diagnostics level, never stored. The sweep resolves a named row at
its ping when it holds no address, a failure, or a success older than 30 minutes, through
the **Name Resolver** (`tokio::net::lookup_host`, 5 s, first IPv4 answer) off the actor.
A name that does not resolve is one silence for that pass, judged by the offline guard.
The swept lists take the resolved address and filter it like a listed one; the status
sweep, as list health, does not consult the IP filter. A reply is written to the row
whose name resolved to its source.

**A server's UDP crypt facts are durable.** The managed row carries **Server UDP Crypt**:
obfuscation UDP and TCP ports, the `ServerUDPKey` and our public IPv4 when it was learned
(absent if none was known). It is rmule's own bookkeeping, so a downloaded list never
writes it and a merge keeps ours. Every challenge-matched `0x97` refreshes it; a body
shorter than 40 bytes clears it, as aMule zeroes the fields. The level is seeded from the
store before the actor takes its first command, so a restart uses the durable copy from
the first datagram: the engine resolves an answering source by this run's capability
record, else by the row's durable obfuscation UDP port. The key is handed out on aMule's
gate: non-zero, the server's flags say it supports UDP obfuscation, and it was learned
under the public IPv4 we hold now.

## Consequences

- Deterministic tier: the wrong-challenge negative (dropped, no mutation), the
  progressive `0x97` decode at each size boundary (12/16/24/28/32/40) against golden
  vectors, store population, `0x94`-versus-`0x9A` selection and the description trigger.
  Lugdunum answers status pings, and its `0x97` is the captured vector.
- Opening rmule refreshes what is stale and holds back what is fresh. A server that did
  not answer before a restart may be probed again inside its window: one datagram per
  such server per restart.
- The Networks tab dims a dead row and says `dead` in its Fail cell; the column sorts by
  tally, never by the word. The Networks log and the Run Log
  (`server_health.marked_dead`, `server_health.answered_again`,
  `server_health.sweep_unheard`) record each edge once, read from the level.

## Considered options

- **Endpoints-only server list with flags passed ad hoc.** Rejected: the flags are
  per-server state with several readers, so they need a typed record.
- **The challenge as a formality.** Rejected: a forged `0x97` would poison the store.
- **Legacy `0x9A` only.** Rejected: it cannot ask for files over 4 GiB.
- **aMule's cadence.** Rejected: without persisted ping times, every start and import
  would crawl at one row per ~10 s and then freeze for hours.
- **Removing dead servers, as aMule does.** Rejected: removal is the operator's call.
- **Counting a failure at send, as aMule does.** Rejected: the tally would move while the
  network is down.
