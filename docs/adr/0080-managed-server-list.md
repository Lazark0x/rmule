# The managed server list is a core-owned model, changed only by command and published whole as a level

## Context

A server.met row carries a server's name, description and priority (ADR-0066), and the
acquisition pipeline of ADR-0065 reconciles a downloaded list with aMule's
add-new/update-known posture. A list kept as bare `(host, port)` pairs throws all of that
away: a cold start acquires a thousand servers and cannot name one. An operator also
needs what aMule's Servers tab gives: add, remove, prioritise and pin servers, refresh
the list from a URL, see each server's ping, load, health and grants, and connect to the
one they pick.

A server's facts have different writers and lifetimes. The row's identity and the
operator's choices are configuration. Ping, users, files and limits are what the server
last reported. Which server is connected is a fact about the session, not about any row.

aMule citations are to aMule 2.3.3. Evidence: the aMule-written `server.met` goldens
under `crates/rmule-ed2k/tests/fixtures/server_met/captured/` carry the figure tags,
including `ST_LASTPING` 0 beside a user count reported over TCP.

## Decision

### The model

```rust
pub struct ManagedServer {
    pub endpoint: ServerEndpoint,          // the list key
    pub name: Ed2kText,                    // ST_SERVERNAME
    pub description: Ed2kText,             // ST_DESCRIPTION
    pub priority: ServerPriority,          // ST_PREFERENCE: Normal | High | Low
    pub is_static: bool,                   // the operator's pin
    pub fail_count: u32,                   // aMule's m_failedcount
    pub figures: Option<ServerFigures>,    // what the server last reported, with when
    pub grants: Option<ServerGrantsReport>,// its last login's SRV_TCPFLG_* word, with when
}
```

- The strings are `Ed2kText`: server banners are routinely Windows-1252 or mojibake
  (ADR-0019), and a list that renders "?" beats one that refuses the row.
- `ServerPriority` is `rmule_ed2k::ServerPriority`, re-exported. Its wire mapping
  (`Normal = 0`, `High = 1`, `Low = 2`, out of range → `Normal`) is also the persisted
  mapping, so the file format and the store cannot drift.
- **Server Figures** (`ServerFigures`): ping, users, files, soft and hard file limits,
  version, the UDP flags word of the last challenge-matched `0x97`, and two wall-clock
  dates. `answered_at` is the server's last **status answer**: a challenge-matched `0x97`,
  or an import's `ST_LASTPING`, and nothing else (aMule's `SetLastPingedTime`,
  `ServerUDPSocket.cpp:191`, which `OP_SERVERSTATUS` never moves, `ServerSocket.cpp:465-479`).
  `counted_at` is when the user and file counts were last reported: by a status answer, a
  login's `OP_SERVERSTATUS` or an import. Each is `None` until something dated it, so a
  server only a login reported on has dated counts and no status answer. aMule keeps the same figures in
  server.met (`SaveServerMet`, `ServerList.cpp:776-789`; read back by
  `CServer::AddTagFromFile`, `Server.cpp:182-270`), so they survive a restart.
- **Grants** (`ServerGrantsReport`): the raw `SRV_TCPFLG_*` word of the server's last
  `OP_IDCHANGE`, with when. The raw word is stored so unknown bits survive; a front end
  words each bit it knows.

### Aux ports

A server can be dialed on a port other than the standard one it lists. aMule keeps both
on its `CServer` (`port`, the one it connects to, and `realport`, the "official" one the
list keys on and advertises, `Server.h:69-73`). `ManagedServer.aux_ports`
(`Option<ServerAuxPorts>`: the standard port and the aux-ports list) is rmule's form of
that pair, present only while they differ — aMule's own condition for writing
`ST_AUXPORTSLIST` (`ServerList.cpp:763-765`). The row's `endpoint` stays the **dialed**
endpoint and the key, so a running session, its events and its facts keep one name; the
standard endpoint is `standard_endpoint()`.

- **An aux-port login re-ports the row.** The `OP_IDCHANGE` that names a standard port
  (`ServerSocket.cpp:337-355`) records it on the dialed row and starts the list at the dialed
  port when it was empty. A port of zero, or the dialed port itself, changes nothing, and
  so does a slot equal to the assigned id: a captured Lugdunum answer fills the slot with
  the id (id 936, "port" 936), which aMule would still write into the row.
- **A server.met row's header port is the standard port**, and its `ST_AUXPORTSLIST` starts
  with the port to dial (`Server.cpp:222-231`): the imported row is dialed there.
- **One row per server.** aMule's `AddServer` refuses a second row for one `(address, port)`
  of the standard kind (`ServerList.cpp:223-237`). A downloaded row therefore finds a row
  by its dialed endpoint first and its standard endpoint second; and when a login reveals
  that the standard endpoint is a row of its own, that row is absorbed into the dialed one
  (name, priority, pin and any figures, grants or UDP crypt it lacks), which keeps the key
  the session runs on. The merge's `(ip, port)` reconciliation against a downloaded list
  projects a row at its standard endpoint.
- A downloaded row's own list is taken only for a row dialed on the very port it lists.
- **A server.met row's UDP crypt tags land in the row's UDP crypt record** (ADR-0052): the
  obfuscation TCP and UDP ports and the `ServerUDPKey` with the address it was learned
  under. A downloaded row only fills what the row lacks, except the TCP port, which is the
  server's own word; a key a status answer taught is not replaced. The key still keys UDP
  only while it was learned under the address we hold now.
- **The UDP flags word an imported row names is kept even when the file dates no answer**
  (`listed_udp_flags`): aMule holds it per server whether or not it was pinged. The last
  status answer's flags, when there are any, outrank it.

### One merge rule

`ManagedServer::fold` is the whole reconciliation policy, aMule's `LoadServerMet`
duplicate branch and its `AddServer` for a known server: **the name always takes the
fresh value, the description only when the fresh one is non-empty, and priority, the
static pin, the failure tally and the grants stay ours.** Figures keep whichever side
is dated later, by the later of its two dates. An imported server.met fills figures only when it carries a last-ping
time that is non-zero and not in the future (aMule rejects a future `ST_LASTPING`,
`Server.cpp:196-200`), because a figure with no time behind it cannot say how old it is.
Both the list update and an operator re-add go through `merge_server` and the one
`fold`. A downloaded list may rename a server; it may not re-prioritise, unpin or absolve
it. `SetServerPriority` and `SetServerStatic` are how those change.

### The core owns the list

The store is a seam: `ServerListStore` (`servers`, `merge_server`, `remove_server` and
the `set_*` mutators, which report `false` when no row holds the endpoint), held as
`Arc<dyn ServerListStore>` over the store of ADR-0083. `AppConfigStore` is a supertrait
of it, so a front end opens one store, but the actor is handed only the narrower trait:
reaching a server row does not come with the identity and the SUI keypair.
`CoreBuilder::server_list` hands the store over, and from then on **the core is the
list's only writer**; a front end reads the level.

### Commands

`CoreCommand::ServerList(ServerListCommand)`:

| Command | Answer |
|---|---|
| `AddServer { server }` | `ServerAdded` \| `ServerUpdated` (a fold) |
| `RemoveServer { server }` | `ServerRemoved` \| `UnknownServer` |
| `SetServerPriority { server, priority }` | `ServerPriorityChanged` \| `UnknownServer` |
| `SetServerStatic { server, is_static }` | `ServerStaticChanged` \| `UnknownServer` |
| `UpdateServerList { url }` | `ServerListUpdateStarted`, then `ServerListUpdated` \| `ServerListUpdateFailed` |

The events are edges; the list is a level, so no consumer folds them into a list of its
own. Rejections: `UnknownServer`, `ServerListStoreFailed` (the store's reason is traced),
`ServerListFetchUnavailable`, `ServerListUpdateInFlight`.

**Removing the connected server removes the row and keeps the session**, as aMule's
`RemoveServer` does. The list is configuration and the connection is a session fact; a
core that hung up because a row was deleted would invent a coupling.

**The update runs in two steps so the fetch never holds the list.**
`acquire_server_met` projects the installed rows onto server.met rows and runs the
pipeline of ADR-0065 (bounded GET, parse before install, add-new/update-known, a plan)
without touching the store; `install_server_met_plan` folds the plan in. The actor never
holds the store across the fetch, which runs on a spawned task behind a one-at-a-time
guard, so a command landing in the gap is neither blocked nor lost. The fetch capability
is injected as `ServerListFetcher`, the object-safe form of the `Fetcher` seam, with a
blanket impl over every `Fetcher`; without one, `UpdateServerList` is refused with
`ServerListFetchUnavailable`, as ADR-0047's Honest Capability Advertisement requires of
our own machinery. DNS-named rows have no `(ip, port)` key, so the reconciliation neither
projects nor touches them. The Join Sequence's first-run fetch (ADR-0067) uses the same
two calls.

### Connecting is a separate command

`CoreCommand::ConnectToServer { server }` connects to a **listed** server
(`UnknownServer` otherwise), one at a time (`ServerConnectInFlight`). It is not a
`ServerListCommand`, because no list command reaches the session. It is the only login
(ADR-0095): activities ride the session the operator made and dial nothing themselves.
`DisconnectFromServer` ends the operator's intent to stay connected; while the intent
stands, a lost session is re-made (ADR-0096).

The dial runs off the actor and answers with the `ServerConnectionEvent` trail:

```
Disconnected(old) → Connecting(new) → Connected(new) | ConnectFailed(new)
```

The switch holds the session slot, ends the old session and waits for it to report
itself gone before dialing, so the order holds by construction. The trail and the
`connected_server` level are written by the session layer (`ServerFacts`), not the
actor arm, so the two cannot disagree. Its event sender is weak, because long-lived
holders such as the server-UDP engine would otherwise keep the event channel open and
hang shutdown.

**What survives a switch.** Peer transfers run on their own connections and lose
nothing; the upload queue and credit ring are untouched. A running search dies with
`SearchFailed { ServerDisconnected }`, because its results arrive down the one session.
A download keeps its sources; a lookup parked at the switch fails the same way. The serve
activity follows the session: each session the operator makes gets the share set
announced (`OP_OFFERFILES`) as aMule re-sends it on every connect, unless the Announce
Policy of ADR-0099 withholds it, and peer hellos read the live session, so a new client
id is named at once.

### The level

```rust
pub struct ServerDiagnostics {
    pub server: ManagedServer,
    pub ping: PingState,
    pub users: Option<u32>,
    pub files: Option<u32>,
    pub age: Option<Duration>,          // since the later of the figures' two dates
    pub status_age: Option<Duration>,   // since the last status answer
    pub health: ServerHealth,           // ADR-0052
    pub grants_age: Option<Duration>,
    pub resolved_address: Option<ResolvedAddress>,
    pub dead_since: Option<DeadSince>,
}
```

`DiagnosticsSnapshot::servers: Vec<ServerDiagnostics>` rides the shared
`DiagnosticsState`, so the sync `Core::diagnostics_snapshot()` reports it without an
actor round trip. It is republished whole, never patched, and always read back from the
store under the same lock as the mutation that changed it; the actor publishes once
before taking its first command. `None` means never measured, never zero.

**The Ping State** (`PingState`) is what core knows of a row's status ping, so the ping
is never a bare blank:

- `Measured(rtt)`: the round trip of the last challenge-matched `0x97`, durable with the
  figures, so a restart shows it.
- `NotAskedYet`: no measured round trip, and the Status Ping Sweep has sent the row nothing
  this run.
- `Awaiting`: no measured round trip, and a probe is out. A crypt ping and its plain
  fallback are one wait.
- `Unanswered { since }`: the row's last plain probe was judged silent (ADR-0052, 20 s after
  it left) and nothing has been answered since; `since` dates the first silence of that
  run of silences. It outranks an older measured round trip, because the newest fact about
  the ping is that it went unanswered. A name that gives no address is a silent probe.

The sweep writes the probe half as a run-time fact on the level, keyed by the row as
listed and never stored, as it writes the Resolved Address: a probe sent, a probe judged
silent. A challenge-matched `0x97` clears it. The offline guard decides only the tally: a
silence the network caused is still a ping that went unanswered.

**The connected server is one fact, not a flag on N rows:**
`DiagnosticsSnapshot::connected_server: Option<ServerEndpoint>`, raised by an accepted
login and cleared by the session task on the way out, whichever side ended it. It is not
pruned by a list republish, because a removed server can still be connected.
`DiagnosticsSnapshot::share_announcement` says what the connected session was told of
the share set.

### Writers of the figures and the tally

`ServerFacts` is the one write seam, so the durable tally and the figures change
together for the same round trip:

| Surface | Writes | aMule |
|---|---|---|
| Status-ping sweep, at a silent verdict | `fail_count += 1` (ADR-0052's offline guard) | `ServerStats` → `AddFailedCount` |
| `0x97` challenge gate, on a match | ping, users, files, limits, UDP flags; `answered_at` and `counted_at` now; `fail_count = 0` | `ProcessPacket` → `SetPing` / `SetUserCount` / `SetFileCount` / `ResetFailedCount`, `SetLastPingedTime` |
| Connected session's `OP_SERVERSTATUS` | users, files; `counted_at` now; `answered_at` never moves | `CServerSocket::ProcessPacket` (`ServerSocket.cpp:465-479`) |
| Connected session's `OP_SERVERIDENT` | name, description | `SetListName` / `SetDescription` |
| Tagged `0xA3` | version; no date moves | ADR-0068 |
| Failed TCP connect | `fail_count += 1` | `ConnectionFailed` |
| Accepted login, `OP_IDCHANGE` | grants, dated; `fail_count = 0` | `ResetFailedCount` |

- **A ping counts as a failure at its silent verdict, and an answer clears the whole
  tally** (ADR-0052). A crypt ping is never judged alone; its plain fallback is.
  `fail_count` reads *consecutive failures to
  reach this server, by any means, since it was last reached*, on aMule's single
  `m_failedcount`.
- A connect refused by the IP filter reports its edge and leaves the tally alone: the
  dial never happened.
- **The challenge gate is the measurement gate.** The RTT is stamped where the challenge
  is registered and read where the reply passes the gate, so the check that keeps forged
  capabilities out (ADR-0052) keeps forged measurements out too. A failed gate moves
  nothing. Challenge entropy stays injected, so a swept round trip is byte-deterministic
  under test.
- A store write that fails is logged and dropped: none of these writes is load-bearing for
  the wire, and a sweep that cannot record a tally must still ping.
- A reply from an unlisted server is inert, because the store edits only rows it holds;
  removing a server drops its figures, so a re-added endpoint starts unknown.
- **The status sweep walks the managed list**, re-read from the store each tick, at
  ADR-0052's cadence (a first-contact burst, then one refresh per 5 s tick, each server
  at most once per 20 min, the first probe one tick after start). The global source sweep walks a projection of the same
  list (ADR-0051).
- A login measures no UDP round trip, so a connected server with no `0x97` yet shows
  dated counts, no status answer, and the Ping State the sweep reports for it.
- Health follows the tally under the Server Policy of ADR-0052: dead servers are marked,
  never removed, and `is_static` is the operator's pin against any future cleanup.

### Presentation of a row

The TUI's Servers table has an **Age** column (`59s`, `59m`, `47h`, `99d`, then weeks)
sorted as a quantity, with a never-answered server last in both directions; it reads the
later of the figures' two dates and is the last figure to give way, so no figure shows
without its age; a row nothing has dated says the same word as its ping there. The
**Ping** cell reads the Ping State: the round trip, or its reason in one word of at most
four cells, `soon` (not asked yet), `wait` (awaiting) or `lost` (unanswered). A missing
user or file count says the same word as that row's ping, or `unset` when the server
answered without one. Ping sorts by the state's rank, measured (by round trip), awaiting, not asked,
unanswered (by how long), never by the word. Under the table, a detail
pane says for the selected row, one sentence each: **Grants** (the last login's TCP
grants and their age, or never logged in), **UDP** (the last status answer's flags with
its own age, none named, or no status answer yet with the Ping State's reason; counts a
login reported are not a status answer), **Health** (answered with age; not reached; failing, with the
tally out of the Dead Server Limit; or dead since when — a row already dead when the list
was read says it was dead before this run), and **Shares** (for the connected server,
what it was told; for any other, what its next login would do under the Announce Policy).
Flag words are listed in bit order, never sorted by spelling. Every bit aMule 2.3.3
(`Client2Server/TCP.h:65-71`, `UDP.h:50-57`), eMule (`Server.h:40-53`) and emule-qt's
IPv6 bit define is named; any other set bit is said by position ("bits 6, 7 and 12, which
no client names", bit 0 being `0x1`), and the lean Run Log writes the raw TCP and UDP
words in hex as a `server.grants` record when either changes. The pane takes the height
its sentences wrap to, at least four lines; where it would take more than half the
table's body it collapses to one wrapped line.

## Consequences

- One list, one writer, one level: front ends, the status sweep and the source sweep all
  read the same rows, and nothing re-derives a server's name or health.
- An operator can judge a server before connecting to it: its figures, age, health and
  last grants survive a restart.
- Activity commands still carry a server argument they never dial; a download records the
  server its link was found on only as a source hint.
- The list is never pruned automatically; a dead server stays listed and marked.

## Considered options

- **Measurements beside the list, in a per-endpoint runtime map.** Rejected: a restart
  forgot every ping and count, which aMule keeps in server.met. Keeping them on the row
  preserves what the separate map bought — a republish cannot clobber a figure, an
  unlisted reply is inert, a removed row takes its figures with it.
- **A per-row connected flag.** Rejected: a second copy of one session fact, kept in step
  only by care.
- **A lazy re-target on connect** (record the choice, connect at the next activity).
  Rejected: the operator presses connect and nothing happens.
- **A timer per outstanding ping.** Rejected: counting at send and absolving on the answer
  is aMule's posture and needs no timer state.
- **A detail column per grant.** Rejected: the 80-column budget has no room, and a column
  narrower than its words wraps every row.
