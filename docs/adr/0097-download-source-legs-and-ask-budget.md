# A download asks whichever source leg is up, waits when neither is, and shares one Source Ask Budget

## Context

A download's sources come from two legs, the server session and Kad, and a run's first act
is a source lookup. Nothing dials a server but the operator (ADR-0095), so a run may start
with no session, and a session may come up, drop and come back while it runs. aMule resets
each file's local source request at login (`ServerSocket.cpp:434`,
`DownloadQueue.cpp:1011-1015`) and paces `OP_GETSOURCES` with one frame clock for its whole
queue (`DownloadQueue.cpp:1044`, `:1127`).

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**A download's sources are independent.** A download's server and Kad sources are two legs. With
Kad running and no session, the run starts on Kad at once; it reads **No network** only when
neither exists. **Every server session that comes up while a run runs is asked for the file's
sources** (`download/runner/server_leg.rs`, woken by the **Session Generation**), as aMule resets
each file's local source request at login (`ServerSocket.cpp:434`, `DownloadQueue.cpp:1011-1015`).
The leg never dials. A download's stored server is only an optional **source hint**
(`StartDownload { source_hint: Option<ServerEndpoint> }`), so a Kad-only operator can search and
download with no server configured.

**Waiting for a connection.** A run's first act is a source lookup, which needs the node's one
server session or a running Kad node. A lookup ending in `ServerDisconnected` with Kad not
running is not a failure: the run stays in the Download Set as `WaitingForConnection`, its row
keeps its lifecycle, Transfers reads **No network**, its Known-File Mark stays Downloading, and
pause and cancel reach it. A filtered server, a silent logged-in server and a lookup that found
no usable source are still failures. The run subscribes to the **Reach Generation** (ADR-0060) (session and
Kad presence) and asks again at once when either comes up; it never redials its stored server on
its own, and if a session exists that the lookup could not ride it asks again after five seconds.
A one-shot front end (`rmule-cli download start`) ends on `WaitingForConnection` with the reason.

**The Source Ask Budget.** The Download Set shares one budget per **Session Generation**: a
rolling 15 `OP_GETSOURCES` per 300 s on that session, as aMule's one frame clock for its whole
queue (`DownloadQueue.cpp:1044`, `:1127`), zeroed at each login. An ask is admitted against the
session that will carry it — an operator connect in flight is waited out first — and counted on
the generation that session installed. A run's server leg asks only a session newer than the one
its first lookup rode. rmule asks every new session at once, where aMule keeps its 800 s per-file
stamp across servers (`SERVERREASKTIME`, `Constants.h:36`); the budget bounds that.

## Consequences

- A Kad-only operator can search and download with no server configured.
- Lugdunum answers the first seven asks of a burst of fifteen in one segment; whether that is per
  segment, per read or per second, and whether stock aMule meets the same cut, is unmeasured.

## Considered options

- **Failing a run that found no connection.** Rejected: the absence of a session and of Kad is a
  state of the node, not a fault of the download.
