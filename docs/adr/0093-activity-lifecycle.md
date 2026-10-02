# Activity lifecycle: one retire per activity, deaths are stops, quit is every stop in order

## Context

The core actor runs several long-lived activities — the Kad node, serving, downloads,
searches, port-mapping leases, the server-UDP front, the Registry Check, directory scans —
and each one acquires resources when it starts: tasks, sockets, binds in Address Learning
(ADR-0084), rows in the Desired Mapping Set (ADR-0086), advert halves (ADR-0047),
diagnostics rows, roster relations (ADR-0059). If no single owner returns that set, every start, stop,
death, disable and quit updates a different subset: a listener's bind outlives it and its
lease is renewed for a port nobody listens on, a download keeps a copy of "Kad is running"
after Kad died and waits forever, a quit leaves tasks running detached and the store open.
The lifecycle spans six activities, so it is its own decision rather than a section of any
one activity's ADR.

aMule references are to 2.3.3 (`4e8f2b3c`) unless a line names kno's fork; read, never
ported (ADR-0082).

## Decision

### Activities

**Every activity the actor starts is one value in the actor's ledger, owning everything its
start took. One `retire` per activity takes that value out and returns the whole set. A stop
asks the activity to end, then retires it. A death retires it with the reason its join
handle gives. Quit retires every activity in dependency order, each within a bound. Every
liveness reader reads the ledger at the moment it decides and keeps no copy.**

Invariants:

1. **A stop returns exactly what the start took.** Leaving a resource to be dropped and
   reclaimed later does not count.
2. **A death is a stop.** An activity that ends on its own goes through the same `retire`;
   only the reason differs, and it comes from the task's `JoinHandle`.
3. **Quit is every stop, in dependency order, bounded.** Consumers stop before what they read;
   every socket closes before the mapping in front of it is released; each retire has a grace
   period and aborts the task past it, so a quit finishes even when a task hangs.
4. **No reader of an activity's liveness holds a copy.** "Is Kad running", "is serving" and
   "is a download active" are answered by the ledger, or by a handle the ledger owns and
   clears on retire.

| Activity | Transitions | Resources acquired at start and returned at retire |
|---|---|---|
| **Kad node** | start (`EnableKad`); disable (`DisableKad`: fire its lever, wait ≤ 5 s, abort, retire); death (the pump ends, panics or is aborted — a `kad_ended` watch and a watchdog on the `AbortHandle` both wake the reaper); quit | discovery pump task and watchdog, `KadPublisher` task and share-changed sender, the ed2k→Kad handoff forwarder, its shutdown lever, the keyword-search channel, the node id, the `CT_EMULE_UDPPORTS` Kad half, and the one lease on Self Reach's Kad half (**Kad Presence** and the Kad verdicts) |
| **Serve** | start (`StartServing`); stop (`StopServing`: join within 5 s, abort past it); death (listener closed, task failed); quit | the serve adapter, the TCP listener Family Pair and accept pump, the TCP bind in Address Learning (and so a Desired Mapping Set row and its lease), tunnel admit, handshake cell, dialed-serve sink, the `serve_listener` cell, the `CT_EMULE_UDPPORTS` client half, the `0x90` reask inbox, upload diagnostics rows, and every Upload roster relation |
| **Download** | start (`StartDownload`, `ResumeDownload`); stop (`CancelDownload`, `PauseDownload`); death (complete or failed); quit (abort and join, no lifecycle write) | the runner task and stop watch, the file-known "downloading" entry, store lifecycle `Active`, its diagnostics rows; inside the run, each Pending Callback routing entry and Pending Tunnel Claim, the Download and Queued roster relations, the reask reply sink — all dropped on every road the run ends by |
| **Search** | start, cancel, finish, quit | the task, the global-UDP sweep, the live-search registration |
| **Port-mapping lease** | acquire; release when its row departs (before the replacement's `Map`); quit (`release_on_exit` within `RELEASE_BUDGET`) | one lease per Desired Mapping Set row and its diagnostics row |
| **Server-UDP front** | core start; quit (abort, then join each task) | the server-UDP Family Pair and its five tasks (engine, status-ping sweep, global-callback relay, `0x99` answer forwarder, global source discovery) and, through the status chain, the server list's store view |
| **Registry Check** | core start; quit (raise the flag, join the thread off the executor within `QUIT_JOIN_GRACE`) | its worker thread, input channel, the folder watch it owns, the Withheld Rows it rules into; no death transition |
| **Directory Scan**, one per scanned Shared Directory (ADR-0102) | start, an entry removed, replaced or covered, its worker's end, quit (raise every flag, join each within the grace) | a blocking-pool task per directory, its stop flag, its progress cell, the consent reply half |
| **Client-UDP socket and NAT-T front** | core start; dropped with the actor | the one UDP Family Pair, its front, the NAT-T demux and accept pump, the `0x90` inbox; no stop and no death transition; traversal attempts belong to ADR-0091 |

Consequences of the ledger, stated as rules:

- The actor holds one `Option<KadActivity>`; "Kad is running" is its presence. A download reads
  it through Self Reach (ADR-0060) at each decision, re-sampled on its reask tick, so a Kad death reaches
  every reader — Self Reach, the serve bridge's and the Firewalled Front's `0x99` / `0x95`
  gates, a download's liveness — at the one retire.
- The serve retire forgets the TCP bind its start recorded, so the Desired Mapping Set loses
  the row and the lease is released.
- A death notice carries its activity's generation, and a notice naming an activity the
  ledger no longer holds retires nothing. The same holds for a download's finish notice, and
  the download's file-known entry is returned by its own retire.

### Quit order

Every directory scan, then the Registry Check, then search, then download, then serve, then
Kad, then the server-UDP front, then port mapping, then the credit checkpoint. Searches and
downloads consume the server session and the Kad source channel, so they stop first. Serve
closes the listener and Kad's retire clears the advert half every later hello would read. Port
mapping comes last among the network activities because it releases the ports those sockets
held, as aMule deletes its UPnP mappings only after closing the listen socket
(`amule.cpp:1407-1423`); no retire depends on another being alive, so the order between serve
and Kad does not matter. `Core::quit` owns quit, and no front end sends a stop before it. Each
step with something to stop is announced as `CoreEvent::Quitting { step }` before it runs, so a
front end shows quit's progress from the quit itself. `Core::shutdown` stops every activity and
awaits the mapping runtime's release pass. A quit aborts the download task, so its diagnostics
row ends with the core rather than being put to rest.

## Consequences

- A stop, a death and a quit all return the same set; a quit finishes even when a task hangs, and
  a core restarted in the same process can open the store again.

## Considered options

- **A section of the port-mapping ADR.** Rejected: it would make port mapping the owner of Kad's
  teardown.
- **A bespoke Kad shutdown lever awaited by the front end before quit, and a status bar on a
  timer.** Rejected: Kad's retire is one stop among the others, and quit's progress comes from
  quit's own events.
