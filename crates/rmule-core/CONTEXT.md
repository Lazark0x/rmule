# rmule-core

The application-facing **Core Orchestrator**: it coordinates the protocol services, owns scheduling/storage/verification policy, and exposes a long-lived command/event service. Both halves of participation live here — pulling files (download) and serving files (upload) — because both need cross-connection truth that no single session can hold.

## Language

**Activity**:
One long-lived unit of work the core actor manages: a search, a download, the Kad node (**Kad Activity**), or (serve side) the listener-fed upload service. The core actor owns a *set* of activities, not a single active download. Each is one value in the actor's ledger that owns everything its start took — tasks, sockets, adverts, diagnostics rows, Address Learning binds and so their mapping leases — and its liveness *is* its presence there: a reader outside the actor reads a handle the ledger owns (**Kad Presence**, the serve listener cell), never a value sampled at its own spawn (ADR-0093). The port-mapping runtime and the client-UDP socket with its NAT-T front live for the core's whole life and end only at **Quit**. `CoreCommand` / `CoreEvent` are thin top-level enums wrapping per-activity vocabularies (`SearchCommand`/`SearchEvent`, `DownloadCommand`/`DownloadEvent`, `ServeCommand`/`ServeEvent`), so one activity's event never carries another activity's id.
_Avoid_: job, task (reserved for Tokio tasks), session

**Activity Transition**:
What moves an **Activity** in or out of the ledger (ADR-0093). **Start** acquires its resource set. **Stop** (`StopServing`, `DisableKad`, `CancelDownload`/`PauseDownload`, `CancelSearch`) asks it to end and then **retires** it. **Death** is an end nobody asked for — a closed listener, a dead Kad pump, a download or a search that completed or failed — and retires through the same place; a death notice names the generation of the activity it reports, so one arriving after a stop and a restart retires nothing. **Retire** (`retire_kad`, `finish_serve`, `retire_download`, a search's `retire` in the `Searches` ledger) is the one place an activity's resources come back, all of them. `DisableKad` is the Kad node's stop.
_Avoid_: reclaim (the retired name of the death-only reaper), teardown, cleanup

**Download Set**:
The download half of the **Activity** ledger: every download with a live run, keyed by its `DownloadId`, any number side by side (aMule's `CDownloadQueue`). A download joins the set at its start (`StartDownload` / `ResumeDownload`) and leaves it at its one retire — stop, death or **Quit** — so membership *is* "this download runs". The set bounds nothing by count; the one refusal is per file: a file (hash + size) is at most one live download, which the **Durable Store** enforces at row creation (`DuplicateDownload`), because every per-download table keyed by file — source discovery registries, the **File-Known Predicate**'s downloading half — assumes it. Everything a run holds on a surface shared by the set is keyed by its own id or file, never a single slot: its File-Known entry, its reask reply-sink install on the one client-UDP socket (ADR-0057), its roster relations.
_Avoid_: active download (singular), download slot, download queue (aMule's name for the same set, but "queue" here means the **Upload Slot Queue**)

**Source Hint**:
The server a download's link was found on, stored with its row: optional since store version 9, so a Kad-only operator's download records none. Nothing dials it or asks it; a run's sources come from the operator's session and Kad, and every session that comes up later is asked.
_Avoid_: the download's server (a download has none of its own)

**Restart**:
The operator's one action on a failed download (ADR-0094, "Restart"): `ResumeDownload` on a `Failed` row. Core picks what it means by what is on disk — it continues from the parts that still check (damaged ones dropped and fetched again), or, when the part file is gone or no recorded part matches it, starts over from nothing in the download's place, the part file removed. `DownloadRestarted` says which (`RestartOutcome::Continued` / `StartedOver`) and what it cost. Only the operator's Restart starts over; attach's restore and a paused download's resume fail with the fault instead. An unreadable part file never starts over.
_Avoid_: start over (not an action of its own), retry, re-add (the Failed mark's confirm sends the same Restart)

**Quit**:
`Core::shutdown`, or every `Core` handle dropped: every **Activity**'s stop in dependency order, each within a bound — search, download (aborted, its store row left as the operator last set it, so attach starts a running one again and leaves a paused one paused), serve, Kad, then the port-mapping runtime's release pass, awaited — before the credit flush (ADR-0093). A front end issues no stop of its own before it: `Core::quit` hands back the rest of the event stream, where each step that runs is announced as a `CoreEvent::Quitting` — what the TUI's status bar names.
_Avoid_: exit, teardown

**Core Settings**:
The operator's preferences that change what core does, and the one door to them (ADR-0069): a `CoreSettings` value the builder reads from the store it is given (or a test injects), and a synchronous handle — `Core::settings()` on a running core, or opened on the store alone where no core runs. `set(Setting)` validates — a download directory against the **Shared Directory List**'s guards too, refusing it with the guard's reason, and a **Temp Directory** against the list, which it must lie apart from — persists, and answers `TakesEffect::Now` (`Remember peers`, the **Dead Server Limit**, the **Announce Policy**, the download directory, whose scan core starts with the answer the front end's confirm gave, the **Temp Directory**, which downloads started after the change place their part files in, and the **Obfuscation Policy**, which every surface reads as it decides) or `NextStart` (every other key, and every key set through a handle no core runs behind). A live key shares the actor's one inbox with the commands, so a command sent after `Now` runs under it. The nickname and the two ports live in the identity rows and the rest in the preferences table; the handle hides which, and `CoreSettings::credentials` is the one place the nickname and TCP port become what a login, a hello and a Kad dial present: no command carries credentials. An injected TCP port of `0` takes one the OS assigns, and the port presented is the one the listener bound; the store refuses `0`. The front end's own keys (theme, table sorts, Run Log level, connect at start, last server, player command) share that table through a raw key/value surface core never interprets.
_Avoid_: config (that is `CoreConfig`, the engineering knobs: timeouts, concurrency, cadences), preferences (the stored key/value rows)

**Serving Started**:
`ServeEvent::ServingStarted` — the **bind** fact and nothing more: the inbound
listener is bound on the address the event names and is accepting peers. It says nothing about the
server login the same `StartServing` causes; that login runs on afterwards and reports itself on
the **Server Session Switch** trail, so a server that accepts and then says nothing can never make
a serving node look like one that never bound. The bind happens on the actor, before the serve task
exists, so the event and the **Bind Generation** bump describe the same instant. Its two siblings
complete the answer to every `StartServing`: `ServingFailed` (a named start failure — a bind
`io::ErrorKind`, or an adapter this core no longer has — after which the adapter is still there and
a retry is a real retry) and **Serving Stopped**.
_Avoid_: serving ready, logged in and serving (the login is a separate fact), listening
(the bind is one of two things serving means; answering peers is the other)

**Serving Stopped**:
`ServeEvent::ServingStopped { reason }` — the serve activity ended *and the adapter is back*
. The actor emits it, not the serve task, and only once the returned adapter is in the
wiring with its listener down and its port free, so it is exactly the moment serving becomes
startable again: a front end may answer it with `StartServing` and race nothing. The
`ServeStopReason` separates news that is not the same — `Requested` (an operator's `StopServing`,
or the core going down), `ListenerClosed` (the accept pump died and nobody asked for it), and
`TaskFailed` (the serve task ended abnormally and took the adapter with it — the one stop from
which serving does *not* recover).
_Avoid_: listener closed (one of three reasons, not the event), serve shut down, unserving

**Search Activity**:
A core-owned **Activity** that submits an **eD2k Server Search**, correlates streamed **Search Results** to a caller-visible search id, and exposes app-facing search lifecycle events. Its legs — server, **Global Search Sweep**, Kad — are independent (ADR-0034): each is sent, waiting (for a session, or for Kad) or settled on its own, and one that waits holds no other back; a sent server leg whose session is lost waits for the reconnect while the **Server Intent** stands and is sent again, else ends unanswered; with Kad alone the Kad leg goes out and the server leg waits only while the Server Intent stands — as it does when its session ends before its request reaches it — and otherwise settles as not sent, so the search completes on its other legs. It does not own packet encoding, Kad behavior, UDP fanout, or automatic download start policy.
_Avoid_: protocol search, desktop search screen, source lookup

**Search Result Set**:
The in-memory, append-only collection of **Search Results** accumulated for one **Search Activity** during the current process. It is not durable history, a local search index, or a replacement for the **Shared File Registry**.
_Avoid_: search database, search history, file library

**Search Attribution**:
How a **Search Result** finds its **Search Activity** when the answer carrying it names none (ADR-0034): it belongs to every live search whose query it satisfies and to no other. The server's answer to a search's own request (its *owner*, known by the answer's place on the link) keeps rows unless a field they carry contradicts the query; every other live keyword search must prove each clause. A row reaching no live search is dropped and counted, never shown. A **Related-Files Search** is attributed by place alone.
_Avoid_: routing, demux (by id — there is none), search queue, sweep turn

**Owed Set**:
A server session's requests whose answer wait ran out unanswered, each with the instant it was given up on (ADR-0034, "Owed answers lapse"). While it holds any entry an answer's place names no owner. An answer arriving with nothing outstanding pays back the oldest entry; an entry lapses 60 s after it was made, the server taken to have dropped the request.
_Avoid_: debt counter, missing answers

**Search Pager**:
The one search on a server session whose server holds more rows for it (ADR-0036): its own answer said so while its request was the newest on the link, and no search request has gone out since. Only it may ask for the next page (`OP_QUERY_MORE_RESULT`, which names no search); any later search request ends it, since the server replaces the rows it kept.
_Avoid_: cursor, continuation, more-results flag (the flag is the byte; the pager is the search)

**Search Quiet Timeout**:
The core-owned inactivity window that closes a **Search Activity** as complete, counted only once no leg holds it open (a leg holds it while sent or waiting for a session — a Kad leg waiting for Kad lets go once the others settle) — the connected server answered (or its 12 s answer wait ran out), the **Global Search Sweep** sent its last datagram, the Kad keyword walk ended (or its 45 s lifetime ran out) — and reset by each accepted **Search Result** batch and each leg settling. A search nobody answers still completes with zero results, after the answer wait. It defaults to 3 seconds in `CoreConfig` and is an app-facing lifecycle boundary, not an eD2k protocol end-of-results packet.
_Avoid_: server completion marker, search deadline, socket timeout

**Upload Slot Queue**:
The core-owned, cross-connection queue of remote peers requesting files we share, with a bounded slot budget and assigned queue rank — the serve-side sibling of the download scheduler (ADR-0026). A `PeerSession`'s **Server Capability** only reports inbound requests and obeys grant/queue/refuse commands; it holds no queue. Core computes rank, sends `OP_QUEUERANKING`, promotes on slot free, and pushes part bytes down via `SendBlock`.
_Avoid_: upload manager, seed scheduler, slot (a slot is one grant within the queue)

**Asked File**:
The one shared file a remote peer is currently asking us about — aMule's per-client upload file (`SetUploadFileID`). Its name ask, status ask, bundle and slot ask each set it; a waiter's place in the **Upload Slot Queue** follows it (the place kept), and its UDP reask is answered only when it names it (ADR-0055 §Name-ask surface). A slot holder's slot keeps its own file until it asks a slot for another. The asker's part status is still kept per peer *and* file, not reset when the Asked File moves.
_Avoid_: request file (that is our own download's file on the requester side), upload file (reads as the slot's)

**Per-Address Queue Cap**:
The third limit on admission to the **Upload Slot Queue**, beside the slot budget and the wait-list cap (ADR-0088): at most three **waiting** entries per **Accounting Key** — one IPv4 address, one IPv6 `/64`. Counted at `UploadSlotQueue::admit`, which every route into the queue reaches (accepted connection, dialed connection's serve half, adopted callback, risen **Tunnel**); a granted slot is not a queue place, and a queued peer's re-ask is its existing place rather than a fresh arrival. The answer is **silence** — the reference frames no packet at all — so `upload_address_cap_refusals_total` is the refusal's only trace.
_Avoid_: per-IP ban (this refuses one ask, it does not enter the **BanStore**), queue-full (that is the wait-list cap — it answers with the same silence, but counts as its own fact)

**Buddy**:
The single Kad-recruited relay relationship (ADR-0061) — one slot, either direction: the open node relaying callbacks/reasks for a firewalled client we accepted, or the open node relaying for *us* while we are firewalled. Recruited only when **Reachability** says both TCP and UDP are firewalled (UDP-open nodes take the direct-callback route instead); kept alive by `OP_BUDDYPING`/`PONG` over its TCP link.
The two directions are asymmetric in one way, and it decides who owns the socket: **the firewalled side dials**. As somebody's buddy we *attach* the connection the firewalled client opened to us and relay over it; as a firewalled node we open the link ourselves on the verified `0x5A`, ping it, and notice its loss — which empties the slot and re-arms the walk at once.
The attach is decided at the accept path's triage, and **by the hello, never by the address** — a recruit behind a NAT can dial from anywhere, so the user hash its `OP_HELLO` reports is what must equal the hash its `0x51` recruited on. The two readings of that hash live in different byte orders on the wire (Kad writes it word-swapped, eD2k raw), and that mismatch alone once kept the accept path from adopting a recruited buddy: the Kad codec normalises, and everything above it holds only the raw form.
_Avoid_: helper (that's the UDP firewall-test role), relay peer, friend (unrelated eMule concept)

**Firewalled Front**:
The one core task that enacts the firewalled half of the **Buddy** relationship (ADR-0061). It dials the recruited buddy, holds that link, paces its keepalive, and answers everything that arrives on it — an `OP_CALLBACK` through the relayed-callback gates to a dial-back, an `OP_REASKCALLBACKTCP` split by its forwarded tail into an ordinary reask (which re-enters the reply matrix with the injected requester standing in for the datagram source) or a rendezvous for the **Acting Path** — plus the client-UDP surface's standalone rendezvous and direct callbacks. Every dial-back it opens enters the serve pipeline through the admit seam as the dialer's side; a `0x95`'s may be obfuscated toward the requester's own User Hash first, since that body names both a hash and a crypt stance where the `0x99` relay names neither. It is the firewalled slot's only owner and only writer: the slot is a plain struct on its task, the `0x5A` the Kad pump verified reaches it as an `AdoptBuddy` command it answers with its verdict, and every other reader goes through the **Buddy Snapshot** it publishes. Its buddy dial and its dial-backs go through one Dialer seam: the real adapter dials the buddy with `PeerConnection::connect_identified` and a dial-back through the admit seam, a test's is scripted and records both. It does not own the recruit trigger (that is the **Kad Pump State**'s rule over the Buddy Snapshot and **Self Reach**) and it does not own the burst (that is the **NAT-T Front**'s, which holds the send half). Its `0x99`/`0x95` gates read **Kad Presence** live rather than a task-local copy: a node's start reaches it through a latest-wins cell beside its inbox rather than as a command — so a full inbox cannot lose it, and an unseen start is applied before any command — carrying the dial identity and the new node's Kad ID the slot is re-seated against, and a stopped node's buddy is let go the moment Kad Presence changes, awaited rather than polled, rather than on a dedicated command. A late dial outcome — a link or a failure — acts only on the buddy it was dialed for. One buddy, one dial, one link: a second adopt while a dial to that buddy is in flight starts none (`buddy_dials_refused_total`), and a second link landing for a buddy already held is shut, the first kept.
_Avoid_: buddy manager, firewalled node service (`crate::firewalled` is the sans-I/O decision half beneath it)

**Buddy Snapshot**:
What the **Firewalled Front** publishes of its slot after every change (`BuddySnapshot`, a `watch`): whether a buddy is adopted or its link held and since when, when the last one was lost, the buddy row a Kad source publish names (with the held link's `bi6`), and the advert a hello's buddy tags name while the link is held. Its readers never touch the slot: the hello (gated by **Self Reach**'s `IsFirewalled()` union per hello), the **Kad Pump State** (the publish posture and the recruit rule, whose instant re-arm is a loss newer than its last walk), and the **Reachability Trail**. Beside it the Kad pump publishes its **Recruit Status** — a walk in flight and the last recruit refusal — so a reader composes the operator's `BuddyState` from the two owners, each with one writer.
_Avoid_: slot state, shared slot

**Recruit Status**:
The Kad pump's published reading of its own ADR-0061 recruit rule (`RecruitStatus`): whether a FINDBUDDY walk is in flight, and why the last recruit tick refused to walk. Its one writer is the **Kad Pump State**, which restates it fresh when a node starts and drops the walk when the node stops; the **Firewalled Front** copies it into the diagnostics beside its own slot's state, and the **Reachability Trail** writes `buddy=walking` from it.
_Avoid_: recruit state, walking flag

**Buddy Link**:
The enacted open half of the **Buddy** relationship (`BuddySlot`, ADR-0061): the `0x51` recruit's accept, the attached held link an identified inbound peer's user hash earns, the verified `0x52`/`0x94` relays that link carries, and `OP_BUDDYPING`'s pong — gated to the held link, the connection-identity check aMule's `GetBuddy() != client` also runs.
An inbound `OP_CALLBACK` is not gated that way: aMule's `case OP_CALLBACK:` carries no buddy/role check at all — unlike `OP_BUDDYPING`, it acts on any `0x99` whose check-ID inverts to the receiving node's own KadID, on whichever socket it arrives, so `BuddySlot::consume_callback` applies the identical rule `firewalled::relayed_callback::apply` gives the **Firewalled Front**'s own consume, without a held-link requirement. Live: the serve bridge routes every served link's `0x99` there, gated on the **Kad Presence** and the file-known predicate, and a `Dial` enters the serve pipeline through the same admit seam the **Firewalled Front**'s dial-backs use — plaintext, since the `0x99` body names no hash to key a crypt handshake on.
_Avoid_: firewalled front (the other half — the link *we* dial), buddy manager

**Kad Presence**:
Whether a Kad node runs on this core, and as which Kad ID — one cell with one writer: the **Kad Activity** in the actor's ledger holds the only lease on it from start to retire (ADR-0093), taken through **Self Reach** together with the Kad verdicts' reset, so "Kad running" and "nothing proven" flip as one fact at the one retire; a stale lease never clears a restart's successor. Every reader reads it: Self Reach's `kad_running` (the download's liveness at each decision, the route chooser, the `KadNotRunning` guard), and the readers that live on a task of their own — the serve bridge's and the **Firewalled Front**'s `OP_CALLBACK`/`OP_DIRECTCALLBACKREQ` gates. A reader that must act on a change subscribes to it instead of polling: the **Firewalled Front** lets its buddy go the moment the cell reads no node. Core builds the cell once, with the rest of the `KadCells` every Kad start is lent, so a swapped-in factory publishes into the cell every reader already holds.
_Avoid_: kad_running (a task-local copy), Kad status, Kad Liveness (the retired second flag)

**Reachability**:
The Kad pump's accumulator for whether we can be reached, fed by the Kad self-check (ADR-0058): TCP open/firewalled/checking (≥2 connect-back acks = open) and UDP open/firewalled/unverified (with the preferred Kad UDP port). The pump publishes its settled verdicts as the Kad family of **Self Reach**, and every reader — the pump's own included — asks that owner, never this store. The server-probed IPv6 verdict (ADR-0084) lives beside it as a published cell — it is *told* to us by the server session, not self-checked, and dies with the session that said it. A fact about us, not about any peer — peer-side reachability lives on the peer's source entry. It holds no address: that is **Address Learning**.
_Avoid_: firewall status (ambiguous about whose), connection state (that's the server session), NAT type

**Self Reach**:
The one live owner of our own reachability (ADR-0060 "Self Reach"; `SharedSelfReach`), over families each with one writer: the Kad TCP and Kad UDP verdicts and whether the node has joined (the Kad pump, reset to unproven at a node's start and end), the **Server High ID** (the session self-facts), the NAT-T front's liveness (its liveness only — the front's command half rides the wiring of whoever sends to it), whether the client-UDP send half is bound (the client-UDP bind: set at the actor's prologue, cleared at Quit), and whether the **Server Coordinator** is live (the server session: set when the login's punch keepalive starts, cleared when the session ends). aMule's union rules live here and nowhere else — `IsFirewalled()` (High ID or Kad TCP open), `!IsFirewalledKad()` (Kad TCP open), `CanDoCallback` (the **Callback Capability**), the direct-callback bit, `GetID` (the **Presented Client ID**) and the **Route Position** — and every reader asks the question aMule asks at the moment it needs the answer, or subscribes to the **Reach Generation**; no reader holds a copy or composes two facts itself. The serve listener is not a reach family but `CanDoCallback`'s own conjunct; the owner carries its cell (bound and cleared by the actor's ledger) so that answer is composed here too, and so is the port a callback invites a dial to.
_Avoid_: reachable/firewalled flag (a copy), Reachability (the pump's accumulator)

**Presented Client ID**:
The client id every hello and hello answer names for us, answered by **Self Reach** at each hello (`SharedSelfReach::presented_client_id`) in aMule's `GetID` order: a Kad node that has joined and whose TCP verdict is open names our address (the **Address Learning** verdict) as a High ID, even under a server Low ID; otherwise a live session names the id its server assigned last; otherwise a joined, firewalled Kad node names `1`; otherwise `0`. The `1` matters: a peer reads `0` as "use the address I see", so a serverless firewalled node that said `0` would be taken for a High ID and dropped as a buddy. Never the server's id alone.
_Avoid_: client id (unqualified: the server-assigned one is the session's), own ID, hybrid ID

**Route Position**:
Our own half of the ADR-0061 route tree, answered by **Self Reach** in one read (`SharedSelfReach::route_position`, a `RoutePosition`): reachable, client-UDP up, Kad running, the **Advertised IPv6** the **Dial Chooser** pairs with a peer's, and whether the **Server Coordinator** can introduce us. **Peer Reach** reads it at each reach and the **NAT-T Front** reads it when a coordinator fails; the selector takes it as a value, which is how a route-tree test states a position directly.
_Avoid_: `SelfReach` (reads as the owner, **Self Reach**), our facts

**Reach Generation**:
The change event of **Self Reach** (`SharedSelfReach::changes`): one wake for a Kad verdict write or the node's join, a session write (login, re-assignment, server move, end), the NAT-T front's end, a serve-listener bind or clear, the client-UDP bind or its clear, or the **Server Coordinator** going live or dark. It says only that something moved — the subscriber re-reads the owner. The readers that must cache subscribe: the Kad pump (the publish byte and the buddy row it tells the sans-I/O node), a download runner (the brain's **Callback Capability**), the **Firewalled Front** (releasing the buddy when Kad TCP opens), and the **Reachability Trail** (the Kad verdicts it writes).
_Avoid_: reachability event, High-ID watch (names one family; the generation wakes for every family)

**UDP Firewall Helper**:
A Kad node asked to prove somebody else's Kad UDP port reachable (ADR-0058). The asking is peer TCP — the requester dials the helper's eD2k port, completes the hello and sends `OP_FWCHECKUDPREQ` (`0xA7`: its intern and extern Kad ports and its UDP verify key for the helper's IP) — and the answer is a Kad datagram, `KADEMLIA2_FIREWALLUDP` (`0x62`), to each port named. Both roles are the Kad pump's: as requester it enacts every helper the node engages and reports how the link ended — **cancelled** when the request never went out (a refused dial, a hello that never finished, a helper whose hello names no Kad port or a Kad version below 6, *or* a candidate the **Peer Roster** already knows, checked before the dial and never sent one) — **failed** when the link ended after it did (aMule's 40 s idle close) — and as helper it hands an inbound `0xA7` from the triage to the node, which answers, biased (`errorcode 1`) when the requester is a routing-zone contact *or* the Peer Roster says we already have an active upload with it. The node finds its helpers with the **Helper Lookup**; no helper it was seeded with, or ever sent a datagram, can serve. A biased answer reads to the requester's own tester exactly like a cancelled one: neither pass nor fail, the next candidate engaged in its place.
_Avoid_: buddy (the relay role, unrelated), firewall checker (that is the `0x53` responder), STUN server

**Peer Roster**:
The core-owned set of IPs this session already has an eD2k relationship with (ADR-0059 "Roster relations"; aMule's `CClientList::FindClientByIP`) — the union of every live **Roster Relation**, kept per endpoint, so an IP is known while any relation on any endpoint holds it and a peer with no relation left leaves. Read by the **UDP Firewall Helper**'s requester gate and helper bias — always the one `SharedPeerRoster` the builder creates, never a copy. IPv4 only: a relation over IPv6 is not recorded, so a dual-stack peer we deal with only over IPv6 reads unknown to both rules. A chat session is not fed in (rmule has no chat).
_Avoid_: client list (that's aMule's whole peer-tracking object; this is one membership question), ban store (a different enforcement, unrelated criteria)

**Roster Relation**:
One owner's hold on a peer endpoint in the **Peer Roster**, added by that owner's start event and removed only by its own terminal event — never by a purge that guesses (ADR-0059 "Roster relations"). Four exist: a **Download Relation** (one download's worker whose hello completed — `Connected` — ended by `EndWorker` or the fleet's whole-fleet shutdown on completion or failure, held per download so two downloads on one peer never retire each other's), a **Queued Relation** (one download's **Remote-Queued Pool** membership, held to its Source Book's RemoteQueued stage after each brain step, so every way out of the pool ends it — a TCP full ask, a `0x92`, a merge, an endpoint another record took), a **Waiter Relation** (`PeerQueued`, ended by `WaiterLeft` — purged or cancelled — or turned into an Upload Relation by a promotion, and carried to the waiter's new link by `WaiterRelinked`), and an **Upload Relation** (`UploadSlotGranted` ↔ `UploadSlotReleased`). Waiter and Upload share one membership, as aMule's one upload state does. The owning activity's end — a serve stop or listener death, a download's run ending on any road, a quit's abort — ends every relation it still holds.
_Avoid_: known client (aMule keeps an object per client whether or not any state is live; a relation is a live state), mark/forget as nouns (those are the roster's write calls)

**Crypt Stance** (of a peer):
What rmule believes about one peer's obfuscation — supports / requests / requires, through aMule's getter ladder — plus the User Hash an obfuscated dial is keyed on (`PeerCrypt`; ADR-0049's amendment). Stated by the peer's own hello (`CT_EMULE_MISCOPTIONS2`), relayed by records (`0x44`, source exchange v4, a Kad row's `TAG_ENCRYPTION`) or carried by one request (`0x53`, `0x95`, the buddy's `0x5A`). Each stance rides one place in the download's **Source Book** — the hello's on the endpoint its worker read it on (read by both the TCP re-dial and the `0x90` reask), the run tier's record-stated crypt by endpoint for a High-ID source, a `LowIdCandidate` for a Low-ID one — or a verdict for a request. The hello outranks every record; among records the newest *statement* wins, a record with no crypt byte is silence and never overwrites one, and a record naming another User Hash replaces the older record whole. Unstated reads all lights dark at the dial and is never stored as a statement. The node's *own* stance is a separate cell (ADR-0048).
_Avoid_: obfuscation policy (that is ours, `ObfuscationPolicy`), crypt options (the wire byte a source states it with), encryption status (aMule's per-connection `GetObfuscationStatus`)

**Obfuscation Policy**:
The node's own crypt choice (ADR-0042/0046) — off, supported, requested or required — one value for every peer stream and datagram, the server login, the NAT-T frames, the server-UDP crypt-ping and the Kad node. A running core holds it in one cell, `SharedObfuscationPolicy`, which the server session cell owns and the Hello Adverts every hello starts from share, so the login and a hello state one policy; the builder settles from **Core Settings** and the actor alone changes when the operator sets it live (`TakesEffect::Now`). No surface keeps a copy: each reads the cell as it decides — the next dial's options, the next accept's byte-0 rule, the next server login's **Login Link** and crypt flags, the next datagram's send gate and dual-path receive, the next CAPS answer and KEY frame, the next crypt-ping tick — and the Kad pump, whose node caches its arming, wakes on the change and re-arms it whole. A connection that already negotiated keeps what it agreed. The Run Log states it at every build and every change.
_Avoid_: crypt policy (Kad has none of its own), Crypt Stance (that is what we believe about a peer)

**Server High ID**:
The level "a live eD2k session holds a High ID" — the server dialled our TCP port and reached it. Owned by the session self-facts (`SharedOwnIdentity`): written at login, re-written on a mid-session `OP_IDCHANGE`, cleared when the session ends. A family of **Self Reach**, which reads it live as aMule's `IsConnectedED2K() && !IsLowID()` half of `IsFirewalled()` — nothing copies it. It never feeds the Kad TCP verdict.
_Avoid_: High-ID (unqualified, that is any peer's id class), server reachability (that is the server's own)

**Test Connection**:
A plain dial under `ObfuscationPolicy::Required` from an address in the **Awaited Testers** — a server's High-ID port test or a Kad helper's firewall-check connect-back (ADR-0046). Admitted where the byte-0 discrimination decides (`Admitted::TestConnection`), it meets the IP filter and ban gate, is answered its hello, has an `OP_KAD_FWTCPCHECK_ACK` counted, and is closed by its first request to be served; it never reaches the inbound triage. aMule and eMule accept the same dials but then serve them as any peer.
_Avoid_: firewall check (that is the Kad exchange it may carry), probe, callback (a callback is a peer we serve)

**Awaited Testers**:
Who may dial the listener plain under `Required` right now (`SharedAwaitedTesters`, in the session self-facts): the server a login answer is awaited from — written by establishment from the dial until the login is answered or fails, aMule `AwaitingTestFromIP` — and each Kad contact a TCP firewall check was asked of for its 180 s window, written by the Kad pump from `ReachabilityCheckAsked` and dropped at a recheck and at Kad's stop, aMule `IsKadFirewallCheckIP`. A mirrored level the accept pump reads without awaiting anyone, the **File-Known Predicate**'s shape. A window that closed — the server's, or a helper's that lapsed or was dropped — is remembered for 60 s, so a test from its tester after it is reported late (`LoginStep::PortTestLate`, `CoreEvent::KadHelperTestLate`), never admitted.
_Avoid_: whitelist, trusted peers (it grants a hello, not trust)

**File-Known Predicate**:
Whether this session would dial for a file hash — aMule's `GetFileByID`, spanning the **Shared File Registry**'s offered rows (never a **Withheld Row**) and the **Download Set** (ADR-0061). A mirrored membership cell (`SharedFileKnown`), not a query: the serve and download command arms push every share-set and download-lifecycle change into it inline, so the **Firewalled Front**'s `0x99` gate reads it without ever awaiting the actor. The downloading half is the **Download Set**'s files: each start adds its file's hash and its retire removes that hash, never another's.
_Avoid_: known file list (that's the **Shared File Registry** itself), file cache

**Address Learning**:
The core-owned, sans-I/O store of where we are on the wire (ADR-0084): it turns **Address Observations** into one **External Endpoint** verdict per address family and socket role, by descending confidence tier with per-source freshness. The sibling of **Reachability** — that one says whether we can be reached, this one says at which address. A peer's claim about our address is a vote and is never adopted on its own.
_Avoid_: public IP (one source among several), own identity (the user hash lives there, the address only projects there), STUN

**Own Address**:
The node's own external IP and each socket role's external port, per address family — owned by **Address Learning** alone (ADR-0084 "Own address ownership"). Every reader reads the store at use time or subscribes to the **Own Address Generation**; nothing else holds the value, and a withdrawal is a change like any other. The sans-I/O Kad node is the one subscriber that must cache (it cannot read a core store): its verify-key IPv4 and **Extern Kad Port** are restated on every generation and on the recruit tick, the edge for a freshness window lapsing with nobody writing.
_Avoid_: public IP (one projection of it), own IP, our endpoint, advertised address (that is what **Advertised Endpoints** chooses from it)

**Own Address Generation**:
The counter **Address Learning** advances on every write that moved the **Own Address** projection — per family the fresh-or-stale address and the fresh one, per (family, role) the **External Endpoint** verdict, and the learned ports — or the NAT facts read beside it, each family's **NAT Hint** and each role's **Own Mapping**; a write that moved nothing a reader can see advances nothing. The one change event every caching reader subscribes to (the Kad pump, the **Port Mapping** runtime, the **Reachability Trail**). Time alone never advances it: the store names the next instant a remembered observation can lapse (`next_lapse`), where a reader that caches reads again.
_Avoid_: address event, address notification, refresh

**Address Observation**:
One fact about our own address or port from one source — server assignment or reflection, Kad self-check (`0x58`/`0x61`), a peer's vote (keyed on the observer's address), a port-mapping grant, or an operator override — each with its own lifetime. The only input to **Address Learning**; the local interface set is the one source fed wholesale instead, because an enumeration replaces rather than appends.
_Avoid_: report, hint (that is the NAT hint), announcement

**External Endpoint**:
The address and port the outside world can use for one of our sockets (the eD2k TCP listener, the one UDP socket) in one address family, as **Address Learning** currently judges it: Known (a fresh tier holds, with its tier), Stale (last-known only — good enough for crypt keys, not for adverts), or Unknown. The address is learned per family and the port per **Socket Role** — one port pair serves both families — and a verdict joins the two, falling back to the port that role actually bound.
_Avoid_: public endpoint, mapped port (that is one source), bound address (the local one)

**Extern Kad Port**:
The UDP role's **learned** port in **Address Learning** — the best fresh port tier alone, with no fallback to the bound port — answered back to the Kad node after every `0x61` observation (`0` while none holds; ADR-0058). The Kad tier adopts a port two distinct observers name, not necessarily in a row (aMule `SetExternKadPort` compares each answer with every earlier one); addresses from `0x58` keep the consecutive rule. The store is the one owner (ADR-0084): the **Kad Pump State**'s reconciler also restates this answer at Kad start, on every **Own Address Generation** and on the pump's recruit tick — only when it moved, unlike the observation answer — so a `KadCheck` rung's 30-minute window ageing out with no fresh observer reconciles the node's cache within one tick instead of waiting for a round that may not run again soon. Scoped to the current round: `KadEvent::ExternPortRoundStarted` marks the boundary the node draws at every recheck, and the Kad Pump State answers it with an Address Learning write, `forget_kad_port_round(SocketRole::Udp)`, withdrawing that role's `KadCheck` rung alone — the address ladders and every other tier untouched — so a vote from before the boundary cannot back one named after it, matching aMule's `FindExternKadPort(true)` starting each round's observer lists empty.
_Avoid_: external port (ambiguous with the TCP role), mapped port

**Socket Role**:
Which of rmule's own sockets an **Address Observation** or an **External Endpoint** is about — two, because rmule binds two sockets anyone sends *to*: the eD2k TCP listener and the one **client UDP** port, which carries peer reask, the NAT-T frames, the server status pings and the Kad node (ADR-0057's socket unification). Each binds one **Family Pair**, so a role has one port and up to two addresses. Kad had a role of its own while it bound a second port; one role is what makes a Kad `0x58`/`0x61`, the server's observation and a mapping grant votes on **one** External Endpoint. The server-UDP socket is not a role: nobody addresses it, so nothing observes or maps it.
_Avoid_: port kind, service, channel, Kad UDP role (gone with the second bind)

**Confidence Tier**:
One source's rung on a family's ladder in **Address Learning**, descending: Override > Server (High ID) > Kad check > mapping grant > **Low-ID Report** > interface for IPv4; Override > Server > peer quorum > interface for IPv6. A tier absent from a family's ladder is refused there outright — an IPv4 peer vote is never a source. The grade carries no observer identity, so a verdict can name the tier that produced it without carrying who said it.
_Avoid_: priority, weight, trust level, score

**Low-ID Report**:
The address a server's `OP_IDCHANGE` reports for us when it assigned a **Low ID** — its own **Confidence Tier** (`ConfidenceTier::LowIdReport`, ADR-0084), IPv4 only, below the mapping grant and above the interface. A Low ID is the server saying it could not reach us, so its report is the weakest reflection on the ladder; it wins only when no Kad check and no grant holds, which is where aMule's `SetPublicIP(dwServerReportedIP)` needs it (the UDP crypt keys). A report naming the connected server's own address is refused — ed2k-rust writes its own `this_ip` there.
_Avoid_: server tier (that is the High ID alone), reported IP (the wire field, not the grade)

**Listen Before Login**:
The rule that no eD2k Server Login precedes the eD2k listener's bind (ADR-0086; aMule binds in `ReinitializeNetwork` before autoconnect). A core built to restore at attach binds the listener at attach (ADR-0095, "Connecting is the operator's act"); otherwise the **Server Session Switch** starts the **Serve** activity when none is live, on the actor, before its connect task dials. A failed bind is reported and the login still goes out Low ID, as aMule's does. Since the Switch is the only login, the rule holds for every session rmule opens.
_Avoid_: autoserve, listen-on-connect (the rule is the order, not the trigger)

**Session Generation**:
The count `SharedServerSession` bumps each time an establishment installs a live session
(ADR-0095). A follower that must act on every new session wakes on it instead of polling the
slot: the **Session Follower**, and the actor's waiting keyword searches, which start on the
session that just came up.
_Avoid_: session event (the ADR-0080 trail is the operator's; this is the internal wake)

**Server Intent**:
The operator's standing wish to be connected to one server (ADR-0096, "A lost session is re-made"): begun by their `ConnectToServer`, ended by `DisconnectFromServer` (the row menu's Disconnect, or `c` on that row), a connect elsewhere (`ReconnectEnd::Replaced`), or Quit; Kad is left as it is. While it stands a lost session is re-made through the one establishment, to that server only, after a delay growing from 30 s to 10 min and then repeating at it, without end unless `CoreConfig::server_reconnect_attempts` bounds it; the operator's own connect that fails is not retried. Not durable: after a restart only Autoconnect dials.
_Avoid_: auto-connect (the start-time preference), reconnect policy (it is the operator's intent, not a policy of rmule's)

**Session Follower**:
What the Serve activity does in place of a login (ADR-0095): it dials nothing, and for each
session the operator makes it announces the share set (`OP_OFFERFILES`) — unless the
**Announce Policy** withholds it from a server that grants related search. The listener's hellos
are not sent by it: they read the live session through the **Hello Source**.

**Hello Source**:
Where a long-lived surface reads the hello it presents: our identity under the **Presented
Client ID** and the live session's server, read from **Self Reach** at each connection, never
kept as a copy — the listener's accept pump and its admissions (tunnels, callback dial-backs),
the firewalled front's buddy dial and the Kad node's dial-backs. Every dial and every accept
therefore names the id Self Reach answers then and the live session's server, or none between
sessions.
_Avoid_: hello context cell, handshake snapshot
_Avoid_: serve login (retired), announce relay

**Login Mapping Wait**:
The bounded wait (`LOGIN_MAPPING_WAIT`, 10 s — eMule's UPnP connect delay) between the operator's connect and its dial, while a **Port Mapping** runtime runs: until the **Desired Mapping Set** holds the listener's IPv4 TCP row and its **Mapping Status** reads Mapped, Degraded or Failed. Read off the rows the runtime publishes on a watch. A grant landing later does not re-log in; its Exact recheck and the Kad TCP verdict carry the reachability instead.
_Avoid_: UPnP delay (three backends race), login retry

**Login Link**:
How one dial of an eD2k Server Login opens its link (ADR-0042, aMule `ServerSocket.cpp:786-795`): **obfuscated**, to the server's obfuscation TCP port with the server-form crypt handshake before the login, when the **Obfuscation Policy** requests or requires obfuscation and the server's row says it takes it (an obfuscation TCP port from its last status answer, and `TCPOBFUSCATION` in its UDP flags or its last login's TCP flags); otherwise **plain**, to its own port, naming why — the policy does not initiate, the server has not said, or the obfuscated attempt failed. A failed obfuscated attempt earns one plain one under `Requested` and none under `Required`, which like aMule dials a server that said nothing plain. Whatever the link, the login's flags state the policy. Chosen at each dial and reported as a **Login Step**.
_Avoid_: crypt dial, server crypt mode

**Login Step**:
One step of an eD2k Server Login between its session edges (`CoreEvent::ServerLogin`, ADR-0075 Run Log): the **Login Mapping Wait**'s end, the **Login Link** each dial takes, a dial that did not come up and why (an obfuscated one's crypt handshake included), the login sent with what it claimed of us (listen and UDP ports, advertised IPv6), a close before the answer, the server's High-ID port test (its window opening, a connection from the server arriving and how it was admitted, how a test from it ended, the window closing with or without one), the answer with the id, our public IPv4 or the server's own address refused as ours, and the TCP flags it granted, the same answer again mid-session, the server's IPv6 probe verdict, and the Kad recheck a High ID asks for. Evidence for a reachability diagnosis: no level moves with it, and every field is ours or the server's, never a peer's. A dial to the own **Buddy** that did not hold a link is the sibling step `CoreEvent::BuddyDialFailed`, whose buddy address is a peer's.
_Avoid_: login trace, handshake log (a step is a typed event, not a log line)

**Advertised Endpoints**:
The one core-side chooser that combines Known **External Endpoints** with **Reachability** to decide every advert: the connect-options bits (ADR-0047), hello/login/ExtSX tags, and Kad publish tags. No advert site reads the two stores on its own.
_Avoid_: capability registry (that is ADR-0047's bit registry, one consumer), hello builder

**Port Mapper**:
The core-owned, sans-I/O brain of port mapping (ADR-0086): it derives the **Desired Mapping Set** from the bound Family Pairs, races the mapping backends, grades every trial by **Mapping Grade**, schedules each **Mapping Lease**'s renewal, tracks gateway epochs and backs off on failure — returning commands a runtime enacts. Explicit time only; testable against a fake backend.
_Avoid_: UPnP module (one backend of three), NAT helper, port forwarder

**Desired Mapping Set**:
The mappings rmule wants on the router right now — one per bound Family Pair role (the TCP listener, the one UDP socket) per family, never the server UDP socket — derived from what actually bound, never configured. Two roles, so a firewalled node holds two router mappings per family rather than three: Kad rides the client-UDP bind. Re-derived whenever the **Bind Generation** or the **Own Address Generation** advances — the set's second input is an IPv6 pinhole, wanted only while a Known IPv6 exists — and again on the mapping runtime's own clock, for a Known verdict that lapses with nobody writing.
_Avoid_: port list, forwarding rules

**Bind Generation**:
The counter **Address Learning** advances every time a socket records what its Family Pair bound. What the **Port Mapping** runtime waits on, so "a socket came up" is read from the table the **Desired Mapping Set** is derived from rather than from a notice sent beside the bind — which is a race the starter always wins and loses silently (the eD2k listener's mapping, the one that earns a High-ID, went missing for whole sessions that way).
_Avoid_: bind event, bind notification (the point is that it is not one)

**Client-UDP Bind Failure**:
The one **Socket Role**'s Family Pair refusing *every* selected family at core start (ADR-0057) — not a one-family refusal, which the pair tolerates and simply binds around. Named three ways from the one fact the actor records at the bind site: `DiagnosticsSnapshot::client_udp_bind_failure` (a row that persists for the session), `CoreEvent::ClientUdpBindFailed` (fired once, at start), and `KadUnavailableReason::UdpUnbound` (the same port and `io::ErrorKind`, carried into every `EnableKad` refused afterward). Permanent for the session — there is no re-bind; an operator restarts rmule (ADR-0057 amendment).
_Avoid_: UDP bind error (too generic — this is specifically the whole-pair refusal, not a partial one), Kad unavailable (that is the rejection's *name*; this is the fact behind one of its causes)

**Half-Bound Pair**:
The other outcome a Family Pair can have (`rmule_net::family::HalfBound`): the role came up, but without a family it selected. Settled in **Address Learning**'s bind table beside the families themselves — one writer, so "which families" and "what that costs" cannot disagree — and read back three ways: `DiagnosticsSnapshot::half_bound_pairs`, `CoreEvent::SocketBoundWithoutFamily` (once, at the bind) and `KadUnavailableReason::UdpFamilyMissing` (Kad rides the client-UDP pair's IPv4 half and no other, so a `::`-only pair refuses `EnableKad`). The adverts follow it: the chooser names no endpoint for an unbound family, the login's `0xF9` is omitted rather than zeroed (its presence *is* the punch-target flag), and the hello's `CT_EMULE_UDPPORTS` client half is withheld at `0`.
_Avoid_: partial bind, degraded bind (neither says which family or what it costs), **Client-UDP Bind Failure** (that is the whole-pair refusal — this one has a socket)

**Mapping Grade**:
How well one backend's trial served the **Desired Mapping Set**: Exact (every mapping on its own port) > Mismatched > Partial > None. Exact ends the race; a Mismatched TCP grant is **Degraded** because the hello cannot advertise another port, while a Mismatched UDP grant becomes an **Address Observation**.
_Avoid_: score, success (too coarse)

**Mapping Lease**:
One granted mapping with the lifetime the router actually returned (clamped), its renewal timer, and its **Mapping Grade** contribution; released on exit. The lifetime *is* the freshness — an adopted grant's rung in **Address Learning** expires with the lease, so a mapping that stopped being renewed stops being advertised without anyone cancelling it.
_Avoid_: forwarding, rule, port map (the whole subsystem)

**Mapping Grant**:
What one gateway actually gave for one desired mapping — the external endpoint joined from the address it reported and the port it granted, plus that lifetime. The **Port Mapper**'s one non-command output: a usable grant enters **Address Learning** as an **Address Observation** at the mapping-grant tier, which is what puts the granted endpoint on the `CT_EMULE_UDPPORTS` advert and the `0x95` without any advert site knowing a port mapper exists. The *granted* port is the whole point: it is what **Mapping Grade** compares against the internal one.
_Avoid_: mapping result (that is the runtime's answer channel), reservation

**Mapping Status**:
How one mapping reads to an operator: NotMapped, Probing, Mapped, **Degraded**, Failed — one row per *desired* mapping, granted or not, because "the eD2k listener is not mapped" is the fact an operator most needs and a success-only table cannot state it. Degraded means granted but unusable: a different TCP port (the hello carries one port and no external-port tag) or an external address that is private or carrier-grade. Distinct from **Mapping Grade**, which ranks a whole *trial* during the race.
_Avoid_: forwarded (a boolean hides Degraded), health, state

**Recheck Reachability**:
The core-side command that starts a Kad firewall self-check outside its hourly clock — fired once per fresh Exact **Mapping Lease** grant, on a gateway epoch reset, and by the operator's recheck (which also re-races the **Port Mapper**). Rate-limited and guarded like the scheduled check.
_Avoid_: firewall test (the wire-level helper exchange), reprobe (that is the mapper's half)

**Dial Chooser**:
The one core-side decision of *which address family* a peer is dialled at (ADR-0087): a peer with a usable IPv6 while we hold a Known IPv6 is dialled directly over IPv6 — rung 0 of the ADR-0061 route tree, ahead of every callback and ahead of the plain High-ID dial; otherwise the IPv4 identity and the classic LowID rules. The AND is the whole rule: the peer's address alone is not enough, because dialling from an address we cannot corroborate breaks reply attribution and dial-back. Lives beside **Advertised Endpoints**, reads the **Advertised IPv6**, and also decides whether a source is admitted at ingest at all; no dial site decides family on its own. Its pick is the *first* family only: a dual-stack High-ID source whose first dial never completes its handshake is dialled once in its other family before it retires — one dial per family. A failed dial — a spawn failure included — spends its endpoint, a single-address source's as much as a half, for one to two re-ask periods; a dial that connected never does.
_Avoid_: resolver preference, prefer-IPv6 setting (there is none)

**Advertised IPv6**:
The **Advertised Endpoints** chooser's IPv6 verdict, read by everything that acts on it (ADR-0087): the hello's `CT_MOD_IP_V6` tag, the login's, a Kad source publish's `ip6` tag, the **Dial Chooser**, and source ingest. A view over **Own Address**'s owner and the server's probe verdict, settled at every read and never cached — an IPv6 prefix renumber or an RFC 4941 rotation is routine, and naming an address we no longer hold is worse than naming none. Empty is the honest default.
_Avoid_: our IPv6 (the store holds several; this is the one we may name), local address

**Publish Connect Options**:
The **Connect-Options Byte** rmule's own Kad source publish carries as `TAG_ENCRYPTION`, composed in core from the owners of each bit: the crypt ladder from the obfuscation policy, the direct-UDP-callback bit from **Reachability** (firewalled by aMule's union — no **Server High ID**, Kad TCP not reachable — and UDP verified open), and the NAT-T transports rmule's claim names while the NAT-T front is armed on the node's bind (uTP; QUIC dark). The Kad pump states it before the node's first publish and re-derives it on every reachability transition, the Server High ID moving included; once the owners have answered it is always stated, zero included. The node assembles none of it.
_Avoid_: crypt options (three of its bits), capability claim (that is the hello's, and states what rmule can speak, not what it serves now)

**Kad UDP Key**:
The private per-install seed every Kad UDP verify key rmule hands a counterparty derives from, per target IP (aMule `thePrefs::GetKadUDPKey()` into `CPrefs::GetUDPVerifyKey`). Minted once from OS entropy and persisted as a preference where aMule persists `/Obfuscation/CryptoKadUDPKey`, because a counterparty checks the key we echo against the one it derived for us — a seed that changed across a restart makes every learned key a mismatch. A core-owned key of **Core Settings** (ADR-0069), never set by the operator: core reads it at build (`AppConfigStore::ensure_kad_udp_key`) and hands it to the node in `KadNodeIdentity`; no command carries it. Never transmitted. It arms nothing by itself: the node's Kad-UDP crypt (datagram obfuscation plus verify keys, armed together) follows the one **Obfuscation Policy** — any set policy arms it, unset leaves Kad plaintext (ADR-0046), and a live change re-arms the running node through the **Kad Pump State**'s reconciler (`KadCommand::SetObfuscation`). Our own public IP never enters this seed's per-target derivation — only a *learned* contact key binds to it: `KadCommand::SetOwnPublicIp`, told by the **Kad Pump State**'s reconciler from Address Learning's IPv4 verdict, moves that binding when the verdict moves, retiring keys learned under the old address exactly as aMule's `CKadUDPKey::GetKeyValue` does.
_Avoid_: Kad crypt key (the RC4 key is per datagram), verify key (that is one IP's derivation of this), Kad crypt policy (there is none — the policy is `CoreSettings::obfuscation`)

**NAT-T Rung**:
Rung 1 of the ADR-0061 route tree after ADR-0091: a LowID↔LowID candidate attempts a **Rendezvous** and **Punch** instead of being dropped, and any pair whose callback stays silent for 12 s falls to it. Core owns the attempt budgets, the two-direction relay limiters (service given to strangers vs our own path), relay admission (buddy relations only, capped), and the PCP `PEER` follow-up on success. Pairs the punch cannot reach retire as *temporarily unreachable* with a reason. The core's NAT-T machines (`acting`, `requester`, `relay`, the pure part of the server punch) are already sans-I/O and take core state as inputs; they stay in core because `rmule-peer` depends on primitives only, and moving them would close dependency cycles through `rmule-ed2k` and `rmule-net` while only relocating a few hundred lines.
_Avoid_: NAT-T mode, fallback (it is a rung, not a mode)

**Rendezvous Coordinator**:
Who introduces the two sides of a **Punch** (ADR-0091) — the **NAT-T Rung**'s one required fact beyond our client-UDP surface being up. Two, tried in order. **Our connected server first**: its introduction names an endpoint it *observed* for both sides, it needs no Kad and no buddy, its keepalive leaves our client-UDP socket so the mapping it advertises is the one a **Tunnel** rides, and the target's NAT-T support need not be known — the server knows it and refuses with a reason. **The target's Kad serving Buddy** is what is left when the target is on another server or ours does not speak the punch (which is only ever learned by its silence). Fallback runs server → buddy and never back.
_Avoid_: relay (the limited-relay tier is a different, parked thing), signalling server, STUN server

**Server Coordinator**:
The core side of ed2k-server's punch, one cell shared by the three places that need it: *establishment* advertises `0xF9` and starts the 60 s keepalive — only with an IPv4 client-UDP bind and its send half, and only over an IPv4 session; the *session multiplexer* hears the answers; the **NAT-T Front** asks it for an introduction. The keepalive is owned by the session because the session is its lifetime. Establishment records the live session's request half — weakly, so the cell never keeps a session alive — and the session's end clears it: that cell is **Self Reach**'s "Server Coordinator live" family, and the half the front puts its `0x60` on without awaiting it. An introduction has no sender gate (it arrives on our own session) and no claim to judge (the endpoint was observed) — only public, not ourselves, not punched this window, which is also what absorbs the server's re-sends. `0x61` names no target, so it settles a pending request only when exactly one is outstanding.
_Avoid_: server punch client, holepunch manager

**Acting Path**:
A **Rendezvous** relayed *to us*, and whether rmule punches because of it. Gated in this order: the carrier is our **Buddy** (its TCP link by address, or its exact UDP endpoint for a standalone frame — kno's stricter reading; eMuleAI has no sender gate at all), the requester claims a transport we can raise, the precedence rule resolves a public endpoint, that endpoint is not one of our own interfaces, and — last, so only an honoured rendezvous stamps the clock — it has not been punched inside the window. Holds its own limiter, never the **Relay Service**'s. Both carriers reach it live through the **Firewalled Front**, which owns the buddy slot the gate reads; a punch it grants is enacted as a **Punch Expectation** on the responder side, because the requester asked and therefore dials.
_Avoid_: rendezvous handler, accept path

**Relay Service**:
The rendezvous forwarding rmule performs as somebody's serving **Buddy**. Verify the buddy ID, confirm a held link, and only then admit — because admission stamps a per-source limiter and takes one of ten pending slots, and a datagram naming the wrong buddy must be able to do neither. A forwarded relay that asked for one is answered with an **Endpoint Hint** from the same socket the `0x94` arrived on; a refused one is owed nothing. Its limiter and the **Acting Path**'s are separate tables: traffic a stranger can generate never spends a budget rmule needs for itself (amule#1177 correction 5).
_Avoid_: relay tier (the parked data relay), buddy relay (that is the ordinary `0x94`/`0x52` forwarding this sits beside)

**NAT-T Front**:
The one core task that turns the **NAT-T Rung**'s decisions into a risen **Tunnel** (ADR-0091). It owns both ledgers — the rendezvous requester's and the **Punched Path**s' — plus the **Punch Expectation** table and one **Traversal Attempt** per target, so no lock orders them and no two can read the same instant differently. It drives `rmule_net::natt`'s demux and engines from the client-UDP front's NAT-T inbox, emits every rendezvous, burst and keepalive on that same bind and every server `0x60` on our session — rung 1's one emitter, handed one traverse command per target by **Peer Reach** — and hands a risen Tunnel to the serve pipeline's accept channel as the inbound source it is. Its uTP accept is a pump of its own: a cancelled accept drops a handshake the peer already completed, and its hand-off to the accept channel is an **Adopter** of its own, because the loop that feeds the demux may never wait on a consumer it does not drain — a stalled serve pipeline would otherwise silence every tunnel on the node, not just the one being handed over.
_Avoid_: NAT-T manager, tunnel service, punch handler (the demux in `rmule_net::natt` is the *transport* front, not this)

**Traversal Attempt**:
One target's punch end to end, owned by the **NAT-T Front** and keyed by the target's
**User Hash** like every other name a punch has (ADR-0091). It outlives a
**Rendezvous Coordinator**, which is why it exists: the server's `0x62` and its fifteen
seconds of silence surface on the server session, which knows a `ClientId` and nothing
about the target, so the attempt carries the join to the user hash and the candidate's own
facts — and, reading **Self Reach**'s **Route Position** at that moment, asks the one
selector who is next. It keeps no snapshot of our position. Server first, buddy on its refusal or silence, never back up. With no buddy to
ask it retires carrying *what the coordinator said* ("the server refused: target has no
UDP") rather than the schedule's "attempts exhausted", which would claim rendezvous that
were never sent. Every way it can die — a spent **Rendezvous Schedule**, a refusal with
no successor, a **Dial Schedule** budget spent — exits through the one place that counts
the retirement and tells the **Pending Tunnel Claim**'s holder. Its lifecycle is one
table (ADR-0091 "Attempt lifecycle"): *Introducing*, *Rendezvous*, *Held*,
*Opening*, then *Adopted*, *Retired* or *Abandoned* — the last when the claimant lets go
(its slot lapsed, or the callback landed first), which ends the attempt with no
retirement reported. One attempt per peer: a second trigger joins it. Every state has a
deadline, backed by the attempt's own 120 s run; an ending takes the hold and the dial
schedule with it; and a `0xA1` only re-arms a live attempt's dial, never starts one.
_Avoid_: rendezvous attempt (that is one schedule's try), punch session, introduction
(the coordinator's single act, which an attempt may make twice)

**Punch Expectation**:
What rmule expects back from an address it punched at, and which side dials. Keyed by **IP**, not by endpoint, because the port a peer's NAT mapped is exactly what a hint can get wrong — the `OP_HOLEPUNCH` that arrives *corrects* it, and rmule dials the source it observed rather than the one it was told. But an address is not a peer: two clients behind one CGNAT share it, so the entry is a **bounded set** of at most four `{target hash, role, nominal endpoint, since}`, keyed inside by the hash, oldest evicted and counted, aged out after the attempt's own budget. Attribution refuses to guess — one expectation takes the tunnel, several are told apart only by a unique nominal-port match, and anything else is attributed to **none** and counted, because a wrong `UserHash` is worse than none and the hello names the peer a few round trips later. A `0xA1` behind several Dialer expectations likewise dials the one its port names, or nothing: one unauthenticated datagram may not fan out into several dials. The side that asked for the introduction dials and the other accepts; without that asymmetry an rmule↔rmule pair would raise two tunnels on one pinhole. An unexpected punch is dropped in silence and counted, never answered.
_Avoid_: pending punch, punch session, dial queue

**Dial Schedule**:
What the **NAT-T Front** spends an attempt's 120 s budget on. `librqbit-utp` sends a dial's opener **once** and never retransmits it, so one long `connect()` is a wait on a datagram nothing will send again: each dial is bounded at 3 s and the attempt issues a *fresh* `connect()` instead — at once on a `0xA1` from the expected peer, every 5 s otherwise, with a fresh punch burst ahead of the cadence re-dial whenever the acting path's destination limiter allows one. Keyed by the **target**, not by its address, so two peers behind one CGNAT are two traversals; one dial in flight per target. The attempt ends at the budget with the ordinary `RendezvousFailure::Transport` retirement, saying how many openers it spent.
_Avoid_: dial retry loop, reconnect backoff, dial pool

**Held Burst**:
The requester's punch burst after a trusted **Endpoint Hint**, held for half the relay round trip it measured so both ends' bursts land together (ADR-0091, DCUtR's policy), then followed by a dial. The **NAT-T Front** releases it at its own deadline: its loop sleeps toward the earliest hold in the same `select!` as its inbox and its one-second tick, on its one task. A hold belongs to its **Traversal Attempt**: whatever ends the attempt (a **Tunnel** adopted, a retirement, a run gone idle) cancels it, and so does a close notice from the path it was aimed at — both by the peer once one is attributed, not by the literal endpoint the hint named, because a NAT may have remapped its port. A lone peer pending behind an address is attributed by the address alone, on any port; several are told apart only by the Tunnel's own hello, so both holds survive until it names one. A release therefore never dials a second Tunnel after the first has served (before that fix the tick released it 0–1 s late and dialed again, run `1790117113`).
_Avoid_: delayed punch, scheduled burst

**Prediction Plan**:
One introduced peer's **Port Prediction** at the **NAT-T Front** (ADR-0091's amendment), decided when `Introduced` arrives (or a **Held Burst** is released) from our **Own Mapping** in Address Learning and, where an attempt holds the candidate's advertised client-UDP port, the **Peer Mapping** veto. It fires its two attempts on the front's tick, each on a task of its own so the loop never awaits a paced burst, remembers the Fans it opened and the current **Probe Set**, and ends with the Tunnel (keeping the Fan socket that Tunnel rides), with its **Traversal Attempt**, or 120 s after the introduction. `None` in the front's wiring is the knob off, and then no plan ever exists.
_Avoid_: prediction session, port-guess job

**Punched Path**:
A UDP path a **Punch** opened and a **Tunnel** still uses. Its NAT mapping is implicit and lives by the router's idle timer, so two things hold it: a 60 s keepalive on an *idle* path (an empty `OP_HOLEPUNCH` — a busy Tunnel is its own keepalive), and one PCP `PEER` pin asked for when the path first works, whose refusal is ordinary and which a path never depends on.
Its close is not a frame the dialect has, so the Tunnel travels inside a **Punched Path Guard** whose drop tells the **NAT-T Front** — the only signal that fires for every reason a session ends. The front attributes the closed address to a **Punch Expectation** the same way it does an accepted Tunnel, so the peer's own **Held Burst** dies with it even when the close arrives on a port the NAT remapped away from the one that expectation named. The same sender the guard's drop reports through is also what the inbound triage's own adoption reports a confirmed hello back over: every adoption it grants names its peer to the front as `Risen::Identified`, which ends that peer's attempt and hold exactly as a closed path does.
_Avoid_: hole, pinhole (that is the IPv6 firewall opening ADR-0086 makes), session

**NAT Hint**:
A diagnostics-level fact that two fresh **Address Observation** tiers disagree about our address (server sees one, the gateway granted another, Kad reports a third) — the trace of double NAT, CGNAT or hairpin. Published, never resolved by overwriting.
_Avoid_: NAT type (a verdict this store does not make), error, warning

**Source Book**:
Where one download's sources live and who owns each (ADR-0090): one record per source,
known by its aliases — up to two endpoints, a `CallbackKey`, a **User Hash** — through one
index, and carrying exactly one stage: pooled in a lane, dialing, worker, callback pending
(with its road's deadlines) or remote-queued, so one owner holds it by construction; a
worker's stage holds the peer's **Peer Identity** (`rmule-peer` glossary) once its hello is
read, so the hello's facts end with that worker (ADR-0049). Its
one entry takes a **Source Sighting** and merges a held source rather than pooling it
twice; two records merge only on wire proof, never on a matching User Hash. It holds the
blocks — the **Reserved Range** check (against the sighting's **Informant**, `rmule-primitives`
glossary), the IP filter and address family it judges each half of a sighting by, the spent
names (a failed dial's endpoint, and every **Ask Name** of a source that said it lacks the
file), turned once a period at the brain's tick, and the **Distrusted Peer**s — the
attachments that ride each record (its queue standing, its **Advertised Parts** and its
**Source Ask Clock** facts among them), and picks the next dial in lane order. **Download State** maps its outcomes to
decisions and keeps the slots' numbers and the part scheduler.
_Avoid_: source list (aMule's `m_SrcList` is only the pool), ledger (the Activity ledger,
NAT-T, credit and `SeedLedger` already are)

**Advertised Parts**:
The parts one source said it holds of this download's file — its latest `OP_FILESTATUS` to a worker or the status in a `0x91` ack — over the file's real parts (count `0` is every part; the phantom part is never read). A record-tier attachment of its **Source Book** record (ADR-0112): replaced by each status, gone with the record, never stored. A worker is handed a part from them only once its own probe answers: what an earlier connection or a merged-in record left is not that worker's word.
_Avoid_: availability, bitmap, file status, part picture (the download's own, ADR-0094)

**Part Frequency**:
Per part, how many **Source Book** records' **Advertised Parts** hold it — aMule's `m_SrcpartFrequency` — kept by the book on every write, merge and removal. The scheduler's only rarity input; very rare is at most `max(1, m × n / 100)` (ADR-0112).
_Avoid_: availability, source count

**Source Sighting**:
One channel's statement that a peer has the file, with the one road it names
(`rmule-primitives` glossary). Every channel — a server answer, a source exchange, a link,
a Kad source row, a peer that asked us about the file — hands the **Source Book** this one value.
_Avoid_: exchanged source, Kad source (each was one channel's copy)

**Distrusted Peer**:
A peer proven to have served a download's file bad data — the AICH recovery pinned corrupt blocks on it, or it alone sent a part that failed its hash. Keyed by **User Hash**, not address, and held for the download's life beside its durable record, so a resumed run starts from it: a source whose record names it is never pooled, and one reached without its hash is retired at its hello (ADR-0090 "Source ownership"). A per-file avoidance, not the core-wide, IP-keyed, expiring ban.
_Avoid_: banned peer (that is `BanStore`), blacklist, bad source

**Reask Routes**:
Where a reask reply (`0x91`/`0x92`/`0x93`, which names no file) goes when several downloads
pool one peer: each running download's reply sink, and the one `0x90` in flight per peer
client-UDP endpoint with the download that sent it. The reply reaches that download alone;
a second download's ping to the endpoint waits until the first is answered or lapses at
the 20 s lead; a reply nothing asked for drops (ADR-0107).
_Avoid_: reply fan-out (a reply reaches the one download that asked)

**Source Ask Budget**:
How many `OP_GETSOURCES` the **Download Set** may put on one server session: fifteen in
any five minutes, counted per **Session Generation** — aMule's one frame and its spacing.
Lookups for different files otherwise run side by side; a lookup the budget holds waits,
stoppable, and its bound starts once admitted (ADR-0107).
_Avoid_: lookup lock, lookup queue (nothing takes turns)

**Source Ask Clock**:
One download's facts, per peer, of when it last asked for sources (stamped when the
session sends the ask), when the peer answered, what its hello said about source exchange
and whether its last advertisement was complete, plus the file's own last-answered time:
aMule's `IsSourceRequestAllowed`, kept per (peer, download). The peer's facts ride its
**Source Book** record and are read under its **Ask Names**. With the file's source need
they decide whether a connection carries a source-exchange ask, and whether a pooled
source's UDP reask gives way to the TCP ask (ADR-0108).
_Avoid_: SX throttle (that is the serving side's)

**Ask Name**:
One of the names the **Source Ask Clock** knows a peer by: its **Source Book** record's
aliases — its TCP endpoint, a Low-ID callback's `(server, low_id)` when the server that
assigned the id is known — and the User Hash the record knows. A stamp lands on the record; a read merges what the run kept under each of its
names and every live record sharing its User Hash, so a peer is the same peer to the gate
across connections — aMule's `FindMatchingClient` (ADR-0108).
_Avoid_: peer key (several names, one peer)

**Source Seeds**:
The peers one download keeps in the store so a restart can dial them before asking anyone —
aMule's `.seeds` file, kept for every running download. Up to `Remember peers` (1–255,
default 10) directly dialable peers, keyed `(DownloadId, endpoint)` with the User Hash and
crypt stance when known — a `required` policy cannot dial a peer whose stance is unknown — ranked: sent bytes this run, then granted a queue rank, then merely known; newest first
within each. Written every 10 minutes and at **Quit**; at attach a restored run puts the ones
under 24 hours old ahead of every other candidate and dials them before any lookup, its
workers marked `remembered`. Deleted with the download's completion, cancel or clear
(ADR-0109).
_Avoid_: seed (alone — a seed is also a complete uploader in the wider P2P world), saved sources

**Dial End**:
Why one source's dial ended before its hello — a policy refusal, never dialed, or lost before
the peer identified — kept on the download's diagnostics row per peer with when and whether
it was a seed. It outlives the slot's next peer and the run's end, leaves when a slot dials
that peer again, is cleared when a run starts, and the row keeps the newest 64 (ADR-0110).
_Avoid_: dial failure (`DialFailure` is a server dial's)

**Remote-Queued Pool**:
The **Source Book** records in their RemoteQueued stage, each holding its queue standing at a remote uploader **without a connection**: the rank, the UDP contact and peer-UDP crypt target the identity it queued under stated, the reask clock and its one-ping latch (ADR-0057, ADR-0090). Entered when a worker on the uploader's queue — its upload request out, ranked or not yet — hangs up, or when a worker's **Advertised Parts** hold no part we lack (rank 0, the no-needed-parts mark, ADR-0112); kept alive by the reask heartbeat the brain's tick runs while we are connected to a server or Kad (UDP ping first — a called-back source's at the address it called in from — TCP full ask as fallback, a called-back source's by its callback road); left on grant (the uploader dials back), file-not-found (which spends it), the TCP full ask, or — queue-full or holding no part we lack, while the file holds 80 % of aMule's default source limit — one of the book's purges. Queue standing is a fact about the remote peer, not about a socket.
_Avoid_: waiting workers (no worker exists while pooled), source cache, reconnect list, pool (as a list apart from the book)

**Slotless Standby**:
A download worker that sent `OP_CANCELTRANSFER` because the scheduler had no part to assign it, surrendered its remote upload slot, and stays connected awaiting a released part — at which point it re-runs the full ask cycle from the start-upload request (ADR-0056). Distinct from an idle worker, which still holds its granted slot.
_Avoid_: parked worker, dormant connection, cancelled worker (the transfer is cancelled, not the worker)

**Had Set**:
The durable set of file hashes that were in the **Shared File Registry** and whose file has since left the disk, each with the name it last had and when it left (ADR-0105). A row joins it in the step that removes the row; a share of the same content, from any source, takes the hash out in the step that stores the row, and nothing else does. A renamed or copied file moves its row and never passes through it. It shares nothing and answers nothing on the wire; it exists so the operator can be told they once had a file.
_Avoid_: history, known.met, deleted files

**Hash Trust Rule**:
A stored file hash is trusted, unread, while the file's path, size and modification time match its **Shared File Registry** row or its **Spare Copy** record (ADR-0102). A file at a new path is trusted too when its **File Identity**, size and modification time match a record's: a rename within one filesystem is not read again. A file that differs on size or time is a new file.
_Avoid_: hash cache, fingerprint, verification

**Spare Copy**:
A file under the download directory whose content is already shared from another path: hashed once, recorded durably by its path with its size, modification time and **File Identity**, and trusted unread after that (ADR-0104, "What the scan remembers"). It shares nothing and answers nothing on the wire. It exists only beside a **Shared File Registry** row of its content, and a row whose file vanishes or changes moves to it without a read.
_Avoid_: duplicate, alias, second share

**Whereabouts**:
What one **Download Directory Scan** holds while it looks for where a gone row's content lies (ADR-0106, "The registry against the disk"): the rows it found gone and keeps in the registry while a file of their size, settling or waiting to be hashed, may turn out to be their content, and the **Spare Copies** it can move a row to without a read. Kept across the pass and every round of the watch. A held row is withheld from the moment it is held; a row that finds its content moves, and one that finds none joins the **Had Set**. The module and the type share the name because they are one thing: no existing term covers held rows and spare copies together.
_Avoid_: move tracker, rename detector, lost-and-found

**File Identity**:
A file's device, inode number and birth time, read from its metadata only on a filesystem whose identities are stable (APFS, HFS+, ext4, btrfs, XFS) and only when a birth time exists (ADR-0104). It is the path-independent evidence that lets the **Hash Trust Rule** carry a hash across a rename. It is never enough alone: size and modification time must match too.
_Avoid_: inode, file id, fingerprint

**eD2k Identity**:
An eD2k file's hash plus its exact size — the pair a file is known by, since a hash alone does not decide part geometry. The **File History**, the Known-File Marks and the duplicate rule all key on it. Not the **File Identity** of a file on disk (device, inode, birth time).
_Avoid_: file key, hash-and-size pair

**Download Directory Scan**:
The activity that keeps the **Shared File Registry** equal to what lies under one directory of the **Shared Directory List** — walked at start, watched afterwards, hashed one file at a time across every directory (ADR-0102). One per scanned directory; the name is the first directory it served, the download directory.
_Avoid_: library scan, indexer, import

**Shared Directory List**:
The directories whose contents rmule offers (ADR-0101, "Shared Directories"): the download directory first, from the Core Settings, never stored and never removable, and guarded like an add whenever core names it — refused, it is listed, never scanned, and covers nothing; then each directory the operator added and confirmed, keyed by its canonical path, stored in order of adding, and guarded again where its path leads at attach and when it appears after missing — refused, it stays listed, never scanned, covering nothing. A file under a refused entry, and under no passing entry nearer to it, is a **Withheld Row** however readable. Always recursive. An entry under another is covered by it; a listed directory that is not there stays listed, missing, its files **Withheld Rows**.
_Avoid_: shared folders, library, share roots

**Set-Aside Row**:
A registry row a removed **Shared Directory List** entry took out, or a **Spare Copy** under it, kept durably by its path with its stamp, identity, content and part hash set (ADR-0101, "Shared Directories"). It shares nothing and answers nothing on the wire; a pass that finds the same path, size and modification time takes its entry instead of reading the file, so adding the directory again reads nothing.
_Avoid_: hash cache, tombstone, dormant row

**Withheld Row**:
A **Shared File Registry** row kept, with its hash set, while nothing is offered for it, because its file is not readable now: its folder is missing, it cannot be opened or read, or it is gone or changed and awaits a ruling (ADR-0106, "The registry against the disk"); or because it lies under a **Shared Directory List** entry the guards refuse (ADR-0101). Held in memory with its reason and when rmule noticed; a withheld row is in no serve snapshot, no announce, no Kad publication and not in the **File-Known Predicate**'s shared half. It is offered again once a look finds it readable, unless it lies under a refused entry.
_Avoid_: hidden, disabled, offline file

**Registry Check**:
The activity that holds every **Shared File Registry** row to the disk outside a live, watched **Download Directory Scan**: it looks at every row at start, watches the parent folder of each row it rules on, looks again at each **Withheld Row** every minute, and looks at a row whose serve read failed (ADR-0106). The offered rows are what it last found readable.
_Avoid_: validator, fsck, poller

**File History**:
What rmule's own records say about files the operator has already met: every **Shared File Registry** entry with where it lies, every file of the **Had Set**, and every download cancelled before it completed. Read on request (`DumpFileHistory`) from its owners, never kept as a seam of its own; a front end draws its **Known-File Marks** from it and the live download edges (ADR-0100). A part whose read failed is named in the answer, never shown as empty.
_Avoid_: known files (the File-Known Predicate is a different question), library, download history

**Shared File Registry**:
The durable source of truth for what we serve: the files the **Download Directory Scan** of each shared directory hashed and auto-registered completed downloads, less what `UnshareFile` withdrew — each row carrying the modification time the **Hash Trust Rule** compares. The serve side answers probes and hash-set requests against its offered rows (every row but a **Withheld Row**) and announces them via `OP_OFFERFILES`. Every entry a read answers with is whole — the row *and* its ED2K part hash set — so a serve state seeded from the registry answers a hash-set probe for a file shared before the last restart. A new abstraction — not a widening of `DownloadRepository`. A download's offer is a **Partial Share**, never a row.
_Avoid_: shared folder, library, content index

**Served Download**:
What a download larger than one part — queued, running, completing or paused — tells the serve side, keyed by file hash (ADR-0113): size, name, both paths and which one holds the bytes, the part hash set once whole, its **Verified Range**, its **Part File Identity**, its source-exchange pool, and an inbox for askers. Written by one holder at a time, under a lease: the run, then its completion move, and the core actor while the download is queued or paused; the actor ends it. Answers probes from the row's start.
_Avoid_: downloading slot, partial entry

**Partial Share**:
A **Served Download** that is offered: it has a verified part, holds the whole hash set, and its destination is not refused. It stays offered while its download is paused (ADR-0113). Announced as incomplete, published as a Kad source, granted slots. Never a registry row, a keyword or an AICH source.
_Avoid_: partial file share, incomplete share

**Verified Range**:
The parts whose recorded part hash equals the whole set's. These are the only bytes the serve side reads from a part file; a request outside it ends the slot.
_Avoid_: downloaded range, gap list

**Part File Identity**:
What a read of a **Served Download**'s part file is checked against before it reads (ADR-0113): the file key (device and inode, on Windows volume serial number and file index), the length and the modification time, taken from the **Held Part File** handle at pause or from the handle the **Offer Check** read through. The key is always compared, the length and time only while no run writes the file; a mismatch sends nothing and empties the **Verified Range**. Kept in memory only.
_Avoid_: part file fingerprint, stored identity

**Offer Check**:
The core actor's re-read of every recorded part of a queued or paused download after a restart, hashed against its record, before it is offered again (ADR-0113): Resume's own revalidation, with Resume's effect, run on the blocking pool behind the scans, one download at a time. A Resume stops it and the run's own check takes over. Each check applied is said as `OfferChecked`, with the bytes read and how long the read took.
_Avoid_: share recheck, Registry Check (that one is for registry rows)

**Share Totals**:
What the serve activity has done for each file across every run — upload requests drawn, slots granted, bytes served — aMule's all-time `CFileStatistic` figures from `known.met`. Kept on the Durable Store beside the **Shared File Registry**'s row, keyed by the same file hash but not inside it: they outlive an unshare, a rename and a file that left and came back, as aMule's known list does, and a share of the same content picks them up. Written as absolute figures once a minute and at **Quit**, so a crash loses at most a minute of counting.
_Avoid_: known.met, statistics (the whole Statistics view), lifetime counters

**Data Directory**:
Where the **Durable Store** and the data files beside it live, resolved by the one rule every front end uses: `--data-dir`, then `RMULE_DATA`, then `$XDG_DATA_HOME/rmule` or `$HOME/.local/share/rmule` on Unix and `%LOCALAPPDATA%\rmule` on Windows (local, not roaming: part files run to gigabytes). Core reads no environment; the front end hands in how a variable is read.
_Avoid_: profile dir, workspace, config dir

**Temp Directory**:
The Core Setting naming where new downloads keep their part files (ADR-0115). Defaults to `Temp` in the **Data Directory**; never the download directory, a shared directory, inside one, or holding one. A download keeps the part path placed at its start when the setting changes.
_Avoid_: incoming, cache dir

**Durable Store**:
The single on-disk home of every durable seam — download records, the Shared File Registry and its Had Set, the credit ledger, identities and the server list — opened once per process and owned by core. Seams are views over it, not files of their own; a change that must hold across seams can be one atomic step.
_Avoid_: database file (there is one, but callers see seams), config file, cache

**Run Log**:
The file in the **Data Directory** (`rmule.log`) a front end's run appends core's **records** to (ADR-0075, `run_log`) — always on in the TUI, whose terminal is the alternate screen, because a defect met in an ordinary session must leave evidence, and opened by `rmule-cli` for a command that runs a core; both read its level from the one *Full run log* preference (`run_log::PREFERENCE_KEY`). A front end writes the records of the events it receives; core writes the **Reachability Trail** itself. A record is an event code plus typed fields, each field added by what it is (own address, peer address, file name, file hash, port, count, code); the field's **kind** decides, in one place, the lowest level that admits it, and every event and reason projects into records beside its type. It is written at one of two **levels**: **lean** by default (reachability evidence — own addresses, ports, the port mapping, the server endpoint, login steps, verdicts — and codes, no peer address, file name, path or hash) or **full** by the preference *Full run log*, which adds the rest and also lets free-form `tracing` lines through. Search text and File History paths are never written. Bounded: at 16 MiB it is moved aside as the single predecessor `rmule.log.1`. `RMULE_LOG` is the filter; the default level is `info`. Even lean names the operator's own addresses, so it is the operator's to share; full names peers and files.
_Avoid_: debug log, trace file, console, verbose log

**Reachability Trail**:
Core's own reachability levels written into the **Run Log** as they move (ADR-0075's first path, `run_log::trail`): the connected server and the server list's health edges and grant words, the **Port Mapping** rows, the **Own Address** rows, the Kad verdicts with our own **Buddy**'s state, and the NAT-T **Own Mapping**. Each level is read from its one owner when that owner's change notice wakes — the server half of the diagnostics level, the mapping runtime's published rows, the **Own Address Generation** and **Bind Generation** (and the next lapse the store names), the **Reach Generation**, the **Buddy Snapshot** and the **Recruit Status** — and written only when its records differ from the ones last written: a level that moved is its record once, a wake that moved nothing is none. Every field is ours or the operator's own list's, so a level's records read the same at both levels; it is written at lean. It starts with the actor's prologue, writing every level once, and stops as Quit begins.
_Avoid_: snapshot diff, reach log, state dump

**Part Path Slot**:
A download row's `.part` file, held, or released once a terminal row gave the path up to a new row so that the store's one-writer-per-`.part` rule lets the new row in. A released slot is not a path; stored, it is the stand-in text `"\0released:{key}"`, which the row's unique index sees as a value no other row can hold.
_Avoid_: part path string, tombstone

**Download File Path**:
Where a download's bytes lie now: its `.part` until it completes, the finished file after (ADR-0114). Read from the stored record by one accessor, never from a released **Part Path Slot**; carried as `file_path` on `DownloadQueued` and `DownloadRecovered`, moved by `DownloadCompleted`'s `final_path`. A front end hands it on and never composes one.
_Avoid_: part path (half of it), download location

**Content Store**:
The byte I/O abstraction. Download writes verified parts into a `.part` file and promotes it to `final_path`; serve reads ranges (`read_range`) from shared files, and from a download's part file inside its **Verified Range** through a handle checked against its **Part File Identity** (`read_checked`). One abstraction, both directions.
_Avoid_: storage backend, file manager

**Held Part File**:
The one handle a download's run holds on its `.part` file from its first act to finalize (ADR-0094, "The run holds its part file"). Every verified part is written through it, never by path. Before each part, at finalize, and each second while the run waits (for a connection, or for sources with nothing in flight) the run compares the path's device and inode (on Windows its volume serial number and file index) with the handle's, and the handle's length with the recorded parts' end, and reports what it found — `Gone`, `Replaced` or `Truncated` — as `PartFileLost`, with what it cost — or, when the store cannot say which parts were lost, with no count, and the download fails as a store failure. The part file is the operator's to delete; rmule never recreates it behind them. It carries the sparse flag on Windows; each write punches its **Extension Gap** and reads **Allocated Bytes** (ADR-0111).
_Avoid_: part file lock (nothing is locked), reopen

**Sparse Part File**:
A download's `.part` under ADR-0111: positional, never pre-sized, holding only hash-verified bytes. Where the **Hole Verdict** is `HoldsHoles` it occupies only the bytes written plus slack. Its length is the end of the highest part written.
_Avoid_: temp file, preallocated file

**Extension Gap**:
For a write at `offset` into a file whose length was `end`, the range `[end, offset)`. The only range a write can make a filesystem zero-fill; punched after the write, aligned inward to 4 KiB.
_Avoid_: hole, gap

**Allocated Bytes**:
What the filesystem reserved for the part file, read on the held handle at the hold and after each write; published as `DownloadDiagnostics::allocated_bytes`. A storage reading, not a **Transfer Byte Counter**: it can fall and can exceed the file's length. Shown only in the Transfers details modal's On disk row.
_Avoid_: disk usage, sparseness

**Hole Probe**:
The run's one measurement when it first holds its part file: a dot-prefixed probe file beside the part, written through the same write and punch, `fsync`ed, read, then deleted (ADR-0111).
_Avoid_: filesystem detection

**Hole Verdict**:
`HoldsHoles`, `HoleLess`, or `Unknown` with the OS error kind, from the **Hole Probe**. Published as `DownloadDiagnostics::hole_verdict`; a `HoleLess` run also sends `HoleLessDestination` once. Never a scheduling input or a reason to refuse.
_Avoid_: sparse support

**Hole-less Destination**:
A directory whose **Hole Verdict** is `HoleLess`; `DownloadEvent::HoleLessDestination`, sent once per run whose part file lies in one, names it (ADR-0111).
_Avoid_: non-sparse disk

**Completion Move**:
A run's last step, after its last verified part (ADR-0115): the part file checked against the file hash, the destination named — the row's final path or its **Free Name** — and stored with `Completing` before anything moves, then a rename, waiting while a program holds the file, or the **Completion Copy** across volumes; with the finished file in place the core actor writes its registry row, and only then is the part file deleted and `Completed` stored. Each step that waits or copies is told as `DownloadEvent::Completing`.
_Avoid_: completion (alone), rename (one of its steps)

**Free Name**:
The numbered `stem (n).ext` beside a name that is taken, `n` counting from one, the first for which nothing stands (ADR-0115, `free_name`). A placement and a **Completion Move** choose by the one rule, and a move numbers from the name its download was placed under, every time, as aMule does, so numbered names never stack.
_Avoid_: unique name, collision suffix

**Completing**:
The durable lifecycle between the last verified part and the finished file in place (ADR-0115): renaming, waiting for a program to release the file, or copying across volumes. Attach resumes the move; a Pause or Cancel stops it until the file is in place and is refused after.
_Avoid_: finalizing

**Completion Copy**:
The move across volumes: a dot-prefixed copy beside the destination, hashed as it is read, synced, then renamed into place; one copy at a time (ADR-0115).
_Avoid_: backup

**Completion Gate**:
The one instant a run's finished file lands in place, shared by the run and the core actor (ADR-0115): a Pause or Cancel before it closes the gate and the run lands nothing; after it the stop is refused (`DownloadCompleting`). Held settling only across a rename, and across the look a recovered row's run takes at the disk, so a stop that meets it waits no longer than that.
_Avoid_: lock, commit flag

**Download Metadata**:
The name + exact byte size core recorded for one download, with the origin that says where it learned them (ADR-0078). Stored with the durable record at creation, backfilled from the canonical link for pre-v2 rows, and reported on both surfaces — the `DownloadQueued` / `DownloadRecovered` edge and the `DownloadDiagnostics` level row — so a consumer never re-derives a name from a link or a size from a part count. Name bytes stay wire-faithful (`Ed2kText`, ADR-0019); the origin is a fact about core's own knowledge, never a caller's claim about a UI (there is no "from search" origin).
_Avoid_: file info, display name, file details

**Streaming Priority**:
Downloads whose **Download Metadata** name is in aMule's video, audio or archive table (`is_streaming_priority()`); aMule's is video and archive behind `PreviewPrio` (`PartFile.cpp:1941-1945`), rmule adds audio, no switch (ADR-0112).
_Avoid_: preview priority, sequential flag

**Previewable**:
A download whose name is in aMule's video or audio table (`is_previewable()`), read by core off the raw bytes, never re-derived (ADR-0112, ADR-0114).
_Avoid_: media file, playable

**Download State**:
The sans-I/O scheduling brain for one download (`download/state.rs`). It owns every channel-free decision — which part a peer works, how cross-peer blocks assemble (ADR-0029), when a raced part completes and clears its losers (ADR-0026), which candidate backfills a retired worker (ADR-0030), when a pooled source is reasked and when a callback road lapses — and returns an ordered `Vec<Decision>` the async runner *enacts* (the only async surface). Time is an argument: each entry takes `now`, `on_tick(now)` runs the reask sweep, turns the spent period and expires deadlines, and `next_wake()` names when the runner wakes it next. Persistence is a fallible effect, so it round-trips through `on_persist_result`. Touching no socket, clock, store, or channel is what makes the racing / resume / retire-all / backfill / reask behaviours assertable as plain decision sequences instead of only through a live Tokio actor.
_Avoid_: download manager, actor, scheduler (the `DownloadScheduler` is one of the bags it owns)

**Preview Band**:
aMule's head-and-tail set (`PartFile.cpp:1958-1972`): part `0`, the last, and the last-but-one when the last part's length plus one is below `PARTSIZE / 3`. Only for **Streaming Priority**; ranks below a very rare part, above the **Streaming Window**; no latch (ADR-0112).
_Avoid_: first and last chunks, preview parts

**Streaming Window**:
`[anchor, anchor + N)`, the lowest unverified part and `CoreConfig::streaming_window_parts` (default 8, `0` none), fetched in order by a **Streaming Priority** download; recomputed per assignment (ADR-0112).
_Avoid_: sequential download, buffer

**Serve State**:
The sans-I/O serving brain, the serve-side mirror of **Download State**: it owns every
clock-free serve decision — probe/status/hash-set answers from a **Shared File
Registry** snapshot and its copy of the **Served Downloads** (a registry row wins), slot
admission via the **Upload Slot Queue** it contains, AICH
tree building from round-tripped byte reads, credit recording, and **Secured
Identity** binding — and returns an ordered `Vec<ServeDecision>` that the `ServeTask`
enacts (sockets, registry snapshot refreshes, ledger lock, `ContentFileStore` reads).
Byte reads are fallible effects that round-trip through `on_read_result`, the
read-side twin of `on_persist_result`. Explicit `Instant` parameters only (the
**Upload Slot Queue** contract); no clock, socket, store, or channel.
_Avoid_: serve manager, upload scheduler (the queue is one bag it owns), handle_serve_event (the retired I/O-interleaved shape)

**Kad Pump State**:
The sans-I/O brain of the Kad pump (`KadPumpState`, `adapters/kad_runtime/pump_state.rs`),
the Kad-side mirror of **Download State** and **Serve State**. Every input is handed in
with an explicit `now` (ADR-0043): the core's commands (each with the sources sampled as it arrived),
the node's events, the 30 s recruit tick, samples of
the sources it reads taken when they move — **Self Reach** on a **Reach Generation**,
**Address Learning** on an **Own Address Generation**, the **Obfuscation Policy** on its
live change, the **Buddy Snapshot** — and the answers to its own effects: whether a node command landed, what the
open-node buddy service decided, room again in the node's inbox, and the **Firewalled Front**'s verdict on a buddy it was asked to adopt. It
holds the ADR-0061 recruit rule: a pure decision over the Buddy Snapshot, Self Reach and its own recheck
clock, with its own pacing stamp and walk-in-flight flag, published as the **Recruit Status**. It holds who
rides each keyword walk (ADR-0062) and who waits on each Callback Walk, as addresses it never writes to.
Everything leaves as an effect the pump's driver carries out:
node commands, source answers and each search's rows and facts, a Callback Walk's retirement, Address Learning writes, bans, the Kad
verdicts and the diagnostics it writes, the `AdoptBuddy` command to the Firewalled Front and its own
Recruit Status, and the dial-back and buddy-service spawns. One reconciler inside works out the whole desired node state — the
TCP level, own IPv4, **Extern Kad Port**, **Publish Connect Options**, publish posture,
the datagram crypt and the **Advertised IPv6** — after every input and commands only what the node does not already hold, so no input
can forget to restate one. The core's commands become node commands told one at a time, in the order sent, once the
node holds every level; one the node's full inbox turns away waits in the brain, which then takes no further core
command, so the core's commands wait in the pump's own bounded channel and nothing the pump took is lost. The driver
(`node/pump.rs`) owns the select loop, the `KadNetHandle` and the channels, never waits for inbox room while it holds
the loop — it waits for room beside the node's events — and decides nothing.
_Avoid_: Kad state (the **Kad State** level; `rmule-kad`'s node has its own), Kad manager, feed (it holds one desired node state, not a cache per level)

**Transfer Byte Counters**:
The monotonic payload totals core publishes on its `DiagnosticsSnapshot` (ADR-0077): per-download `received_bytes`, per-upload-peer `bytes_sent`, and the process-lifetime `SessionCounters`. Facts only — running totals of payload that crossed core's wire boundary, counted where a block is delivered (download runner) or handed to a connection writer (serve enactor). Core derives nothing from a clock, so a *rate* is always the consumer's own differencing of two snapshots (ADR-0069 dataflow). The per-transfer rows retire with their transfer; the session totals never decrease.
_Avoid_: statistics, throughput, speed, bandwidth (all imply a time window core does not own)

**Trusted AICH Root**:
The **AICH Root Hash** a download trusts as the anchor for **AICH Block Recovery**,
resolved per-download with precedence link `h=` > trusted-set vote > none. A single
peer's claimed root is never trusted: unlike the **ED2K Part Hash Set** (whose hashes
re-hash to the **ED2K File Hash**), the AICH root has no self-verifying anchor, so with
no link `h=` rmule commits a root only when enough distinct peers report the same one.
With no trusted root, recovery is disabled and a failed part falls back to retire-all.
_Avoid_: AICH root hash (that is the raw value; this is the per-download trust decision), verification authority (that is the MD4 identity authority; AICH is orthogonal)

**AICH Block Recovery**:
The **Download State** failure-path upgrade (ADR-0038, amending ADR-0029): when a part
fails MD4 verification and a **Trusted AICH Root** exists, rmule SHA-1s each 180 KiB
block, localizes the corrupt one(s), retires only the contributing peer(s) by
*per-block provenance*, and refetches only those blocks — instead of retiring every
contributor. The contiguous-prefix *build phase* stays as ADR-0029; a *repair phase*
turns the completed-but-failed buffer into a block-set with holes punched where AICH
found corruption.
_Avoid_: retire-all (that is the no-root fallback), AICH verification (MD4 is verification; this is recovery)

**Peer Reach**:
The one module that reaches a peer (ADR-0061, ADR-0091), over handles the core already shares: **Self Reach**, the client-UDP send half, the **NAT-T Front**'s command half, the Kad pump's and the event bus. Its one call, `reach(peer, retire)`, reads the **Route Position**, asks the route tree for the road, carries it out — a direct `0x95`, a buddy `0x52` or its **Callback Walk**, or rung 1 handed to the NAT-T Front whole — and reports the road taken. Both callers end in it: an operator's `ReachPeer` (nothing to retire) and a download's Low-ID candidate (its **Pending Callback**, whose road the brain already chose and whose retire channel hears at once when the road never opens).
_Avoid_: reach arm (the actor's arms are one call each into this), enactment helpers

**Low-ID Callback**:
The mechanism (ADR-0039) that makes a **Low-ID** source usable: rmule cannot dial it,
so rmule asks the connected server (`OP_CALLBACKREQUEST`) to tell that peer to dial
rmule instead. The peer arrives on the inbound listener and rmule downloads from it. A
Low-ID source is callback-able only via the server that assigned its id, so the callback
covers connected-server sources only; a Low-ID source discovered over server UDP is not one.
_Avoid_: reverse connect (that is the generic term; this is the eD2k server-relayed form), Kad callback (a different transport, parked)

**Adopted Inbound Worker**:
A download worker built from a connection that *dialed in* (a callback'd Low-ID peer)
rather than one rmule dialed out. The worker body is identical (ADR-0031's session is
bidirectional); only construction differs — adoption skips dial + the outbound hello
and enters the requester flow directly. The core actor routes a matched inbound
connection here at accept time; unmatched inbound connections go to the serve path as
before.
_Avoid_: inbound peer (that is any accepted connection; this is one routed to *download*), dialed worker (the opposite construction)

**Served Link**:
An accepted connection that took the serve road, filed (`SharedServedLinks`) under the
address a dial would reach its peer at: the link's own address with the hello's listen port,
where the peer is a source. A download about to dial that address joins the link instead of
dialing (ADR-0107, "One peer, one link"): its requests go out on the link and the link's
requester events come back to it, as aMule asks a client over the socket it already holds.
The link lives while its serve side or its download holds it, takes one download at a time,
and is taken again by a later one; a newer link of the same peer replaces its filing.
_Avoid_: shared connection (every link is bidirectional; this is the accepted one a download rides), second link

**Callback Capability**:
Our own half of the **Low-ID Admission** — aMule's `CanDoCallback`: whether we
may ask a candidate to dial us back. It holds when the inbound listener is bound *and* we
are reachable by either fact — the **Server High ID** or an open Kad TCP verdict — with one
carve-out: while Low-ID on our server but Kad-open, never for a candidate on that server. So
it is asked *of a candidate*. A server relays a callback for us only on the Server High ID.
It is **Self Reach**'s answer, given the listener — the actor ledger's own
handle for whichever serve activity is current, `SharedServeListener`. The
download runner asks it at start, on every **Reach Generation** and on its tick (for the
listener), and hands **Download State** a new sample when it moves; a serve started or stopped after the
download's spawn lands the same way. A flip retires no callback already asked for — only
the next admission reads it. Where it does not hold, a Low-ID candidate is left to the other half of the rule.
Distinct from a peer's advertised **Capability Block**.
_Avoid_: reachability (too broad), High-ID (that is one of the two facts)

**Low-ID Admission**:
The rule that decides whether a **Low-ID Candidate Record** is a usable source at all,
and which road it takes: *a callback, or a coordinator* — **Callback Capability** holds,
or the candidate's own facts admit a **Rendezvous Coordinator** (on our server, or NAT-T
plus a **Buddy**). Among callbacks the candidate's own **Direct UDP Callback** goes
first (its row's own type-6 verdict plus a Kad UDP endpoint — never bit 3 alone, a type-3/5
**Buddy** row falls to its buddy even with bit 3 set), then a
server relay, then its **Buddy Callback** — aMule's `TryToConnect` order.
A candidate learned from
a **Kad source row** is in no server's namespace, so the server-relay half never applies
to it however capable rmule is: its own direct invitation or its buddy's is its only
road. It names the road too: any callback road holds a slot for the relay and may fall
to a punch twelve seconds later; the punch road asks for no callback and falls *on
admission*, because a LowID↔LowID pair has no silence to measure (ADR-0091 rung 1). Stated once and
read by both the brain's slot fill and the runner's pre-fleet `NoUsableSources` check.
Whether a coordinator is *available* is not asked here — that is the route selector's,
against rmule's live position, and its refusal comes back as an `AttemptRetirement` on the
road's own key: on the callback road it retracts the claim, on the punch road it lapses the
candidate, because that road was the only one.
_Avoid_: callback capability (that is one half of it), reachable (that is about rmule,
not about the pair)

**Awaited Inbound**:
The one registry of the fact *a download is waiting for this peer to reach us*, whatever
road the peer takes (`AwaitedInbound`). A download holds one registration per pending
callback, as an `AwaitedInboundHandle`, and the registration carries both of the callback's
keys: the **Pending Callback**'s `(server, low id)` and the **Pending Tunnel Claim**'s User
Hash, with its dial-back flag. Either key reaches it. Inbound triage asks one question per
identified connection, giving how the connection came in (accepted, or a **Dialer Tunnel**
toward a named hash) and what its hello says (User Hash, server, low id). The answer is one
of three. *Adopt*: the registration is spent, both roads with it, under one lock. *Mismatch*:
a Dialer Tunnel's hello names somebody else, so the connection is closed and the claim stays
pending. *Unclaimed*: the connection takes the serve road. Dropping the handle releases both
keys at once, so however a callback ends (adopted, lapsed, or with its run) it cannot leave
one road behind to hand the download a second worker. Several downloads may wait on one key,
and the oldest is adopted first (ADR-0107).
_Avoid_: callback table, claim table

**Pending Callback**:
A held worker-slot state: a download took one of the **Low-ID Admission**'s two roads for
a candidate and awaits the inbound adoption — a relayed callback it emitted a
`RequestCallback` for, or, when no callback was possible, the **Tunnel** the punch it
asked for may raise. Cleared by adoption, released by a per-callback deadline on its
**Source Book** record, which
retires the candidate and frees the slot for the next one, or retired early when its road
never opened (the ask could not leave). `OP_CALLBACK_FAIL` carries no id, so it releases
nothing. Every one a download still holds ends with the download, however its run ends.
The **Awaited Inbound** registry files a pending callback under `(connected server, low id)`
because low-ids are unique only per server. It holds the **Low-ID Candidate Record** it was requested
for, and — when that record admits a **Rendezvous Coordinator** — a second deadline, the
**Callback Silence Fallback**.
_Avoid_: queued (that is the upload-side rank), pending source (the candidate pool term)

**Low-ID Candidate Record**:
Everything a download learned about a source it cannot dial: the Low ID, the server
namespace the id belongs to (`None` = the connected server, which is also the
`on_our_server` fact the route tree reads), and — as the channel that named it carried
them — the target's **User Hash**, its **Buddy** contact, its NAT-T bit, its Kad UDP
endpoint and its IPv6 — plus whether it came from a **Kad source row** at all, which is
what says no server can be asked to relay for it. A Kad type-3/5 row is the one channel
that names a **Buddy**, and (only from an eMuleAI publisher) the one that can name the
NAT-T bit. Every field is `None`/`false` unless the bytes said otherwise.
It is keyed by its namespace, its id and the port that tells two apart: a server-assigned
id by its server, a Kad row by its observed address and Kad UDP port (ADR-0090). A source
learned twice under one key merges, newer non-`None` winning and a silent channel
withdrawing nothing; a sighting naming another User Hash is another owner of the key and
replaces the record whole. It exists because a Low-ID candidate never speaks to rmule until its callback
works, so facts not kept at discovery are gone when rung 1 needs them.
_Avoid_: candidate (that is the High-ID pool's unqualified term), peer facts (that is
`PeerReach`, the public record this projects into)

**Callback Silence Fallback**:
ADR-0091's 12 s deadline, set on the callback's record by the download brain *beside*
ADR-0039's slot-release one whenever the candidate's own facts admit a **Rendezvous Coordinator**. On its fire
the callback's candidate is handed to the one route selector as a NAT-T attempt, and
nothing is retracted: the slot stays held, the slot-release deadline stays armed, and
whichever connection arrives first — the relayed callback or the punched **Tunnel** —
takes the slot.
_Avoid_: callback timeout (that is the 30 s slot-release deadline), retry (nothing is
re-requested; a second route is attempted beside the first)

**Pending Tunnel Claim**:
What a download registers when it falls to NAT traversal — on its **Callback Silence
Fallback**, or on admission when no callback was possible — so the **Dialer Tunnel** the
punch may raise comes back to *it* instead of taking the serve road (ADR-0091). The **Pending Callback**'s sibling with the only key a punch has — the
target's **User Hash** — filed in the same **Awaited Inbound** registration as that
callback, so an adoption down either road ends one pending callback and spends both roads. A
candidate no channel gave a User Hash claims nothing: there is nothing to file it under,
and nothing a hello could confirm. A claim is also released early, with a reason, when
the **Traversal Attempt** toward its target retires — the callback keeps its slot and
its 30 s, because only the punch road closed. Several downloads may claim one target, one claim each, and the
oldest takes a Tunnel (ADR-0107). Only the download that registered a claim retracts
it, and the last claimant's retraction tells the **NAT-T Front** the attempt is
*Abandoned*.
_Avoid_: pending callback (that is the server-relayed road, keyed by `(server, low id)`),
reservation (nothing is held for it; the claim is consulted, never waited on)

**Direct UDP Callback**:
A download's road straight to a Kad-sourced candidate, no server or **Buddy** involved
(ADR-0061 route 2): a plaintext `0x95 OP_DIRECTCALLBACKREQ` to the
candidate's own Kad UDP endpoint, naming our TCP port and User Hash, and the candidate
dials us back. Taken ahead of every other callback road when we are callback-capable and
the candidate's row is its own Kad **Direct-Callback Source Row** verdict (type 6)
plus a Kad UDP endpoint — matching aMule's `TryToConnect`, which tries this before
the server relay (`BaseClient.cpp:2043`, ahead of `:2114`), and aMule's own gate: it keeps
the observed connect IP for the `0x95` only on a type-6 row (`DownloadQueue.cpp:1797`), so
a type-3/5 **Buddy** row stating the same `SupportsDirectUDPCallback` bit still falls to
its buddy — the bit alone is the advert, not the road's fact. Governed like
the other callback roads: the 30 s slot release, and the 12 s **Callback Silence
Fallback** only for a candidate whose facts admit a coordinator. Claimed the same way a
**Buddy Callback** is — by the candidate's User Hash, since a Kad candidate's
`CallbackKey` is a synthetic id no hello reports — so a retiring punch beside it leaves
the **Dial-Back Claim** standing too. A Kad **Direct-Callback Source Row** names a
candidate for this road alone — it carries no buddy — so a downloader that cannot be
called back has no road to it, as aMule drops the row when it is firewalled itself.
_Avoid_: `ReachPeer`'s direct-UDP route (the ordinary, non-download selector path through
`select_callback_route`, which this download road bypasses — the admission rule has
already decided it)

**Buddy Callback**:
A download's road to a firewalled Kad source through that source's **Buddy** (ADR-0061 route 4):
a plaintext `0x52 KADEMLIA_CALLBACK_REQ` to the buddy, which relays
it as `OP_CALLBACK` over the link it holds, and the source dials us back. Taken when we are
callback-capable and the candidate names a buddy and a User Hash, ahead of the punch and
behind the candidate's own **Direct UDP Callback** when its row is a type-6 verdict too
(never for a plain type-3/5 row's bit 3 alone) — the order
aMule's `TryToConnect` uses — so an aMule buddy row, which states no NAT-T and no
direct-callback bit, is reachable at all. Governed like the server
callback: the 30 s slot release, and the 12 s **Callback Silence Fallback** only for a
candidate whose facts admit a coordinator. When the 30 s lapse finds a known-endpoint buddy
whose `TAG_BUDDYHASH` reads as a different ID the eMule way, one more `0x52` goes out under
that spelling and the 30 s is armed again before the road ends (source-derived).
A buddy the row named by ID alone is reached by
a **Callback Walk** (`rmule-kad`); a walk that reaches nobody retires the road
(`BuddyNotFound`, or `CallbackWalkBusy` when a walk toward that ID already runs) and the
candidate falls to the punch at once, or releases its slot when nothing can coordinate one.
With no Kad node running, neither the known-endpoint emit nor the walk can leave at all, and
the road retires the same way, at once, with `KadNotRunning` — matching aMule's
own `IsConnected()` check ahead of both (`BaseClient.cpp:2123-2130`); the **Direct UDP
Callback** road above carries no such check in aMule and is unaffected.
_Avoid_: buddy rendezvous (that is rung 1's punch through the buddy coordinator), server
callback (`0x1C`, keyed by `(server, low id)`)

**Dial-Back Claim**:
The **Pending Tunnel Claim** a **Buddy Callback** or a **Direct UDP Callback** registers:
the same entry, keyed by the target's User Hash,
that also admits a connection nothing here aimed — the source dialing us back — when its
hello names that hash. Consulted only when the ADR-0039 callback key misses, because a
Kad candidate's key is an id no hello reports. A punch claimed later for the same
callback keeps the dial-back standing; a punch's claim alone never adopts an undirected
path (ADR-0091's accepted-Tunnel rule). Confirming one reports the peer's hello back to the
**NAT-T Front** as `Risen::Identified`, so a peer's own held burst or still-pending
attempt ends with it; a second claim standing behind the same address is untouched — only the
named peer's hold dies.
_Avoid_: pending callback (keyed by `(server, low id)`)

**Dialer Tunnel**:
A **Tunnel** rmule raised by dialing a **Punched Path** it asked for — as against one it
accepted, which somebody else aimed at us. Only a Dialer Tunnel carries a target hash
into the inbound triage, because only for a dial does this node know who it meant to
reach; the stream's role says who spoke first, not who was aimed at.
_Avoid_: outbound connection (that is a TCP dial), initiator (that is the `0x61` role
byte, which names who asked for the introduction)

**Correctness Tier**:
The deterministic, in-process interop bar (ADR-0040): a **Fake eD2k Server** over real
localhost sockets, run by ordinary `cargo test`, that models a **Back-Connect Probe**,
Low-ID assignment, and the callback relay across two client sessions — faithful to
*behaviour*, not to wire bytes. Catches interop-shaped bugs in rmule's logic
deterministically. Sits beneath the **Compatibility Tier**.
_Avoid_: unit test (too narrow; this drives real sockets), mock (it is a behavioural server, not a stub)

**Compatibility Tier**:
The opt-in, best-effort Docker harness (ADR-0033) running the real eserver + aMule. Proves
real-wire compatibility *when it runs*; documented-flaky for the Low-ID multi-client topology
and **not** the correctness gate (the **Correctness Tier** is).
_Avoid_: smoke (loosely — it is the smoke, but the term names the *tier*, not the run), integration test (ambiguous across both tiers)

**Back-Connect Probe**:
A real eD2k server's High-ID reachability check, modeled by the **Correctness Tier**: on
login, dial the client's advertised TCP port; reachable → **High-ID**, refused → Low-ID.
Makes serve-bind-before-login a precondition the positive callback loopback depends on.
_Avoid_: ping (wrong protocol), health check (this assigns identity, not liveness)

**Global Source**:
A source learned over **server-UDP** (`OP_GLOBFOUNDSOURCES`) from a server rmule is *not*
logged into (ADR-0051), as opposed to one from the connected server's TCP `OP_GETSOURCES` or
peer source-exchange. A **High-ID** global source goes straight into the candidate pool; a
Low-ID global source is callbackable only via its own source-server, never the connected one,
so it waits in the **Source Book**'s global Low-ID lane, apart from the connected server's.
_Avoid_: peer source (the exchange term), found source (ambiguous across the TCP/UDP paths)

**Managed Server List**:
The core-owned list of eD2k servers rmule knows (ADR-0080), one `ManagedServer` row per
endpoint: the server.met facts (name, description, priority) plus rmule's own bookkeeping
(the operator's static pin, the failure tally) and the server's **Server Figures**. Core is its only writer once a front-end hands
over a `ServerListStore`; it changes only by `CoreCommand::ServerList` — including
`UpdateServerList`, the on-demand re-run of the Join Sequence's server.met acquisition — and is
published whole on the **Diagnostics Snapshot** level. A downloaded list may rename a row; only
an explicit command re-prioritises, pins or absolves one. Distinct from the *connected* server
(a session fact). The **Global Search Sweep** and **Global Source Discovery** walk a projection of it:
every listed server minus the dead, the IP-filtered and the connected one, recomputed on every change (ADR-0051).
A row dialed on an **aux port** keeps its dialed endpoint as the key and gains the server's standard port plus an aux-ports list (store version 14, which also keeps the UDP flags word an import named for a never-pinged row), learned from an aux-port login's ID answer or a server.met `ST_AUXPORTSLIST`; a downloaded row names the server by its standard port and finds the row there (ADR-0080).
_Avoid_: server database, server config, connected server

**Dead Server**:
A listed server whose consecutive failure tally is at or above the **Dead Server Limit**
(ADR-0052). Derived from the tally, never stored as a flag. It stays listed and shown (its
**Server Health** is `Dead`), the **Status Ping Sweep** still pings it at the refresh pace, and the
swept list is published without it, so the **Global Search Sweep** and
**Global Source Discovery** pass it by. Any answer — a `0x97` or an accepted login — resets the tally
and it lives again. A static server can be dead. The operator may always connect to one.
_Avoid_: removed server, offline server (the network, not the server)

**Announce Policy**:
Whether rmule withholds its share set from a server that grants related search
(`SRV_TCPFLG_RELATEDSEARCH`) — `ServerPolicy::withhold_from_related_search`, off by default
(ADR-0099). The **Session Follower** applies it per session: it announces, withholds, or —
when the policy was switched on after an announce — sends nothing more, since an offer cannot be
taken back in the session. Withheld shares stay available over Kad and on other servers.

**Server Grants Report**:
What a server last reported it grants: the raw `SRV_TCPFLG_*` word of its last `OP_IDCHANGE`
and when (ADR-0080). Durable on the **Managed Server List** row (store version 10); a
server never logged into has none. Its UDP twin is the `udp_flags` of the **Server Figures**.

**Dead Server Limit**:
The failure tally at which a server is a **Dead Server**: aMule's `/eMule/DeadServerRetry`,
default 3, at least 1. Core-owned server-list configuration (`ServerPolicy::dead_after`), read from
the store at start and changed live through **Core Settings**.

**Server UDP Crypt**:
How to key UDP to a server, as its last challenge-matched `0x97` said: the obfuscation UDP and TCP
ports, the `ServerUDPKey`, and our public IPv4 when the key was learned (ADR-0052). Durable on
the **Managed Server List** row (store version 12), as aMule keeps them in server.met; every `0x97`
refreshes it, and a body too short to carry it clears it. Read back at start: a server this run
has not heard is found by its saved obfuscation port, and the key keys UDP only while it is non-zero,
the server advertises UDP obfuscation, and we still hold the public IPv4 it was learned under.

**Server Health**:
The surfaced row's code for how reaching a server has gone, ranked for sorting: `Answered` (tally 0,
it has answered), `Unproven` (tally 0, never answered), `Failing` (below the limit), `Dead`. A dead
row also carries **Dead Since**: how long ago the level saw it die, or that it was dead before this
run started — a run-time fact, never stored.

**Server Figures**:
What a server last reported about itself and when: its ping, user and file counts, soft and hard file limits and version, and `answered_at`, the wall-clock time of its last answer. Durable on the **Managed Server List** row (store version 9), as aMule keeps them in server.met. A `0x97` answer writes and dates them, `OP_SERVERSTATUS` and a tagged `0xA3` fill in without re-dating, and an import brings its own `ST_LASTPING` date or no figures. The surfaced row carries their age.
_Avoid_: dynamics, measurements (they are not kept beside the list), server stats

**Server Facts**:
The write side of what happened with a server (ADR-0080 amendments, `server_list::ServerFacts`)
— the one seam over the **Managed Server List** store, the **Diagnostics Snapshot** level and the
event bus, so a round trip's failure tally, its measurement and its reported edge change together.
Four surfaces hold one: the **Status Ping Sweep** counts a silent ping's failure at its verdict, the **Server-UDP
Engine**'s `0x97` gate lands the measured ping / users / files and clears the tally, the connected
session's welcome burst lands the counts (`0x34`) and folds the server's own name (`0x41`), and the
**Server Session Switch** reports connecting / connected / failed / disconnected. The measurements
live in a per-endpoint map joined into the rows list-first at snapshot time, never in
`ManagedServer`: a list republish cannot clobber one, and a removed row takes its measurement with
it. Its event sender is weak — the sweep and the engine outlive no actor, and a strong clone would
hang `Core::shutdown`.
_Avoid_: server capability store (what a server *proved it can do*, keyed for gating consumers),
server status (the `0x34` packet itself)

**Server Session Switch**:
`CoreCommand::ConnectToServer` (ADR-0080 amendment) — aMule's "connect to the selected
server", and the only road that opens a server session (ADR-0093, "Connecting is the operator's
act"): no activity dials; each rides the live session or waits for one. Runs off the actor and answers with a `ServerConnectionEvent`
trail: `Disconnected(old)` → `Connecting(new)` → `Connected`/`ConnectFailed`. The switch holds the
session slot and waits for the old session to report itself gone before dialing, which is what
makes the **Connected Server** marker never name the wrong server and needs no generation counter.
A failed connect counts a failure through **Server Facts**; an accepted login absolves the tally.
The failure is typed: `Unreachable` for a dial that never came up, `LoginRefused` for an
`OP_REJECT`, `ClosedBeforeAnswer` for a server that hung up before answering, `LoginTimedOut` for a server
that accepted the socket and then never answered inside `CoreConfig::server_login_timeout` (the
eD2k session's own login deadline, not a second timer), `Filtered` for one never dialed.
Peer transfers ride their own sockets and survive; a running search dies with its session;
the **Session Follower** announces the share set to the new server. The switch keeps **Listen Before Login**: it
starts the Serve activity when none runs and dials only after the **Login Mapping Wait**.
_Avoid_: reconnect (nothing re-establishes a dropped session), lazy login (removed: no activity
dials), server list command (the list is a
config fact; no `ServerListCommand` reaches the session slot)

**Connected Server**:
`DiagnosticsSnapshot::connected_server` — the one endpoint rmule holds a live eD2k session with,
`None` when there is none. One session fact, never a flag repeated across list rows. Raised by an
accepted login and cleared by the session task on the way out however it ended, so it reports a
connection that exists rather than one intended. Deliberately not pruned by a list republish:
removing a server does not disconnect from it, so the marker may honestly name an unlisted
endpoint.
_Avoid_: selected server (the *choice*, which outlives a failed connect), current server

**Status Ping Sweep**:
The `0x96` pacing loop (ADR-0052 breakdown 3, `server_udp::StatusPingSweep`) with two paces:
a server with no answer younger than the 20 min window gets its *first contact* at one per 250 ms (at attach the burst takes only the rows whose **Server Figures** are absent or stale), and every
later *refresh* is due once a 20 min window lapses (aMule `UDPSERVSTATMINREASKTIME`) and paced at one
per 5 s across the list (aMule `UDPSERVERSTATTIME`); DNS-named rows walked past. It walks the **Managed Server List** re-read from the store
each tick — this is list health, not download sourcing — while **Global Source Discovery** stays on
the command-set list. Every probe counts a failure through **Server Facts** at send and the gated
reply clears it, so an unanswered ping needs no timer: the tally reads *tries since this server last
answered*. A ping is judged 20 s after it left, and a silence counts only when a ping sent within
60 s of it was answered (the offline guard, ADR-0052's dead-server amendment): when every ping of a pass goes unanswered
the network is down, and no tally moves. A lone living silence with no neighbour is inconclusive: one
*vouching ping* to the server that answered last decides it (answered, the silence counts; silent,
the network is down). It pings a **Dead Server** too, at the refresh pace only, so
one that answers can come back. rmule marks and never evicts (aMule's `DeadServer` removal is not
transplanted).
_Avoid_: global search sweep (a per-search fan-out), server-list refresh (the server.met update)

**Global Source Discovery**:
The Core-level service (ADR-0051) that batches all active downloads' file hashes and, on an
interval, queries every server in the **Managed Server List**, routing each
`OP_GLOBFOUNDSOURCES` answer's High-ID sources to the matching download via
`DownloadState::on_sightings` (`Channel::Global`). The ask form is per-server from the **Server Capability
Store** (ADR-0052): `0x94` size-extended entries when the server advertises
ExtGetSources2 (unlocking > 4 GiB files), legacy bare-hash `0x9A` otherwise; large files are
skipped toward servers without proven LargeFiles support; ≤31 files per datagram with
ExtGetSources, one without. Runs only while a download is active.
_Avoid_: search (that is keyword search, a different UDP opcode), connected-server lookup (the TCP path)

**Server-UDP Engine**:
The single owner of the server-UDP socket's receive side (ADR-0051, `server_udp`): one Core task
drains the transport and demuxes each datagram on its leading packet's opcode — `0x9B` feeds
**Global Source Discovery**'s channel; `0x97` is consumed in-engine through the status-challenge
gate into the **Server Capability Store** (ADR-0052); the global-search (`0x99`) and description
(`0xA3`) rows plug into the same demux. Each consumer's inbox gets its datagrams tagged with
the answering server's standard endpoint, whichever of the server's ports they came from.
Sends go through the **Server-UDP Seal**; receive must be owned once because eD2k UDP packets
carry no length prefix, so packet boundaries inside a datagram are the consuming concern's
decode.
_Avoid_: discovery channel (the get-sources consumer, not the socket owner), server-UDP transport
(the socket seam the engine reads — `adapters::ServerUdpTransport`)

**Server-UDP Seal**:
The one send gate of the server-UDP socket (ADR-0046, `server_udp::ServerUdpSeal`), aMule's
`CServerUDPSocket::SendPacket`. Every sender — the **Status Ping Sweep**, the engine's `0xA2`,
**Global Source Discovery**, the **Global Search Sweep** and the callback relay — hands it a
server's standard endpoint and a plain frame. While the obfuscation policy is set and the
server's **Server UDP Crypt** offers a key (this run's `0x97` record first, else the row's
saved facts), the frame is sealed under that `ServerUDPKey` and sent to the server's
obfuscation UDP port; otherwise it goes plain to standard port + 4. The crypt-ping alone goes
raw, to standard port + 12. The transport behind it knows no port rule.
_Avoid_: send gate (the peer-UDP one, keyed on a peer's User Hash), crypt layer (the whole
datagram obfuscation, both directions)

**Related-Files Search**:
A **Search Activity** whose query is a file, not words: it asks the connected server which files its users hold beside that one (ADR-0037). It travels to the connected server over TCP alone — never the **Global Search Sweep**, never Kad — and only to a server that grants it. In code it is the `SearchQuery::RelatedFiles` kind; the sweep and Kad accept only `KeywordQuery`, so the rule is held by the type.
_Avoid_: similar files, recommendations, related:: search (the wire term, not the concept)

**Global Search Sweep**:
One search's UDP fan-out over the managed server list (ADR-0051, `search::GlobalSearchSweep`):
one server per 750 ms tick (aMule's `m_searchTimer`), the connected server skipped (it received
the TCP search), fire-and-forget, no retries, done when the list is exhausted. The variant per
server reads the **Server Capability Store** — `0x90` (LargeFiles + ExtGetFiles, caps-tag
prefix), `0x92` (ExtGetFiles), `0x98` baseline — and a 64-bit-size query is skipped toward
servers without proven large-file support. Each search sweeps on its own, side by side with
the others. Its `0x99` answers flow engine → forwarder → **Search Attribution**:
each row reaches every live keyword search that proves it and merges into that search's one
result set; a row no live search proves is dropped and counted. Its last send settles the
search's global leg.
_Avoid_: global source discovery (the get-sources sweep — different opcodes, different cadence),
server-list refresh (the status ping sweep)

**Server Capability Store**:
The typed per-server record a challenge-gated `OP_GLOBSERVSTATRES` populates
(ADR-0052, `server_capabilities`), keyed by the server's TCP endpoint: UDP flags
(ExtGetSources2/ExtGetFiles/LargeFiles/obfuscation), `ServerUDPKey`, obfuscation ports, and
user/file counts. Written only by the **Server-UDP Engine**; read by the gating consumers — the
`0x94` get-sources upgrade, global-search variant selection (ADR-0051), datagram
crypt (ADR-0046). The challenge (`0x55AA0000 + rand16`, echoed as the reply's first field) is
per-server anti-spoof state — a mismatched or unsolicited reply is dropped with no mutation, so
a forged `0x97` cannot inject flags or a key. Absent fields stay `None` (older servers stop
early); a server with no record has no proven capabilities and gets legacy/baseline emits.
_Avoid_: server status (the TCP `OP_SERVERSTATUS` 0x34 user/file counts), server list (endpoints
to query — the store holds what those servers *proved*)

**Kad Source Discovery**:
The second **Source Discovery Policy** channel (ADR-0043): a Core task started by
`CoreCommand::EnableKad`, owning the live Kad node only through the `KadSourceChannel` seam
(projected vocabulary — file hashes and each row's **Source Sighting**, never Kad wire types,
because the Kad Source Row Projection is sealed in `rmule-kad`; a row crosses whole, so the brain
sees the buddy of a firewalled source instead of only the address of a dialable one). Sweeps the active downloads for due source
asks (first ask immediate, re-asks on eMule's 1-hour `KADEMLIAREASKTIME`) and publish-registers
every shared file once (the node owns the 5-hour republish). Routes answers to
`DownloadState::on_sightings` (`Channel::Kad`). Never enabled ⇒ zero behavioral change.
_Avoid_: Kad lookup (the walk is the node's concern, not Core's), DHT search (keyword search is out of scope)

**Source Discovery Engine**:
The one Core mechanism behind per-download source discovery: an active-download
registry (file hash → sink), an ask-cadence sweep (due-check per file; the global
channel re-asks every sweep, Kad honors `KADEMLIAREASKTIME`), answer routing, and an
RAII deregistration guard — generic over a **Discovery Channel** adapter. Two
adapters exist: the server-UDP global sweep (ADR-0051) and the Kad channel
(ADR-0043). Distinct from **Source Discovery Policy**, which is the per-download
*selection* of channels; the engine is the shared mechanism they run on. Share
publishing is not discovery (see **Kad Publisher**); the global-callback relay is
transport plumbing owned by the server-UDP adapter, not the engine.
_Avoid_: discovery task twins (the retired GlobalSourceDiscovery/KadSourceDiscovery copies), source lookup (the eD2k TCP exchange), scheduler

**Kad Publisher**:
The small Core task that keeps the Kad node's source publications equal to the offered
**Shared File Registry** rows and the **Partial Share**s: it registers each newly offered
file once, and withdraws each file no longer offered (unshared, gone, a **Withheld Row**,
or a download whose offer ended) from the node's 5-hour republish cadence (ADR-0106,
ADR-0113).
Split out of Kad discovery because publishing is registry-driven, not
download-driven — it runs even with zero active downloads.
_Avoid_: republish timer (the node's), discovery sweep, announce (the eD2k `OP_OFFERFILES` path)

**Diagnostics Snapshot**:
The core's level of observable facts (`DiagnosticsState`, read whole by `diagnostics_snapshot()` or a `DumpDiagnostics` echo, which return the same value — ADR-0028): per-activity rows (downloads, uploads, servers, Kad facts) and the counters each module bumps. Its writers are one-line counters written where their owning module makes the decision — NAT-T in the NAT-T Front, buddy and callback in the **Firewalled Front**, serve in the serve runner, downloads in the download runner, server health in the server-list facts — so a family's writes already sit with its owner; there is no later settle point to gather them behind, unlike a download's positional part-state vector.
_Avoid_: stats, metrics (the operator-facing Statistics view reads it, but it is not that view)

**Kad State**:
Where the **Kad Activity** stands, as a level on the **Diagnostics Snapshot** (`kad_state`): `Off`, `Running` or `Stopping`, written by the actor at the activity's start, its stop's begin and its retire. The TUI's Kad switch (`K`) reads it to start or stop Kad, and the Kad pane reads a running node nobody has answered yet as joining. Disconnecting from the server leaves it as it is (ADR-0096, "Disconnect, and Kad's own switch").
_Avoid_: Kad connected (Kad has no session), Kad on

**Kad Activity**:
The **Activity** for a running Kad node (ADR-0093): one
`KadActivity` value in the actor's ledger holding the owned `JoinHandle`s on
the **Kad Source Discovery** task (whose channel closes the moment the deep
node's own pump does) and its watchdog, the **Kad Publisher** and its
share-changed trigger, the ed2k→Kad handoff forwarder, the search
channel `StartSearch` reads, and this activity's own **Kad
Shutdown Lever** handle — always installed. It holds the one **Kad Presence** lease, which is
what `RoutePosition::kad_running`, the `KadNotRunning` guard and every
download read. `EnableKad` fills it at once; `retire_kad` takes
every piece back — the lease dropped, the **`CT_EMULE_UDPPORTS`** advert's Kad half
cleared (aMule's `Kademlia::IsRunning() ? kadPort : 0`), every
task joined (bounded, aborted past grace) — whether `DisableKad` asked, the
discovery task ended on its own, or **Quit** stopped it. The discovery task's
own end-of-loop bump is cooperative code, so an abort or a panic mid-`await`
never runs it: the watchdog polls its `AbortHandle` and bumps the
same watch with the activity's generation once it reads finished.
It installs its fact reader into the shared diagnostics state at start and
clears it at retire, so the snapshot reports how many long-lived tasks it holds
as `kad_tasks_live` (`0` with no activity).
_Avoid_: Kad pump (the deep node/pump.rs task the discovery task's channel rides,
one layer below this), Kad Source Discovery (one task in the bundle, not the
bundle itself), Kad Shutdown Lever (the stop mechanism this bundle now owns
one instance of, not the bundle)

**Kad Shutdown Lever**:
A `KadShutdownSlot`/`KadShutdownHandle` pair reaching the
node's driver-pump task directly as one more `select!` branch, bypassing the
`Arc`-shared `RuntimeKadChannel` that otherwise only drops its last holder
when the process itself exits. One owner: `on_enable_kad`
always installs the activity's own on `KadEnableConfig::kad_shutdown`,
the one `DisableKad`, a death and **Quit** reach through `stop_kad`,
falling back to an abort of the actor's discovery-task wrapper if the
confirmation does not land within grace. A caller may still hand in a lever
of its own before `EnableKad`, as `ed2k serve start --kad`'s SIGTERM/SIGINT
handler does to confirm the ADR-0022 tap has finalized before the process
exits; the activity takes that slot's pump half and makes it a caller of the
same stop — its request bumps the ledger's stop watch with the activity's
generation, and the retire fires its confirmation when the pump ended clean.
The `rmule` app's `Flow::Quit` (`App::graceful_quit`) installed one
the same way at first, then moved onto `CoreCommand::DisableKad`
instead — the TUI needs no tap-finalize confirmation, so it is no longer a
lever owner, and `rmule::kad::enable_config` leaves
`KadEnableConfig::kad_shutdown` `None`.
_Avoid_: DisableKad (the command that fires this activity's *own* lever, not
the lever itself), Kad Activity's retire (`retire_kad`, what runs after
either lever stops the pump — join the tasks back, clear liveness and the
advert, emit the event — not the stop signal itself)

**Kad Cells**:
What core lends each Kad node for its life (`KadCells`): the Kad half of **Self Reach**'s verdicts, the table size, keyword index size and traffic counters the pump keeps moving, **Kad Presence**, the slot the handoff forwarder is left in, the diagnostics state, and the `AdapterCells` the node meets the peer surfaces on. Core builds the one set before any start and hands it to `KadRuntimeFactory::start`, because a node starts, stops and starts again over the same readers: a runtime that made its own would leave every reader holding a cell no pump of the core's writes, and a fake runtime states what it publishes through the same cells.
_Avoid_: Kad context, Kad state (the **Kad State** level)

**Mailbox**:
The cell holding the one live sender of a node that starts, stops and starts again over a socket or a front that outlives it (`Mailbox<T>`): the Kad node's datagram inlet, its pump and its bootstrap handoff, and the serve activity's dialed-connection sink. Empty while no node runs — the emptiness is the gate a sender reads — and a send never waits: it says whether a message was dropped for want of a node or for want of room, and each caller counts or logs the reason it cares about. A node's start fills it and takes a **Lease**.
_Avoid_: inbox (the channel a task drains; a mailbox holds only the sender into one), slot

**Lease**:
One node's claim on a **Mailbox** (`Lease<T>`), returned when its start fills the cell and dropped at its teardown. The drop empties the Mailbox only while it still holds the sender this lease installed, so a node whose stop timed out, still tearing down after its successor filled the cell, never empties the successor's. It holds that sender weakly: a task that pushes to its own node through the lease never keeps the node's channel open.
_Avoid_: guard, token; not a **Mapping Lease** (a router grant's lifetime) nor the **Kad Presence** lease the **Kad Activity** holds (its one writer's claim)

**Join Sequence**:
Core's cold-start orchestration: load persisted state, acquire a server list on first run if empty, then join the eD2k and Kad networks in parallel — each gated only on its own per-network config, all enabled by default. Unattended dual-network join is core policy, overridable per network by the caller. A stranded Kad side (empty table, empty dial list) idles with a named event rather than fetching anything unattended.
_Avoid_: boot script (caller territory), connection retry policy (per-session concern), autostart

**ed2k→Kad Handoff**:
Core's cross-network recovery route (ADR-0067): a connected eD2k peer whose hello carries a Kad node hint (`CT_EMULE_UDPPORTS` kad half + Kad version > 1, parsed peer-side as `PeerIdentity::kad_bootstrap_port`) bootstraps our Kad node — the moment one eD2k peer connects, a stranded Kad side can join with zero seeds. Core brokers it: the peer surfaces push the peer's (connection IP, Kad UDP port) into a shared sink that is empty until `EnableKad` installs its sender (that emptiness is the gate's **running** leg), and the running node's factory forwards it to the sans-I/O `KadNode`, which applies the **not-joined** and **shared 10 s throttle** legs before feeding it into the one Bootstrap Dial List. One-way — aMule has no Kad→ed2k handoff and none is invented.
_Avoid_: Kad bootstrap fetch (that's the manual nodes.dat route), peer source exchange (a different peer-to-peer fact), Kad callback (parked)

**Ban Store**:
The core-owned record of flood-offender IPs (IP plus banned-until, lazily expired). Protocol
nodes report offenders into it — they never enforce — and the peer-TCP surface is the sole
enforcement point: inbound peer connections from banned IPs are refused and banned source
candidates are not dialed. Kad and server traffic are never gated by it, matching where aMule's
client-layer ban lands.
_Avoid_: IP filter (local policy file), Kad ban (no such gate exists), blocklist

**IP Filter**:
The core-owned local-policy verdict store (aMule 2.3.3 `CIPFilter` parity): built
once, before the actor spawns, from `ipfilter.dat` + `ipfilter_static.dat` (static loaded second,
its lines overwriting overlap — including allow-holes punched through blocked ranges), keeping
only ranges whose access level is strictly below the `FilterLevel` threshold (default 127).
Consulted at the accept gate, the peer dial gate, the server dial (the resolved address for a
DNS-named server, aMule's post-resolve check), the global-source server-list install, and every
source-ingest path (server snapshot, global-UDP, Kad, source exchange — High-ID rows only;
Low-ID rows have no IP until they connect). The Kad node consults the same live table through
`rmule_kad::KadContactAdmission` (armed by the Kad factory) at its contact-store,
bootstrap-dial-seed, and lookup-response intakes — aMule's four `kademlia/` `IsFiltered` sites —
so a blocklisted IP never becomes a routing contact, walk candidate, or bootstrap dial. Client
and server surfaces each have their own on/off gate, both defaulting on with an empty table —
aMule's out-of-box posture.
IPv6 rules from the same two files fill a second table under the same rules; each address is
judged by its own family's table, and a source's two halves are never linked (ADR-0085).
Distinct from the **Ban Store**: this is an operator-loaded policy file, not a runtime-observed
offense record.
_Avoid_: ban list (that's the Ban Store), blocklist download (auto-update is deferred), firewall

**Undialable Family Drop**:
A candidate source dropped at ingest because rmule holds no address in its
**Address Family** to dial it *from* — an IPv6 source while the **Advertised
IPv6** is empty (ADR-0087). The dialect itself is implemented; what is missing
is our own end of it. Dropped on the same pass as the **IP Filter** verdict
and counted on diagnostics, so "no sources" never quietly hides a family gap,
and no worker slot is spent on a conversation rmule cannot hold.
Distinct from the **IP Filter** (operator policy) and the **Ban Store**
(observed offense): this is a capability statement about rmule itself.
_Avoid_: unsupported peer, bad source, v6 filter

**Unanswerable Family Datagram**:
An inbound client-UDP datagram the demux front drops because the **opcode it
carries has no wire form that can express the sender's Address Family**
(ADR-0087) — the sibling of the **Undialable Family Drop** one layer down:
there the *source* is undialable, here the *body* is unanswerable. The whole
surface is a **Family Pair**, but the ruling is per opcode, not per socket: the
reask quartet and `OP_DIRECTCALLBACKREQ` name no address in any body and reach
both families, while `OP_REASKCALLBACKUDP` (`0x94`) stays IPv4 because the
`OP_REASKCALLBACKTCP` relay it becomes injects the requester into 32 bits, and
a firewalled client reading a sentinel there would answer the reask to the
broadcast address. Counted on diagnostics, so a dialect gap reads as a gap and
not as packet loss. Kad's own `0xE4`/`0xE5` drop is *not* one of these — Kad is
IPv4-only end to end, so a **declared** `0xE4`/`0xE5` on the v6 half of the pair is
counted here too — the same kind of gap — while an *unclaimed* leading byte
there is dropped uncounted, because noise is noise in either family.
_Avoid_: malformed datagram (that decodes and fails), unsupported peer, v6 drop

**Unasked Family Datagram**:
An inbound **server-UDP** datagram dropped because rmule never asked in that
**Address Family** (ADR-0087's server-UDP ruling). Not the client surface's
**Unanswerable Family Datagram**: there the per-opcode body decides, here one
reason covers the whole surface. Server-UDP is strictly request/response with
rmule always the requester, servers resolve A-first, and the send half reaches
only an IPv4 literal — so an IPv6 datagram answers nothing rmule sent. The one
body that could never widen anyway is `OP_GLOBCALLBACKREQUEST` (`0x9C`), which
writes *rmule's own* contact in 32 bits for the server to relay to a firewalled
third party: **Ed2k Wire Form**'s omission rule applies, and for a request whose
entire content is that address, omitting is dropping. Traced, not counted — a
datagram from a family we never asked in is unsolicited, not a dialect gap.
_Avoid_: unanswerable datagram (that is the client surface), v6 server (a
v6-only server is reachable over TCP, just never asked over UDP)

**Serverless Tolerance**:
With the Kad node running, a failed server login degrades a download to a sourceless start
(unassigned Low-ID self, empty pools, no callback capability) that waits on discovery instead of
failing, and a serve activity binds its listener and serves peers even when its announce login
fails (announce stays best-effort) — it does not even *wait* for that login, since **Serving
Started** is the bind. rmule stays fully functional with no eD2k server anywhere —
proven by the serverless E2E (`kad_serverless_e2e.rs`).
_Avoid_: offline mode (peers are very much online), Kad-only mode (a config posture, not this mechanism)

## Relationships

- The core actor owns the unified set of live peer **Connection**s; the **download scheduler** and the **Upload Slot Queue** are two consumers over that one set (a connection may both pull and serve — wired on accepted connections first, dialed connections later).
- The inbound accept loop routes by asking the **Awaited Inbound** registry (ADR-0039, ADR-0091): an accepted connection whose identified `(server, low id)` matches a **Pending Callback**, or whose hello confirms a **Pending Tunnel Claim**, becomes an **Adopted Inbound Worker** for that download; every other accepted connection flows to the serve path as a **Served Link**, which a later download of its peer rides instead of dialing it. So the accept stream is a third reader of the unified connection set, feeding the download scheduler — not only serve.
- A **Search Activity** consumes search support from the eD2k server protocol service and presents app-facing result streams; selecting a result starts a separate download workflow rather than mutating the search.
- Search uses its own `SearchCommand` / `SearchEvent` vocabulary under `CoreCommand::Search` / `CoreEvent::Search`; it is not a hidden phase of `DownloadCommand`.
- A **Search Result Set** is process-local state for one **Search Activity**; durable search history and searchable local result indexes are later product features.
- A **Search Activity** completes after every leg has settled and its **Search Quiet Timeout** then elapses without new results, or ends earlier by explicit cancellation; eD2k search packets do not provide the app-facing completion boundary.
- Cancelling a **Search Activity** drops core's active search correlation and ignores late search results; it does not disconnect the shared eD2k server session.
- The first **Search Activity** slice allows only one active server search per live eD2k server session because search-result packets do not carry a query correlation key; overlapping searches are rejected or require cancelling the active one.
- A **Search Activity** uses the shared persistent server session; it does not create a search-specific eD2k connection or bypass the session that also owns source lookup and announce.
- A completed download auto-registers into the **Shared File Registry**, the single join point where the download and serve halves meet.
- Verification splits: `compute_*` hashes (announce/share) and `verify_*` (download receipt) share one `hashing` module; `resolve_hash_set_authority` stays download-only.
- Reason taxonomy: peer-retirement reasons are one enum (public event + diagnostics row unified); `PartReleaseReason` stays distinct and nests `PeerRetired(PeerRetirementReason)` rather than copying its variants.
