# Core-owned search: searches run side by side, each leg on its own, and a row belongs to every search it answers

## Context

An operator's keyword search can be answered by three sources: the connected server
over TCP (`OP_SEARCHREQUEST` / `OP_SEARCHRESULT`), the other servers on the managed list
over server UDP (`OP_GLOBSEARCHREQ` / `OP_GLOBSEARCHRES`, `0x98` / `0x99`), and Kad
keyword storers. A front end holds several searches live at once, side by side.

None of those answers names the search it answers. A TCP answer carries no search id; a
`0x99` is a fire-and-forget datagram; a Kad storer applies nothing but the keyword. Two
searches running together must neither wait on each other nor see each other's rows.

An eD2k server answers one link's requests in order, one answer each: ed2k-server runs a
frame to completion before reading the next and answers even an unparseable request
(`connection.rs:421-445`, ed2k-server at `eacf7f1`), and aMule and eMule end their one
in-flight search on each answer (aMule `ServerSocket.cpp:421-431`, eMule
`ServerSocket.cpp:366-378`).

## Decision

### Ownership

- `rmule-ed2k` owns the search packets and the session's search commands and events;
  `rmule-core` owns the Search Activity: identity, legs, attribution, accumulation into a
  Search Result Set, completion, cancellation, and the handoff from a chosen result to a
  download by fresh source lookup.
- **The caller names the search.** `StartSearch` carries a `SearchId` from
  `SearchId::mint` (process-wide and increasing, so front ends sharing a core never
  collide). Every outcome — `SearchStarted`, results, skips, `SearchCompleted`,
  `SearchCancelled`, `SearchFailed`, `SearchRefused` — carries it. A `StartSearch` under
  an id a running search holds is rejected with `SearchIdInUse` and the running search is
  untouched.
- **Searches run side by side.** A new search joins the running ones; `CancelSearch` ends
  one.

### Legs

A keyword search has three legs — server (TCP), Global Search Sweep (server UDP) and Kad
walk — and each is sent, waiting or settled on its own. A waiting leg holds no other leg
back. Core reports the whole picture on every move as
`SearchLegsChanged { legs: SearchLegs { server, sweep, kad } }`.

- **Server leg.** Sent when a live session exists. Its states:
  - `WaitingForSession` — no session, and the operator's Server Intent (ADR-0096) stands:
    their connect is in flight, a reconnect is pending, or the session ended as the
    request reached it. Ended by the session the intent brings, by the intent ending, or
    by a cancel; never by a timer. Holds completion.
  - `Sent` — on the link, its answer due. Holds completion.
  - `Settled` — answered, empty included, or its answer wait
    (`CoreConfig::search_server_answer_timeout`, 12 s, as amule-kno's
    `SERVER_ANSWER_TIMEOUT_MS`, `SearchList.h:491`) ran out.
  - `Unanswered` — sent, and its session ended before the answer with no intent to re-make
    it.
  - `NotSent(NoServer)` — no session and no intent at the start, or the intent ended while
    it waited unsent.

  An unsent leg counts as settled. Settled is final: a session that comes up later sends
  only legs still waiting, so a finished search is never reopened on nobody's word.
- **A session lost under a sent leg** ends the leg, not the search. An answered leg is not
  re-sent and its rows stand. A sent, unanswered leg goes back to `WaitingForSession` while
  the intent stands and is sent once more on the re-made session; the sweep beside it is not
  re-sent. With no intent it ends `Unanswered`. The Kad leg and every row received stand.
  `SearchFailed { ServerDisconnected }` remains only for a Related-Files Search (ADR-0037)
  whose request met a session already ending.
- **Global Search Sweep.** Needs the same session, as in aMule, which refuses a search while
  not connected (`CSearchList::StartNewSearch`, `SearchList.cpp:595-597`): it waits with the
  server leg, goes out with it, or is not sent with it. Each search sweeps on its own, one
  server per 750 ms tick (aMule's `m_searchTimer`, `SearchList.cpp:769`), with no turns; one
  datagram carries one expression tree, so it cannot serve two searches. The leg settles when
  its sweep has sent its last datagram and carries `sweep_servers: SweepTally { asked,
  answered }` — servers sent to, and server-UDP addresses whose `0x99` brought this search at
  least one row.
- **Kad walk.** Sent when Kad runs, otherwise `WaitingForKad`; a waiting Kad leg does not hold
  completion, and reads `NotRun` if every other leg settles first. A walk is per lead keyword —
  aMule's rule: the first token of three or more bytes, or for several words the longest word
  holding no separator (`SearchList.cpp:126-141`). Every live search on that lead keyword
  subscribes to the walk, receives each row that proves its own query, and on joining a running
  walk is replayed the rows found so far. The walk's end settles every subscriber: `Settled` if
  it asked storers, otherwise `NotSent` with the reason (`NoKadContact`, `KadKeywordHeld` when
  another kind of walk holds the target per ADR-0062, `NoKadKeyword`, `KadStopped`), or
  `WalkStopped` when Kad stopped under it, its rows standing. Each search gets its own sink;
  rows travel lossy so a slow search never stalls the Kad pump, while leg facts — including
  `SearchDeferredKadPublish` when the walk took its keyword from the Kad Publisher — travel on a
  lane that loses nothing. The Kad leg settles at the latest after
  `CoreConfig::search_kad_lifetime` (45 s, aMule's `SEARCHKEYWORD_LIFETIME`).
- **Neither session nor Kad.** The whole search waits (`SearchWaitingForConnection`) and starts
  on whichever comes first; its legs are then placed by the rules above. A cancel reaches it while
  it waits. An operator connect in flight orders searches behind it.

### Completion

A search completes when no leg holds it open and the Search Quiet Timeout
(`CoreConfig::search_quiet_timeout`, 3 s) has passed, reset by each batch that reaches the search
and by each leg settling. A row that arrives while the search is live still lands; after it, the
row is counted, not shown.

### Attribution

**A Search Result belongs to every live search whose query it satisfies, and to no other.** A
search is live from `SearchStarted` to its terminal event. A row that reaches no live search is
dropped and counted (`SessionCounters::search_rows_unattributed_total`).

- **Keywords.** The query's words — one AND-ed `0x01` term per word on the wire — split into
  tokens on whitespace and on every separator either known matcher uses: aMule's
  `()[]{}<>,._-!?:;\/"` (`SearchManager.h:135`) and ed2k-server's filename separators
  (`keyword_index.rs:47-56`). Tokens and names fold by case and accent (NFD, combining marks
  dropped). A row satisfies the keywords when every token is a whole word of one of its names; a
  quoted run proves only as its words in order, side by side. This is the loosest reading either
  server showed: both match whole words, Lugdunum folds accents and ed2k-server does not, so a
  search must not lose a row the other server would give it.
- **File type** by the row's class — from its name's extension, else `FT_FILETYPE` — at wire
  resolution (`Ed2kFileClass::search_term`); **size bounds** inclusive; **availability** against
  the reported source count; **extension** from the name or `FT_FILEFORMAT`, ASCII
  case-insensitive.
- **Two strengths of proof.** For the search the answer is known to answer — its owner — the
  server's verdict on the keywords stands, and a constraint excludes a row only when a field the
  row carries contradicts it. For every other live keyword search the row must prove every clause,
  and an absent field excludes. A row arriving in another search's answer reaches a search that
  already holds it only by proving its query, then merges into the held row.
- **Ownership by place.** The session keeps the requests it put on a link in order; each answer
  — rows, empty, or undecodable — belongs to the oldest unanswered request and settles that
  search's server leg. Place is trusted only while the Owed Set is empty: a request whose answer
  wait runs out adds an owed entry; an answer arriving with nothing outstanding pays back the
  oldest; an entry lapses after `OWED_LAPSE` (60 s). While any answer is owed, answers have no
  owner and their rows go only where they prove a query. The Owed Set lives and dies with the
  session.
- **`0x99` answers** have no place: their rows go to every live keyword search that proves them.
- **The same query twice** sends both requests; each answer satisfies both, so both show the same
  rows.

## Consequences

- A search never waits behind another, and a row never appears in a search it does not answer.
- A Kad-only operator can search; a search with no server leg completes on its walk.
- If a server ever answered a link's requests out of order while nothing was owed, two owners
  would swap answers; no server is known to.
- An answer later than `OWED_LAPSE` past its wait shifts the next place by one; every row still
  reaches every search it proves.
- Front ends read leg states and render them in their own words; core events carry no prose.

## Considered options

- **Replace the running search on each `StartSearch`, as aMule does.** Rejected: front ends hold
  every search of the run live.
- **A server queue with sweep turns and a Kad same-query rule.** Rejected: a search would wait
  behind others (up to 24 s for the third of three), and a late answer could land in the next
  search.
- **A core-minted id with a caller token echoed beside it.** Rejected: one search with two names.
- **Joining an identical query's request.** Rejected: it ties the second search's leg to the
  first's lifetime to save one small request.
- **Moving dial and login inside the session task, queuing requests in a `Connecting` state.**
  Rejected: the operator-connect claim states the same ordering at the existing seam without
  re-routing every establishment failure path.
