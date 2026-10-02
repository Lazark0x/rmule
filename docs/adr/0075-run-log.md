# The Run Log: a lean level safe to share and a full level, each value classed by its type

## Context

The Run Log is what an operator attaches to a report when reachability fails or a defect
shows in an ordinary session. A log that holds peer addresses, file names or search text
cannot be shared in public; one that holds too little cannot answer what rmule claimed,
what the network did with it and where it stopped.

## Decision

The **Run Log** (`rmule.log`) is evidence for reachability diagnosis and for defects met
in an ordinary session. It is written at one of two levels, chosen by the preference
*Full run log* (stable key `run_log_full`), off by default.

- **Lean** holds reachability evidence and event codes: rmule's own addresses and ports,
  port mappings, the server endpoint, login steps, verdicts, counts. It holds no peer
  address, file name, path, hash or peer software string. **Full** adds everything lean
  withholds, except what is never written.
- **The class of a value is decided by its type, in one place.** A log line is a
  `Record`: a stable event code plus typed fields, each added by a method naming what the
  value is (`own_address`, `peer_address`, `file_name`, `file_hash`, …). The kind's class
  is one exhaustive match, and a line renders at a level by dropping the fields the level
  does not admit. No event or field is formatted whole and no line comes from Debug
  output.
- **Every core event is projected by an exhaustive match** with no wildcard arm, so a new
  variant fails to compile until it is classed.
- **Never written at either level:** search query text, the names in search results
  (only counts are written), and File History paths (only its size). No `Record` method
  accepts them.
- **Lean writes only records.** Free-form `tracing` lines reach the file at the full level
  alone, under the `RMULE_LOG` filter; at lean `RMULE_LOG` still filters records.
- **A step a reachability diagnosis needs is an event, never a free-form line.** Each
  answer to "what did rmule claim, what did the network do with it, where did it stop"
  reaches the lean log by one of four paths: a **level** the core already holds (connected
  server, port mappings, learned addresses, Kad verdicts and own buddy state, NAT-T own
  mapping), written by the reachability trail on change; an **edge** of a server session
  (`ServerConnectionEvent`); a **login step** (`CoreEvent::ServerLogin { server, step }`,
  one `LoginStep` per row below, evidence that no front end folds into state); and a
  **buddy dial that did not hold** (`CoreEvent::BuddyDialFailed { buddy, cause }`).
  Anything else — per-datagram drops, a plain dial the crypt policy refused with no
  address, a serving buddy's relays, a failed store write, the TUI's failures to reach
  the core — is a defect trail written at full; a step a diagnosis turns out to need is
  promoted to an event, never by widening lean.

| Step | When the core emits it | Lean fields |
|---|---|---|
| Mapping wait | the Login Mapping Wait ends, only with a mapping runtime | own listen port, settled or not |
| Dial failed | the TCP dial to the server does not come up | server endpoint, cause code, OS error kind and number |
| Login sent | the link is up and the login has left | server endpoint, transport family, own TCP port, own client-UDP and Kad UDP ports as advertised, own IPv6 as advertised |
| Closed before answer | the server ends the link before answering | server endpoint, close cause code, OS error kind |
| Port test awaited | the link is up and the server's High-ID test may dial in plain until the login is answered | server endpoint |
| Port test arrived | a connection from the awaited server is accepted inside that window | server endpoint, admission code |
| Port test ended | a connection from the awaited server, inside the window or late, ends | server endpoint, end code (including, for one admitted as an ordinary peer, who closed it) |
| Port test window closed | the login is answered or ends | server endpoint, whether a test arrived |
| Port test late | a connection from a server whose window closed within the last 60 s arrives | server endpoint, milliseconds since the close, admission code |
| Answered | the server assigns an id at login | server endpoint, own client ID, own public IPv4 as the login establishes it (or the server's address where rmule refused a Low ID's report of it as ours), each TCP flag granted |
| Reassigned | the server assigns an id again mid-session (`OP_IDCHANGE`) | as Answered |
| IPv6 probe | the server states a probe verdict on our IPv6 | server endpoint, verdict code |
| Kad recheck | a High ID lands while Kad's TCP verdict reads firewalled | server endpoint |

Two events outside a login carry a full-only address: **Buddy dial failed** (cause code,
OS error kind and number; the buddy's TCP address at full) and **Kad helper test late**
(`CoreEvent::KadHelperTestLate`: a connection from a Kad helper whose TCP-check window
closed within the last 60 s; milliseconds and admission code; the helper's address at
full). The Awaited Testers remember the last server window and each helper window for
60 s after it closes, and the listener's plaintext refusal carries the dialer's address,
so a late test is reported rather than lost.

| Field kind | Method | Class |
|---|---|---|
| Own address (external, listen, an address of ours a server or peer reported) | `own_address` | lean |
| Server endpoint | `server_endpoint`, `server_address` | lean |
| Own client ID | `own_id` | lean |
| Port | `port` | lean |
| Count, counter size, rank, index, download or search number | `count` | lean |
| Code (event, reason, verdict, state, protocol, family, OS error kind and number) | `code` | lean |
| Peer address (endpoint, Kad UDP endpoint, a peer's Low ID, the own buddy's address) | `peer_address`, `peer_id` | full |
| Peer software | `peer_software` | full |
| File name, size of a named file | `file_name`, `file_size` | full |
| File hash, part hash | `file_hash`, `part_hash` | full |
| User hash, a peer's Kad ID | `user_hash`, `kad_id` | full |
| Path | `path` | full |
| URL (a server.met mirror) | `url` | full |
| Search query text, search result names, File History paths | (no method) | never |

| Event | Lean fields | Full-only fields |
|---|---|---|
| Download: queued, recovered | id, state, failure code, counts | file hash, name, size |
| Download: progress restored, damaged parts, part file lost, finished file rejected, restarted, hash set, part assigned, released, verified, completed, cancelled, cleared, paused, resumed, failed, failure not recorded, waiting for sources, waiting for connection | id, part index, counts, codes | part hashes of a damaged part |
| Download: server login accepted | id, own client ID | none |
| Download: sources found | id, counts | none |
| Download: source exchanged, peer selected, queued, slot granted, slot timeout, remote queued, reask acked, reask queue full, reask dropped, part assigned, part released, peer retired | id, rank, part index, codes | peer address |
| Serve: shared, unshared, offered | none | file hash |
| Serve: withheld | reason code | file hash |
| Serve: shares unwatched, share rejected, files announced, serving failed, serving stopped | codes, counts | none |
| Serve: serving started | own listen address | none |
| Serve: upload slot granted, peer queued, sources served | rank, count | peer address, file hash, peer software |
| Serve: queue full, low-ID abuse refused, reask or name ask malformed, address cap reached, slot released, waiter left | cause code | peer address |
| Search: every event | search number, counts, leg states, codes | none (results are counted, never listed) |
| Scan: every event | counts, reason codes, OS error kind and number | directory and file paths |
| Server list: added, updated, removed, priority, static | priority, static flag | none |
| Server list: update started | none | URL |
| Server list: updated, update failed | counts, failure code | none |
| Server connection: connecting, connected, connect failed, disconnected, reconnecting, reconnect ended | server endpoint, own client ID, step and failure codes, attempt and delay counts | none |
| Server login step | as in the step table | none |
| Buddy dial failed | cause code, OS error kind and number | buddy address |
| Kad helper test late | milliseconds since the window closed, admission code | helper address |
| Secured identity mismatch | none | user hash |
| Command rejected | reason code, port | none |
| Peer reach routed | route code, own low ID where the route names one | peer address, Kad UDP endpoint, buddy Kad ID |
| NAT-T tunnel risen | transport and role codes | peer address |
| Client UDP bind failed, socket bound without a family | port, family, role, OS error kind | none |
| File history | entry count | none |
| Kad stopped, quitting | reason and step codes | none |
| Reachability level change | own addresses, ports, statuses, protocols, verdicts, lease seconds, buddy state code | none (the buddy's address is never written from the level) |

- The level is one shared handle read by every writer and by the subscriber's filter, so a
  change in Settings applies to the next line.
- At 16 MiB the file moves aside as the single predecessor. A failed rotation is retried
  only after another cap's worth of bytes.

## Consequences

- A lean Run Log can be attached to a public report without leaking peers, files or
  searches; a new core event cannot ship unclassified.
