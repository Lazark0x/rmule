# The source-exchange ask follows aMule's gate, per peer and download, under every name the peer is known by

## Context

A source-exchange ask (ADR-0055) that goes out on every connect ignores aMule's cadence and
draws empty answers from the counterparty's throttle. aMule keeps the facts the gate reads on
its one client object per peer; rmule runs one worker per (peer, download) (ADR-0107), and a
peer may be reached by endpoint, by Low ID or by User Hash.

Every `file:line` is stock aMule 2.3.3 (`4e8f2b3c`), the counterparty the bench runs;
aMule facts are read, never ported (ADR-0004).

## Decision

**A source ask is sent only when aMule's gate would send it**, keyed per (peer, download), with
a per-download file clock.

aMule's `IsSourceRequestAllowed` (`DownloadClient.cpp:179-212`), with `uSources` the file's source
count, `valid` its sources on queue, downloading or connected (`PartFile.cpp:3467-3496`), `client`
the time since this peer last answered sources and `file` the time since any peer did, both plus
`CONNECTION_LATENCY` (22.05 s):

| Rule | aMule | rmule |
|---|---|---|
| the peer speaks the extended protocol | `DownloadClient.cpp:191` | `PeerSession::source_request_allowed` |
| SX2, or an SX1 nibble above 1 | `DownloadClient.cpp:191` | `PeerSession::source_request_allowed` |
| fewer sources than 90 % of `MaxSourcesPerFile` (default 300), at most 1000 | `DownloadClient.cpp:193`, `Preferences.h:270-273`, `Preferences.cpp:1027` | `SOURCE_ASK_SOFT_CAP` = 270 |
| very rare: not complete, never asked or `client` > 40 min, `uSources` ≤ 10 | `DownloadClient.cpp:196-199` | `source_ask_clock::wants` |
| rare: not complete, never asked or `client` > 40 min, `uSources` ≤ 50 or `uSources − valid` ≤ 25, `file` > 5 min | `DownloadClient.cpp:201-205` | `source_ask_clock::wants` |
| common: never asked or `client` > 160 min, and `file` > 20 min | `DownloadClient.cpp:207-209` | `source_ask_clock::wants` |
| an ask stamps the peer and the file clock to "answered 40 min − 44.1 s ago", inside `SendFileRequest`, only when the ask goes out | `DownloadClient.cpp:249-262`, `PartFile.cpp:2520-2523` | the record's asked stamp, on the session's `FileRequestSent` saying the request carried the ask |
| an answer stamps both clocks now | `ClientTCPSocket.cpp:1513-1515`, `:1538-1540` | the record's answered stamp |
| a UDP reask is skipped while a source ask is due, so the TCP ask can carry it | `DownloadClient.cpp:1269-1273` | every sweep reads `source_ask_clock::due` off each RemoteQueued record's facts |

The constants match both references: `SOURCECLIENTREASKS` 40 minutes (`Constants.h:38`; eMule
`Opcodes.h:68`), `SOURCECLIENTREASKF` 5 minutes, `MINCOMMONPENALTY` 4, `CONNECTION_LATENCY`
22 050 ms. `MIN_REQUESTTIME` is a different window (the uploader's spacing between one client's file
requests) and the gate never reads it. aMule runs the peer's window from its last **answer**
(`GetLastSrcAnswerTime`, `DownloadClient.cpp:184`), eMule from its last **ask**; rmule follows aMule,
so a peer asked and silent is asked again on its next connection.

aMule finds its one client object by whatever identifies the peer — a High ID by IP and port, a Low
ID by IP and port or `(low id, server IP, server port)`, any one by User Hash last
(`FindMatchingClient`, `ClientList.cpp:264-297`, `:334-343`). rmule has no client object; the facts
ride the peer's **Source Book** record (ADR-0090), inside one download, and its **Ask Names** are the
book's aliases and the User Hashes the record knows:

| Ask Name | Known | On the record |
|---|---|---|
| the peer's TCP endpoint | a High-ID source before its dial; any connection's remote end | an endpoint alias — the worker's key |
| `(server, low_id)` | a Low-ID candidate before its callback or punch | its `CallbackKey` alias, joined at adoption by the connection's endpoint |
| the peer's User Hash | a candidate record that carried it (`0x44`, SX v ≥ 2, Kad); any hello | the candidate's, the one a record stated with its crypt, or the live worker's hello |

A stamp lands on the record. A read merges the record's facts with those of every live record
sharing one of its User Hashes, and with what the book kept under each of its names: a name the
record stops answering to — its worker's hello hash at the worker's end, an endpoint or key it
drops, every name when it leaves the book — keeps the facts stamped so far in the book's run
tier, until aMule would have deleted the client object holding them: its client-list cleanup, a
pass every 34 minutes (`ClientList.cpp:975-1003`, `CLIENTLIST_CLEANUP_TIME`), forgets a name no
record answers to at that pass. A decision made before any connection reads the names the record
already holds.
Each record holds four facts:

1. **Asked** — stamped on `FileRequestSent` when the request the session wrote carried a source ask:
   the stamp is what was sent, not what was expected.
2. **Answered** — stamped on `SourcesReceived`, empty or not.
3. **Source Exchange Support** — the extended protocol, the SX1 nibble, SX2, as the session reads
   them off the hello and any legacy `OP_EMULEINFO` (aMule `ProcessMuleInfoPacket`,
   `BaseClient.cpp:843`, `:893`, `:918-921`, `:973-975`, `:986-988`), carried by the peer's
   `PeerIdentity`. One sender, in the session's order: the connection's router hands the identity up
   whole with `ConnectionEvent::Identified` and again at every revision
   (`ConnectionEvent::IdentityRevised`) — an adopted worker's own, read at accept, goes before the
   router starts; the later value wins, and the router forwards events already read before it closes
   the socket. `source_ask_clock::due` = support known and askable, and `wants`; a record
   whose facts the run never read is not due.
4. **Complete** — the peer's last advertisement for this file, from a probe (`FileProbed`) or a `0x91`
   status, false on a probe or `0x92` saying the peer lacks the file. **A peer is complete only when it
   says so with aMule's part-count-0 sentinel, or answers the name ask of a one-part file**
   (`DownloadClient.cpp:362`, `:405-409`, `:428`; eMule `:473`, `:516`). A spelled-out bitmap with every
   part present is not complete, in both trees. The session expands the sentinel for everything else
   that reads parts and says beside it whether the status was the sentinel
   (`FileProbeStatus::Available::complete`).

The gate's constants sit at `Constants.h:38`, `:39`, `:43`, `:66`, `:70` in 2.3.3 (`:44`, `:45`, `:51`,
`:78`, `:82` in the fork), with the same values.

## Consequences

- Source-exchange asks follow aMule's cadence, which spares the counterparty's source-exchange throttle;
  a peer's ask facts follow it under every name it is known by, so a Low-ID peer reached twice is not a
  stranger.
- The cadence is proven against fakes; a bench topology with a queuing stock sharer that has
  another source to name is what would prove it live.

## Considered options

- **A source ask on every connect.** Rejected: it ignores aMule's cadence and draws empty answers from the
  counterparty's throttle.
- **Counting a full bitmap as a complete source.** Rejected: neither tree does; such a peer is a part file
  whose last parts arrived and is asked on the rare cadence.
- **Running the peer's window from its last ask, as eMule.** Rejected in favour of aMule, the counterparty
  the bench runs.
