# The Announce Policy: shares may be withheld from servers that answer related searches

## Context

On a server that grants related search (`SRV_TCPFLG_RELATEDSEARCH`, `0x40`, in its
`OP_IDCHANGE`), anyone can ask which files are shared alongside a given file, and the answer
includes what this operator shares together. rmule controls only what it announces, and to which
server.

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**The Announce Policy:** announce by default; a preference, off by default, withholds the share
set from servers that grant related search (`ServerPolicy::withhold_from_related_search`, stored
as `WithholdSharesFromRelatedSearch`). Withheld shares stay available over Kad and on every server
that does not grant it; there is no per-server switch. It is core-owned server-list configuration
beside the Dead Server Limit (ADR-0052): a Core Setting (ADR-0069) the actor starts under,
changed live through the settings handle.

The Session Follower decides per session, from the session's grants as they stand:

| Policy | Server grants related search | Told this session | The follower |
|---|---|---|---|
| off | either | anything | announces the current set (`OP_OFFERFILES`) |
| on | no | anything | announces the current set |
| on | yes | nothing, or Withheld | sends nothing: **Withheld** |
| on | yes | Announced | sends nothing more: **Announced before withholding** |

Switching the policy off while a session is Withheld announces at once. What was announced cannot
be taken back in the session: aMule's offers are incremental (`SharedFileList.cpp:1599-1607`,
`:1657-1665`), and an empty `OP_OFFERFILES` is the keep-alive the Lugdunum author recommends
(`ServerConnect.cpp:641-648`), not "forget my files"; the operator is told a disconnect ends it.
An announce's result is typed (`AnnounceOutcome::Announced { file_count }`,
`Withheld { file_count, reason }`, or `Unsaid`), and the serve raises
`ServeEvent::FilesAnnounced` or `ServeEvent::FilesWithheld` from it, so a withheld set is never
logged as announced. `DiagnosticsSnapshot::share_announcement` carries what the connected session
was told, and the Networks server details word it (ADR-0080).

**The Offer Queue.** The follower hands a session the whole set; what crosses the link is what the
connection has not been told, in batches, at a pace the server allows. One queue per session, in
the session's own task, like the search spacing (ADR-0035):

- **Offers are incremental.** aMule marks each file published per connection and sends only the
  unmarked (`SharedFileList.cpp:636-643`, `:691-697`). A file goes again only when its completeness
  changed, as `RepublishFile` does (`:657-663`). The newest set replaces the queue, so a file that
  left the set before its turn never goes; what was told stays told. An empty delta sends nothing.
- **Whatever the server's limits, one packet stays under them.** ed2k-server closes a connection on
  an `OP_OFFERFILES` declaring `hard_limit_files` or more (`connection.rs:748-760`, Lugdunum's rule,
  7 500 in its shipped config), so a share that size in one packet cost the session and then every
  reconnect. A batch is at most `min(ST_SOFTFILES, 200)` (`SharedFileList.cpp:707-710`) and under
  `ST_HARDFILES`.
- **The legacy pace is 200 records a minute** (`ED2KREPUBLISHTIME`, `Constants.h:45`), kept as a
  bucket in records, as ed2k-server keeps its own: a small delta costs a small part of the minute
  instead of waiting for it. Lugdunum may black out an address that publishes faster (ed2k-server
  README, *OFFERFILES v1*), which nothing here measures.
- **OFFERFILES v1 is adopted.** Every login asks with the string-named `uint32` tag `offerfiles_v`
  of `1`, and the session's first `OP_SERVERIDENT` decides for its whole life: all five values
  present once each and `uint32`, version `1`, soft and batch and interval above 0, hard above
  batch, or legacy. A later ident changes nothing. A v1 connection sends the smallest of the soft
  budget left, `offerfiles_batch_max`, `ST_HARDFILES - 1` and 1 000, one batch's worth per
  `offerfiles_min_interval_ms`, and stops when the budget is spent: a re-offer takes no budget
  (README, *Re-offers*), and a new file past it would not be indexed. At the server's defaults a
  55 000-file share goes in under three minutes instead of four and a half hours.
- **The first batch waits for that ident**, because a 200-record batch against a smaller
  `offerfiles_batch_max` is not indexed. It waits at most 5 s; a server that says nothing in that
  time is legacy, and the ident's own soft and hard files, or else the Server Figures', set the
  batch.
- **A file the server cannot take is left out**, not the announce with it: a large file to a server
  with no large-file grant (`SharedFileList.cpp:732`).
- **Withholding stops the queue.** The policy switched on mid-way leaves what was told told and
  sends no more.

`share_announcement` reads `Announcing { told, of }` while the queue drains, or while a spent budget
leaves part of the set untold, and `Announced` once the set is out; `AnnounceOutcome::Announced`
says the set was taken up. The login tag rides only through `LoginAdvert::offer_pace`, so a login
without it stays aMule's byte for byte.

## Consequences

- Whether Lugdunum drops a client's offered files on disconnect, and what it does with an empty
  offer, are unmeasured; nothing here rests on either.
- A share past a server's soft budget on a v1 connection stays part-told, and the operator reads
  how much. On a legacy connection the queue runs to the end, as aMule's does.
- Whether a stock Lugdunum takes the login tag, and a burst of small deltas, are bench claims.

## Considered options

- **A per-server announce switch.** Rejected: the policy is one rule about a server capability.
