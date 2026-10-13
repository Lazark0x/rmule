# The registry against the disk: what is offered is readable now, and a peer is answered honestly when it is not

## Context

A shared file can vanish, change, or become unreadable at any time — deleted, renamed,
edited, its volume unplugged — and a peer asking for it must be answered honestly. aMule
drops the client and leaves the file shared on a read error
(`UploadDiskIOThread.cpp:318-364`, `UploadQueue.cpp:280-282`).

aMule citations are to 2.3.3 unless they say kno's fork; read, never ported (ADR-0082).

## Decision

**What rmule offers a peer is readable now; when it turns out not to be, the peer is answered
honestly and the row is corrected at that moment, not at the next start.**

- **Offered and withheld.** A row is *offered* while its file was last seen readable; otherwise it
  is **withheld** — kept in the registry with its hash set and source, its reason and the time rmule
  noticed, but offered for nothing. The withheld set is in memory only, since every start looks
  again.
- **Nothing is offered before it is looked at.** At start the **Registry Check** looks at every row
  once (one `stat`, nothing read). Until then the serve snapshot, the announce, the Kad publisher and
  the File-Known Predicate wait; the look's end fires the share trigger, which announces.
- **One look, five answers** (a row with no recorded time is compared on size alone):

  | The path now | Answer | The row |
  |---|---|---|
  | a file whose stamp matches | readable | offered |
  | a file whose size or time differ | changed | leaves, not Had; a scan hashes it again |
  | nothing, in a folder that is there | gone | leaves and joins the Had Set (ADR-0105) |
  | nothing, and no folder either | folder missing | withheld, with no time bound |
  | an error other than "not found", or a file that cannot be opened | unreadable | withheld, never Had |

- **Who rules.** A row under a live, watched scan's directory is the scan's: *gone* and *changed*
  only withhold it, and the scan rules (a move, a rehash, a leave). Every other row is the Registry
  Check's. A row the start look finds gone or changed is withheld at once and ruled on at the first
  recheck, a minute later, so a scan started in that minute can detect a move.
- **The Registry Check** runs on a thread of its own (it lives as long as the core, and a pool task
  that never ends would hold the runtime's shutdown), reads the registry through the actor, and ends
  within a quarter second of its stop flag. Every minute it looks again at each withheld row and
  nothing else, opening (not reading) a file its stamp says is back; a row withheld as unreadable is
  never offered again on its stamp alone, and a row under a shared directory the guards refuse
  (ADR-0101) is never offered again while it is refused: no look touches it then — not the start
  look, a recheck or a change notice — and the actor, which knows when a list change lifts the
  refusal, has it looked at that moment. It watches the parent directory of each row outside every
  shared directory, non-recursively, one watch per distinct parent, looking a second after quiet
  (at most five) and once a second after each watch begins. When that watch cannot start, the
  operator is told once; nothing polls in its place.
- **The serve path is a detector.** A failed read of a shared file (a block or an AICH build) stops
  the offer at once: the file leaves the serve snapshot, and every peer queued or holding a slot for
  it is told `OP_FILEREQANSNOFIL` and released, waiters first, so the freed slot never goes to another
  asker of the same file. Then the row is looked at and ruled on. aMule drops the client and leaves the
  file shared on a read error (`UploadDiskIOThread.cpp:318-364`, `UploadQueue.cpp:280-282`). A
  Partial Share (ADR-0113) is no row: a failed read ends its offer and is not looked at here.
- **What is announced is what is offered.** The serve snapshot (the `OP_OFFERFILES` announce and every
  file request) and the Kad publisher read the offered rows. A row withheld is re-announced without
  it and its Kad republish withdrawn; Kad has no unpublish, so a storer keeps the entry up to its
  5 h lifetime and a peer that finds it is told `OP_FILEREQANSNOFIL`. A row offered again is announced
  and published again.
- **Per-file serve counters** are keyed by hash and outlive the offer.
- **Dates** are when rmule noticed, never when the file was deleted, and the front end says so.

### What the front end shows

Shared Files has a **State** column — `shared`, or why the row is withheld and the day noticed —
sorted by rank (offered, missing, changed, folder missing, unreadable, folder refused), never by its words; a
withheld row's name is dimmed. Its title names the scans' progress. A strip of the shared
directories filters the table (ADR-0073). The events read as sentences in the status feed and the
log.

## Consequences

- Nothing unreadable is offered.
- Known disagreements with the disk: a Kad storer's entry outliving a withheld row by up to
  5 h; the first minute after start, when a row found gone is withheld but not yet ruled; a
  mid-file I/O error behind a readable start, offered again at each recheck and withheld
  again at the next failed read.

## Considered options

- **A durable withheld set.** Rejected: every start looks again, so it would only hold a stale answer.
