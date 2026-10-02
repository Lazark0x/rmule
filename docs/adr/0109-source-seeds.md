# Source Seeds: a restart dials first the peers the last run knew, without asking anyone

## Context

A download that ran before a restart knew peers that had the file. **Source Seeds** are that record:
per download, the peers a restart dials first, without asking anyone.

A restart that waits for a server or Kad before dialing anyone loses peers that were sending
a moment ago, and a Kad-only or server-less run has nobody to ask. aMule keeps a `.seeds` file
beside a rare file's part file (`PartFile.cpp:941-1013`).

Every `file:line` is stock aMule 2.3.3 (`4e8f2b3c`), the counterparty the bench runs;
aMule facts are read, never ported (ADR-0004).

## Decision

- **The set:** one per download, keyed `(DownloadId, peer endpoint)`, held in rank order (the store's
  children table). Each seed holds the endpoint (either family), the peer's User Hash and **crypt
  stance** (supports / requests / requires, stored as the source-exchange v4 options byte) when the run
  learned them — the hello's first, else the record's — its rank class, and when it was written. The
  stance is required: under a `required` policy a peer whose stance is unknown is refused before any
  socket (`PeerCrypt::outbound`, ADR-0049).
- **Who is a seed:** a directly dialable peer — a High-ID source, or a Low-ID candidate's IPv6 half —
  never one reached by callback, buddy relay or NAT-T (its Low ID belongs to one login), never a
  distrusted peer (ADR-0090). Up to **N** per download, the preference `Remember peers` (1–255,
  default 10), ranked **Received** (sent a block this run), **Ranked** (granted a queue rank or slot),
  **Known** (held by an owner and not spent); newest fact first within a class, by the brain's own
  sequence.
- **Written** every 10 minutes and at quit, before the runs are aborted, from the ranking each run
  publishes every reask sweep; a write replaces the set, an empty ranking writes nothing, and a write
  for a completed or cancelled row writes nothing.
- **Age:** a seed older than 24 hours is deleted at load, never dialed.
- **The dial:** attach loads the fresh seeds of every download it restores (`Active`, `Queued`) and says
  once how many it will dial for how many downloads (`DownloadEvent::SeedsLoaded`); a run the operator
  resumes or restarts loads its own. Seeds pass the same ingest gates (IP filter, dial family, distrust),
  go ahead of the link's sources in the candidate pool (ADR-0030), and the fleet starts at once, so they
  are dialed before any lookup answers, with no server or Kad at all. A seed-fed run that has tried every
  seed waits for a connection (`SourceWait::NoSession`) until its first lookup is answered. Peers are not
  servers: the connect rule of ADR-0095 does not cover these dials.
- **Deleted** in the transaction that moves the row to `Completed` or `Cancelled`, and with the row when a
  completed download is cleared; a paused or failed row keeps its seeds until they age out.
- **Visible:** a worker dialed from a seed carries `remembered` on its diagnostics row; each seeded run
  reports `DownloadEvent::SeedsDialled { written, dialled, answered }` once every dialled seed has
  answered or ended, or when the run ends first.

| Rule | aMule 2.3.3 (`PartFile.cpp`) | rmule |
|---|---|---|
| which downloads | rare files only: more than 20 sources writes none (`:955-957`) | every running download |
| how many | `MAX_SAVED_SOURCES` 10 (`:941`) | `Remember peers`, default 10 |
| order | sources downloading now, then the list from its end (`:960-981`) | received, ranked, known; newest first |
| Low ID | skipped (`:964`, `:975`) | directly dialable only, IPv6 halves included |
| what is kept | id, port, User Hash, crypt options (`:1005-1013`), one time | endpoint, User Hash, crypt stance, rank class, time |
| when written | at exit, behind a preference (`amule.cpp:1390-1393`) | every 10 minutes and at quit; no preference |
| age | 2 hours (`:1092`) | 24 hours |
| when dialed | once the IP filter has loaded, as `SF_SOURCE_SEEDS` | at attach or a resume, ahead of every other source |
| where | a `.seeds` file beside the part file (`:988`) | the Durable Store, beside the download's row |
| on cancel and completion | a cancel removes the file; a completed file's stays | deleted, both |

## Consequences

- A restart resumes from the peers the last run knew, with no server and no Kad.

## Considered options

- **Seeds without the crypt stance.** Rejected: under a `required` policy every seed was refused before its
  socket, silently.
