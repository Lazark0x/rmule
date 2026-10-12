# File links: every field a reference reads is read, and the link's sources are the run's first candidates

## Context

An eD2k file link carries more than a hash, name and size: part hashes, an AICH root, peer
and web sources, and fields only one client writes, such as emule-qt's `s6=`. aMule 2.3.3
(`src/ED2KLink.cpp`) and eMule 0.70b (`srchybrid/ED2KLink.cpp`) each read a different
subset and skip what they do not know. Links are read leniently and packets strictly
(ADR-0008).

## Decision

rmule reads every file-link field a reference reads, skips and names what neither reads, and
refuses only what is malformed. References: aMule 2.3.3 `src/ED2KLink.cpp` and eMule 0.70b
`srchybrid/ED2KLink.cpp`.

| Field | eMule | aMule | rmule |
|---|---|---|---|
| `p=` part hashes | `ED2KLink.cpp:174-206` | `ED2KLink.cpp:234-259` | read as a `PartHashSet` |
| `h=` AICH root | `ED2KLink.cpp:208-215` | `ED2KLink.cpp:260-268` | read as an `AichRootHash` |
| `s6=[v6]:port,…` | — (emule-qt's own) | — | read |
| `sources,<host>:<port>,…` | `ED2KLink.cpp:228-321` | `ED2KLink.cpp:191-233` | read into `LinkSources::peers` |
| `sources@YYMMDD,…` | `ED2KLink.cpp:238-259`: none taken past the date | not read | read; the date applied at intake |
| `<host>:<port>:<crypt>:<hash>` entry | port only | crypt byte, and the user hash when bit `0x80` is set (`ED2KLink.cpp:215-230`) | crypt byte and user hash kept |
| `s=<url>` web source | becomes an HTTP source (`ED2KLink.cpp:140-173`) | skipped | read into `LinkSources::web`; nothing consumes it |
| `kadsources,<hash>:<kadid>` | nothing dialable read | skipped | accepted and ignored |
| any other field | skipped (`default: ASSERT(0)`, `:216-217`) | skipped (no `else`, `:188-270`) | skipped, and named in `LinkRead::skipped_fields` |

- One bad entry never costs the link or the rest of the list (eMule's `nInvalid` skip). An
  entry is skipped when its port is missing, zero or past `u16`, its crypt byte does not parse,
  or bit `0x80` is set with no 32-hex user hash. A host that is not an IPv4 literal is kept as
  a name. Peers and `s6=` hints are capped at 64 together (emule-qt `kMaxLinkSources`). Field
  names match case-insensitively. Still refused: an empty field, a field with nothing before
  its `=`, a bad hash, size or source list.
- The canonical link a download row keeps carries the web sources in the parameter section
  and the peers after `s6=` in the source section, as eMule writes them
  (`AbstractFile.cpp:439-443`), so a resumed run starts from them again.
- **A link's sources are the run's first candidates.** As both references hand them to the
  download at once (aMule `DownloadQueue.cpp:1497-1500`; eMule `DownloadQueue.cpp:262-295`),
  the runner turns each peer into a `SourceSighting` (a High ID with the link's crypt byte
  and user hash; an `s6=` hint as an IPv6 source), resolves names off the actor (5 s per name,
  IPv4 answers only), drops the lot past the `@` date, and puts them at the front of the
  candidate pool (ADR-0030) through the same ingest gates as a server's answer. A run whose link
  carries a usable source neither waits for a connection nor fails on a silent server.
- **A second link** for a file a live, running download holds is a second link, not a second
  download, as in both references: its sources reach the run's later-link inbox and core
  reports `LinkSourcesAdded` (named, admitted, new). A second link naming no source, or one for
  a download with no run, is refused `DuplicateDownload`, before the store's path check.

## Consequences

- A link either reference accepts, rmule accepts, and a skipped field is named rather
  than lost silently.
- `s=` web sources are kept and used by nothing; HTTP download is a non-goal.

## Considered options

- **Refusing every unknown link field.** Rejected: both references skip one and read the rest,
  so a link either client accepts, rmule accepts.
