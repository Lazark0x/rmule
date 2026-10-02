# Known-File Marks: every search result says whether rmule has, fetches, failed, had or dropped the file

## Context

A search result that does not say whether the operator already has the file, is fetching
it, or dropped it invites a file fetched twice or a rejected one fetched again. rmule knows
a file through its download rows and the Shared File Registry; a file placed in the
download directory by hand would be unknown to it.

## Decision

A search result carries at most one of six marks, by this precedence:

| Mark | Meaning | Drawn |
|---|---|---|
| Downloading | a running, waiting or paused download | mark colour, bold |
| Failed | a download whose run ended in an error; it still holds the file's place | `mark_failed`, bold and underlined |
| Have | in the Shared File Registry and offered — on disk now | mark colour, dim |
| Withheld | in the registry, but rmule cannot read the file now | `mark_withheld`, underlined |
| Had | was in the registry; its file has since left the disk | mark colour, italic |
| Cancelled | a download dropped before it completed | mark colour, struck through |

An unmarked row keeps the source-count tint; a marked row takes the mark's colour in its
place, and the attribute is the second cue so a mark survives a monochrome terminal. Marks
hold no column and are no Table Sort key (ADR-0070). Failed ranks above Have because the
store refuses a new download of the file while the failed row holds its place. Had and
Cancelled stay apart: one says the content was worth finishing, the other that the operator
gave up on it.

Have is membership of the Shared File Registry, filled only from shared directories
(ADR-0101); Withheld is the registry's withheld state (ADR-0106); Had is the Had Set
(ADR-0105).

**Adding a marked file.** Downloading is refused (the store refuses a second live download).
Failed asks once, naming the failure, and a yes restarts that download in place (ADR-0094).
Have, Withheld, Had and Cancelled ask once, naming the mark (and, for Have, the path; for
Withheld, the path, reason and day; for Had, the name the file last had and the day it left);
a yes starts the download at a free name. Nothing is duplicated silently and nothing
legitimate is forbidden.

## Consequences

- An operator sees, on every search result, whether they have, are fetching, failed, withheld, had
  or dropped the file.

## Considered options

- **A set of known-but-unshared hashes for Have.** Rejected: a second source of truth for what is on
  disk.
