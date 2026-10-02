# Upstream source is never committed; protocol references are cached locally from pinned sources

## Context

Implementing eMule-family protocols means reading a lot of outside material: the eMule
protocol specification, aMule and eMule wiki pages, other wikis, and the source trees
of eMule, aMule and their forks. Contributors need to read it offline and to know that
what they read is the exact revision a note cites, and the interop bench builds its
counterparty images from some of those source trees. Much of the material carries a
licence that does not clearly allow redistribution, and the source code is code that
ADR-0004 forbids porting. Committing it would redistribute it and put portable source
next to rmule's own code.

## Decision

**Upstream eMule and aMule source, forks included, is never committed or vendored.**
It may be cached locally, gitignored, cloned from a pinned commit, both for reading and
for building the interop images. The cached trees are the eMule Reference Source,
emule-qt and eMuleAI (ADR-0082) and the `kno/amule` fork
(`docs/reference/amule-kno/`). Docs and code comments cite source by pinned URL: a
commit SHA and a file path, as in `docs/protocol/source-map.md`.

`docs/reference/` holds the cache. **For a cached reference, git tracks only its
metadata sidecar and its licence file:** one `<slug>.meta.toml` per source (source URL,
retrieval date, licence, integrity pin, and why the source is kept) and one
`LICENSE.md` per source family. The bytes themselves are gitignored. Beside the cache,
git tracks the rmule-authored topic notes under `docs/reference/notes/` (ADR-0015). A
sidecar carries everything needed to rebuild its cache entry by hand, and
`docs/reference/README.md` gives the fetch and verify steps for each source kind.

Each source is pinned so that re-fetching returns the same bytes:

- A `git` source records a commit SHA, not a branch or tag; git objects are
  content-addressed, so the SHA is the integrity check. Its clone path is gitignored
  by path.
- A `file` source records an immutable revision URL where the upstream offers one
  (`?oldid=NNN` for MediaWiki, snapshot URLs, a retrieval date for static PDFs and
  pages without permalinks), plus the `sha256` of the fetched bytes. Wiki pages are
  fetched from raw or printable endpoints where available.

Bytes are stored exactly as fetched, with no conversion to Markdown or text. A
reference is a snapshot, not a living document: an upstream change is picked up by a
deliberate re-pin (new revision, new hash, new retrieval date).

A reference document that is not source code, such as a specification or a wiki page,
may be **vendored**, its bytes committed, only after licence review confirms
redistribution is allowed; it then leaves the gitignore with the same sidecar. No
document is vendored, so every reference is cached the same way.
`docs/reference/README.md` holds the licence tiers and the steps for adding a source.

## Consequences

- No eMule or aMule source byte, fork or upstream, enters git history, so the
  repository redistributes none of it and ADR-0004's no-porting rule is backed by
  physical separation.
- The interop images build from the same pinned local clones contributors read, so
  the bytes behind a capture and the source that explains them are the same revision.
- A fresh clone has dangling local-cache paths in the notes until the populate script
  runs; citations lead with the pinned URL and give the cache path second.
- The `sha256` in each `file` sidecar stays audit-meaningful. The populate script
  checks it on fetch; there is no CI gate on the cache.
- Conversion errors and sidecar drift cannot happen, because no derivative form is
  kept.
- rmule-authored notes are the implementation-facing documentation; cached references
  are supporting evidence.

## Considered options

- **Vendor every referenced source regardless of licence.** Rejected: it redistributes
  material without confirmed permission.
- **Links only, no local copies.** Rejected: it forces online reading, gives no
  guarantee that the page read is the revision a note cites, and leaves the interop
  images nothing pinned to build from.
- **Convert wiki HTML to Markdown and PDFs to text, or keep converted copies beside the
  originals.** Rejected: conversion introduces errors, and a second form drifts from
  the pinned bytes.
- **Track current-page URLs and accept upstream drift.** Rejected: the pinned hash
  would stop matching and the citation would stop meaning one revision.
- **Vendor upstream source under `docs/reference/` with a "reference only, do not
  port" notice.** Rejected: physical separation enforces ADR-0004 more reliably than an
  in-tree notice.
