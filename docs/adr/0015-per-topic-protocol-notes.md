# rmule-authored protocol notes are organised one file per protocol topic

## Context

Knowledge about one protocol mechanism, such as login, tags, AICH or Kad, is scattered
across several upstream sources: the eMule specification, wiki pages, and eMule and
aMule source. Implementation work needs one place per mechanism that gathers the wire
format, edge cases and behaviours to test, with citations back to those sources.

## Decision

rmule-authored protocol notes live at `docs/reference/notes/<topic>.md`, one file per
protocol topic (for example login, tags, packet framing, eD2k hash, links, server
protocol, server UDP, source lookup, AICH, Kad, peer transfer, LowID callback,
obfuscation, secure identification, user hash), indexed by
`docs/reference/notes/README.md`. Each note is implementation-facing: wire-format
tables, byte offsets, edge cases and behaviours to test. It cites cached references
by upstream URL first and local cache path second, and link-only sources by pinned
URL (ADR-0013).

## Consequences

- Implementation work consults one notes file per topic rather than several source
  summaries.
- A note stays tables and references, not a rewrite of an upstream page. A note that
  grows into a paraphrase is a sign that the upstream should have been vendored after
  licence review instead.
- `docs/protocol/source-map.md` stays an index of sources, not a home for notes; each
  crate's `CONTEXT.md` stays a glossary.

## Considered options

- **One summary per upstream source.** Rejected: implementers would cross-reference
  several summaries for every mechanism.
- **Expand `docs/protocol/source-map.md` inline.** Rejected: it mixes the source index
  with protocol content.
- **Glossary only, in each crate's `CONTEXT.md`.** Rejected: a glossary has no room for
  wire tables and edge cases.
