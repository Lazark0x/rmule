# The Related-Files Search is its own query kind, on the connected server only

## Context

A server that grants related search (`SRV_TCPFLG_RELATEDSEARCH`, `0x40`, in its `OP_IDCHANGE`)
answers which files are shared alongside a given file, for a query naming that file's hash.
aMule types the request into the search box as a phrase. The query carries no keyword, so
content attribution (ADR-0034) cannot prove its rows, and sent to Kad or the global sweep it
would travel as a keyword.

## Decision

- Its own query kind, holding one file's hash and name; core writes the `related::<HASH>` term and
  routes by kind, never by matching a prefix in text. The wire form is in
  `docs/protocol/related-files-search.md`.
- Connected server, TCP only: the sweep and Kad legs are settled from the start. It is offered
  wherever a row names a file, and withheld, with the reason shown, when not connected or when the
  server does not grant `SRV_TCPFLG_RELATEDSEARCH` (`SearchRefused`).
- It shares no words with its query, so it is attributed by place alone and is only ever an owner;
  its rows also reach every live keyword search they prove. Answered while an answer is owed, it
  cannot be told from a late one: nothing is shown and it fails with
  `RelatedAnswerUnattributable`.
- The session keeps its own copy of the grant, from the login and moved by each `OP_IDCHANGE`, and
  puts a related request on the link only under a grant it holds. A request already on the link
  keeps its place and answer after a withdrawal, as every reference does; one still waiting its turn
  is refused by its own search (`RelatedSearchNotOffered`). The eD2k session reports the
  `OP_IDCHANGE` before refusing and refuses in order, so a refusal is always the newest related
  request on the link.
- An empty answer claims only what rmule knows — none found, or too few sources to answer. A server
  that grants the search without implementing it looks the same, and rmule keeps no per-server
  verdict.

## Consequences

- A file hash never reaches Kad or the global sweep as a keyword.
- A related answer that cannot be placed is refused by name rather than shown under the
  wrong search.

## Considered options

- **A Related-Files Search typed as a phrase into the query, as aMule does.** Rejected: routing by a
  string match sends a file hash to Kad and the sweep on one miss.
