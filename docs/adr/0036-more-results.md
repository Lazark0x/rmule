# More results: only the operator asks, and only the newest search on the link pages

## Context

A server may hold more rows than one answer carries. `OP_QUERY_MORE_RESULT` names no search: a
server pages the link's last search request and replaces it on every new one (ed2k-server
`connection.rs:68-70,435`). eMule offers a *More* button; neither stock client asks on its own.
Search requests share one spaced link (ADR-0035), and an answer belongs to its search by
place (ADR-0034).

## Decision

- Only the operator asks, as with eMule's *More* button: `SearchCommand::MoreResults
  { search_id }`. Neither stock client asks on its own.
- `OP_QUERY_MORE_RESULT` names no search; a server pages the link's last search request and
  replaces it on every new one (ed2k-server `connection.rs:68-70,435`). The session therefore names
  at most one **pager**: the search whose own owned answer said more while its request was still
  the newest on the link. Any later search request ends it. A request the eD2k session refused never
  reached the server and gives its place back, restoring the pager it ended. The pager is published
  as `DiagnosticsSnapshot::search_more_results`.
- A request for more is a request like any other: spaced, owned by the search that asked, answered
  in its place. One still waiting when a search request goes out is dropped unsent; one from a
  search that is not the pager is refused (`SearchMoreRefused`).
- The page joins the same result set. The search is live again from `SearchMoreRequested` and
  completes again after the page and the quiet window. At most five pages follow the first
  (eMule's `MAX_MORE_SEARCH_REQ`); past them the operator is told rmule has stopped.

## Consequences

- A page never reaches a search the server is not paging, and paging never goes faster than
  the spacing allows.
- An operator sees when rmule stops paging, after the fifth page.
