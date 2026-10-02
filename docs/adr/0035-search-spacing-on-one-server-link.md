# Search requests on one server link go at least two seconds apart

## Context

The servers have their own rules. An eD2k server answers one link's requests in order,
one answer each: ed2k-server runs a frame to completion before reading the next and
answers even an unparseable request (`connection.rs:421-445`, ed2k-server at
`eacf7f1`), and aMule and eMule end their one in-flight search on each answer (aMule
`ServerSocket.cpp:421-431`, eMule `ServerSocket.cpp:366-378`). Lugdunum, closed source,
was measured on the bench (the `search-spacing` and `search-wire` flows; frames and
rulings in `docs/protocol/search-request.md`): it reads a link's searches by its clock's
whole second. A search in the same whole second as the link's previous one is answered
empty; one in the same or the next whole second is a strike; strikes add up over all of
an address's links, and the fourth closes the link, after which the server ignores every
later search from that address, a new login included. Neither stock client ever has two
server searches in flight or paces searches with a timer (eMule
`SearchResultsWnd.cpp:428-435`, `:455-467`, `:1225`; aMule `SearchDlg.cpp:441`,
`SearchList.cpp:378`, `:397-408`).

## Decision

- The session puts a server's search requests on one link **at least 2000 ms apart**
  (`SEARCH_SPACING`): a request two seconds after the previous one lands at least two whole
  seconds later, so it is neither answered empty nor a strike. The spacing applies to every
  server, because which server family it is cannot be known before it answers, and no server is
  owed faster than the stock clients go. It belongs to the session: a new session starts with no
  last send.
- A request waiting its turn holds its place; its answer wait counts from its send. Core reports
  `SearchWaitingForTurn { search_id, send_in }` while held and `SearchSentToServer` when it goes.
  A held request whose search ended is dropped unsent.

## Consequences

- Lugdunum's flood rule is never tripped by rmule's own searches; a more-results walk counts
  against the same spacing.

## Considered options

- **Spacing of 1000 or 1500 ms.** Rejected by measurement: 1000 ms makes every gap a strike and
  1500 ms about half of them.
