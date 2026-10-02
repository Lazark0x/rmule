# Kad notes are handled by Empty-Storer Parity: rmule behaves as an aMule storer that never holds a note

## Context

Kad's notes layer carries file comments and ratings: `KADEMLIA2_SEARCH_NOTES_REQ`
(`0x35`) and `KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`). It is human-layer metadata with no
transfer or source-discovery meaning, and rmule has no comments or ratings feature.

aMule's own storer is silent on the wire in every refusal path:

- **`0x35`:** the handler has no gates; it parses `<target16><filesize8>` and calls
  `SendValidNoteResult`
  ([KademliaUDPListener.cpp#L1250](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1250)),
  which replies only inside the index-hit branch. A miss sends nothing, and so does a hit
  whose rows all fail the file-size filter
  ([Indexed.cpp#L869](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L869)).
- **`0x45`:** a silent return while UDP-firewalled
  ([#L1276](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1276)),
  a silent drop outside `SEARCHTOLERANCE` unless on a LAN
  ([#L1287](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1287)),
  and a `0x4B` ack only when `AddNotes` succeeds
  ([#L1329](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1329)).
  A publisher facing silence keeps walking, as it does past a storer at capacity
  (`KADEMLIAMAXNOTESPERFILE` 150).

## Decision

**rmule is an Empty-Storer Parity citizen for notes:** it behaves byte for byte as an
aMule storer whose notes index is permanently empty and permanently refusing. It builds no
notes state, and every silence it produces is one some legitimate aMule 2.3.3 storer
produces today.

- The node routes `0x35` and `0x45` to `rmule_kad::notes` before general message decoding,
  beside the keyword dispatch, as deliberate handlers rather than unknown-opcode
  accidents.
- Each handler classifies a request through aMule's gate order, purely for counting, and
  emits nothing. `0x35`: parse the 24-byte payload and record it served empty
  (`KadEvent::NotesSearchServedEmpty`). `0x45`: refused while UDP-firewalled (ADR-0058),
  then outside tolerance, then a bounded tolerant tag walk (FILENAME and FILESIZE
  first-wins, unknown tags skipped, aMule's own parse at
  [#L1300](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1300))
  that only finds the payload's end, then refused at capacity. Every tag is discarded.
  Malformed payloads take the envelope-tolerance path.
- rmule never sends `0x35` or `0x45`. aMule sends them when its user looks up or writes a
  comment
  ([Search.cpp#L549](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Search.cpp#L549),
  [#L747](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Search.cpp#L747)),
  and rmule has no such feature.

## Consequences

- Because the gates sit in aMule's order, a real notes store would replace exactly one
  point, the always-refusing `AddNotes` equivalent, with something shaped like ADR-0062's
  `keyword_store`. Nothing else would reopen.
- The rows are graceful, so the evidence is the deterministic tier (ADR-0045): decode
  vectors (well-formed `0x35`, truncated `0x35` and `0x45`, oversized and malformed `0x45`
  tag lists), the load-bearing silence assertions (no datagram from any branch), one
  counter test per gate, and a mesh-sim notes-publish walk that meets the rmule storer,
  gets no ack and proceeds unbroken.

## Considered options

- **Acknowledging without storing** (`0x4B` with load 100). Rejected: aMule never acks a
  refused note publish, so the ack would be an invented byte that tells the publisher its
  note is stored while searchers find nothing.
- **A full notes storer.** Rejected: it is feature semantics, and the rows are graceful.
- **Leaving both as unknown opcodes.** Rejected: identical on the wire, but impossible to
  name in tests and counters.
