# Low-ID callback download via an adopted inbound worker

## Context

Server source answers (`OP_FOUNDSOURCES`) and global source answers carry Low-ID
sources: firewalled peers with a server-assigned id and no dialable endpoint. rmule
cannot dial them; they must be told — through the server that assigned the id — to dial
rmule. Dropping them leaves a download starved on exactly the files a first-class peer
must fetch, and wastes sources already paid for.

rmule never learns a Low-ID peer's real address; that is the point of Low-ID. The only
link between a callback request and the connection that answers it is the id the peer
reports in its hello, and that id is unique only per server.

## Decision

A Low-ID source is a first-class candidate whose connect verb is a server-relayed
callback; the called-back connection arrives on the inbound listener and is adopted as
that download's worker.

- **One pool, one fill loop.** The candidate pool (ADR-0030) holds Low-ID candidates
  beside dialable ones. Filling a worker slot with a Low-ID candidate emits
  `Decision::RequestCallback` and holds the slot pending until adoption or timeout.
- **The candidate is a record.** `LowIdCandidate` carries the Low ID; its server
  namespace (`None` for the connected server, `Some` for a global source whose own server
  must relay, ADR-0051); and, when the channel said so, the facts the other roads of the
  route tree need — User Hash, buddy contact, direct-UDP-callback support, Kad UDP
  endpoint, crypt options and the NAT-T bit (ADR-0061, ADR-0091). Every field is what a
  channel's bytes said or nothing; a source learned twice merges, newer facts winning, and
  silence withdraws nothing.
- **Callback Capability decides, per candidate, whether we may ask.** It is aMule's
  `CamuleApp::CanDoCallback` (`amule.cpp:3207-3256`) over three facts: the inbound
  listener is bound, our Server High ID, and the Kad TCP verdict (ADR-0060). A bound
  listener is required; either reachability fact is enough; and a node that is Low-ID on
  its server but Kad-open never asks its own server to relay, as aMule warns that breaks
  the protocol and earns a ban. The value is Self Reach's answer, re-read on every Reach
  Generation, never a login-time copy. Whether the listener is bound is read live
  (ADR-0031). A candidate we may not call back stays parked in the pool rather than spent,
  or takes another road of the route tree (ADR-0061, ADR-0091).
- **Correlation by namespaced Low ID.** A pending callback is keyed by `CallbackKey`
  `(server, low_id)`, where the server is the one that relays the callback and that the
  called-back peer reports as its connected server. The callback table holds, per key, an
  ordered list with one entry per requesting download, each carrying the file to request
  and the adoption channel. An inbound adoption spends the oldest entry; the others stay
  pending to their own deadlines, and only an entry's owner removes it (ADR-0107).
- **Triage decides late, per connection, in the adapter.** Accepting does not wait for
  the hello, so the routing key is known only once the connection identifies. Each
  accepted connection's adapter task pumps its events; on the first identification it
  consults the callback table. No match: the connection continues as a serve connection,
  unchanged. A match: bridging stops, the owned connection is driven as a download worker
  (`drive_peer_worker`) with the identity already known, and the worker goes to the
  registering download over its adoption channel. The serve side is told with
  `ServeConnEvent::Readopted`, never a false `Disconnected`. Triage sits after the IP
  filter and the ban gate, so adoption cannot skip them, and it is also where a dialer
  tunnel raised for a silent callback is adopted (ADR-0091). Core owns the table's policy;
  the adapter owns only the mechanism, keeping `rmule-peer` types out of core scheduling.
- **Two deadlines, both runner-owned.** The sans-I/O brain exposes only
  `on_callback_timeout`; the runner keeps a deadline heap. The slot-release deadline
  (`CoreConfig::callback_timeout`, 30 s) releases the slot, retires the candidate and lets
  the loop try the next. A candidate whose facts admit a rendezvous coordinator also arms
  `CALLBACK_SILENCE_FALLBACK` (12 s); when it fires the brain emits
  `Decision::FallToNatTraversal` and retracts nothing — the slot stays held and the
  callback may still land. Both share the one `CallbackKey`, so a single cancel ends the
  whole callback.
- **`OP_CALLBACK_FAIL` is diagnostic.** It carries no id and cannot be attributed to a
  pending callback, so the session only logs it and the deadline releases the slot.
- **`NoUsableSources`.** The terminal failure means no reachable source of any kind, not
  merely no High-ID source.

## Consequences

- The advertised TCP port and the inbound listener matter for downloading, not only for
  serving: without a bound listener Callback Capability is false.
- The server packets `OP_CALLBACKREQUEST`, `OP_CALLBACKREQUESTED` and `OP_CALLBACK_FAIL`
  are pinned from aMule source and rewritten, never ported (ADR-0004).
- Callback correctness — the server's reachability probe, relay and correlation — is
  regressed deterministically by `FakeEd2kServer` (ADR-0040), and live against real
  counterparties by the harness (ADR-0033).

## Considered options

- **Callback only as a fallback when dialable sources run short.** Rejected: a second-class
  tier of sources with its own code path; eMule treats Low-ID sources as ordinary.
- **A second listener or pool for callbacks.** Rejected: one connection registry already
  serves several consumers (ADR-0031).
- **Matching any unattributable inbound connection to a pending file.** Rejected: a fuzzy
  heuristic where the hello's reported id gives a precise key.
- **Routing the raw connection to a core-level router.** Rejected: it leaks `rmule-peer`
  connection types across the serve adapter seam.
- **Moving the accept loop into the adapter.** Rejected: the accept loop stays where the
  serve activity owns it.
