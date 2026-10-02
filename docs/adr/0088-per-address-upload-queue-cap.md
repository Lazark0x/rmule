# At most three waiting upload-queue entries per address, an IPv6 /64 counting as one

## Context

Every route into the upload queue — an accepted connection, a dialed connection's serve
half, an adopted callback, a peer risen through a NAT-T Tunnel — admits a waiter
(ADR-0031). Without a per-address bound one host fills the queue. An IPv6 end site mints
addresses inside its `/64` at will, so the bound must count a `/64` as one address, as
kno's hardenings do for every IPv6 rate limit and cap (ADR-0087).

## Decision

At most `MAX_WAITING_PER_ADDRESS = 3` **waiting** entries per `AccountingKey` — one IPv4
address or one IPv6 `/64` — counted at `UploadSlotQueue::admit`, which every route into the
queue reaches (an accepted connection, a dialed connection's serve half, an adopted callback,
a peer risen through a NAT-T Tunnel, keyed by its remote endpoint).

- **Three, and the unit is the wait list.** eMule refuses at `>= 3` same-IP waiters
  (`srchybrid/UploadQueue.cpp:603-613`); aMule counts the requester plus every in-scope client
  on its wait list, refusing at `> 3` (`src/UploadQueue.cpp:493-516`, `:341-349`). A granted
  slot is not a queue place.
- **The answer at the cap is silence** — no `OP_ACCEPTUPLOADREQ`, no `OP_QUEUERANKING`, no
  `OP_OUTOFPARTREQS` — as both references `return` before framing anything. `OP_QUEUEFULL 0x93`
  is the UDP reask reply, not this. The refusal is counted
  (`SessionCounters::upload_address_cap_refusals_total`, fed by
  `ServeEvent::UploadAddressCapReached`), because the wire carries no trace of it.
- **A re-ask is not an arrival:** the cap is tested after the queue's two idempotent paths,
  as both references return from the duplicate scan first.
- **The `/64` is the point.** An end site mints addresses inside its `/64` at will, so a
  per-`/128` cap caps nothing (kno's `RateLimitScope`, `PeerAddressing.h:205-233`).
- Behind CGNAT the cap stays three, as aMule's already is for IPv4; no heuristic tells a
  CGNAT range from a farm.

## Consequences

- One host, or one IPv6 `/64`, holds at most three places in the queue; a fourth ask is
  answered with silence and visible only in the counter.
- Hosts behind one CGNAT address share three places, as they already do on aMule.

## Considered options

- **eMule's second, deleted-clients gate on the upload queue**
  (`srchybrid/UploadQueue.cpp:614-618`). Rejected, as aMule rejected it
  (`src/UploadQueue.cpp:502-516`): it locked out clients behind a shared address for two hours
  after they merely cancelled downloads.
- **A per-address queue cap relaxed for CGNAT.** Rejected: it would hand the queue to whoever
  claims to be shared.
