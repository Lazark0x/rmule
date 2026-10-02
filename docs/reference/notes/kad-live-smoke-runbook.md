# Kad live smoke runbook (manual, unscored)

**Scope:** Kad source discovery (ADR-0043).

This is the one place in the Kad source-discovery work where rmule touches the **public Kad
network** — the mixed-fleet check where non-aMule implementations (eMule builds,
mods) ever exercise rmule. It is a **manual** procedure run by a human operator.

## Doctrine — read before running

These rules are load-bearing, not advice. They mirror the **Private Mesh
Evidence** doctrine in `crates/rmule-kad/CONTEXT.md`.

- **Never CI.** The public DHT is nondeterministic; this smoke never runs in an
  automated gate and never becomes a scored exit criterion. Scored Kad exit
  criteria are private-mesh and deterministic only (ADR-0043).
- **No public bytes committed as evidence.** Nothing observed on the public
  network is promoted to a fixture, ever. Real-client protocol facts are proven
  only on the private, self-owned mesh (`kad-source-capture`,
  `kad-distance-ordering-capture`). `rmule-cli kad join` writes **no capture tap
  to disk** by design — its observability is human-readable stdout you read and
  discard.
- **Observation only.** The smoke proves rmule *survives and behaves* as a live
  citizen. It proves no wire-format fact — those are already captured privately.

## What it checks

`rmule-cli kad join` spawns one live `rmule-kad-net` node on rmule's persisted
Kad identity (random KadId + stable UDP port, generated once and kept in the
Durable Store — ADR-0043, ADR-0083), bootstraps to operator-supplied public contact endpoints,
and runs for a bounded window printing a routing census. Optionally it fires one
source lookup and prints the projected **Peer Source** rows.

This is the **node**-level health check. Core's download integration (the second
Source Discovery Policy channel) is proven separately and deterministically by
the serverless E2E (`crates/rmule-core/tests/kad_serverless_e2e.rs`), so the live
smoke does not need to download anything.

## Prerequisites

1. Build the CLI: `cargo build -p rmule-cli` (or `--release` for a long run).
2. A data directory for rmule's databases. The identity is generated on first
   use; check it with `rmule-cli --data-dir <DIR> identity show`. The Kad
   identity is minted on the first `kad join`.
3. One or more **public bootstrap contact endpoints** as `A.B.C.D:PORT`. rmule
   has no `nodes.dat` import or hostname warm-start yet (deferred to the
   public-join slice, see Backlog), so you supply concrete IPv4 endpoints — e.g.
   a contact read out of a known-good `nodes.dat`, or a peer you already run.

## Procedure

```sh
# 30-minute join, routing observation only:
rmule-cli --data-dir /tmp/rmule-kad-smoke \
  kad join --bootstrap A.B.C.D:PORT [--bootstrap A.B.C.D:PORT ...] --duration 1800

# Same, plus one source lookup on a known-popular file hash after warmup:
rmule-cli --data-dir /tmp/rmule-kad-smoke \
  kad join --bootstrap A.B.C.D:PORT --duration 1800 \
  --search 'ed2k://|file|name|SIZE|HASH32|/'
```

The node prints, every 15 s:

```
routing: live=<N> peak=<N> responded=<N> served_lookups=<N> elapsed=<T>s
```

- `live` — contacts currently in the routing table (`ContactAdded` −
  `ContactEvicted`).
- `peak` — the high-water mark of `live`.
- `responded` — contacts that answered rmule's probe (validated-live).
- `served_lookups` — `KADEMLIA2_SEARCH_SOURCE_REQ` from strangers that rmule
  answered.

## Checkpoints (what "passing" looks like)

1. **Routing grows and survives.** `peak` climbs past a small threshold (tens of
   contacts is a healthy sign on a reachable network) and `live` stays non-zero
   across the full ≥30-minute window — the table does not collapse to zero after
   the initial bootstrap.
2. **rmule keeps serving strangers.** `served_lookups` (and inbound routing
   traffic generally) is non-zero: real peers route through rmule of their own
   volition and rmule answers — the same bidirectional-acceptance idea the
   private interop join asserts, observed live.
3. **A real source lookup resolves.** With `--search` on a known-popular hash,
   the node prints `kad: sources found (<N> row(s))` with at least one
   `source: dial <ip:port>` line — a projected direct **Peer Source**. Non-direct
   rows (firewalled / low-id) are reported as diagnostics and not dialed.

A run that meets 1 + 2 is a healthy citizen; 3 additionally exercises the
requester walk against the real network.

## Recording observations

Append what you saw to `08-live-smoke-runbook.md` under `## Comments`: the
bootstrap endpoint(s) used, the peak/live/responded/served numbers over the run,
whether a source lookup resolved, and any rough edges. **Do not paste raw
datagram bytes** — record behavior, not wire bytes.

## Findings → backlog

Rough edges and divergences are follow-up work for joining the public network,
not implemented here. Expected members, all deferred by ADR-0043:

- Packed `0xE5` **emit** (decode is already in scope).
- Kad UDP obfuscation (the encrypted transport wrapper).
- `nodes.dat` import/export + routing warm-start (so bootstrap is not
  hand-supplied endpoints).
- Rate limits and IP filtering for public exposure.
- Robust self-IP / self-port detection (firewall/NAT awareness).
- Hostname bootstrap resolution.

**eMule-under-Wine trigger (and only this).** If live behavior diverges from the
private aMule-mesh results in a way that implicates a **non-aMule lineage** (i.e.
the divergence cannot be explained by rmule or by aMule's known behavior), that —
and only that — is the trigger to add an eMule-under-Wine oracle (ADR-0043).
Ordinary rough edges (missing warm-start, self-IP detection, rate limits) are
backlog, not lineage divergences.
