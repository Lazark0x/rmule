# A cold start rests on seeds the binary carries; a fetched list adds to them and never replaces them

## Context

A cold start used to take every server and every Kad seed from one fetch. The default
mirror URLs are plain `http`, as aMule's are, so whoever sits on the path answers that
fetch. The reserved-range check of ADR-0085 judges where a row points, not who wrote it.
A forged list therefore chose every server rmule could log in to and every contact its
routing table began from, and search results, source lists and own-address reports all
come from those parties. It happens once per install, and the result persists.

aMule does the same. That makes it compatible, not safe, and the wire does not depend on
it: how a list reaches rmule is outside the protocol.

Every list on the mirror path is the word of whoever delivered it. HTTPS improves that
where a mirror offers it, but nothing in this repository or its references shows that
`upd.emule-security.org` serves either file over `https`, and an on-path party can also
block port 443. A root of trust that does not depend on the path is needed either way.

## Decision

**The binary carries a seed list, and the seed list is the root of trust.**
`crates/rmule-bootstrap/seeds.txt` is one checked-in data file of eD2k servers and Kad
nodes, compiled in. Each release refreshes it. It is read through `Seeds`, which
`BootstrapConfig` carries: the `rmule` app takes the compiled-in list through its
deployment, and every other caller, tests and tools included, starts with none, so a
default configuration never names a public host.

**A seed is a row, and it comes first.** On a cold start the seeds go in before any
fetch, whether or not the fetch is switched on:

- **eD2k:** a server list empty at start receives every seed server, at `High` priority,
  before the first-run fetch runs. A seed is an ordinary list row from then on: the
  operator can remove or reprioritise it, and it is dead by the rule of ADR-0052.
- **Kad:** with no persisted contact and no operator seed, the seeds open the Bootstrap
  Dial List. A fetched nodes.dat dials after them.

**A fetched row is a claim beside the seeds, never over them.**

- The add-new / update-known merge keeps a seed where it is. A list can name a row that
  matches a seed, which fills in its name and description as for any row; it cannot
  remove one, or change its priority or its place.
- A fetched nodes.dat never enters the routing table directly. The Kad ID and the
  verified flag in it are the mirror's word, so each contact becomes a dial candidate
  that must answer first, at most 50 of them. A persisted nodes.dat is rmule's own and
  stays trusted.

**A failed or odd fetch leaves the seeds as they are.** Because the seeds are installed
first, falling back to them takes no step of its own: the failure is reported and the
list stands. A list is **odd**, and is refused whole, when, after the reserved-range
check of its URL's host:

- it holds more than 4,096 rows, which no mirror lists;
- no row is left that names a usable address;
- more than half of its rows were dropped, since a mirror does not list what no server
  can be at; or
- with at least 8 rows left, more than half of them sit in one IPv4 `/24` or one IPv6
  `/48`, the shape of one party listing itself many times.

The same judgement runs on every fetched server.met, however it was started, and on every
fetched nodes.dat. It never runs on a persisted file or on the seeds. Oddity is a cheap
filter for lazy forgeries and broken mirrors, not proof of origin: a careful forgery
passes it, and what bounds that forgery is that the seeds stay.

**A warm start reads neither seeds nor mirror.** Anything persisted, a server row or a
Kad contact, means rmule is past its cold start, and that side of the network neither
re-adds seeds nor fetches. A seed the operator removed stays removed, and a fixed set of
hosts does not take every install's traffic on every start. An operator who empties the
list has a cold start again on the next run. A release's refreshed seeds reach new
installs and emptied lists, not a list that already works.

**HTTPS where the mirror offers it.** The fetcher speaks `https` with the bundled root
store, and a redirect from `https` to `http` is refused, because following it would give
back what the first hop gained. A default URL changes to `https` once the mirror is seen
to serve the file there; until then the defaults stay aMule's, overridable in Settings.

**An empty seed list is stated, not hidden.** A build whose file holds no seeds has no
root of trust, and the fetch is all it has. It behaves as before this decision, and a
cold start says so to the operator once and writes it to the Run Log.

## Consequences

- With at least one live seed, an on-path party can add rows, but it cannot choose every
  server or every Kad seed. A cold start with every fetch failing still has a list to
  connect to.
- An on-path party can still block a seed's address. Seeds bound the choice of servers;
  they do not promise reachability.
- A forged row can stay in the list beside the seeds. Connecting is the operator's act
  (ADR-0095), so it is dialed only if picked, and the seeds stand apart from it at `High`
  priority. The attack this leaves is a row an operator picks by its name.
- The nodes.dat fetch still runs beside Kad seeds on a cold start, so a binary whose
  seeds have all gone stale still joins. A joined node stops dialing, so a candidate
  behind a live seed is never dialed at all.
- A list from a laboratory with eight or more servers in one network is refused as odd.
  Such rows are added by hand, or served as separate lists of fewer than eight.
- Each release takes a fresh look at the seed file. A seed list left to age degrades to
  the fetch alone.
- `Fetcher::get` returns a boxed future, so `dyn Fetcher` exists and core holds the
  capability directly.

## Considered options

- **A signed list.** Rejected: it needs a publisher who runs a key and signs a list on a
  schedule, for a mirror rmule does not operate, and a key to guard, rotate and revoke.
  Embedded seeds give the same floor with no key, and refreshing them is a line in a
  release.
- **Seeds only when the fetch fails.** Rejected: a forgery is a fetch that succeeds, so
  the seeds would be absent in the one case they exist for.
- **Seeds replacing the fetch.** Rejected: a release's handful of servers would be the
  whole list, and stale seeds would strand an install with no way to recover.
- **Re-adding the seeds on every start.** Rejected: it brings back rows the operator
  removed and points every install at the same hosts at every start.
- **Trying `https` first on the default mirror, then `http`.** Rejected: an on-path party
  turns it into `http` by dropping port 443, and every other client pays a timeout. The
  scheme is in the URL, so it is the operator's and the release's to state.
