# Bootstrap lists are fetched over HTTP by rmule-bootstrap, behind one Fetcher seam, with aMule's defaults

## Context

A fresh install has no server list and no Kad contacts, so it cannot join either network
unaided. aMule acquires them over HTTP:

- **server.met:** `UpdateServerMetFromURL`
  ([ServerList.cpp#L830](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerList.cpp#L830))
  downloads to a temp file, merges with `LoadServerMet`, saves, and reconnects if idle.
  In amuled the first-run "download a server list?" prompt is compiled out
  (`#ifndef AMULE_DAEMON`), so the daemon fetches unconditionally on a cold start
  ([amule.cpp#L580](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/amule.cpp#L580)).
- **Auto-update:** aMule walks the `addresses.dat` URL list, merging each, gated on
  `AutoServerlist`, which defaults off, and the file ships empty, so the path is dormant
  ([ServerList.cpp#L868](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerList.cpp#L868),
  [Preferences.cpp#L1052](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Preferences.cpp#L1052)).
- **nodes.dat:** fetched only on a user or remote-control request (`UpdateNotesDat`,
  [amule.cpp#L2016](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/amule.cpp#L2016)),
  never on first run; an empty routing table logs and waits. On success aMule swaps the
  file and restarts Kad.
- aMule's default URLs are plain `http://upd.emule-security.org/…`
  ([Preferences.cpp#L1248-L1249](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/Preferences.cpp#L1248)),
  because its wxHTTP client cannot do TLS.

A bootstrap payload is trust-critical: a poisoned server.met is an eclipse-attack vector.

## Decision

**A crate of its own, `rmule-bootstrap`, owns URL acquisition.** Its pipelines are
deterministic and return a plan, never an applied effect, behind one I/O seam:

- **`Fetcher`**, `get(url) → bounded bytes`, is the only I/O seam. `ReqwestFetcher`
  (feature `reqwest-fetcher`, on by default) is the production implementation: `reqwest`
  with rustls, no native TLS, `default-features = false`, with redirect, size and timeout
  caps. Core depends on the crate without the feature and receives the fetcher injected,
  so no HTTP client links into core or any protocol crate.
- **server.met** (`fetch_server_met`): a bounded GET, then parse in memory before any
  install through the `rmule_ed2k::ServerMet` decoder (ADR-0066), so a payload that fails
  to parse leaves the existing list untouched; then aMule's add-new / update-known merge
  into a `ServerMetInstall` plan. Core installs the plan into the Managed Server List
  (ADR-0080) in a separate step, so a caller sharing the store with a live actor does not
  hold it across the fetch. Connecting is the Join Sequence's step (ADR-0067).
- **Auto-update** (`fetch_server_met_auto_update`): the `addresses.dat` role as a
  configured URL list (`auto_update_urls`), walked in order, each URL merged, one failure
  not stopping the walk. The toggle `auto_update_enabled` defaults off.
- **nodes.dat** (`fetch_nodes_dat`, `decode_nodes_dat`): a bounded GET, the normal reader
  with a fallback to the v3 bootstrap-edition reader (ADR-0066), then a `NodesDatInstall`
  plan whose contacts become the Kad node's seeds (ADR-0067). There is no file swap and no
  Kad restart.

**Defaults and first run.**

- **Default URLs** are aMule's exact values (`DEFAULT_SERVER_MET_URL`,
  `DEFAULT_NODES_DAT_URL`), overridable in config. The repository bundles no server list or
  contact list; these are URLs fetched at run time.
- **First-run server.met fetch:** when eD2k is enabled, the managed server list is empty at
  session start and `auto_fetch_server_met` is on (the default),
  `should_auto_fetch_server_met` says fetch. Default behaviour matches amuled's cold start;
  the divergence is that an off-switch exists. One shot, no retry loop: a failure waits for
  the operator, as in amuled. The `rmule` TUI decides it at attach and shows the switch in
  Settings as *Fetch list* (ADR-0067).
- **nodes.dat stays opt-in:** `auto_fetch_nodes_dat` defaults off, which is parity, and
  `should_auto_fetch_nodes_dat` fetches only when Kad is enabled, there are no seeds and a
  front end has opted in. The `rmule` TUI opts in (ADR-0067).
- **Hardening** that legitimate mirrors never notice: a response size cap, a redirect cap
  and a request timeout.

## Consequences

- A TLS-capable client is a wire-compatible hardening: the GET and payload are aMule's, and
  an operator can point the config at an https mirror.
- The deterministic tier drives the pipelines with a fake `Fetcher`: URL order,
  parse-failure-keeps-the-old-list, the merge, the trigger truth tables, one-shot no-retry,
  cap enforcement and the auto-update default. The cold-start test runs the whole arc in
  process: empty list, faked fetch, parse and merge, and a login with the parsed endpoint
  against `FakeEd2kServer` (ADR-0040).
- The capture tier is an open gap: its golden would be an aMule-authored `server.met` and
  `nodes.dat` (a pinned aMule's `SaveServerMet` and v2 writer) served to rmule from a local
  HTTP fixture. No public mirror snapshot is ever evidence.

## Considered options

- **`ureq`.** Rejected: a blocking client bridged into an async core.
- **Hand-rolled HTTP/1.1.** Rejected: a bespoke parser guarding an eclipse-critical input
  to save one dependency, with redirects and chunked encoding becoming our code.
- **`reqwest` with full features.** Rejected: rustls and the minimal feature set are all
  bootstrap needs.
- **Acquisition inside `rmule-core` or `rmule-net`.** Rejected: core would carry an HTTP
  client and pipeline state in the actor crate, and `rmule-net` is the protocol-socket
  runtime, not application-layer HTTP.
- **An unconditional first-run fetch, exactly as amuled.** Rejected: default behaviour is
  identical, and a headless daemon that contacts a third party with no off-switch is a
  shape rmule need not copy to be a good citizen.
- **Upgrading the default URLs to https automatically.** Rejected as invented behaviour;
  parity defaults with an operator override instead.
- **A nodes.dat fetch on every cold start.** Rejected as the default: aMule never fetches
  one unattended.
