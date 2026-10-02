# rmule-bootstrap

Zero-config bootstrap acquisition: the first HTTP capability in rmule. A fresh install ships with no server list and no Kad contacts, so it cannot join either network unaided. This crate owns **URL acquisition** — the deterministic, explicit-time pipelines that fetch a `server.met` (and, on command, a `nodes.dat`) and reconcile the bytes into an install *plan* — all behind a single I/O seam (ADR-0065). The wire decoders live in `rmule-ed2k` and `rmule-kad`; this crate is pipelines-over-a-seam, not a decoder home.

## Language

**Bootstrap Acquisition**:
The crate's bounded context: turning a URL into a reconciled, ready-to-install plan for a network rmule cannot otherwise join cold. Spans the `server.met` pipeline, the first-run decision, the auto-update URL walk, and the command-only `nodes.dat` pipeline. It acquires and reconciles; it never persists, dials, or holds protocol state.
_Avoid_: bootstrap service, downloader, updater, server-list manager

**Fetcher Seam**:
The crate's sole I/O seam — `get(url, max_bytes) -> Result<Vec<u8>, FetchError>`, an `-> impl Future + Send` (RPITIT, not `async_trait`). Every pipeline is generic over it, so the fetch is the only corner that ever touches a socket and no unit test opens one. `FetchError` is deliberately HTTP-client-agnostic (`Transport` / `Status` / `TooLarge` / `Timeout`) so no `reqwest` type leaks past the seam.
_Avoid_: HTTP client, downloader trait, transport layer, reqwest wrapper

**ReqwestFetcher**:
The sole production `Fetcher`: reqwest over rustls (never native-tls), with redirect / timeout caps baked into the client and the body cap enforced while streaming. Confined behind the optional, default-on `reqwest-fetcher` feature — the crate's only corner that links an HTTP client or TLS stack. Disable the feature and the crate is the pure seam + pipelines + decision, so a consumer that only needs the machinery (`rmule-core`'s Join Sequence, `rmule_core::join`) never pulls reqwest/rustls into its tree.
_Avoid_: the Fetcher (it is one impl of it), TLS layer, HTTP client config

**server.met Pipeline**:
`fetch_server_met`: one bounded GET → **Parse-Before-Install** → **Add-New / Update-Known Merge** against the installed list → a `ServerMetInstall` plan. One-shot, no retry (a failed cold-start fetch waits for the user, aMule parity), so exactly one `Fetcher::get` call and the first failure returned as-is.
_Avoid_: server-list sync, refresh loop, retrying fetch

**Parse-Before-Install**:
The pipeline parses fetched bytes fully in memory before any install; a parse failure rejects the whole payload and leaves the caller's installed list untouched. aMule's temp-file discipline (download to temp, parse, only then swap) collapsed to a value-level pass that mutates nothing on failure.
_Avoid_: streaming install, partial merge, temp-file swap

**ServerMetInstall**:
The reconciled outcome of a `server.met` acquisition — a *plan* the caller applies, not an applied effect. Carries the reconciled `servers` (installed first with duplicates folded, fresh appended) plus honest `added` / `updated` counts, and projects onto the store seam via `endpoints()` (dropping — with a logged warn — any row that cannot form a `ServerEndpoint`, e.g. a zero port). Touches no store and no socket, so its merge semantics are assertable as plain values.
_Avoid_: applied install, server store, side-effecting result

**Add-New / Update-Known Merge**:
aMule's `LoadServerMet` reconciliation, keyed by `(ip, port)`: a fresh row whose endpoint is already installed folds in via `ServerMetEntry::merge` (listname always taken fresh, description only when the fresh one is non-empty, priority kept); a new endpoint appends. Installed order is preserved, and a duplicate within one fresh payload folds into the row it duplicates.
_Avoid_: replace, dedup, overwrite, upsert

**First-Run Decision**:
`should_auto_fetch_server_met` — a pure predicate over three facts: eD2k participation on ∧ server list empty at start ∧ the operator auto-fetch switch (default ON). amuled fetches a list unconditionally on a cold start; rmule reproduces that default exactly but gates it. This crate owns the *decision*; the *hook* that supplies the facts and runs the pipeline is `rmule-core`'s Join Sequence (`rmule_core::join`).
_Avoid_: first-run hook, auto-fetch loop, cold-start trigger (that is the hook, not the predicate)

**Auto-Update Walk**:
`fetch_server_met_auto_update` — the `addresses.dat` role. Walks every configured URL in order, fetching and merging each through the `server.met` pipeline against the running accumulated list; one URL failing does not stop the walk. Returns per-URL outcomes plus one aggregate `ServerMetInstall` whose `added` / `updated` are the per-URL counts summed across the whole walk. Default OFF (aMule's `AutoServerlist`, dormant with an empty list).
_Avoid_: mirror failover, retry list, parallel fetch

**nodes.dat Pipeline**:
`fetch_nodes_dat` / `decode_nodes_dat` — the Kad counterpart, **command-only**: aMule's `nodes.dat` fetch is user-/EC-triggered with no first-run auto-fetch, so no `should_auto_fetch_*` decision exists for it. Try-normal-then-fallback dispatch: the normal reader first, falling back on `BootstrapEdition` to the v3 bootstrap-edition reader over the identical bytes. Yields a `NodesDatInstall` plan — `Contacts` (merge straight into a running node) or `BootstrapCandidates` (dial only).
_Avoid_: Kad bootstrap service, auto-fetch nodes, routing-table writer

**BootstrapDialList**:
An `rmule-kad`-owned dial list this crate *loads*, never owns: the v3 bootstrap-edition `nodes.dat` candidates land in the caller's list via `decode_nodes_dat`, to be dialed one at a time on Kad's 15 s / 2 s cadence, unified with the config-endpoint seeds (`KadCommand::SeedBootstrapDialList`). The crate reconciles bytes into it; the running `KadNode` owns and drains it.
_Avoid_: routing table, contact list, bootstrap-crate type (it belongs to rmule-kad)

**Cold-Start Arc**:
The full amuled first-run path proven end-to-end in `tests/bootstrap/cold_start_e2e.rs`: empty list → real GET of a `server.met` naming a live fake server → parse/merge → the acquired endpoint logs in against the ADR-0040 `FakeEd2kServer`, in-process. The correctness-tier proof that the pipeline's plan actually joins a network.
_Avoid_: smoke test, unit fixture, capture golden

## Relationships

- The wire decoders live elsewhere: `rmule-ed2k` owns `ServerMet` / `ServerMetEntry`, `rmule-kad` owns `NodesDat` / `BootstrapDialList`. This crate is **pipelines-over-a-seam** — fetch, parse through those decoders, reconcile — and adds no wire format of its own.
- Every pipeline is generic over the **Fetcher Seam**; the only concrete I/O is **ReqwestFetcher**, confined behind the optional `reqwest-fetcher` feature so `rmule-core` can depend on the seam + pipelines + decision without linking an HTTP client or TLS stack.
- Pipelines return **plans, never effects** (`ServerMetInstall`, `NodesDatInstall`): they touch no store and no socket beyond the fetch. Persisting a plan and reconnecting an idle session are the caller's effects — `rmule-core`'s Join Sequence (`rmule_core::join`).
- The **First-Run Decision** is `server.met`-only. `nodes.dat` has no auto-fetch decision anywhere in this crate or in core, preserving aMule's own asymmetry (`UpdateNotesDat` is command-triggered only).
- A `NodesDatInstall` plan is injected into a running `rmule_kad::KadNode`: `Contacts` via `KadCommand::MergeContacts`, `BootstrapCandidates` via `KadCommand::SeedBootstrapDialList`.
- The crate depends on `rmule-ed2k`, `rmule-kad`, and `rmule-primitives`, plus optionally `reqwest`; it does not depend on `rmule-core` (core depends on it). Its pipelines are `async` but bind no runtime — a driving runtime (tokio) enters only at `rmule-core`.
- Unlike the sans-I/O protocol crates, `rmule-bootstrap` emits **Diagnostic Trace** (`tracing`): flow at `debug`, and a `warn` when a reconciled row is dropped for not forming a valid `ServerEndpoint`. Library-first — it installs no subscriber; a consumer does.
