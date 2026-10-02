# Durable state lives in one redb file behind the rmule-store typed layer; protocol crates stay storage-free

## Context

rmule keeps durable state across five seams in `rmule-core`: `DownloadRepository`,
`SharedFileRegistry`, `CreditStore`, and `AppConfigStore` ⊃ `ServerListStore`. The
protocol crates model file identifiers, part hashes, ranges, sources and protocol state;
none of that needs a database schema, and protocol fixtures are repository files.

The store has to be safe under concurrent async callers, transactional where one logical
write spans several records (the provisional hash-set write is twenty part hashes plus an
authority update), and checked by the compiler rather than by SQL text. A store handle
that is not `Sync` forces a `tokio::sync::Mutex` around every seam, which serialises the
whole core across each disk `.await`, including the per-block verified-part write.

## Decision

**Protocol crates are storage-free.** `rmule-primitives`, `rmule-ed2k`, `rmule-peer` and
`rmule-kad` depend on no store. The value types durable records carry (hashes,
`ServerEndpoint`, `Ed2kText`) derive `serde` behind an off-by-default `serde` feature, so
the wire crates stay serde-free. Repositories belong to `rmule-core`; file content lives
in filesystem files, not in the store.

**One `redb` database file**, `rmule.redb` in the data directory, spoken to through
`rmule-store`, a thin domain-free typed layer:

- **Engine: `redb` 4.x** — pure Rust, no mandatory third-party dependencies, ACID with
  MVCC readers and a single writer, `Database: Send + Sync`, a documented file-format
  stability promise, and an in-memory backend.
- **One file, one `Database`.** Every seam holds an `Arc` to the one store and its own
  table set, so cross-seam atomicity is a choice. `redb` takes an exclusive file lock: one
  process owns rmule's state, and tooling that wants live state goes through the core.
- **Typed layer, not a query language.** A `Record` trait (serde, `const NAME`,
  `const VERSION`); one generic `Packed<T: Record>` implementing `redb::Value` with
  `type_name() = "rmule:{NAME}@v{VERSION}"`, so the engine refuses a table written under a
  different record version; an `Indexed<T>` wrapper that owns a record's primary table and
  its declared secondary indexes and is the only write path, so an index cannot rot because
  a caller forgot it; `open` / `open_in_memory`; a store-wide version ladder. Values are
  encoded with `postcard`.
- **Store handles are `Sync`.** Every seam method takes `&self`; the core holds each seam
  as an `Arc` of the trait object (or a generic where the trait is not dyn-compatible),
  with no mutex wrapper.
- **Durability: `Immediate` on every commit**, a real device flush (`F_FULLFSYNC` on
  macOS). Everything a caller is told is durable flushes where it is written: downloads,
  registry writes, the server list, `bind_public_key`. **One exception:** credit accrual
  (`record_upload` / `record_download`, once per transferred block) commits through
  `Store::begin_write_deferred` (`Durability::None`). Every later read sees it, and the
  flush waits for the next immediate commit of any seam; `CreditStore::checkpoint` forces
  one, and the core calls it on shutdown beside the `clients.met` save. A crash between
  checkpoints loses that window of accrual.
- **Schema evolution: a store-wide version and a linear ladder.** A meta table holds
  `STORE_VERSION`. Each upgrade step opens the old table under the old `Record` type,
  rewrites it into the new one and drops the old, in one write transaction. A record
  change bumps `Record::VERSION` and lands a step, and so does a new table whose absence an
  older build would write past, because the operator's store holds downloads a reset would
  lose. A step's old types are compiled only while the step exists.
- **No in-memory twins.** One implementation per seam; tests and front ends that need
  isolation open the engine's in-memory backend.
- **A first run creates a fresh `rmule.redb`.** Files of any other storage engine in the
  data directory are ignored — never read, renamed or deleted.

## Consequences

- Two invariants are rmule's to keep, not the engine's: every record kind writes through
  `Indexed<T>` (enforced by visibility — the raw tables are private to the wrapper), and
  every record change lands a ladder step (a review rule).
- `redb` has no `CREATE TABLE IF NOT EXISTS`: a read on a table no write has created
  fails, so `open` creates every table in one write.
- A second process cannot open the store while rmule runs.
- If a measured hot path ever needs batching, `Durability::None` per transaction is the
  lever; on the prototype a 64-commit batch cost 90 µs per block.
- Cold open is slower than an SQL engine's (about 5–20 ms against 90 µs, because redb
  flushes on open), paid once per process.

## Considered options

- **SQLite through `rusqlite`.** Rejected. A `rusqlite::Connection` is `!Sync`, which
  forced a mutex around every seam; the schema lived as SQL strings the compiler never saw;
  and four files carried four `PRAGMA user_version` ladders. On a prototype (Apple M1 Pro,
  APFS, criterion means) redb read 8–12× faster (`credit_totals` 5.95 → 0.50 µs,
  `download_load` 8.60 → 0.71 µs), wrote single rows 2.6–3.1× faster at matched
  device-flushing durability, and wrote the twenty-hash provisional set 61× faster
  (twenty-one auto-commits, 359 ms, against one transaction, 5.9 ms). File-backed write
  timings on APFS varied up to 35× run to run and are order-of-magnitude figures. SQLite's
  plain `fsync` also does not reach the device on macOS.
- **`native_db`** (typed models over redb). Rejected: pinned to redb 2.x, no durability
  control, composite keys type-checked at runtime by name string, stale upstream, and
  fourteen more dependencies including a second `thiserror` major.
- **Other pure-Rust engines.** Each failed at least one hard criterion: an in-memory
  backend, active maintenance, or a compatible licence.
- **Pure storage traits with the engine chosen later.** Not needed: the traits exist (the
  five seams), and the engine is chosen.
- **Importing state from an earlier storage format.** Rejected: there is no prior user
  state to carry, and an importer would keep a C library and four legacy decoders in the
  tree for one caller.
