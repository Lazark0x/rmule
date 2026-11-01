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
  (`record_upload` / `record_download`, once per transferred block) lands in the ledger's
  memory, the whole ring's totals, loaded at the first call. Every read of the ring is
  answered from there, so the serve loop and the download runner never wait on the store
  to rank a peer or count a block (ADR-0031): one read costs 0.8 µs (release build, Apple
  silicon, 10,000 rows), so ranking 5,000 identified peers took 4.2 ms for every input the
  loop saw, and an accrual queued behind any immediate commit's device flush. What moved
  reaches the store as one immediate transaction at the next `CreditStore::checkpoint`:
  the actor calls it once a minute on the blocking pool, and on shutdown beside the
  `clients.met` save. A crash between checkpoints loses at most that window of accrual.
- **Schema evolution: a store-wide version and a linear ladder.** A meta table holds
  `STORE_VERSION`. Each upgrade step opens the old table under the old `Record` type,
  rewrites it into the new one and drops the old, in one write transaction. A record
  change bumps `Record::VERSION` and lands a step, and so does a new table whose absence an
  older build would write past, because the operator's store holds downloads a reset would
  lose. A step's old types are compiled only while the step exists. The ladder has a floor,
  the oldest version a published build wrote: 13, which v0.1.0 shipped. A file under it is
  refused with its version and the floor, and so is one newer than the build, on a read-only
  handle before the writing open touches a byte, so the build that can read the file finds
  it as it was. A file its last run left open has to be repaired to be read at all, which
  keeps every row; its refusal comes behind the repair.
- **Nothing climbs without a way back.** Before the first rung of a climb the store copies
  the file to `rmule.redb.v<found>` beside it, written whole under another name and renamed
  into place. A copy that fails refuses the climb and leaves the file as it was; a copy of
  that version already there is kept, because it is the older of the two. A climb that
  stopped resumes at its rung, and the version found then gets a copy of its own. Copies
  are never deleted by rmule, since they hold what a rung's bug would otherwise take.
- **A part file can outlive the store.** Beside each `<name>.part` lies `.<name>.part.link`, one
  line: the canonical ed2k link, with the Part Hash Set as soon as it is known, which is before
  any part is verified. When the store has no row for a part file that stands, attach adopts it
  as a Paused download: every part of that set is recorded as a claim, and the resume's re-hash
  (ADR-0094, "Damaged parts") is the proof, as it is for any record. The line is plain text, so
  an operator can also read it by hand.
- **The Data Directory is private.** One owner, `data_dir::make_private`: the directory is
  0700, and `rmule.redb`, its copies and the Run Log's two files are 0600, enforced at every
  open and so repaired on an install older than the rule. The store holds the Secure
  Identification key, the User Hash and every download's name; the log at the full level
  holds peer addresses. On Windows the directory's inherited ACL stands.
- **A refused open is typed to the operator.** `StoreError` keeps the engine's reason;
  `open_refusal` sorts it into another process holding the file, a newer store, a damaged
  file, a disk that said no, and a climb that failed, and `CoreError::StoreRefused` carries
  that to the front end's words. A repair or a climb says so while it runs. The TUI does not
  enter its alternate screen over a core it could not attach: it prints the reason and
  exits 1 (ADR-0069).
- **One failed store write stops the store until a restart.** The engine latches every
  failed write: each later call answers `PreviousIo` until the file is reopened. The store
  counts that as stopped, not as a failed call. It does not reopen under its live handles: a
  reopen must run the repair, and the disk that refused the write has not changed. The core
  tells the operator once to free the disk and restart. The volume the store lies on is held
  to the free-space floor beside every part's own (ADR-0094), so a disk filled by downloads
  stops them before it stops the store.
- **One unreadable row costs that row.** A read of a whole table yields per row. Only a
  decode fails per row; an engine failure still fails the read. The core reports the row it
  could not read and goes on with the rest. A rung still refuses a row it cannot read, and
  the copy above holds what it refused.
- **A part or final path inside the Data Directory is stored relative to it** (store version
  17), so moving the directory carries every download, to the very place it finishes; a path
  outside it stays absolute, because a directory the operator set keeps the downloads placed
  in it (ADR-0115). The Temp Directory setting takes the same rule (store version 18); the
  Download Directory setting is never inside it (ADR-0101). A shared file row keeps its absolute
  path: no shared directory lies inside the Data Directory, and a finished file reaches it only
  through a tool's `--out`. A `Completing` row rewrites a stale one, and a finished one is found
  gone by the Registry Check.
- **Every live record's bytes are pinned by a test.** postcard is positional and the engine
  compares only the tag, so a shape edit with no bump passes everything but a byte pin. This
  is a file format.
- **No in-memory twins.** One implementation per seam; tests and front ends that need
  isolation open the engine's in-memory backend.
- **A first run creates a fresh `rmule.redb`.** Files of any other storage engine in the
  data directory are ignored — never read, renamed or deleted.

## Consequences

- Two invariants are rmule's to keep, not the engine's: every record kind writes through
  `Indexed<T>` (enforced by visibility — the raw tables are private to the wrapper), and
  every record change lands a ladder step (a review rule, backed by each record's byte pin).
- `redb` has no `CREATE TABLE IF NOT EXISTS`: a read on a table no write has created
  fails, so `open` creates every table in one write.
- A second process cannot open the store while rmule runs.
- If a measured hot path ever needs batching, `Durability::None` per transaction is the
  lever, added with the caller that needs it; on the prototype a 64-commit batch cost
  90 µs per block.
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
