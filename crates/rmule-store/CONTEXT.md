# rmule-store

The domain-free durable layer (ADR-0083): one engine file, spoken to through typed records rather than a query language. It knows nothing about downloads, credit or servers — the domain crates declare their record kinds and indexes against it and own every table they register.

## Language

**Store**:
One durable state file (or the same store on the engine's in-memory backend) opened by exactly one process, plus the read and write transactions that see it. A caller does not open and close a transaction by hand: it hands the store a closure, which commits when the closure returns and aborts when it fails. Every write commits durably before it returns, unless the caller asked for a **deferred write** — a commit with no device flush, for a counter whose last few seconds are worth less than the flush, made durable by the next ordinary commit or by a **flush**. A store is opened against a **Schema** — the full list of tables its owners have registered — and a **Version ladder**; all registered tables exist from the moment the open returns, so a read can never trip over a table nobody has written yet.
_Avoid_: database (the engine's word), connection, repository (a domain seam that rides the store, not the store)

**Record**:
A value type a domain crate declares durable: a name that identifies the kind and a version that identifies its shape. The name and version together are the type the engine checks a table against on open, so a record whose shape changed without a version bump is a review failure, and a table written under another version is refused rather than misread.
_Avoid_: row, model, entity, mirror struct (the record *is* the domain type, derived, not copied)

**Packed value**:
A record's stored form — its bytes under the record's name and version. Packing can fail only for a record the codec cannot represent; unpacking can fail only when the bytes do not match the record's shape, and both are typed errors, never panics.
_Avoid_: blob, serialized value, cell

**Index**:
A declared secondary lookup on a record kind, maintained by the store whenever the record is written or removed — never by a caller. A **unique** index maps an index value to at most one primary key and refuses a write that would map it to a second; a **multimap** index maps an index value to any number of primary keys. Each index is declared once, next to its record, with the function that derives the index value from the record.
_Avoid_: view, lookup table, join

**Indexed table**:
A record kind's primary table together with every index declared on it, and the only path through which that kind is written. Inserting, updating or removing a record keeps every index exactly in step; reads by primary key, by key range, or through an index work on both read and write transactions. The raw tables behind it are not reachable, so an index cannot rot because a caller forgot it.
_Avoid_: table (the engine's word; an indexed table is several), collection, DAO

**Child table**:
A record kind that belongs to another row, keyed by its parent's key and its ordinal — one parent's children are a contiguous key range in ordinal order, so the engine keeps them sorted and no caller sorts them back. Listing a parent's set, replacing it wholesale and dropping it when the parent goes are the table's own operations, so the cascade is a call rather than something each seam remembers.
_Avoid_: foreign key, join table, sub-record, detail row

**Sequence**:
A named monotonic counter, taken inside the transaction that writes the row it numbers, so the number and the row land together or not at all. Values start at 1 and only ever rise: a removed row's key is never handed out again, so a key identifies the same thing for the life of the file.
_Avoid_: rowid, auto-increment, identity column

**Schema**:
The set of tables one store owns, assembled by the domain crates that declare them and handed to the store at open. Each declaration creates its tables if they are missing and refuses them if they exist under another record version.
_Avoid_: migration (that is the ladder), DDL

**Version ladder / Upgrade step**:
The store-wide version and the ordered steps that carry a file from one version to the next. Each step rewrites the tables of one version into the next inside a single durable write and stamps the new version before the next step runs; a file newer than the running build is refused, a rung with no step is refused, and a fresh file is stamped at the current version with no steps run. Old record shapes exist only as long as the step that reads them.
_Avoid_: schema migration (SQL vocabulary), user_version, data patch
