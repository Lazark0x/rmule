//! The typed layer's integration surface, one binary with a leg per
//! concern. Every leg that touches a store runs against both backends —
//! a temp file and a shared in-memory backend the fixture can reopen — so
//! the two are proven to behave alike, ladder included.
//! `cargo test -p rmule-store --test store indexes::` runs one leg.

mod fixture;

// Records and their packed form: the version tag the engine refuses on.
mod records;

// Index maintenance across insert, update, put, remove; key-ordered reads;
// the unique-index refusal.
mod indexes;

// The version ladder: fresh stamp, ordered steps, refusals.
mod ladder;

// One store shared across threads behind an `Arc`.
mod sharing;
