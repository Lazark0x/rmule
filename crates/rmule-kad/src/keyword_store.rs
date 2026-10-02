//! The **Kad Keyword Store** and storer halves (ADR-0062, execution breakdown
//! 2): dual-form entries, caps, load, aggregation, and firewalled refusal for
//! `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`) and `KADEMLIA2_SEARCH_KEY_REQ`
//! (`0x33`). Counterpart of `source_store.rs`, but self-contained: unlike
//! `source_store` — whose gate logic sits in the node and whose storage sits
//! in the store — this module owns its wire codec as well as its storage, so
//! the node's dispatch hands it a datagram and takes back an outcome.
//!
//! ## Provenance
//!
//! Every cap, load formula, aggregation rule, and serve-order fact below is
//! read directly from the pinned aMule source the ADR cites throughout
//! (commit `4e8f2b3c3f90cda23765730546b04c684a92e4f5`):
//!
//! - `CIndexed::AddKeyword` (`Indexed.cpp`): the global cap
//!   (`KADEMLIAMAXENTRIES`) checked unconditionally first; the entry
//!   validation gate (non-empty filename, non-zero size); the per-keyword cap
//!   (`KADEMLIAMAXINDEX`) and the `KADEMLIAMAXINDEX - 5000` duplicate-refresh
//!   guard, gated **only** on the refresh branch (a net-new file is bounded
//!   only by the hard per-keyword cap); the load formula (`1` for a keyword's
//!   first-ever file, else the pre-insert count as a percentage of the
//!   per-keyword cap, `100` on any cap reject).
//! - `CIndexed::Clean` (`Indexed.cpp`): the 30-minute sweep throttle
//!   (`if (m_lastClean > tNow) return;` / `m_lastClean = tNow + MIN2S(30)`).
//! - `CKeyEntry::MergeIPsAndFilenames` / `ReCalculateTrustValue` /
//!   `WriteTagListWithPublishInfo` (`Entry.cpp`): the aggregation model — a
//!   per-entry bounded (100) FIFO of tracked publisher IPs, a global `/24`
//!   subnet publish-count map every entry's trust reads, the trust formula
//!   (`10.0 / subnet_count`, summed over the entry's tracked IPs), the
//!   case-insensitive filename-popularity list, and the served tag order:
//!   FILENAME (the most-popular name) and FILESIZE synthesized fresh, then
//!   the verbatim rest, then `TAG_PUBLISHINFO` = `(names&0xFF)<<24 |
//!   (publishers&0xFF)<<16 | (trust*100 as u16)`.
//! - `Process2PublishKeyRequest` / `Process2SearchKeyRequest`
//!   (`KademliaUDPListener.cpp`): the UDP-firewalled silent-refusal gate
//!   (checked before a single payload byte is read); the `SEARCHTOLERANCE`
//!   distance gate with the LAN bypass; the `[keyword(16)][count(2
//!   LE)]`-then-per-file `[fileID(16)][tagCount(1)][tags]` publish wire shape;
//!   the `[keyword(16)][startpos(2 LE, top bit = restrictive flag, low 15
//!   bits = offset)]`-then-optional-tree search wire shape.
//! - `CreateSearchExpressionTree` (`KademliaUDPListener.cpp`, the `_aOps`
//!   table): the numeric-relation operator byte map the query layer reads
//!   and the codec leaves verbatim — `0x00`=`=`, `0x01`=`>`, `0x02`=`<`,
//!   `0x03`=`>=`, `0x04`=`<=`, `0x05`=`<>`; any other byte fails the whole
//!   search expression's parse, never reaching evaluation.
//! - `Constants.h` / `FileTags.h`: `KADEMLIAMAXENTRIES` (60 000),
//!   `KADEMLIAMAXINDEX` (50 000), `KADEMLIAREPUBLISHTIMEK` (24 h), and the
//!   tag bytes (`TAG_FILENAME` `0x01`, `TAG_FILESIZE` `0x02`, `TAG_FILEFORMAT`
//!   `0x04`, `TAG_PUBLISHINFO` `0x33`).
//!
//! ## Documented simplifications
//!
//! - **No per-size sub-entries.** aMule's `AddKeyword` keeps a short list of
//!   entries per (keyword, file) distinguished by declared size (a defensive
//!   branch for a file ID republished with conflicting sizes); rmule collapses
//!   this to one entry per (keyword, file) and treats a size change as an
//!   ordinary refresh. A citizen bar-neutral simplification: the CONTEXT.md
//!   **Kad Keyword Store** term already describes entries as keyed by
//!   `(keyword, fileID)`.
//! - **No fast-refresh popularity suppression.** aMule skips a filename's
//!   popularity bump when the same IP republishes faster than
//!   `KADEMLIAREPUBLISHTIMES - 1h` (a CPU/anti-inflation nicety); rmule always
//!   bumps on a matching name. Documented divergence, not evidence-blocking.
//! - **Restrictive-tree string-term tokenization** reuses
//!   [`crate::keyword::search_keywords`] (the search-direction fold: split,
//!   keep >= 3 UTF-8 bytes, lowercase, keep duplicates) rather than a
//!   dedicated no-floor tokenizer; aMule's real string-term tokenizer keeps
//!   any non-empty token. A short token (1-2 bytes) in a restrictive tree is
//!   the only observable difference, and rmule never emits trees itself (v1).
//! - **`TAG_PUBLISHINFO`'s trust\*100 saturates** at `u16::MAX` (Rust's
//!   defined `as` cast) rather than C++'s implementation-defined narrowing —
//!   only observable for a trust value beyond any single test's reach (tens
//!   of distinct sole-publishing `/24` subnets on one entry).

mod entry;
mod query;
mod result;
mod store;
mod wire;

pub use self::entry::{KeywordFileOutcome, KeywordPublishFile, KeywordPublishOutcome};
pub use self::query::UnknownSearchOperator;
pub use self::result::{KadKeywordResult, KeywordResultRow};
pub use self::store::KeywordStore;
pub use self::wire::{
    KeywordDecodeError, decode_publish_key_req, decode_search_key_req, decode_search_key_res,
    encode_publish_key_req, encode_search_key_req, encode_search_key_res,
};

use std::time::Duration;

use crate::opcode::{KADEMLIA2_PUBLISH_KEY_REQ, KADEMLIA2_SEARCH_KEY_REQ, KADEMLIA2_SEARCH_RES};

// ---------------------------------------------------------------------------
// Tag bytes
// ---------------------------------------------------------------------------

const TAG_FILENAME: u8 = 0x01;
const TAG_FILESIZE: u8 = 0x02;
/// `TAG_FILETYPE` — the publisher's own file classification (`"Audio"`,
/// `"Video"`, …), present only when the file classifies (a capture against
/// aMule corrected ADR-0062 here). aMule's requester reads it into the search
/// row's type (`Search.cpp:1016`, forwarded to `CSearchFile` as `FT_FILETYPE` in
/// `SearchList.cpp:1015`), so rmule's typed projection carries it too.
const TAG_FILETYPE: u8 = 0x03;
const TAG_FILEFORMAT: u8 = 0x04;
/// `TAG_SOURCES` — the complete-sources count a publish carries and a served row
/// re-serves verbatim; the requester's typed projection reads it.
/// Documentation-backed byte, `[pending]` capture recipe 1.
const TAG_SOURCES: u8 = 0x15;
const TAG_PUBLISHINFO: u8 = 0x33;

// ---------------------------------------------------------------------------
// aMule constants (`Constants.h`)
// ---------------------------------------------------------------------------

/// Global cap across every keyword's indexed rows (aMule's
/// `KADEMLIAMAXENTRIES`). Any publish past this is rejected with `load = 100`,
/// a refresh of an already-indexed row included: aMule checks this cap
/// unconditionally as `AddKeyword`'s first statement — before the entry
/// validation and the net-new/refresh split — so once the global index is
/// full, even a republish of an existing row is refused early.
pub const KEYWORD_GLOBAL_CAP: usize = 60_000;

/// Per-keyword cap on distinct indexed `(keyword, file)` rows (aMule's
/// `KADEMLIAMAXINDEX`). Checked before any insert or refresh for the keyword.
pub const KEYWORD_PER_KEYWORD_CAP: usize = 50_000;

/// Once a keyword's row count exceeds this, a **refresh** of an
/// already-indexed file is throttled (rejected, `load = 100`) even though the
/// hard [`KEYWORD_PER_KEYWORD_CAP`] has not been reached; a net-new file is
/// unaffected. aMule's `KADEMLIAMAXINDEX - 5000`, guarding against an
/// already-popular file's republishes crowding out room for newly-published
/// ones as the index fills (`Indexed.cpp`'s own comment: "if we continued to
/// update all the publishes while this index is full, popular files will be
/// the only thing you index").
pub const KEYWORD_DUPLICATE_GUARD_THRESHOLD: usize = KEYWORD_PER_KEYWORD_CAP - 5_000;

/// How long an indexed keyword entry lives (aMule's `KADEMLIAREPUBLISHTIMEK`,
/// 24 h — distinct from the 5 h source-publish lifetime).
pub const KEYWORD_ENTRY_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum interval between expiry sweeps (aMule's `Clean()` throttle,
/// `MIN2S(30)`). A [`KeywordStore::tick`] before this elapses is a no-op.
pub const KEYWORD_SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Most tracked publisher IPs per entry (aMule keeps "max 100 IPs, in order
/// to avoid too much time for calculation/storing/loading" —
/// `MergeIPsAndFilenames`). The oldest is evicted FIFO past this.
pub const KEYWORD_MAX_TRACKED_PUBLISHERS: usize = 100;

/// Most files rmule accepts from one `KADEMLIA2_PUBLISH_KEY_REQ` batch.
/// **Divergence (documented):** aMule trusts the wire's `u16` file count
/// outright; rmule bounds it at the emit side's own cap (a compliant
/// publisher's walk stores at most 50 files per `0x43` packet) — unobservable
/// to any compliant publisher, and a declared count above it is rejected
/// outright rather than partially processed.
pub const KEYWORD_PUBLISH_BATCH_CAP: usize = 50;

/// Rows per `0x3B` datagram when serving a keyword search (same batching as
/// source search results).
pub const KEYWORD_RESULT_ROWS_PER_DATAGRAM: usize = 50;

/// Most rows one keyword search answers, after the requester's offset (aMule
/// caps a search at 300 results on both the requester and storer side).
pub const KEYWORD_RESULT_BUDGET: usize = 300;

/// `PUBLISHPOINTSSPERSUBNET`: each `/24` subnet contributes this many trust
/// points, divided among however many of an entry's tracked publishers
/// currently share it.
const TRUST_POINTS_PER_SUBNET: f64 = 10.0;

/// Entries at or above this trust score serve before every entry below it
/// (aMule's two-pass `onlyTrusted` split in `SendValidKeywordResult`).
const TRUST_WORTHY_THRESHOLD: f64 = 1.0;
