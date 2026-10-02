//! The Kad-network family: flows about rmule's standing as a Kad citizen.
//!
//! Not captures of a single opcode but proofs that the network itself works —
//! rmule answering a real aMule's keyword publish and search from its own store,
//! rmule joining a private aMule mesh and being accepted into its routing table,
//! and two stock aMules reaching "Kad: Connected" on the fake-public subnet at
//! all (the topology check every other Kad flow rests on).

pub(crate) mod inverted_keyword;
pub(crate) mod inverted_keyword_verdict;
pub(crate) mod join;
pub(crate) mod smoke;

pub use self::inverted_keyword::{KadInvertedKeywordOptions, run_kad_inverted_keyword};
pub use self::join::{KadJoinOptions, run_kad_join};
pub use self::smoke::{KadSmokeOptions, run_kad_smoke};
