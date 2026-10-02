//! The Durable Store's words, where a store failure reaches the operator:
//! never the store's own message, which is for the Run Log.

use super::Sentence;

/// A Settings edit on a run with no config store.
pub const NO_CONFIG_STORE: Sentence = Sentence::fixed("no config store (UI-only run)");

/// The server just reached could not be kept for the next start.
pub const LAST_SERVER_NOT_SAVED: Sentence = Sentence::fixed(
    "could not remember this server: connect at start may dial another (see the run log)",
);

/// A Settings edit the store would not keep.
pub const NOT_SAVED: Sentence =
    Sentence::fixed("could not save the setting: the store refused (see the run log)");
