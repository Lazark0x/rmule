//! The TUI's words: every sentence the operator reads in the TUI. The
//! sentences written from core's codes live in `rmule_words`, which the CLI
//! speaks from too, and are re-exported here under the same module names;
//! the modules declared here word the TUI's own types — its command line,
//! a run with no core, a Settings edit, a server-health edge, a search
//! entry's paging, the share set's tally, the player Preview starts —
//! beside the shared words of their domain.
//!
//! The log pane, the status bar's note and the flash take a [`Sentence`],
//! and only a words module — `rmule_words` or this one and its children —
//! makes one (`scripts/guards.sh` holds it), so a `String` built anywhere
//! else cannot reach those surfaces.

pub use rmule_words::{
    Sentence, download, event, kad, login, os, peer, portmap, reach, serve, software, store, units,
};

pub mod app;
pub mod front_door;
pub mod player;
pub mod scan;
pub mod search;
pub mod server;
