//! The download activity: source lookup, the multi-peer runner, the candidate
//! worker pool, and verified-part persistence. The core actor (`service.rs`)
//! drives every member of the **Download Set** through this module, side by
//! side (ADR-0107).

pub(crate) mod persist;
mod reask_routes;
mod runner;
mod runtime;
pub(crate) use runtime::SharedRuntime;
pub(crate) mod source_ask_clock;
pub(crate) mod source_asks;
mod source_book;
pub(crate) mod source_seeds;
mod state;
mod worker_pool;

// The **Callback Capability** answer type: built only by Self Reach
// (`reachability::SharedSelfReach::callback_capability`).
pub(crate) use state::CallbackCapability;

// Where a reask reply goes when several downloads pool one peer (ADR-0107).
pub(crate) use reask_routes::ReaskRoutes;

pub(crate) use runner::{
    CompletionFs, CompletionGate, DiscoveryLiveness, DownloadRequest, DownloadTask,
    FinalFileInPlace, LaterLinkSources, OsCompletionFs, Recovered, RunnerContext, StopAnswer,
    StopReason, file_link_from_record, link_sources, names_sources,
};
