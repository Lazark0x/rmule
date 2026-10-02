//! The download activity: source lookup, the multi-peer runner, the candidate
//! worker pool, and verified-part persistence. The core actor (`service.rs`)
//! drives every member of the **Download Set** through this module, side by
//! side (ADR-0107).

pub(crate) mod persist;
// The Remote-Queued Pool + reask scheduler (ADR-0057), wired live by the
// download `runner`: a ranked-then-hung-up source is pooled (its earned queue
// standing kept without a socket), the reask sweep ticks it out the shared
// client-UDP send as `OP_REASKFILEPING` (`0x90`), and the demux front's
// `0x91`/`0x92`/`0x93` replies feed back through `on_reply_datagram`.
mod reask_routes;
mod remote_queue;
mod runner;
pub(crate) mod source_ask_clock;
pub(crate) mod source_asks;
pub(crate) mod source_seeds;
mod state;
mod worker_pool;

// The **Callback Capability** answer type: built only by Self Reach
// (`reachability::SharedSelfReach::callback_capability`).
pub(crate) use state::CallbackCapability;

// Where a reask reply goes when several downloads pool one peer (ADR-0107).
pub(crate) use reask_routes::ReaskRoutes;

pub(crate) use runner::{
    DiscoveryLiveness, DownloadRequest, DownloadTask, LaterLinkSources, RunnerContext, StopReason,
    file_link_from_record, link_sources, names_sources,
};
