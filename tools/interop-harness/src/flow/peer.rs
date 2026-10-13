//! The peer family: flows where rmule and aMule speak eD2k peer-to-peer.
//!
//! No server mediates the exchange under test (though one may stage it): rmule
//! dials an aMule directly for Secure User Identification, serves an aMule's
//! download, or holds an aMule queued across the `FILEREASKTIME` window to draw
//! — or emit — a peer-UDP source reask, or re-asks a Low-ID one through its
//! callback road, or downloads one file from several partial aMule seeds.

pub(crate) mod direct_sui;
pub(crate) mod lowid_callback_reask;
pub(crate) mod serve;
pub(crate) mod streaming_window;
pub(crate) mod sx1_gate;
pub(crate) mod two_hellos;
pub(crate) mod udp_reask;
pub(crate) mod udp_reask_emit;

pub use self::direct_sui::{DirectSuiOptions, run_amule_direct_sui};
pub use self::lowid_callback_reask::verdict::score_run_dir as score_lowid_callback_reask;
pub use self::lowid_callback_reask::{
    PeerLowIdCallbackReaskOptions, run_peer_lowid_callback_reask,
};
pub use self::serve::run_rmule_serves_amule_downloads;
pub use self::streaming_window::{
    SeedHolding, StreamingWindowOptions, collect_kept_run as collect_streaming_window_run,
    default_seeds, run_streaming_window, score_run_dir as score_streaming_window, seed_holding_arg,
};
pub use self::sx1_gate::{Sx1GateOptions, run_sx1_gate};
pub use self::two_hellos::{TwoHellosOptions, run_two_hellos};
pub use self::udp_reask::{
    DEFAULT_REASK_WINDOW_SECS, PeerUdpReaskOptions, run_peer_udp_reask, score_run_dir,
};
pub use self::udp_reask_emit::{
    PeerUdpReaskEmitOptions, run_peer_udp_reask_emit, score_run_dir as score_emit_run_dir,
    stage_reask_emit_files,
};
