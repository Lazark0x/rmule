//! The peer family: flows where rmule and aMule speak eD2k peer-to-peer.
//!
//! No server mediates the exchange under test (though one may stage it): rmule
//! dials an aMule directly for Secure User Identification, serves an aMule's
//! download, or holds an aMule queued across the `FILEREASKTIME` window to draw
//! — or emit — a peer-UDP source reask, or re-asks a Low-ID one through its
//! callback road, or serves one as a Low-ID node it dialed back on the
//! server's relay, or downloads one file from several partial aMule seeds, or
//! serves an aMule a download it is still fetching, or downloads two files
//! from one aMule over one link, or takes the slot an aMule grants it by
//! dialing it back, or asks many queuing aMules and transfers from every
//! grant, or prefers an aMule whose queue it stands in.

pub(crate) mod dial_back_grant;
pub(crate) mod direct_sui;
pub(crate) mod lowid_callback_reask;
pub(crate) mod one_link;
pub(crate) mod partial_share;
pub(crate) mod queue_fanout;
pub(crate) mod reciprocity;
pub(crate) mod serve;
pub(crate) mod server_callback_serve;
pub(crate) mod streaming_window;
pub(crate) mod sx1_gate;
pub(crate) mod two_hellos;
pub(crate) mod udp_reask;
pub(crate) mod udp_reask_emit;

pub use self::dial_back_grant::{
    PeerDialBackGrantOptions, run_peer_dial_back_grant,
    score_run_dir as score_peer_dial_back_grant, stage_dial_back_files,
};
pub use self::direct_sui::{DirectSuiOptions, run_amule_direct_sui};
pub use self::lowid_callback_reask::verdict::score_run_dir as score_lowid_callback_reask;
pub use self::lowid_callback_reask::{
    PeerLowIdCallbackReaskOptions, run_peer_lowid_callback_reask,
};
pub use self::one_link::{
    PeerOneLinkOptions, run_peer_one_link, score_run_dir as score_peer_one_link,
    score_severed_run_dir as score_peer_one_link_severed,
};
pub use self::partial_share::{
    PartialShareOptions, run_partial_share, score_run_dir as score_partial_share,
};
pub use self::queue_fanout::{
    FanoutShape, PeerQueueFanoutOptions, run_peer_queue_fanout,
    score_run_dir as score_peer_queue_fanout, stage_queue_fanout_files,
};
pub use self::reciprocity::{
    PeerReciprocityOptions, ReciprocityLeg, ReciprocityShape, run_peer_reciprocity,
    score_run_dir as score_peer_reciprocity, stage_reciprocity_files,
};
pub use self::serve::run_rmule_serves_amule_downloads;
pub use self::server_callback_serve::verdict::score_run_dir as score_server_callback_serve;
pub use self::server_callback_serve::{ServerCallbackServeOptions, run_server_callback_serve};
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
