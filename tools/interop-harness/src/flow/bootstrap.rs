//! The bootstrap family: how a cold rmule finds a network at all.
//!
//! Two halves. The golden-authoring flows boot a real aMule and let it write its
//! own `server.met` / `nodes.dat`, which are the only trustworthy fixtures for
//! those formats. The consuming flows drive rmule's own bootstrap runners —
//! HTTP fetch, ed2k→Kad handoff — against a live bench and prove the fetched
//! bytes actually join it.

pub(crate) mod ed2k_kad_handoff;
pub(crate) mod http_cold_start;
pub(crate) mod http_goldens;
pub(crate) mod v2_nodes_dat;

pub use self::ed2k_kad_handoff::{Ed2kKadHandoffOptions, run_ed2k_kad_handoff};
pub use self::http_cold_start::{HttpBootstrapColdStartOptions, run_http_bootstrap_cold_start};
pub use self::http_goldens::{HttpBootstrapGoldensOptions, run_http_bootstrap_goldens};
pub use self::v2_nodes_dat::{V2NodesDatHarvestOptions, run_v2_nodes_dat_harvest};

/// The aMule config dir inside the container (amuled runs as root).
pub(crate) const AMULE_CONFIG_DIR: &str = "/root/.aMule";
