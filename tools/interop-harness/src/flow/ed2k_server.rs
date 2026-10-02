//! The eD2k-server family: flows staged around a live Lugdunum eserver.
//!
//! One eserver plus the counterparties a leg needs, with rmule driven against
//! them as client or as server. Spans the skeleton flows (the four
//! `RmuleClientAction` legs plus the Low-ID callback observation), the
//! capability wire-smoke probe, the full server-cycle acceptance run, and the
//! search-wire leg (which stands ed2k-server up beside the eserver), and the
//! announce-switch leg's offer-set probe and rmule legs, the late-port-test
//! leg, the crypt-ping-port leg, the sweep-follows-list leg, and the ask-budget
//! leg.

pub(crate) mod announce_switch;
pub(crate) mod ask_budget;
pub(crate) mod bench_smoke;
pub(crate) mod crypt_ping_port;
pub(crate) mod cycle;
pub(crate) mod late_port_test;
pub(crate) mod rmule_tools;
pub(crate) mod search_wire;
pub(crate) mod skeleton;
pub(crate) mod sweep_follows_list;

pub use self::announce_switch::{AnnounceSwitchOptions, run_announce_switch};
pub use self::ask_budget::{AskBudgetOptions, rescore_ask_budget, run_ask_budget};
pub use self::bench_smoke::{BenchSmokeOptions, run_bench_smoke};
pub use self::crypt_ping_port::{CryptPingPortOptions, run_crypt_ping_port};
pub use self::cycle::{ServerCycleOptions, run_server_cycle};
pub use self::late_port_test::{DEFAULT_HELLO_DELAY_MS, LatePortTestOptions, run_late_port_test};
pub use self::search_wire::{
    SearchSpacingOptions, SearchWireOptions, SearchWireServer, run_search_spacing, run_search_wire,
};
pub use self::skeleton::{RmuleClientAction, ServerSkeletonOptions, run_server_skeleton};
pub use self::sweep_follows_list::{SweepFollowsListOptions, run_sweep_follows_list};

pub(crate) const SEARCH_QUERY: &str = "shared.bin";
