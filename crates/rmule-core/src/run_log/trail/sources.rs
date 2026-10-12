//! Where the trail's levels come from: each level's one owner, read when that
//! owner's change notice wakes.
//!
//! | Level | Owner | Change notice |
//! |---|---|---|
//! | connected server, server list health and grant words | the server half of the diagnostics level | [`DiagnosticsState::server_changes`] |
//! | port mappings | the Port Mapping runtime | its published **Mapping Status** rows |
//! | own addresses, NAT-T own mapping | **Address Learning** | the **Own Address Generation**, the **Bind Generation**, and the next lapse it names |
//! | Kad verdicts | **Self Reach** | the **Reach Generation** |
//! | own buddy's state | the Firewalled Front's slot and the Kad pump's recruit rule | the **Buddy Snapshot** and the **Recruit Status** |

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::diagnostics::{DiagnosticsState, address_rows};
use crate::firewalled::front::BuddyView;
use crate::port_mapping::MappingDiagnostics;
use crate::reachability::{ReachGeneration, SharedSelfReach};
use crate::run_log::{Level, Record, write as write_record};

use super::{ServerLevel, Trail};

/// The owners the trail reads its levels from.
pub(crate) struct TrailSources {
    /// The server half of the level: the connected server and the list's
    /// health.
    pub(crate) diagnostics: DiagnosticsState,
    /// The running Port Mapping runtime's published rows; `None` with no
    /// runtime, whose level is no mapping at all.
    pub(crate) mapping_rows: Option<watch::Receiver<Vec<MappingDiagnostics>>>,
    /// **Address Learning**.
    pub(crate) addresses: SharedAddressLearning,
    /// **Self Reach**.
    pub(crate) reach: SharedSelfReach,
    /// Our own buddy: the slot's snapshot and the recruit rule's status.
    pub(crate) buddy: BuddyView,
}

/// Write every level once, then each level again whenever its owner moves
/// it, until the task is aborted.
pub(crate) fn spawn(sources: TrailSources) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut watched = Watched::new(sources);
        write(watched.every_level());
        loop {
            let records = watched.next().await;
            write(records);
        }
    })
}

/// Write `records` at lean: every field a level carries is lean's, so the
/// level in force would render them the same.
fn write(records: Vec<Record>) {
    for record in records {
        write_record(&record, Level::Lean);
    }
}

/// The trail and a subscription to each owner's change notice.
pub(super) struct Watched {
    trail: Trail,
    sources: TrailSources,
    server_changes: watch::Receiver<u64>,
    own_address: watch::Receiver<u64>,
    binds: watch::Receiver<u64>,
    reach: ReachGeneration,
    buddy: BuddyView,
}

impl Watched {
    /// Subscribe to every owner before anything is read, so a move between
    /// the subscription and the first read is a wake that finds it.
    pub(super) fn new(sources: TrailSources) -> Self {
        Self {
            trail: Trail::default(),
            server_changes: sources.diagnostics.server_changes(),
            own_address: sources.addresses.own_address_changed(),
            binds: sources.addresses.binds_changed(),
            reach: sources.reach.changes(),
            buddy: sources.buddy.clone(),
            sources,
        }
    }

    /// Every level's records, the first a run writes: the server, the
    /// mappings, the addresses, Kad, the NAT-T own mapping, then the server
    /// list's grant words.
    pub(super) fn every_level(&mut self) -> Vec<Record> {
        let level = self.server_level();
        let mut records = self.trail.server(level.connected.as_ref());
        records.extend(self.mappings());
        records.extend(self.addresses());
        records.extend(self.kad());
        records.extend(self.natt());
        records.extend(self.trail.server_health(&level));
        records
    }

    /// Wait for the next owner's notice and answer the records of the levels
    /// it moved — none when the wake moved nothing the trail writes.
    pub(super) async fn next(&mut self) -> Vec<Record> {
        // A wait rather than an instant: the store's clock is the wall's, and
        // a runtime whose own clock is paused or ahead must still wait for it.
        let lapse = self
            .sources
            .addresses
            .next_lapse()
            .map(|at| at.saturating_duration_since(std::time::Instant::now()));
        tokio::select! {
            Ok(()) = self.server_changes.changed() => self.server(),
            changed = mapping_rows_changed(self.sources.mapping_rows.as_mut()) => {
                if changed.is_err() {
                    // The runtime is gone, and nothing is mapped with it.
                    self.sources.mapping_rows = None;
                }
                self.mappings()
            }
            Ok(()) = self.own_address.changed() => self.address_learning(),
            Ok(()) = self.binds.changed() => self.address_learning(),
            () = sleep_for(lapse) => self.address_learning(),
            () = self.reach.changed() => self.kad(),
            Some(()) = self.buddy.changed() => self.kad(),
        }
    }

    fn server_level(&self) -> ServerLevel {
        self.sources
            .diagnostics
            .read_server_half(|half| ServerLevel::of(&half))
    }

    fn server(&mut self) -> Vec<Record> {
        let level = self.server_level();
        let mut records = self.trail.server(level.connected.as_ref());
        records.extend(self.trail.server_health(&level));
        records
    }

    fn mappings(&mut self) -> Vec<Record> {
        let rows = self
            .sources
            .mapping_rows
            .as_mut()
            .map(|rows| rows.borrow_and_update().clone())
            .unwrap_or_default();
        self.trail.mappings(&rows)
    }

    /// The own addresses and the NAT-T own mapping, both Address Learning's.
    fn address_learning(&mut self) -> Vec<Record> {
        let mut records = self.addresses();
        records.extend(self.natt());
        records
    }

    fn addresses(&mut self) -> Vec<Record> {
        self.trail.addresses(&address_rows(&self.sources.addresses))
    }

    fn natt(&mut self) -> Vec<Record> {
        let mapping = self.sources.addresses.own_mapping(SocketRole::Udp);
        self.trail.natt(Some(mapping))
    }

    fn kad(&mut self) -> Vec<Record> {
        let reach = &self.sources.reach;
        let verdicts = reach
            .kad_running()
            .then(|| (reach.kad_firewall_verdict(), reach.kad_udp_verdict()));
        let buddy = self.buddy.seen_state();
        self.trail.kad(verdicts, buddy)
    }
}

/// The next change of the runtime's rows; never, with no runtime.
async fn mapping_rows_changed(
    rows: Option<&mut watch::Receiver<Vec<MappingDiagnostics>>>,
) -> Result<(), watch::error::RecvError> {
    match rows {
        Some(rows) => rows.changed().await,
        None => std::future::pending().await,
    }
}

/// Sleep for `wait`; never, with nothing to wait for.
async fn sleep_for(wait: Option<std::time::Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}
