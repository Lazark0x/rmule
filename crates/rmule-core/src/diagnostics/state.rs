//! The **live diagnostics store**: the one mutable handle behind the records
//! beside it.
//!
//! Everything in the parent module is a fact already settled — a record, a
//! count, a snapshot. This is where those facts are written: a shared
//! [`DiagnosticsState`] the per-download task, the serve task and `Core`
//! itself hold clones of, each write a point-in-time map update that never
//! crosses an `.await`, which is why a `std::sync::Mutex` (not tokio's) guards
//! it. Readers never touch the inner map — they take a
//! [`DiagnosticsSnapshot`] and are done with the
//! lock.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmule_ed2k::ServerGrants;
use rmule_primitives::{FileHash, PeerEndpoint, ServerEndpoint, part_count};

use rmule_primitives::AddressFamily;

mod buddy_and_callbacks;
mod buddy_hash_spelling;
mod download_ends;
mod download_rest;
mod natt_counters;
mod natt_prediction;
mod search_counters;
mod server_health;
mod uploads;
pub use buddy_hash_spelling::BuddyHashSpellingCounters;
pub(crate) use server_health::ServerHalf;

use super::{
    AddressDiagnostics, ClientUdpBindFailure, DiagnosticsSnapshot, DownloadDiagnostics, PartState,
    ServerDiagnostics, SessionCounters, ShareTotals, UploadDiagnostics, WorkerEntry, WorkerSlot,
};
use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::port_mapping::MappingDiagnostics;
use crate::server_list::ManagedServer;
use crate::service::ServeStopReason;
use crate::{CoreError, DownloadId, DownloadMetadata};

/// Shared diagnostics handle held by [`crate::Core`] and the per-download
/// task. `std::sync::Mutex` (not `tokio::sync::Mutex`) because writes are
/// point-in-time updates that never cross an `.await`.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticsState {
    inner: Arc<Mutex<DiagnosticsInner>>,
    /// Bumped after every write to the server half of the level — see
    /// [`server_changes`](Self::server_changes).
    server_changes: Arc<tokio::sync::watch::Sender<u64>>,
}

#[derive(Debug, Default)]
struct DiagnosticsInner {
    downloads: BTreeMap<DownloadId, DownloadDiagnostics>,
    uploads: BTreeMap<PeerEndpoint, UploadDiagnostics>,
    shared_files: super::shared_files::ShareLedger,
    session: SessionCounters,
    servers: Vec<ManagedServer>,
    connected_server: Option<ServerEndpoint>,
    kad_state: super::KadState,
    /// The running Kad Activity's fact reader; `None` while Kad is off.
    kad: Option<super::kad::KadFactsSource>,
    /// What the connected server granted at its last `OP_IDCHANGE`; the
    /// `Default` (nothing) whenever `connected_server` is `None`.
    connected_server_grants: ServerGrants,
    /// The search the connected server holds more rows for (ADR-0036).
    search_more_results: Option<crate::search::ServerMoreResults>,
    /// The **Address Learning** store the rows are read from (ADR-0084), once
    /// the actor installs it. `None` for a state built without a core — those
    /// snapshots simply carry no address rows.
    addresses: Option<SharedAddressLearning>,
    /// The **Port Mapping** rows (ADR-0086), republished whole by the mapping
    /// runtime whenever anything about them changes. A level rather than a
    /// store handle, unlike `addresses` above: the mapper is a task-local state
    /// machine with one writer, so what it publishes *is* the level, and
    /// sharing it behind a lock would put a second reader on a hot state
    /// machine for no gain.
    mappings: Vec<MappingDiagnostics>,
    /// The one client-UDP socket's total bind failure (ADR-0057),
    /// set once by `record_client_udp_bind_failure` and never cleared: the
    /// failure holds for the whole session (there is no retry).
    client_udp_bind_failure: Option<ClientUdpBindFailure>,
    /// The server-UDP pair's **Half-Bound Pair** fact, set once
    /// by `record_server_udp_bind`. Held here, beside the bind table, rather
    /// than inside it: `SocketRole` (the table's key) has no `ServerUdp`
    /// variant on purpose (see its doc) — nothing addresses this socket and
    /// nothing maps it, and a row in that table is exactly what feeds the
    /// **Desired Mapping Set** (ADR-0086). This field is the one writer for
    /// the fact server-UDP still deserves — the same consequence table
    /// (`PairRole::forfeits`) — without ever being readable as a mappable
    /// role.
    server_udp_half_bound: Option<rmule_net::family::HalfBound>,
    /// The **Shared Directory List** as the actor last installed it, each
    /// running scan's own progress cell among it: installed whole at every
    /// change, so a snapshot never shows a scan the ledger no longer holds.
    shared_directories: Vec<crate::directory_scan::InstalledDirectory>,
    /// The server list's health rule and the swept list it keeps in step
    /// (ADR-0052): see `server_health`.
    server_health: server_health::ServerHealthLevel,
    /// What the connected session was told of the share set; cleared with
    /// the session.
    share_announcement: Option<super::ShareAnnouncement>,
}

impl DiagnosticsState {
    /// An empty state: no downloads, no uploads, zeroed session counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the **Address Learning** store every snapshot reads its address
    /// rows from (ADR-0084). Installed once by the actor; the store is the
    /// single writer of those facts, so a snapshot *reads* it rather than
    /// keeping a second copy that could drift from it.
    pub(crate) fn install_addresses(&self, addresses: SharedAddressLearning) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .addresses = Some(addresses);
    }

    /// Record that the one client-UDP socket (ADR-0057) never bound at core
    /// start, and what was asked for. Called at most once per
    /// session, from the bind site alone — there is no retry (ADR-0057
    /// amendment), so the row this seeds outlives the log line the same call
    /// site emits.
    pub(crate) fn record_client_udp_bind_failure(&self, port: u16, kind: std::io::ErrorKind) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .client_udp_bind_failure = Some(ClientUdpBindFailure { port, kind });
    }

    /// The one client-UDP socket's bind failure, read directly rather than
    /// through a whole [`DiagnosticsSnapshot`] clone — the `EnableKad`
    /// rejection path (`on_enable_kad`) needs just this one fact.
    #[must_use]
    pub(crate) fn client_udp_bind_failure(&self) -> Option<ClientUdpBindFailure> {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .client_udp_bind_failure
    }

    /// One role's **Half-Bound Pair** fact, read through to the
    /// **Address Learning** bind table rather than through a whole snapshot —
    /// the `EnableKad` gate needs just this one row, and reading it here is
    /// what stops the rejection disagreeing with what a snapshot reports.
    #[must_use]
    pub(crate) fn half_bound(&self, role: SocketRole) -> Option<rmule_net::family::HalfBound> {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .addresses
            .as_ref()
            .and_then(|addresses| addresses.half_bound(role))
    }

    /// Record what the server-UDP pair's bind did, and hand back
    /// the **Half-Bound Pair** fact it settled, if any — so the bind site can
    /// emit `CoreEvent::SocketBoundWithoutFamily` from the same read that
    /// stored it, with no second lock round trip.
    ///
    /// Called at most once per session, from the bind site alone, exactly
    /// like `record_client_udp_bind_failure` — there is no re-bind for
    /// server-UDP either. Unlike that sibling, and unlike the **Address
    /// Learning** bind table `PairRole::Ed2kListener`/`ClientUdp` read from,
    /// this row is diagnostics-only: `PairRole::ServerUdp` is a real role in
    /// the consequence table, but recording it under `SocketRole` would put a
    /// row nothing maps or advertises into the very table the **Desired
    /// Mapping Set** (ADR-0086) derives from.
    pub(crate) fn record_server_udp_bind(
        &self,
        binds: &rmule_net::family::FamilyBinds,
    ) -> Option<rmule_net::family::HalfBound> {
        let half_bound =
            rmule_net::family::HalfBound::read(rmule_net::family::PairRole::ServerUdp, binds);
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .server_udp_half_bound = half_bound;
        half_bound
    }

    /// Open the row for `download_id` as a run starts, seeding the facts that
    /// never change for its life. A new row's part map is every part of the
    /// file missing: the size fixes the part count (`part_count(size)`), so
    /// the picture exists before the scheduler's first settle or the hash set.
    /// A row already open — one at rest, which a resume runs on —
    /// keeps its part map and counters and restarts its clock, since
    /// `started_at` is the run's (ADR-0094).
    pub fn ensure_download(
        &self,
        download_id: DownloadId,
        file_hash: FileHash,
        metadata: DownloadMetadata,
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner
            .downloads
            .entry(download_id)
            .and_modify(|row| {
                row.started_at = Instant::now();
                row.dial_ends.clear();
            })
            .or_insert_with(|| DownloadDiagnostics {
                download_id,
                file_hash,
                parts: vec![PartState::Missing; part_count(metadata.size) as usize],
                metadata,
                started_at: Instant::now(),
                retired_peers: 0,
                workers: BTreeMap::new(),
                received_bytes: 0,
                known_sources: 0,
                dials_ended: 0,
                reask_replies_ignored: 0,
                dial_ends: BTreeMap::new(),
            });
    }

    /// Count `bytes` of payload a peer just delivered for `download_id`
    /// (ADR-0077). The session total always advances; the per-download row
    /// advances only while it exists, so bytes that land after a teardown are
    /// still session-visible instead of silently lost.
    pub fn add_received_bytes(&self, download_id: DownloadId, bytes: u64) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.down_bytes_total = inner.session.down_bytes_total.saturating_add(bytes);
        if let Some(dd) = inner.downloads.get_mut(&download_id) {
            dd.received_bytes = dd.received_bytes.saturating_add(bytes);
        }
    }

    /// Count one source dropped at ingest for naming an **Address Family**
    /// this build cannot dial (ADR-0085).
    pub fn count_undialable_family_source(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.undialable_family_sources_total = inner
            .session
            .undialable_family_sources_total
            .saturating_add(1);
    }

    /// Count one client-UDP datagram dropped because its opcode has no wire
    /// form for the sender's **Address Family** (ADR-0087).
    pub fn count_unanswerable_family_datagram(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.unanswerable_family_datagrams_total = inner
            .session
            .unanswerable_family_datagrams_total
            .saturating_add(1);
    }

    /// Count one peer hello refused under a named code (ADR-0050).
    pub fn count_peer_hello_refused(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let total = &mut inner.session.peer_hellos_refused_total;
        *total = total.saturating_add(1);
    }

    /// Count one IPv6 client-UDP datagram whose crypt header no key opened.
    pub fn count_ipv6_undecryptable_datagram(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let total = &mut inner.session.ipv6_undecryptable_datagrams_total;
        *total = total.saturating_add(1);
    }

    /// Count one Kad datagram the client-UDP front could not hand to the
    /// running node.
    pub fn count_kad_inlet_drop(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.kad_inlet_drops_total = inner.session.kad_inlet_drops_total.saturating_add(1);
    }

    /// Count one reask ping or reply the client-UDP front, or the reply
    /// fan-out behind it, could not hand on.
    pub fn count_peer_udp_inbox_drop(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.peer_udp_inbox_drops_total =
            inner.session.peer_udp_inbox_drops_total.saturating_add(1);
    }

    /// Count one reask reply that answered no ping in flight.
    pub fn count_reask_reply_unasked(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.reask_replies_unasked_total =
            inner.session.reask_replies_unasked_total.saturating_add(1);
    }

    /// Count one `KadEvent::Diagnostic(UndecodableEnvelope)`: an
    /// inbound datagram opened with the Kad protocol byte (or decrypted to
    /// one) but did not decode into a well-formed envelope.
    pub fn count_kad_undecodable_envelope(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.kad_undecodable_envelopes_total = inner
            .session
            .kad_undecodable_envelopes_total
            .saturating_add(1);
    }

    /// Count the client-UDP demux front's transport returning closed
    /// — in production, the receive-error budget exhausted.
    pub fn count_client_udp_transport_ended(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.client_udp_transport_ended_total = inner
            .session
            .client_udp_transport_ended_total
            .saturating_add(1);
    }

    /// Count the server-UDP engine's transport returning closed
    /// — in production, the receive-error budget exhausted.
    pub fn count_server_udp_transport_ended(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.server_udp_transport_ended_total = inner
            .session
            .server_udp_transport_ended_total
            .saturating_add(1);
    }

    /// Republish `download_id`'s whole part map plus its retired-peer tally
    /// and its known-source count (ADR-0079). One call for all three because
    /// the download runner observes them at one point — the settle after a
    /// drain — and one lock keeps the snapshot from ever showing a
    /// half-updated row.
    pub fn set_part_map(
        &self,
        download_id: DownloadId,
        parts: Vec<PartState>,
        retired: u32,
        known_sources: u32,
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(dd) = inner.downloads.get_mut(&download_id) {
            dd.parts = parts;
            dd.retired_peers = retired;
            dd.known_sources = known_sources;
        }
    }

    /// Apply `f` to one slot's row, creating an idle row for the slot if the
    /// download has none yet. A no-op when the download's row is already gone.
    pub fn update_worker(
        &self,
        download_id: DownloadId,
        slot: WorkerSlot,
        f: impl FnOnce(&mut WorkerEntry),
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if let Some(dd) = inner.downloads.get_mut(&download_id) {
            let entry = dd
                .workers
                .entry(slot)
                .or_insert_with(|| WorkerEntry::new(slot));
            f(entry);
        }
    }

    /// Drop the download's row and everything under it. Its bytes stay counted
    /// in [`SessionCounters`], which is process-lifetime.
    pub fn remove_download(&self, download_id: DownloadId) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.downloads.remove(&download_id);
    }

    /// Republish the whole managed server list (ADR-0080). Whole, never a
    /// patch: the store is the list's single source, so a published level is
    /// always a list the store actually held.
    /// Republish every **Port Mapping** row (ADR-0086). Whole, never a patch:
    /// the mapper holds one row per *desired* mapping, so a published level is
    /// always the whole set — which is what lets "the TCP listener is not
    /// mapped" be a row rather than an absence.
    pub(crate) fn install_shared_directories(
        &self,
        list: Vec<crate::directory_scan::InstalledDirectory>,
    ) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .shared_directories = list;
    }

    pub(crate) fn set_mappings(&self, mappings: Vec<MappingDiagnostics>) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .mappings = mappings;
    }

    /// Republish the whole managed server list (ADR-0080). Whole, never a
    /// patch: the store is the list's single source, so a published level is
    /// always a list the store actually held.
    pub fn set_servers(&self, servers: Vec<ManagedServer>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        Self::install_servers(&mut inner, servers);
        drop(inner);
        self.server_moved();
    }

    /// Read the managed server list back from the store and publish it in one
    /// critical section on the level (ADR-0083: the store handle carries no
    /// lock, so this is where read-back and publish stay atomic). Two writers
    /// that each mutate then call this can interleave freely: whichever read
    /// lands last also publishes last, so the level can never settle on a
    /// read that predates a later one. A failed read publishes nothing.
    pub(crate) fn publish_servers_from(
        &self,
        read: impl FnOnce() -> Result<Vec<ManagedServer>, CoreError>,
    ) -> Result<(), CoreError> {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        Self::install_servers(&mut inner, read()?);
        drop(inner);
        self.server_moved();
        Ok(())
    }

    fn install_servers(inner: &mut DiagnosticsInner, servers: Vec<ManagedServer>) {
        inner.servers = servers;
        inner
            .server_health
            .project(&inner.servers, inner.connected_server.as_ref());
    }

    /// Publish which server rmule holds a live session with, or
    /// `None` once it is gone. Deliberately *not* touched by
    /// [`set_servers`](Self::set_servers): the list and the session are
    /// separate facts, and aMule's own `RemoveServer` leaves a live connection
    /// alone.
    ///
    /// The server's grants ride with it, under one lock, so a reader never
    /// sees one session's endpoint beside another's grants.
    pub fn set_connected_server(&self, server: Option<(ServerEndpoint, ServerGrants)>) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let (server, grants) = server
            .map_or((None, ServerGrants::default()), |(server, grants)| {
                (Some(server), grants)
            });
        // The announcement names its own server, so a login that publishes
        // after the follower already decided keeps it; a session's end or
        // another server's clears it.
        if inner
            .share_announcement
            .as_ref()
            .is_some_and(|told| server.as_ref() != Some(&told.server))
        {
            inner.share_announcement = None;
        }
        inner.connected_server = server;
        inner.connected_server_grants = grants;
        let level = &mut *inner;
        level
            .server_health
            .project(&level.servers, level.connected_server.as_ref());
        drop(inner);
        self.server_moved();
    }

    /// Publish where the Kad activity stands.
    pub(crate) fn set_kad_state(&self, state: super::KadState) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .kad_state = state;
    }

    /// The Kad Activity installs its fact reader at start (ADR-0028: the
    /// snapshot is complete without an actor round trip).
    pub(crate) fn install_kad(&self, source: super::kad::KadFactsSource) {
        self.inner.lock().expect("diagnostics mutex poisoned").kad = Some(source);
    }

    /// The Kad Activity retired: `kad` reads `None` again.
    pub(crate) fn clear_kad(&self) {
        self.inner.lock().expect("diagnostics mutex poisoned").kad = None;
    }

    /// The connected server's grants, or `None` with no session.
    pub(crate) fn connected_server_grants(&self) -> Option<ServerGrants> {
        let inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner
            .connected_server
            .as_ref()
            .map(|_| inner.connected_server_grants)
    }

    /// Re-publish the connected server's grants after a mid-session
    /// `OP_IDCHANGE` re-projected them (ADR-0047). Ignored with no session.
    pub fn set_connected_server_grants(&self, grants: ServerGrants) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        if inner.connected_server.is_some() {
            inner.connected_server_grants = grants;
        }
    }

    /// Clone the whole state under one lock, so every figure in the result was
    /// read at the same instant; the Kad facts are read through the running
    /// activity's installed reader (leaf reads, no lock back into this state).
    #[must_use]
    pub fn snapshot(&self) -> DiagnosticsSnapshot {
        let inner = self.inner.lock().expect("diagnostics mutex poisoned");
        DiagnosticsSnapshot {
            downloads: inner.downloads.clone(),
            uploads: inner.uploads.clone(),
            shared_files: inner.shared_files.counters(),
            session: inner.session,
            servers: {
                let now = std::time::SystemTime::now();
                inner
                    .servers
                    .iter()
                    .map(|server| {
                        let health = &inner.server_health;
                        ServerDiagnostics::at(server.clone(), now, health.policy())
                            .resolved_at(health.resolved_address(&server.endpoint))
                            .died(health.dead_since(&server.endpoint))
                    })
                    .collect()
            },
            status_sweep_unheard: inner.server_health.unheard(),
            share_announcement: inner.share_announcement.clone(),
            connected_server: inner.connected_server.clone(),
            connected_server_grants: inner.connected_server_grants,
            search_more_results: inner.search_more_results,
            addresses: inner.addresses.as_ref().map_or_else(Vec::new, address_rows),
            mappings: inner.mappings.clone(),
            taken_at: Some(Instant::now()),
            kad: inner.kad.as_ref().map(super::kad::KadFactsSource::read),
            kad_state: inner.kad_state,
            shared_directories: inner
                .shared_directories
                .iter()
                .map(crate::directory_scan::InstalledDirectory::read)
                .collect(),
            natt_own_mapping: inner
                .addresses
                .as_ref()
                .map(|addresses| addresses.own_mapping(SocketRole::Udp)),
            kad_tasks_live: inner.kad.as_ref().map_or(0, |kad| kad.tasks_live),
            client_udp_bind_failure: inner.client_udp_bind_failure,
            half_bound_pairs: inner
                .addresses
                .as_ref()
                .map_or_else(Vec::new, half_bound_rows)
                .into_iter()
                // The server-UDP row rides beside the bind table, not
                // through it, so it is appended rather than
                // walked from `SocketRole::ALL` like the first two.
                .chain(inner.server_udp_half_bound)
                .collect(),
        }
    }
}

/// The **Address Learning** rows for one snapshot: every (family, role) whose
/// **Family Pair** actually bound that family, in family-then-role order.
///
/// Only bound combinations are listed. A row for a family a role never bound
/// would read as "unknown" forever and say nothing — absence is the honest
/// rendering of a socket that does not exist.
pub(crate) fn address_rows(addresses: &SharedAddressLearning) -> Vec<AddressDiagnostics> {
    let mut rows = Vec::new();
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let hint = addresses.nat_hint(family);
        for role in SocketRole::ALL {
            if !addresses.bound(role, family) {
                continue;
            }
            rows.push(AddressDiagnostics {
                family,
                role,
                verdict: addresses.endpoint(family, role),
                hint,
            });
        }
    }
    rows
}

/// The **Address Learning**-backed half of one snapshot's **Half-Bound Pair**
/// rows: every role the bind table keys on — the eD2k listener
/// and client-UDP — whose Family Pair came up without a family it selected,
/// in [`SocketRole::ALL`] order.
///
/// The server-UDP pair binds no learned endpoint, so it is not among these:
/// its own row is diagnostics-only (`DiagnosticsState::record_server_udp_bind`),
/// appended by [`DiagnosticsState::snapshot`] rather than read
/// from here — `SocketRole` (this function's key) has no `ServerUdp` variant
/// on purpose, since a row in the bind table is what feeds the Desired
/// Mapping Set (ADR-0086).
fn half_bound_rows(addresses: &SharedAddressLearning) -> Vec<rmule_net::family::HalfBound> {
    SocketRole::ALL
        .into_iter()
        .filter_map(|role| addresses.half_bound(role))
        .collect()
}

#[cfg(test)]
mod tests;
