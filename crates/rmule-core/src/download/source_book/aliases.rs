//! The **Source Book**'s alias index: every endpoint and `CallbackKey` a record
//! answers to points at exactly that record. A User Hash is no alias — a
//! matching one merges nothing (ADR-0090) — so it is read off the records.

use std::collections::HashMap;
use std::net::IpAddr;

use rmule_primitives::PeerEndpoint;

use super::record::RecordId;
use crate::adapters::CallbackKey;

/// The **Source Quota** on one address (ADR-0116): a household behind one NAT.
const ROWS_ON_ONE_ADDRESS: usize = 4;
/// The **Source Quota** on one `/24` or `/64` (ADR-0116).
const ROWS_ON_ONE_SUBNET: usize = 16;

/// Whether `a` and `b` lie in one subnet: a `/24`, or a `/64`.
fn same_subnet(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..4] == b.segments()[..4],
        _ => false,
    }
}

/// Alias → record, one record per alias.
#[derive(Debug, Default)]
pub(super) struct Aliases {
    endpoints: HashMap<PeerEndpoint, RecordId>,
    keys: HashMap<CallbackKey, RecordId>,
}

impl Aliases {
    /// The record `endpoint` names.
    pub(super) fn endpoint(&self, endpoint: PeerEndpoint) -> Option<RecordId> {
        self.endpoints.get(&endpoint).copied()
    }

    /// Whether the book already holds the Source Quota's share of the address
    /// or subnet `endpoint` stands on, every family and informant alike.
    pub(super) fn holds_share_of(&self, endpoint: PeerEndpoint) -> bool {
        let (mut on_address, mut on_subnet) = (0, 0);
        for held in self.endpoints.keys() {
            if same_subnet(held.ip(), endpoint.ip()) {
                on_subnet += 1;
                on_address += usize::from(held.ip() == endpoint.ip());
            }
        }
        on_address >= ROWS_ON_ONE_ADDRESS || on_subnet >= ROWS_ON_ONE_SUBNET
    }

    /// The record `key` names.
    pub(super) fn key(&self, key: CallbackKey) -> Option<RecordId> {
        self.keys.get(&key).copied()
    }

    /// Point `endpoint` at `id`.
    pub(super) fn bind_endpoint(&mut self, endpoint: PeerEndpoint, id: RecordId) {
        self.endpoints.insert(endpoint, id);
    }

    /// Point `key` at `id`.
    pub(super) fn bind_key(&mut self, key: CallbackKey, id: RecordId) {
        self.keys.insert(key, id);
    }

    /// Forget `endpoint`, if it still names `id`.
    pub(super) fn unbind_endpoint(&mut self, endpoint: PeerEndpoint, id: RecordId) {
        if self.endpoints.get(&endpoint) == Some(&id) {
            self.endpoints.remove(&endpoint);
        }
    }

    /// Forget `key`, if it still names `id`.
    pub(super) fn unbind_key(&mut self, key: CallbackKey, id: RecordId) {
        if self.keys.get(&key) == Some(&id) {
            self.keys.remove(&key);
        }
    }
}
