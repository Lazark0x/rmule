//! The **Source Book**'s alias index: every endpoint and `CallbackKey` a record
//! answers to points at exactly that record. A User Hash is no alias — a
//! matching one merges nothing (ADR-0090) — so it is read off the records.

use std::collections::HashMap;

use rmule_primitives::PeerEndpoint;

use super::record::RecordId;
use crate::adapters::CallbackKey;

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
