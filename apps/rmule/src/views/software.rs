//! The Software column's order: a peer's client ranked by [`ClientSoftware`]'s
//! own order, so the column sorts as a quantity. The cell's text is the TUI's
//! [`software_label`].
//!
//! [`software_label`]: crate::words::software::label

use rmule_core::diagnostics::ClientSoftware;

/// Each client the rows of one table name, in [`ClientSoftware`]'s own order
/// (family rank, then version, then mod): a Software column's sort value is
/// its client's place here, so it sorts as a quantity and never by
/// [`software_label`](crate::words::software::label)'s text.
pub(crate) struct SoftwareRanks(Vec<ClientSoftware>);

impl SoftwareRanks {
    /// The ranks of every client in `clients`.
    pub(crate) fn new<'a>(clients: impl Iterator<Item = &'a ClientSoftware>) -> Self {
        let mut clients: Vec<ClientSoftware> = clients.cloned().collect();
        clients.sort();
        clients.dedup();
        Self(clients)
    }

    /// `client`'s rank; `None` for a peer that named none, which sorts last.
    pub(crate) fn rank(&self, client: Option<&ClientSoftware>) -> Option<u64> {
        let at = self.0.binary_search(client?).ok()?;
        u64::try_from(at).ok()
    }
}
