//! The search facts the diagnostics state keeps: rows **Search Attribution**
//! could give to no live search, and the search the
//! connected server holds more rows for (ADR-0034).

use super::DiagnosticsState;
use crate::search::ServerMoreResults;

impl DiagnosticsState {
    /// Count `rows` Search Result rows dropped because no live search's query
    /// they satisfy.
    pub fn count_search_rows_unattributed(&self, rows: u64) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.search_rows_unattributed_total = inner
            .session
            .search_rows_unattributed_total
            .saturating_add(rows);
    }

    /// The session named the search its server holds more rows for, or none.
    pub(crate) fn set_search_more_results(&self, more: Option<ServerMoreResults>) {
        self.inner
            .lock()
            .expect("diagnostics mutex poisoned")
            .search_more_results = more;
    }
}
