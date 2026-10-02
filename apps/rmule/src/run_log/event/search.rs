//! The Run Log's record of each search event. A batch of results is a count:
//! the names in it are what was asked for in effect, and no level holds them.

use rmule_core::SearchEvent;

use crate::run_log::codes;
use crate::run_log::record::Record;

pub(super) fn record(event: &SearchEvent) -> Record {
    use SearchEvent as S;
    match event {
        S::SearchStarted { search_id } => {
            Record::new("search.started").count("id", search_id.as_u64())
        }
        S::SearchResultsReceived { search_id, results } => Record::new("search.results_received")
            .count("id", search_id.as_u64())
            .count("results", results.len()),
        S::SearchResultSkipped { search_id, reason } => Record::new("search.result_skipped")
            .count("id", search_id.as_u64())
            .code("reason", codes::search_skip(*reason)),
        S::SearchCompleted {
            search_id,
            total_results,
        } => Record::new("search.completed")
            .count("id", search_id.as_u64())
            .count("total_results", *total_results),
        S::SearchCancelled { search_id } => {
            Record::new("search.cancelled").count("id", search_id.as_u64())
        }
        S::SearchRefused { search_id, reason } => Record::new("search.refused")
            .count("id", search_id.as_u64())
            .code("reason", codes::related_refusal(*reason)),
        S::SearchWaitingForTurn { search_id, send_in } => Record::new("search.waiting_for_turn")
            .count("id", search_id.as_u64())
            .count("send_in_secs", send_in.as_secs()),
        S::SearchWaitingForConnection { search_id } => {
            Record::new("search.waiting_for_connection").count("id", search_id.as_u64())
        }
        S::SearchLegsChanged { search_id, legs } => Record::new("search.legs_changed")
            .count("id", search_id.as_u64())
            .code("server", codes::search_leg(legs.server))
            .code("sweep", codes::search_leg(legs.sweep))
            .code("kad", codes::search_leg(legs.kad))
            .count("sweep_asked", legs.sweep_servers.asked)
            .count("sweep_answered", legs.sweep_servers.answered),
        S::SearchDeferredKadPublish { search_id } => {
            Record::new("search.deferred_kad_publish").count("id", search_id.as_u64())
        }
        S::SearchSentToServer { search_id } => {
            Record::new("search.sent_to_server").count("id", search_id.as_u64())
        }
        S::SearchMoreRequested { search_id } => {
            Record::new("search.more_requested").count("id", search_id.as_u64())
        }
        S::SearchMoreRefused { search_id } => {
            Record::new("search.more_refused").count("id", search_id.as_u64())
        }
        S::SearchFailed { search_id, reason } => Record::new("search.failed")
            .count("id", search_id.as_u64())
            .code("reason", codes::search_failure(*reason)),
    }
}
