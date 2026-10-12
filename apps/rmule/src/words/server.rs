//! The TUI's own server words, beside the shared ones it re-exports: the
//! log line for an edge of the server list's health and the receipt of a
//! server-policy edit — which word the TUI's own types.

pub use rmule_words::server::*;

use super::Sentence;
use crate::config::PrefEdit;
use crate::state::server_health::HealthEdge;

/// The Networks log's line for an edge of the server list's health.
#[must_use]
pub(crate) fn health_edge(edge: &HealthEdge) -> Sentence {
    use HealthEdge as E;
    match edge {
        E::MarkedDead { server, failures } => marked_dead(server, *failures),
        E::AnsweredAgain { server } => came_back(server),
        E::SweepUnheard => SWEEP_UNHEARD,
        E::Shares(told) => match shares_line(told.shares) {
            Some(what) => shares_log_line(&told.server, what),
            None => shares_log_line(&told.server, SHARES_ANNOUNCED),
        },
    }
}

/// What a saved server-policy edit changed, for the Settings receipt.
#[must_use]
pub fn policy_receipt(edit: &PrefEdit) -> String {
    match edit {
        PrefEdit::DeadServerRetries(limit) => format!("dead after {limit} failed tries"),
        PrefEdit::WithholdShares(true) => {
            "shares withheld from servers that answer related searches".to_string()
        }
        PrefEdit::WithholdShares(false) => "shares announced to every server".to_string(),
        _ => String::new(),
    }
}
