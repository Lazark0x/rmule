//! The search surface's words: why a search failed, was refused or dropped a
//! row, where each of its legs stands, and every search event's line in the
//! Networks log. Each match is exhaustive, so a code core adds cannot reach
//! the screen without its words.

use rmule_core::{
    LegNotSent, RelatedSearchRefusal, SearchEvent, SearchFailure, SearchLegState, SearchLegs,
    SearchResultSkipReason, SweepTally,
};

use super::Sentence;
use super::units::seconds;
use crate::state::MoreEnded;

/// A [`MoreEnded`] as the operator reads it in the entry's status line.
#[must_use]
pub const fn more_ended_words(ended: MoreEnded) -> &'static str {
    match ended {
        MoreEnded::Replaced => {
            "no more to ask for: a newer search replaced the rows the server kept"
        }
        MoreEnded::Answered => "the server sent all it had",
        MoreEnded::Disconnected => "no more to ask for: the server that kept them disconnected",
    }
}

/// Why a request for more results was not sent — one sentence for every
/// cause core folds into `SearchMoreRefused` (ADR-0036).
pub const MORE_REFUSED: &str =
    "no more results to ask for — another search went out since, or the server has none left";

/// Why a **Related-Files Search** cannot be asked, in the words every surface
/// uses — the dimmed menu item, the refused entry, the status bar.
#[must_use]
pub const fn refusal_text(reason: RelatedSearchRefusal) -> &'static str {
    match reason {
        RelatedSearchRefusal::NotConnected => "not connected",
        RelatedSearchRefusal::NotOffered => "server does not offer it",
    }
}

/// Why a search failed, as the operator reads it. Exhaustive, so a failure
/// core adds cannot reach the screen without its words.
#[must_use]
pub const fn search_failure_words(reason: SearchFailure) -> &'static str {
    match reason {
        SearchFailure::ServerDisconnected => "the server disconnected",
        SearchFailure::RelatedSearchNotOffered => refusal_text(RelatedSearchRefusal::NotOffered),
        SearchFailure::RelatedAnswerUnattributable => {
            "the server's answer could not be told from a late one; ask again"
        }
    }
}

/// Why a row of a search answer was dropped, as the operator reads it.
#[must_use]
pub const fn skip_words(reason: SearchResultSkipReason) -> &'static str {
    match reason {
        SearchResultSkipReason::MalformedPayload => "the answer was malformed",
        SearchResultSkipReason::MissingFileName => "the row had no file name",
        SearchResultSkipReason::MissingFileSize => "the row had no file size",
        SearchResultSkipReason::TagDecodeFailed => "a field of the row could not be read",
        SearchResultSkipReason::FileSizeAboveLimit => {
            "the row named a file larger than eD2k allows (256 GiB)"
        }
        SearchResultSkipReason::FileSizeZero => "the row named a file of zero bytes",
    }
}

/// One leg's state as the operator reads it: `leg` names it, and the words
/// for "never ran" depend on which leg it is.
fn leg_clause(leg: &str, state: SearchLegState, reconnecting: bool) -> String {
    let words = match state {
        SearchLegState::WaitingForSession if reconnecting => "waiting for the reconnect",
        SearchLegState::WaitingForSession => "waiting for a connection",
        SearchLegState::WaitingForKad => "waiting for Kad",
        SearchLegState::Sent => "searching",
        SearchLegState::Settled => "done",
        SearchLegState::NotRun if leg == "Kad" => "not running",
        SearchLegState::NotRun => "not asked",
        SearchLegState::Unanswered => "not answered — the session ended",
        SearchLegState::WalkStopped => "cut short — Kad stopped",
        SearchLegState::NotSent(why) => not_sent_words(why),
    };
    format!("{leg}: {words}")
}

/// The sweep's clause: its state, with the servers it asked and those that
/// answered once they are known (ADR-0034's amendment) — "done" alone
/// cannot tell a sweep of none from a sweep of fifty.
fn sweep_clause(state: SearchLegState, tally: SweepTally, reconnecting: bool) -> String {
    let answered = format!("{} answered", tally.answered);
    match state {
        SearchLegState::Settled if tally.asked == 0 && tally.answered == 0 => {
            "other servers: none listed to ask".to_string()
        }
        SearchLegState::Settled => format!("other servers: {} asked, {answered}", tally.asked),
        SearchLegState::Sent if tally.answered > 0 => {
            format!("other servers: searching, {answered}")
        }
        _ => leg_clause("other servers", state, reconnecting),
    }
}

/// Why a leg was never sent, as its clause reads.
const fn not_sent_words(why: LegNotSent) -> &'static str {
    match why {
        LegNotSent::NoServer => "not sent — no server",
        LegNotSent::NoKadContact => "not sent — no Kad contact answered",
        LegNotSent::KadKeywordHeld => "not sent — another Kad lookup holds this word",
        LegNotSent::NoKadKeyword => "not sent — no word of three letters or more",
        LegNotSent::KadStopped => "not sent — Kad stopped",
    }
}

/// A search's legs in one line: each leg of a keyword search and
/// where it stands. A leg that never runs for this kind of search — the
/// sweep and Kad of a Related-Files Search — is left out. `reconnecting`:
/// core is re-making the operator's lost session, which is what a leg
/// waiting for a session waits for.
#[must_use]
pub fn legs_line(legs: SearchLegs, related: bool, reconnecting: bool) -> String {
    let mut clauses = vec![leg_clause("server", legs.server, reconnecting)];
    if !related {
        clauses.push(sweep_clause(legs.sweep, legs.sweep_servers, reconnecting));
        clauses.push(leg_clause("Kad", legs.kad, reconnecting));
    }
    clauses.join(" · ")
}

/// A file class as the search type selector and the Type column name it —
/// aMule's own labels (`GetFiletypeDesc`), in the TUI's words.
#[must_use]
pub const fn file_class_words(class: rmule_primitives::Ed2kFileClass) -> &'static str {
    use rmule_primitives::Ed2kFileClass as C;
    match class {
        C::Audio => "Audio",
        C::Video => "Videos",
        C::Image => "Pictures",
        C::Document => "Texts",
        C::Program => "Programs",
        C::Archive => "Archives",
        C::CdImage => "CD-Images",
    }
}

/// [`MORE_REFUSED`] as the status bar's note.
pub const MORE_REFUSED_NOTE: Sentence = Sentence::fixed(MORE_REFUSED);

/// What the status bar says when a search waits for a connection.
pub const WAITING_FOR_CONNECTION: Sentence =
    Sentence::fixed("search waits for a connection: connect to a server (c) to send it");

/// A search's Kad lookup put off Kad's publishing of the operator's shared
/// files under the same word.
pub const KAD_PUBLISH_DEFERRED: &str =
    "search: Kad publishes your shared files under this word once the search's Kad lookup ends";

/// A search started.
pub const STARTED: Sentence = Sentence::fixed("search started");
/// A search completed.
pub const COMPLETED: Sentence = Sentence::fixed("search completed");
/// A search was cancelled.
pub const CANCELLED: Sentence = Sentence::fixed("search cancelled");
/// The operator asked the server for more of a search's results.
pub const ASKING_FOR_MORE: Sentence = Sentence::fixed("asking the server for more results");

/// Core refused a Related-Files Search before it started.
#[must_use]
pub fn related_refused(reason: RelatedSearchRefusal) -> Sentence {
    Sentence::owned(format!("related search refused: {}", refusal_text(reason)))
}

/// A search failed.
#[must_use]
pub fn failed(reason: SearchFailure) -> Sentence {
    let words = search_failure_words(reason);
    Sentence::owned(match reason {
        SearchFailure::RelatedSearchNotOffered => format!("related search refused: {words}"),
        SearchFailure::ServerDisconnected => format!("search failed: {words}"),
        SearchFailure::RelatedAnswerUnattributable => format!("related search: {words}"),
    })
}

/// A search event's line in the Networks log.
#[must_use]
pub fn log_line(event: &SearchEvent) -> Sentence {
    use SearchEvent as Se;
    Sentence::owned(match event {
        Se::SearchStarted { .. } => "search started".to_string(),
        Se::SearchResultsReceived { results, .. } => {
            format!("search: {} results", results.len())
        }
        Se::SearchResultSkipped { reason, .. } => {
            format!("search result skipped: {}", skip_words(*reason))
        }
        Se::SearchRefused { reason, .. } => {
            format!("search refused: {}", refusal_text(*reason))
        }
        Se::SearchCompleted { total_results, .. } => {
            format!("search completed ({total_results} results)")
        }
        Se::SearchCancelled { .. } => "search cancelled".to_string(),
        Se::SearchWaitingForTurn { send_in, .. } => format!(
            "search waits {} s for its turn on the server",
            seconds(*send_in)
        ),
        Se::SearchWaitingForConnection { .. } => {
            "search waits for a connection or Kad; it is sent when either comes up".to_string()
        }
        Se::SearchLegsChanged { legs, .. } => {
            format!("search legs: {}", legs_line(*legs, false, false))
        }
        Se::SearchSentToServer { .. } => "search sent after its turn".to_string(),
        Se::SearchDeferredKadPublish { .. } => KAD_PUBLISH_DEFERRED.to_string(),
        Se::SearchMoreRequested { .. } => "search asks the server for more".to_string(),
        Se::SearchMoreRefused { .. } => format!("search: {MORE_REFUSED}"),
        Se::SearchFailed { reason, .. } => {
            format!("search failed: {}", search_failure_words(*reason))
        }
    })
}

/// Stop on an entry whose search has not started.
pub const NOT_STARTED: Sentence = Sentence::fixed("the search has not started yet");

/// The Kad method asked for, which every search already uses.
pub const KAD_ALWAYS_ON: Sentence = Sentence::fixed("always on — every search also walks Kad");

/// Why nothing can be sent now: no core attached, and why (`Some`), or the
/// core stopped (`None`).
#[must_use]
pub fn no_core_words(ui_only: Option<crate::state::AttachFailure>) -> String {
    match ui_only {
        Some(failure) => format!(
            "no core is attached (UI-only run: {})",
            super::app::attach_failure_words(failure)
        ),
        None => "the core has stopped".to_string(),
    }
}

/// `n` with no core to send through.
#[must_use]
pub fn nothing_sent(ui_only: Option<crate::state::AttachFailure>) -> Sentence {
    Sentence::owned(format!("nothing sent — {}", no_core_words(ui_only)))
}

/// A server that holds more of a search, or why it no longer does, as the
/// entry's status clause.
#[must_use]
pub fn more_clause(asks_left: u8) -> String {
    if asks_left > 0 {
        "server has more".to_string()
    } else {
        format!(
            "server has more; rmule stops after {} more pages",
            rmule_core::MORE_RESULTS_ASKS
        )
    }
}

/// `n` on a search whose server has more, but rmule has asked as often as it
/// asks.
#[must_use]
pub fn more_spent() -> Sentence {
    Sentence::owned(more_clause(0))
}

/// `n` on a search whose server holds no more for it, and why.
#[must_use]
pub fn more_ended(ended: Option<MoreEnded>) -> Sentence {
    Sentence::fixed(ended.map_or(MORE_REFUSED, more_ended_words))
}

/// A query the lexer refused.
#[must_use]
pub fn invalid_query(error: &rmule_primitives::PrimitiveError) -> Sentence {
    use rmule_primitives::{PrimitiveError, QueryFault};
    Sentence::fixed(match error {
        PrimitiveError::InvalidSearchQuery { fault } => match fault {
            QueryFault::UnterminatedQuote => "not searched: a quote is never closed",
            QueryFault::BooleanOperator => "not searched: rmule does not offer OR or NOT",
            QueryFault::NoWord => "not searched: type at least one word",
            QueryFault::TooManyWords => "not searched: at most eleven words",
        },
        // `KeywordQuery::new` refuses with `InvalidSearchQuery` alone; a
        // variant added to the error is a decision made here, not a fall
        // through to one sentence.
        PrimitiveError::InvalidHashLength { .. }
        | PrimitiveError::InvalidHashEncoding { .. }
        | PrimitiveError::InvalidPartHashSetCount { .. }
        | PrimitiveError::FileTooLarge { .. }
        | PrimitiveError::FileSizeAboveLimit { .. }
        | PrimitiveError::FileSizeZero
        | PrimitiveError::InvalidLink { .. }
        | PrimitiveError::UnsupportedLinkKind
        | PrimitiveError::DuplicateLinkField { .. }
        | PrimitiveError::InvalidServerEndpoint { .. }
        | PrimitiveError::InvalidPeerEndpoint { .. }
        | PrimitiveError::TruncatedPacket { .. }
        | PrimitiveError::InvalidPacketLength { .. }
        | PrimitiveError::UnsupportedProtocolByte { .. }
        | PrimitiveError::TrailingPacketBytes { .. }
        | PrimitiveError::TruncatedTag { .. }
        | PrimitiveError::InvalidTag { .. }
        | PrimitiveError::UnsupportedTagType { .. }
        | PrimitiveError::InvalidSearchResult { .. }
        | PrimitiveError::KeyGenerationFailed
        | PrimitiveError::InvalidPublicKey
        | PrimitiveError::InvalidPrivateKey => "not searched: the query could not be read",
    })
}

/// Why a size the operator typed in the filter form does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SizeFault {
    /// The unit after the number is none of B, KB, MB, GB, TB.
    UnknownUnit(String),
    /// The text is not a number with a unit.
    NotASize(String),
    /// More bytes than a size can hold.
    TooLarge,
}

/// Why the filter form's fields do not make constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterError {
    /// The min size does not parse.
    MinSize(SizeFault),
    /// The max size does not parse.
    MaxSize(SizeFault),
    /// The max size is below the min size.
    MaxBelowMin,
    /// The min sources is not a whole number.
    MinSourcesNotWhole(String),
}

/// A size fault, as a clause.
fn size_fault_words(fault: &SizeFault) -> String {
    match fault {
        SizeFault::UnknownUnit(unit) => format!("'{unit}' is not a size unit (B/KB/MB/GB/TB)"),
        SizeFault::NotASize(text) => format!("'{text}' is not a size (try 700 MB)"),
        SizeFault::TooLarge => "size is too large".to_string(),
    }
}

/// A filter error, as the filter form shows it under its fields.
#[must_use]
pub fn filter_error_words(error: &FilterError) -> String {
    match error {
        FilterError::MinSize(fault) => format!("min size: {}", size_fault_words(fault)),
        FilterError::MaxSize(fault) => format!("max size: {}", size_fault_words(fault)),
        FilterError::MaxBelowMin => "max size must not be below min size".to_string(),
        FilterError::MinSourcesNotWhole(text) => {
            format!("min sources: '{text}' is not a whole number")
        }
    }
}

/// A search refused for a filter that does not parse.
#[must_use]
pub fn invalid_filter(error: &FilterError) -> Sentence {
    Sentence::owned(format!("invalid filter: {}", filter_error_words(error)))
}

/// *Search related* while it cannot be asked.
#[must_use]
pub fn related_unavailable(reason: &'static str) -> Sentence {
    Sentence::owned(format!("search related: {reason}"))
}

#[cfg(test)]
mod tests {
    use rmule_core::{LegNotSent, SearchLegState as L, SearchLegs, SweepTally};

    use super::legs_line;

    /// A sweep that asked twelve servers, seven of which answered.
    const SWEPT: SweepTally = SweepTally {
        asked: 12,
        answered: 7,
    };

    /// The sweep says how many servers it asked and how many answered, so a
    /// sweep of none never reads like a sweep of fifty.
    #[test]
    fn the_sweep_clause_counts_the_servers_asked_and_answered() {
        let legs = |sweep, sweep_servers| SearchLegs {
            server: L::Settled,
            sweep,
            kad: L::NotRun,
            sweep_servers,
        };
        assert_eq!(
            legs_line(legs(L::Settled, SweepTally::default()), false, false),
            "server: done · other servers: none listed to ask · Kad: not running"
        );
        assert_eq!(
            legs_line(
                legs(
                    L::Sent,
                    SweepTally {
                        asked: 0,
                        answered: 2
                    }
                ),
                false,
                false
            ),
            "server: done · other servers: searching, 2 answered · Kad: not running"
        );
        assert_eq!(
            legs_line(legs(L::Settled, SWEPT), false, false),
            "server: done · other servers: 12 asked, 7 answered · Kad: not running"
        );
    }

    /// A server leg's lost session reads as the reconnect it waits for, or,
    /// with none coming, as not answered — never as a failed search.
    #[test]
    fn a_lost_server_leg_reads_as_the_reconnect_or_as_not_answered() {
        let legs = |server| SearchLegs {
            server,
            sweep: L::Settled,
            kad: L::Settled,
            sweep_servers: SWEPT,
        };
        assert_eq!(
            legs_line(legs(L::WaitingForSession), false, true),
            "server: waiting for the reconnect · other servers: 12 asked, 7 answered · Kad: done"
        );
        assert_eq!(
            legs_line(legs(L::Unanswered), false, false),
            "server: not answered — the session ended · other servers: 12 asked, 7 answered · Kad: done"
        );
    }

    /// A Kad leg that Kad stopped under, or before, never reads as done.
    #[test]
    fn a_kad_leg_kad_stopped_under_says_so() {
        let legs = |kad| SearchLegs {
            server: L::Settled,
            sweep: L::Settled,
            kad,
            sweep_servers: SWEPT,
        };
        assert_eq!(
            legs_line(legs(L::WalkStopped), false, false),
            "server: done · other servers: 12 asked, 7 answered · Kad: cut short — Kad stopped"
        );
        assert_eq!(
            legs_line(legs(L::NotSent(LegNotSent::KadStopped)), false, false),
            "server: done · other servers: 12 asked, 7 answered · Kad: not sent — Kad stopped"
        );
    }

    /// A Kad leg whose walk asked nobody says why, and a search that put off
    /// Kad's publishing says so in the log.
    #[test]
    fn a_kad_leg_that_asked_nobody_says_why() {
        let legs = |kad| SearchLegs {
            server: L::Settled,
            sweep: L::Settled,
            kad,
            sweep_servers: SWEPT,
        };
        assert_eq!(
            legs_line(legs(L::NotSent(LegNotSent::KadKeywordHeld)), false, false),
            "server: done · other servers: 12 asked, 7 answered · Kad: not sent — another Kad lookup holds this word"
        );
        assert_eq!(
            legs_line(legs(L::NotSent(LegNotSent::NoKadContact)), false, false),
            "server: done · other servers: 12 asked, 7 answered · Kad: not sent — no Kad contact answered"
        );
        assert_eq!(
            super::log_line(&rmule_core::SearchEvent::SearchDeferredKadPublish {
                search_id: rmule_core::SearchId::from_u64(1),
            })
            .to_string(),
            super::KAD_PUBLISH_DEFERRED
        );
    }
}
