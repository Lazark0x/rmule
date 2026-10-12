//! Kad's words: where the join's seeds came from, and why the node stopped.

use rmule_bootstrap::{FetchError, NodesDatPipelineError};
use rmule_core::diagnostics::KadState;
use rmule_core::{
    BuddyDialFailure, KadSeedOutcome, KadStopReason, KadUnavailableReason, SeedReadFault,
};
use rmule_primitives::Ipv4Endpoint;

use super::Sentence;
use super::os::refusal_words;

/// A dial to our recruited buddy that did not hold a link.
#[must_use]
pub fn buddy_dial_failed(buddy: Ipv4Endpoint, cause: BuddyDialFailure) -> Sentence {
    let why = match cause {
        BuddyDialFailure::Dial { cause } => super::login::dial_words(cause),
        BuddyDialFailure::HelloIncomplete => "it hung up before its hello".to_string(),
        BuddyDialFailure::CryptIncompatible => {
            "its encryption stance and ours cannot meet".to_string()
        }
        BuddyDialFailure::Stranger => "another client answered at its address".to_string(),
    };
    Sentence::owned(format!("buddy {buddy}: dial failed, {why}"))
}

/// Where the Kad join's seeds came from — the note the app sends once the
/// join lands.
#[must_use]
pub fn seed_outcome_words(outcome: &KadSeedOutcome) -> Sentence {
    Sentence::owned(match outcome {
        KadSeedOutcome::Skipped => "Kad off".to_string(),
        KadSeedOutcome::Persisted {
            contacts,
            candidates,
        } => format!("Kad: {} saved contacts", contacts + candidates),
        KadSeedOutcome::Stranded { read_error: None } => {
            "Kad: no saved contacts — waiting for an eD2k peer".to_string()
        }
        KadSeedOutcome::Stranded {
            read_error: Some(fault),
        } => format!("Kad: saved contacts unusable ({})", seed_read_words(*fault)),
        KadSeedOutcome::Acquired {
            contacts,
            candidates,
        } => format!("Kad: fetched {} contacts", contacts + candidates),
        KadSeedOutcome::AcquireFailed(error) => {
            format!("Kad: contact fetch failed ({})", nodes_dat_words(error))
        }
    })
}

/// Why the saved contacts could not be used.
fn seed_read_words(fault: SeedReadFault) -> String {
    match fault {
        SeedReadFault::Io { kind, os_code } => refusal_words(kind, os_code),
        SeedReadFault::TooOld => "an old version-0 nodes.dat".to_string(),
        SeedReadFault::Undecodable => "not a nodes.dat rmule reads".to_string(),
    }
}

/// Why a nodes.dat fetch installed nothing. What a transport said beyond
/// its kind is left to the Run Log.
fn nodes_dat_words(error: &NodesDatPipelineError) -> String {
    match error {
        NodesDatPipelineError::Fetch(fetch) => fetch_words(fetch),
        NodesDatPipelineError::TooOld => "the file is an old version-0 nodes.dat".to_string(),
        NodesDatPipelineError::BootstrapEdition(_) => {
            "the file is not a nodes.dat rmule reads".to_string()
        }
    }
}

/// Why a fetch returned no file.
pub(crate) fn fetch_words(error: &FetchError) -> String {
    match error {
        FetchError::Transport { .. } => "the address could not be reached".to_string(),
        FetchError::Status { status, .. } => {
            format!("the web server answered HTTP {status}, not the file")
        }
        FetchError::TooLarge { cap } => format!(
            "the file is larger than {}",
            super::units::human_size(*cap as u64)
        ),
        FetchError::Timeout { .. } => "the address did not answer in time".to_string(),
    }
}

/// What the app says while the Kad join is still parked behind its arming
/// edge. The Networks panel's bare "Kad: off" cannot tell "Kad is
/// broken" apart from "Kad joins when you connect", so the app says it on the
/// same two surfaces every other fact of its own reaches.
pub const WAITING_FOR_CONNECT: Sentence = Sentence::fixed(
    "Kad: joins after the first server connect, or press K in Networks to start it now",
);

/// A start of Kad that reaches nothing: what carries out the start has ended
/// for this run (the core stopped), so neither `K` nor a login can start Kad.
pub const JOIN_ENDED: Sentence =
    Sentence::fixed("Kad cannot be started: its start-up has ended for this run — restart rmule");

/// K while a stop is still under way.
pub const STOPPING: Sentence = Sentence::fixed("Kad is stopping; press K again once it is off");

/// Why Kad could not start.
#[must_use]
pub fn kad_unavailable_words(why: KadUnavailableReason) -> String {
    match why {
        KadUnavailableReason::UdpUnbound { port, kind } => format!(
            "UDP port {port} could not be bound ({})",
            super::os::kind_words(kind)
        ),
        KadUnavailableReason::UdpFamilyMissing { family, kind } => format!(
            "its {} socket could not be bound ({})",
            super::reach::family_words(family),
            super::os::kind_words(kind)
        ),
        KadUnavailableReason::StartFailed => "the Kad node failed to start".to_string(),
        KadUnavailableReason::TcpPortUnbound => {
            "no listen port: the TCP port is set to 0 and the listener could not start".to_string()
        }
    }
}

/// Why the Kad node stopped.
#[must_use]
pub const fn stopped(reason: KadStopReason) -> Sentence {
    Sentence::fixed(match reason {
        KadStopReason::Ended => "Kad stopped",
        KadStopReason::Stopped => "Kad stopped: you stopped it; K in Networks starts it again",
        KadStopReason::TaskFailed => "Kad stopped: its task failed; restart rmule to rejoin",
    })
}

/// Where Kad stands, as the Kad pane's first line reads it: core's
/// state, with a running node that nobody has answered yet read as joining.
#[must_use]
pub const fn state_word(state: KadState, contact_responded: bool) -> &'static str {
    match state {
        KadState::Off => "Kad: off",
        KadState::Running if contact_responded => "Kad: running",
        KadState::Running => "Kad: joining",
        KadState::Stopping => "Kad: stopping",
    }
}

/// The Kad pane's key hint: what `K` does now; empty while it can do nothing.
#[must_use]
pub const fn switch_hint(state: KadState) -> &'static str {
    match state {
        KadState::Off => " K start ",
        KadState::Running => " K stop ",
        KadState::Stopping => "",
    }
}
