//! Replay every captured welcome burst through a fresh `Ed2kSession` and
//! assert the emitted output sequence matches the curated `events.toml`
//! oracle in the same directory.
//!
//! No-op when no captured fixtures exist. The comparison is on event
//! *types* only (not full fields) — per-field correctness is already
//! covered by Task 14's round-trip test and the handwritten per-packet
//! suites. What's unique here is the state-machine flow: that the
//! session walks from `BeforeStart` through `AwaitingIdChange` into
//! `LoggedIn` and emits the right events in the right order for real
//! wire bytes, and that the terminal `Close(reason)` discriminant
//! matches the oracle's final `Disconnected` reason label.

use std::fs;
use std::path::Path;

use rmule_ed2k::{Ed2kEvent, Output};
use rmule_primitives::session::drain;
use serde::Deserialize;

#[derive(Deserialize)]
struct EventOracle {
    event: Vec<OracleEntry>,
}

#[derive(Deserialize)]
struct OracleEntry {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    reason: Option<String>,
}

#[test]
fn captured_welcome_burst_replays_through_session_matching_events_oracle() {
    let captured_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/server/captured");
    let dirs = crate::fixture::capture_dirs(&captured_root, "s2c.bin");
    if dirs.is_empty() {
        eprintln!("note: no captured/* directories — replay test is a no-op until a capture lands");
        return;
    }
    for dir in dirs {
        let s2c = fs::read(dir.join("s2c.bin"))
            .unwrap_or_else(|e| panic!("read {}/s2c.bin: {e}", dir.display()));
        let oracle_text = fs::read_to_string(dir.join("events.toml"))
            .unwrap_or_else(|e| panic!("read {}/events.toml: {e}", dir.display()));
        let oracle: EventOracle = toml::from_str(&oracle_text)
            .unwrap_or_else(|e| panic!("{}/events.toml parse: {e}", dir.display()));

        let mut session = crate::fixture::session(0);
        session.start();
        session.handle_bytes(&s2c);

        // Drain *all* outputs (events + the terminal Close) so we can
        // cross-check both the event sequence and the close reason.
        let mut session_event_types: Vec<String> = Vec::new();
        let mut session_close_label: Option<&'static str> = None;
        for output in drain(|| session.poll_output()) {
            match output {
                Output::Event(event) => {
                    // The terminal `Disconnected` is validated separately
                    // (against the oracle's terminal reason via `Close`
                    // below); exclude it here so this comparison covers only
                    // the substantive event stream.
                    let label = event_type_label(&event);
                    if label != "Disconnected" {
                        session_event_types.push(label.to_owned());
                    }
                }
                Output::Close(reason) => {
                    session_close_label = Some(reason.label());
                }
                Output::Write(_) => {}
            }
        }

        // The oracle records every event the *driver* observed, including
        // the terminal `Disconnected`. The session now emits that paired
        // `Disconnected` on every close path too, but its reason is checked
        // separately below, so filter `Disconnected` from both sides and
        // compare only the substantive events here.
        let session_oracle_types: Vec<String> = oracle
            .event
            .iter()
            .filter(|e| e.event_type != "Disconnected")
            .map(|e| e.event_type.clone())
            .collect();

        assert_eq!(
            session_event_types,
            session_oracle_types,
            "{}: session event sequence != oracle (excluding terminal Disconnected)",
            dir.display()
        );

        // The oracle's terminal `Disconnected` carries the same reason
        // label the session's `Close(reason)` should bear. If the oracle
        // lacks one, the session must also have no terminal close (e.g.,
        // capture cut while still in `LoggedIn`).
        let oracle_terminal_reason: Option<&str> = oracle
            .event
            .iter()
            .rev()
            .find(|e| e.event_type == "Disconnected")
            .and_then(|e| e.reason.as_deref());
        match (session_close_label, oracle_terminal_reason) {
            (Some(label), Some(expected)) => assert_eq!(
                label,
                expected,
                "{}: session Close label != oracle Disconnected reason",
                dir.display()
            ),
            (None, None) => {}
            (got, expected) => panic!(
                "{}: terminal mismatch — session Close = {:?}, oracle reason = {:?}",
                dir.display(),
                got,
                expected
            ),
        }
    }
}

fn event_type_label(event: &Ed2kEvent) -> &'static str {
    match event {
        Ed2kEvent::LoginRequested { .. } => "LoginRequested",
        Ed2kEvent::LoginAccepted { .. } => "LoginAccepted",
        Ed2kEvent::LoginRejected => "LoginRejected",
        Ed2kEvent::ServerMessageReceived { .. } => "ServerMessageReceived",
        Ed2kEvent::ServerStatusReceived { .. } => "ServerStatusReceived",
        Ed2kEvent::ServerIdentified { .. } => "ServerIdentified",
        Ed2kEvent::ServerListReceived { .. } => "ServerListReceived",
        Ed2kEvent::SourcesFound { .. } => "SourcesFound",
        Ed2kEvent::SearchResultsFound { .. } => "SearchResultsFound",
        Ed2kEvent::SearchResultSkipped { .. } => "SearchResultSkipped",
        Ed2kEvent::PeerCallbackRequested { .. } => "PeerCallbackRequested",
        Ed2kEvent::CallbackFailed => "CallbackFailed",
        Ed2kEvent::HolepunchIntroduced { .. } => "HolepunchIntroduced",
        Ed2kEvent::HolepunchRefused { .. } => "HolepunchRefused",
        Ed2kEvent::CommandRejected { .. } => "CommandRejected",
        Ed2kEvent::UnknownServerPacket { .. } => "UnknownServerPacket",
        Ed2kEvent::CompressedFrameSkipped { .. } => "CompressedFrameSkipped",
        Ed2kEvent::Disconnected { .. } => "Disconnected",
    }
}
