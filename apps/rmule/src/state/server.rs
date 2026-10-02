//! The eD2k server connection marker and the managed-list fold arms.
//!
//! *Which* server the session is on is a level
//! ([`DiagnosticsSnapshot::connected_server`](rmule_core::diagnostics::DiagnosticsSnapshot::connected_server)),
//! so the connection marker carries only what no snapshot reports: the id the
//! server assigned. The list arms are edges with no level twin at all — a list
//! republished whole every tick cannot say *that it changed*, and a fetch in
//! flight has no level to read.

use rmule_core::ServerConnectionEvent;
use rmule_primitives::{ClientId, ServerEndpoint};

use super::{UiState, note};
use crate::words::{Sentence, server as words};

/// eD2k server connection as the UI knows it. HighID/LowID derives from
/// [`ClientId::is_high_id`] — never stored twice.
///
/// Written by exactly one fold arm, `server::fold_connection` — *which*
/// server it is stays on the level (`diagnostics.connected_server`), so this
/// carries only what the level cannot: the assigned id, which no snapshot
/// reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ed2kConnection {
    /// No session — the startup state, and every close.
    #[default]
    Disconnected,
    /// A login was accepted.
    Connected {
        /// The id the server assigned, which decides High ID vs Low ID and
        /// appears in no diagnostics snapshot.
        client_id: ClientId,
    },
}

/// Fold a managed-server-list edge (ADR-0080).
///
/// The list itself is a **level** — republished whole on every data tick — so
/// no arm here rebuilds rows: the Servers tab reads
/// `diagnostics.servers` and gets the same list core holds. What these edges
/// carry that the level cannot is *what just happened*, and only two kinds of
/// that are worth the operator's one status-feed slot:
///
/// - the **update outcome**, which aMule toasts and which is the only edge
///   whose facts (`added`/`updated`/`total`) appear nowhere on the level;
/// - a **single-row CRUD result**, which is the receipt for the keystroke that
///   caused it — suppressed while an update is in flight, because a merged
///   list emits one of these per downloaded row and the operator asked about
///   the batch, not its three thousand parts.
pub(super) fn fold_list(state: &mut UiState, event: rmule_core::ServerListEvent) -> bool {
    use rmule_core::ServerListEvent as E;
    // Receipt for one operator keystroke; a bulk merge's per-row echoes are
    // the batch's business, and `ServerListUpdated` reports the batch.
    let receipt = |state: &mut UiState, text: Sentence| {
        if state.server_list_updating {
            false
        } else {
            note(state, text)
        }
    };
    match event {
        E::ServerAdded { .. } => receipt(state, words::ADDED),
        E::ServerUpdated { .. } => receipt(state, words::UPDATED),
        E::ServerRemoved { .. } => receipt(state, words::REMOVED),
        E::ServerPriorityChanged { priority, .. } => receipt(state, words::priority_set(priority)),
        E::ServerStaticChanged { is_static, .. } => receipt(state, words::static_set(is_static)),
        E::ServerListUpdateStarted { .. } => {
            state.server_list_updating = true;
            note(state, words::LIST_UPDATE_STARTED)
        }
        E::ServerListUpdated {
            added,
            updated,
            total,
        } => {
            state.server_list_updating = false;
            note(state, words::list_updated(added, updated, total))
        }
        E::ServerListUpdateFailed { reason } => {
            state.server_list_updating = false;
            note(state, words::list_update_failed(reason))
        }
    }
}

/// A lost session core is re-making (ADR-0096), as core scheduled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconnect {
    /// The server the operator connected to.
    pub server: ServerEndpoint,
    /// The attempt, its bound and its delay.
    pub step: words::ReconnectStep,
    /// When core dials it, on the monotonic clock: what is left of
    /// the wait is this less the tick's injected `now`.
    pub at: std::time::Instant,
    /// The status note this reconnect last wrote, so the data tick counts
    /// it down only while it is still the note on show.
    pub said: Sentence,
}

impl Reconnect {
    /// The line for this reconnect at `now`.
    #[must_use]
    pub fn line(&self, now: std::time::Instant) -> Sentence {
        words::reconnecting(
            &self.server,
            self.step,
            self.at.saturating_duration_since(now),
        )
    }
}

/// The data tick: a reconnect note still on show is re-said with what
/// is left of its wait, so 'next in S s' counts down.
pub(super) fn count_down(state: &mut UiState, now: std::time::Instant) {
    let Some(reconnect) = state.reconnect.as_mut() else {
        return;
    };
    if state.notable.as_ref() != Some(&reconnect.said) {
        return;
    }
    let line = reconnect.line(now);
    reconnect.said = line.clone();
    state.notable = Some(line);
}

/// Fold a server-session edge (ADR-0080 amendment).
///
/// **The single writer of [`UiState::ed2k`]**. Core emits this family
/// for *every* session however it was established — an operator's Connect, a
/// search, a download's source lookup — so a consumer that folded the
/// per-download `DownloadEvent::ServerLoginAccepted` instead would light the
/// status dot on the same fact twice and, worse, would never put it out: that
/// event has no counterpart for a session ending. `ServerLoginAccepted` keeps
/// its log line and nothing else.
pub(super) fn fold_connection(state: &mut UiState, event: ServerConnectionEvent) -> bool {
    match event {
        ServerConnectionEvent::Connecting { server, leaving } => {
            note(state, words::connecting(&server, leaving.as_ref()))
        }
        ServerConnectionEvent::Connected { server, client_id } => {
            state.ed2k = Ed2kConnection::Connected { client_id };
            state.reconnect = None;
            // A Low ID says the server could not reach our listener; the
            // mapping rows are what can say why (ADR-0086) — the login waited for the listener's
            // row to settle, so it is already on the level this note reads.
            let text = words::connected(&server, client_id, &state.diagnostics.mappings);
            state.connected_server = Some(server);
            note(state, text)
        }
        // The connect is eager and ends any live session first (ADR-0080
        // amendment), so by the time a failure lands there is no session:
        // the marker going down is the fact, not a guess.
        ServerConnectionEvent::ConnectFailed { server, reason } => {
            state.ed2k = Ed2kConnection::Disconnected;
            state.connected_server = None;
            note(state, words::connect_failed(&server, reason))
        }
        ServerConnectionEvent::Disconnected { server } => {
            state.ed2k = Ed2kConnection::Disconnected;
            state.connected_server = None;
            note(state, words::disconnected(&server))
        }
        ServerConnectionEvent::Reconnecting {
            server,
            attempt,
            bound,
            next_in,
            at,
            steady,
        } => {
            let step = words::ReconnectStep {
                attempt,
                bound,
                delay: next_in,
                steady,
            };
            let text = words::reconnecting(&server, step, next_in);
            state.reconnect = Some(Reconnect {
                server,
                step,
                at,
                said: text.clone(),
            });
            note(state, text)
        }
        ServerConnectionEvent::ReconnectEnded { server, reason } => {
            state.reconnect = None;
            note(state, words::reconnect_ended(&server, reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::{CoreEvent, DownloadEvent, ServerConnectionEvent};

    use super::*;
    use crate::fixture::{download_event, download_id, server_connection_event, server_endpoint};
    use crate::state::fold;

    /// A lost session core re-makes reads as that, in the status feed
    /// and on the state the status bar and Transfers read, until it lands;
    /// its 'next in' counts down on the data tick, and once the delay
    /// stops growing the line says the tries go on until a disconnect.
    #[test]
    fn a_reconnect_is_said_counted_down_and_ended() {
        let t0 = std::time::Instant::now();
        let mut state = UiState::default();
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Reconnecting {
                server: server_endpoint(),
                attempt: 2,
                bound: None,
                next_in: std::time::Duration::from_secs(60),
                at: t0 + std::time::Duration::from_secs(60),
                steady: false,
            }),
        );
        assert_eq!(
            state.notable.as_deref(),
            Some("reconnecting to 10.0.0.1:4661 · attempt 2 · next in 60 s")
        );
        count_down(&mut state, t0 + std::time::Duration::from_millis(15_200));
        assert_eq!(
            state.notable.as_deref(),
            Some("reconnecting to 10.0.0.1:4661 · attempt 2 · next in 45 s")
        );
        count_down(&mut state, t0 + std::time::Duration::from_secs(61));
        assert_eq!(
            state.notable.as_deref(),
            Some("reconnecting to 10.0.0.1:4661 · attempt 2 · dialing now")
        );
        // Another note took the slot: the tick leaves it alone.
        note(&mut state, words::ADDED);
        count_down(&mut state, t0 + std::time::Duration::from_secs(62));
        assert_eq!(state.notable, Some(words::ADDED));

        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Reconnecting {
                server: server_endpoint(),
                attempt: 9,
                bound: None,
                next_in: std::time::Duration::from_secs(600),
                at: t0 + std::time::Duration::from_secs(600),
                steady: true,
            }),
        );
        assert_eq!(
            state.notable.as_deref(),
            Some(
                "reconnecting to 10.0.0.1:4661 · attempt 9 · next in 600 s · every 10 min until you disconnect (c)"
            )
        );
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Connected {
                server: server_endpoint(),
                client_id: ClientId::from_u32(0x0100_0000),
            }),
        );
        assert_eq!(state.reconnect, None);
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::ReconnectEnded {
                server: server_endpoint(),
                reason: rmule_core::ReconnectEnd::AttemptsSpent { attempts: 12 },
            }),
        );
        assert_eq!(
            state.notable.as_deref(),
            Some(
                "gave up reconnecting to 10.0.0.1:4661 after 12 attempts; press c on a server in Networks (1) to connect again"
            )
        );
    }

    /// The data tick is what counts the wait down: a snapshot frame re-says
    /// the reconnect note with what is left of core's deadline.
    #[test]
    fn a_snapshot_frame_recounts_the_reconnect_wait() {
        use crate::action::Action;
        use crate::bridge::BridgeSnapshot;

        let t0 = std::time::Instant::now();
        let mut state = UiState::default();
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Reconnecting {
                server: server_endpoint(),
                attempt: 3,
                bound: None,
                next_in: std::time::Duration::from_secs(120),
                at: t0 + std::time::Duration::from_secs(120),
                steady: false,
            }),
        );
        let frame_at = t0 + std::time::Duration::from_millis(37_400);
        state.apply(
            Action::Snapshot(BridgeSnapshot {
                diagnostics: rmule_core::diagnostics::DiagnosticsSnapshot::default(),
                rates: crate::rates::TransferRates::default(),
                taken_at: frame_at,
            }),
            frame_at,
        );
        assert_eq!(
            state.notable.as_deref(),
            Some("reconnecting to 10.0.0.1:4661 · attempt 3 · next in 83 s")
        );
    }

    /// The connection trail is the whole lifecycle, both directions — which is
    /// exactly why it, and not the per-download login echo, owns `ed2k`.
    #[test]
    fn the_connection_trail_raises_and_lowers_the_connection_marker() {
        let mut state = UiState::default();
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Connecting {
                server: server_endpoint(),
                leaving: None,
            }),
        );
        assert_eq!(
            state.ed2k,
            Ed2kConnection::Disconnected,
            "a dial is not a session"
        );
        assert_eq!(
            state.notable.as_deref(),
            Some("connecting to 10.0.0.1:4661")
        );
        // A connect that ended another session says so.
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Connecting {
                server: server_endpoint(),
                leaving: Some(ServerEndpoint::new("10.0.0.2", 4242).expect("endpoint")),
            }),
        );
        assert_eq!(
            state.notable.as_deref(),
            Some("disconnected from 10.0.0.2:4242; connecting to 10.0.0.1:4661")
        );

        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Connected {
                server: server_endpoint(),
                client_id: ClientId::from_u32(100), // below the LowID threshold
            }),
        );
        assert!(
            matches!(state.ed2k, Ed2kConnection::Connected { client_id } if client_id.is_low_id())
        );
        assert_eq!(
            state.notable.as_deref(),
            Some(
                "connected to 10.0.0.1:4661 (LowID) — the eD2k listener has no port mapping; \
                 forward its TCP port to this machine for HighID"
            )
        );

        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Disconnected {
                server: server_endpoint(),
            }),
        );
        assert_eq!(state.ed2k, Ed2kConnection::Disconnected);
        assert_eq!(
            state.notable.as_deref(),
            Some("disconnected from 10.0.0.1:4661")
        );

        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::ConnectFailed {
                server: server_endpoint(),
                reason: rmule_core::ServerConnectFailure::Unreachable,
            }),
        );
        assert_eq!(state.ed2k, Ed2kConnection::Disconnected);
        assert_eq!(
            state.notable.as_deref(),
            Some(
                "connect to 10.0.0.1:4661 failed: it could not be reached — the connection was \
                 refused, unreachable or timed out"
            )
        );
    }

    /// The per-download login echo is the same fact seen from one download.
    /// Folding it too would give `ed2k` a second writer that can only ever
    /// say "connected".
    #[test]
    fn the_per_download_login_echo_does_not_double_book_the_connection() {
        let mut state = UiState::default();
        fold(
            &mut state,
            server_connection_event(ServerConnectionEvent::Disconnected {
                server: server_endpoint(),
            }),
        );
        let dirty = fold(
            &mut state,
            download_event(DownloadEvent::ServerLoginAccepted {
                download_id: download_id(1),
                client_id: ClientId::from_u32(ClientId::LOW_ID_THRESHOLD),
            }),
        );
        assert!(!dirty, "the echo's whole footprint is its log line");
        assert_eq!(state.ed2k, Ed2kConnection::Disconnected);
    }

    /// A Low ID names why, from the listener's mapping row: the one
    /// thing an operator can act on is which port the router did not forward.
    #[test]
    fn a_low_id_names_the_listeners_mapping_status() {
        use rmule_core::SocketRole;
        use rmule_core::port_mapping::{
            DesiredMapping, MappingDiagnostics, MappingError, MappingProtocol, MappingStatus,
        };
        use rmule_primitives::AddressFamily;
        let row = |status, last_error: Option<MappingError>| MappingDiagnostics {
            mapping: DesiredMapping {
                role: SocketRole::Tcp,
                family: AddressFamily::V4,
                internal_port: 4662,
                pinhole: None,
            },
            status,
            method: None,
            external: None,
            lease: None,
            next_renewal: None,
            last_error,
        };
        for (status, error, says) in [
            (
                MappingStatus::Failed,
                Some(MappingError::Timeout(MappingProtocol::Upnp)),
                "the router did not forward TCP 4662 (UPnP: the router did not answer); forward it",
            ),
            (
                MappingStatus::Mapped,
                None,
                "TCP 4662 is forwarded, yet the server's port check did not reach it",
            ),
        ] {
            let mut state = UiState::default();
            state.diagnostics.mappings = vec![row(status, error)];
            fold(
                &mut state,
                server_connection_event(ServerConnectionEvent::Connected {
                    server: server_endpoint(),
                    client_id: ClientId::from_u32(100),
                }),
            );
            let note = state.notable.expect("a connect note");
            assert!(note.contains(says), "{note}");
        }
    }

    /// The list is a level, so the row edges carry no rows — only the receipt
    /// for the keystroke that caused them, which a bulk merge suppresses.
    #[test]
    fn server_list_edges_report_outcomes_and_stay_quiet_during_a_merge() {
        use rmule_core::ServerListEvent as E;
        let mut state = UiState::default();

        assert!(fold(
            &mut state,
            CoreEvent::ServerList(E::ServerAdded {
                server: server_endpoint()
            })
        ));
        assert_eq!(state.notable.as_deref(), Some("server added"));

        assert!(fold(
            &mut state,
            CoreEvent::ServerList(E::ServerListUpdateStarted {
                url: "http://m/x".into()
            })
        ));
        assert!(state.server_list_updating);
        // Every downloaded row lands as one of these; the batch reports itself.
        assert!(!fold(
            &mut state,
            CoreEvent::ServerList(E::ServerAdded {
                server: server_endpoint()
            })
        ));
        assert_eq!(state.notable.as_deref(), Some("server list update started"));

        assert!(fold(
            &mut state,
            CoreEvent::ServerList(E::ServerListUpdated {
                added: 12,
                updated: 3,
                total: 40
            })
        ));
        assert!(!state.server_list_updating);
        assert_eq!(
            state.notable.as_deref(),
            Some("server list updated: 12 new, 3 refreshed, 40 listed")
        );

        // A failed fetch lowers the flag too, or the UI would grey the action
        // forever.
        fold(
            &mut state,
            CoreEvent::ServerList(E::ServerListUpdateStarted {
                url: "http://m/x".into(),
            }),
        );
        fold(
            &mut state,
            CoreEvent::ServerList(E::ServerListUpdateFailed {
                reason: rmule_core::ServerListUpdateFailure::HttpStatus(404),
            }),
        );
        assert!(!state.server_list_updating);
        assert_eq!(
            state.notable.as_deref(),
            Some("server list update failed: the web server answered HTTP 404, not the file")
        );
    }
}
