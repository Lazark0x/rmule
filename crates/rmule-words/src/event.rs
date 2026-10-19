//! Every core event's line in the Networks log (spec §3.4), exhaustive over
//! [`CoreEvent`]: an event core adds cannot reach the pane without its words.
//! Each domain words its own vocabulary; this is where they meet.

use rmule_core::CoreEvent;

use super::{Sentence, download, kad, login, peer, portmap, reach, scan, search, serve, server};

/// A core event as one line of the Networks log.
#[must_use]
pub fn log_line(event: &CoreEvent) -> Sentence {
    match event {
        CoreEvent::Download(event) => download::log_line(event),
        CoreEvent::Serve(event) => serve::log_line(event),
        CoreEvent::Search(event) => search::log_line(event),
        CoreEvent::Scan(event) => scan::line(event),
        CoreEvent::ServerList(event) => server::list_log_line(event),
        CoreEvent::ServerConnection(event) => server::connection_log_line(event),
        CoreEvent::SecuredIdentityMismatch { user_hash } => reach::identity_mismatch(*user_hash),
        CoreEvent::CommandRejected { reason } => super::app::command_rejected(reason),
        CoreEvent::PeerReachRouted { peer, route } => reach::route(*peer, route),
        CoreEvent::NattTunnelRisen {
            peer,
            transport,
            role,
        } => reach::tunnel_risen(*peer, *transport, *role),
        CoreEvent::ClientUdpBindFailed { port, kind } => {
            reach::client_udp_bind_failed(*port, *kind)
        }
        CoreEvent::SocketBoundWithoutFamily { half_bound } => reach::half_bound(half_bound),
        CoreEvent::PeerHelloRefused { refusal } => peer::hello_refused(refusal),
        CoreEvent::DiagnosticsSnapshot { .. } => DIAGNOSTICS,
        CoreEvent::FileHistory { .. } => FILE_HISTORY,
        CoreEvent::KadStopped { reason } => kad::stopped(*reason),
        CoreEvent::Quitting { step } => super::app::quit_step(*step),
        CoreEvent::ServerLogin { server, step } => login::step_line(server, step),
        CoreEvent::BuddyDialFailed { buddy, cause } => kad::buddy_dial_failed(*buddy, *cause),
        CoreEvent::KadHelperTestLate {
            late_by, admission, ..
        } => login::kad_helper_test_late(*late_by, *admission),
        CoreEvent::ObfuscationPolicyAtStart { policy } => reach::obfuscation_at_start(*policy),
        CoreEvent::ObfuscationPolicyChanged { policy } => reach::obfuscation_changed(*policy),
        CoreEvent::MappingReleaseKept {
            mapping,
            protocol,
            external_port,
            kept,
        } => portmap::release_kept(mapping, *protocol, *external_port, kept),
    }
}

/// A diagnostics dump some tool asked for.
const DIAGNOSTICS: Sentence = Sentence::fixed("diagnostics snapshot");
/// The File History answered.
const FILE_HISTORY: Sentence = Sentence::fixed("file history read");
