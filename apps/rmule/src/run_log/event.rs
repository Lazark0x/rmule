//! What the Run Log says of a core event: the one place an event becomes a
//! [`Record`].
//!
//! Every projection is an exhaustive `match` without a wildcard arm, so a new
//! event or a new variant of one fails to compile until it has a record, and
//! the record can only hold what its typed fields allow: the class of a value
//! is the kind of the method that added it, never a choice made at the call.

mod buddy;
mod download;
mod login;
mod scan;
mod search;
mod serve;
mod server;

use rmule_core::CoreEvent;

use super::codes;
use super::record::Record;

/// The record of `event`.
#[must_use]
pub fn record(event: &CoreEvent) -> Record {
    match event {
        CoreEvent::Download(event) => download::record(event),
        CoreEvent::Serve(event) => serve::record(event),
        CoreEvent::Search(event) => search::record(event),
        CoreEvent::Scan(event) => scan::record(event),
        CoreEvent::ServerList(event) => server::list(event),
        CoreEvent::ServerConnection(event) => server::connection(event),
        CoreEvent::SecuredIdentityMismatch { user_hash } => {
            Record::new("identity.secured_mismatch").user_hash("user_hash", user_hash)
        }
        CoreEvent::CommandRejected { reason } => {
            codes::command_rejected(Record::new("command.rejected"), reason)
        }
        CoreEvent::PeerReachRouted { peer, route } => reach_route(peer, route),
        CoreEvent::NattTunnelRisen {
            peer,
            transport,
            role,
        } => Record::new("natt.tunnel_risen")
            .peer_address("peer", peer)
            .code("transport", codes::transport(*transport))
            .code("role", codes::stream_role(*role)),
        CoreEvent::ClientUdpBindFailed { port, kind } => Record::new("client_udp.bind_failed")
            .port("port", *port)
            .os_error(*kind, None),
        CoreEvent::SocketBoundWithoutFamily { half_bound } => {
            Record::new("socket.bound_without_family")
                .code("role", codes::pair_role(half_bound.role))
                .code("missing", codes::family(half_bound.missing))
                .os_error(half_bound.kind, None)
        }
        CoreEvent::PeerHelloRefused { refusal } => hello_refused(refusal),
        CoreEvent::DiagnosticsSnapshot { .. } => Record::new("diagnostics.snapshot"),
        CoreEvent::FileHistory { history } => Record::new("file_history.read")
            .count("shared", history.shared.len())
            .count("had", history.had.len())
            .count("cancelled", history.cancelled.len())
            .count("unread", history.unread.len()),
        CoreEvent::KadStopped { reason } => {
            Record::new("kad.stopped").code("reason", codes::kad_stop(*reason))
        }
        CoreEvent::Quitting { step } => {
            Record::new("quit.step").code("step", codes::quit_step(*step))
        }
        CoreEvent::ServerLogin { server, step } => login::record(server, step),
        CoreEvent::BuddyDialFailed { buddy, cause } => buddy::dial_failed(buddy, *cause),
        CoreEvent::KadHelperTestLate {
            helper,
            late_by,
            admission,
        } => login::kad_helper_test_late(*helper, *late_by, *admission),
    }
}

/// How the route chosen for a peer reaches it. The peer, its Kad UDP
/// endpoint, its Low ID and its buddy are the peer's; only the code is ours.
fn reach_route(
    peer: &rmule_primitives::PeerEndpoint,
    route: &rmule_core::PeerReachRoute,
) -> Record {
    use rmule_core::PeerReachRoute as R;
    let record = Record::new("peer_reach.routed").peer_address("peer", peer);
    match route {
        R::Direct => record.code("route", "direct"),
        R::DirectUdp { target_kad_udp } => record
            .code("route", "direct_udp")
            .peer_address("target_kad_udp", target_kad_udp),
        R::DirectUdpUnavailable { target_kad_udp } => record
            .code("route", "direct_udp_unavailable")
            .peer_address("target_kad_udp", target_kad_udp),
        R::Server { low_id } => record.code("route", "server").peer_id("low_id", *low_id),
        R::Buddy {
            buddy_id,
            emitted_to,
        } => {
            let record = record.code("route", "buddy").kad_id("buddy_id", buddy_id);
            match emitted_to {
                Some(endpoint) => record.peer_address("emitted_to", endpoint),
                None => record.code("emitted_to", "none"),
            }
        }
        R::CallbackWalk { buddy_id } => record
            .code("route", "callback_walk")
            .kad_id("buddy_id", buddy_id),
        R::NatTraversal {
            buddy_id,
            buddy_udp,
        } => record
            .code("route", "nat_traversal")
            .kad_id("buddy_id", buddy_id)
            .peer_address("buddy_udp", buddy_udp),
        R::ServerPunch { low_id } => record
            .code("route", "server_punch")
            .peer_id("low_id", *low_id),
        R::ServerPunchUnavailable { low_id } => record
            .code("route", "server_punch_unavailable")
            .peer_id("low_id", *low_id),
        R::NatTraversalUnavailable { buddy_id, reason } => record
            .code("route", "nat_traversal_unavailable")
            .kad_id("buddy_id", buddy_id)
            .code("reason", codes::nat_unavailable(*reason)),
        R::Dropped { reason } => record
            .code("route", "dropped")
            .code("reason", codes::reach_drop(*reason)),
    }
}

/// A refused peer hello: the code and counts at the lean level; what the peer
/// said of itself only at the full one. Never its address.
fn hello_refused(refusal: &rmule_core::HelloRefusal) -> Record {
    let record = match refusal.code {
        rmule_core::HelloRefusalCode::TagCountShort { declared, written } => {
            Record::new("peer.hello_refused")
                .code("code", "tag_count_short")
                .count("declared", declared)
                .count("written", written)
        }
        _ => Record::new("peer.hello_refused"),
    };
    let text = |text: &Option<rmule_primitives::Ed2kText>| {
        text.as_ref()
            .map(|t| t.to_display_string())
            .unwrap_or_default()
    };
    record
        .peer_software("client_mod", &text(&refusal.client_mod))
        .peer_software("client_name", &text(&refusal.name))
}
