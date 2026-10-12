//! The **Driver Row** every `natt-buddy-rendezvous-*` body writes: one
//! vocabulary shared by the requester, the target and the buddy.
//!
//! One row shape rather than three, for the reason the punch rows learned the
//! hard way: the flow's claims read one name off whichever body
//! wrote the row, and a field only one role writes reads back as a `-1` that
//! looks like a measurement. Every role therefore writes every field; the ones
//! its part of the exchange cannot move stay at their zero, which is a fact
//! about that role rather than a gap.

use std::path::Path;

use anyhow::Result;
use rmule_core::{Core, CoreEvent};

use crate::driver_row::Row;

/// What one body measured about its own NAT-T and buddy surfaces.
#[derive(Debug, Default)]
pub(super) struct BuddyRow {
    /// `requester`, `target` or `buddy`.
    pub(super) role: &'static str,
    /// The serve listener came up — the bind the buddy link is accepted on and
    /// the port the hello advertises.
    pub(super) serving: bool,
    /// An eD2k session was established. Only `--login` asks for one (the
    /// `natt-buddy-recruit-amule` server variant); every other row stands no
    /// server, the bind is what the body needs, and the bind is its own fact
    /// (the bind-is-not-login contract).
    pub(super) connected: bool,
    /// The server-assigned id, when there was a session at all.
    pub(super) client_id: u32,
    /// Why the login did not complete — stated rather than hidden, because a
    /// reader has to be able to tell "no server on this WAN" from "the body
    /// failed to start".
    pub(super) login_failure: String,
    /// `EnableKad` was accepted and a node is running.
    pub(super) kad_enabled: bool,
    /// The Kad node's own ID as hex, so a verdict can name the keyspace
    /// position the walk converged on.
    pub(super) kad_id: String,
    /// How many seeded contacts this body's routing table started with.
    pub(super) seeded_contacts: u32,
    /// The ADR-0061 buddy slot: `None`, `Walking`, `Recruited` or `Held`.
    pub(super) buddy_state: String,
    /// Buddy links established since start — the firewalled half.
    pub(super) buddy_links_held: u64,
    /// Buddy links lost or released.
    pub(super) buddy_links_lost: u64,
    /// Why the most recent recruit tick refused to walk.
    pub(super) buddy_last_recruit_refusal: String,
    /// Seconds from start to the moment the slot first read `Held`.
    pub(super) buddy_held_after_secs: i64,
    /// Buddy dials that did not hold a link.
    pub(super) buddy_dials_failed: u64,
    /// `OP_CALLBACK`s relayed over the held link that the front dialed back,
    /// dropped, and dropped for want of a held buddy.
    pub(super) relayed_callbacks_dialed: u64,
    pub(super) relayed_callbacks_dropped: u64,
    pub(super) relayed_callbacks_no_buddy: u64,
    /// Of the dialed ones, those whose check ID matched our Kad ID only under
    /// the other `TAG_BUDDYHASH` spelling.
    pub(super) relayed_callbacks_swapped_spelling: u64,
    /// Relayed rendezvous this body acted on — the acting path's burst.
    pub(super) acting_punches: u64,
    /// Relayed rendezvous refused, and the last reason.
    pub(super) acting_refusals: u64,
    pub(super) acting_last_refusal: String,
    /// Rendezvous forwarded as somebody's serving buddy — the relay half.
    pub(super) relays_forwarded: u64,
    /// Rendezvous refused as a relay (wrong buddy ID, no held link, caps).
    pub(super) relays_refused: u64,
    /// Rendezvous emitted toward a target's serving buddy.
    pub(super) rendezvous_emitted: u64,
    /// Server `0x60` hole-punch requests put on the session — counted apart
    /// from the buddy rendezvous above.
    pub(super) server_requests_emitted: u64,
    /// **Traversal Attempt**s opened with a buddy as the coordinator.
    pub(super) attempts_buddy: u64,
    /// Attempts opened with a server coordinator — expected zero here.
    pub(super) attempts_server: u64,
    /// Which route the ADR-0061 chooser took for the `ReachPeer`.
    pub(super) routed: String,
    /// Dials the front spent, and how many in its last attempt.
    pub(super) dials: u64,
    pub(super) last_attempt_dials: String,
    /// Tunnels dialed / accepted, and the transport of the last one.
    pub(super) tunnels_dialed: u64,
    pub(super) tunnels_accepted: u64,
    pub(super) last_transport: String,
    /// Endpoint hints dropped without a punch, and the last reason.
    pub(super) hint_refusals: u64,
    pub(super) last_hint_refusal: String,
    /// `OP_HOLEPUNCH` from an endpoint nothing was expected from.
    pub(super) unexpected_holepunches: u64,
    /// The target shared the transfer file once its buddy was held, so the
    /// source publish names that buddy (`natt-buddy-transfer-*`).
    pub(super) published: bool,
    /// The requester started a download of the link it was handed, with no
    /// source named out of band — only Kad can find one.
    pub(super) download_started: bool,
    /// The download completed, and why it did not when it did not.
    pub(super) download_completed: bool,
    pub(super) download_failure: String,
    /// The completed file's size and ED2K hash, taken off the disk.
    pub(super) output_bytes: u64,
    pub(super) output_ed2k_hash: String,
    /// The download's own NAT-T accounting: falls to the punch, the ones with
    /// no User Hash to claim by, and the Tunnels it adopted.
    pub(super) download_fallbacks: u64,
    pub(super) download_fallbacks_unclaimable: u64,
    pub(super) download_adoptions: u64,
    /// The ADR-0058 UDP verdict as the last snapshot read it (`open`,
    /// `firewalled`, `unverified`), and how long after Kad start it read
    /// open (`-1` when it never did) — `natt-udp-selfcheck-cone`.
    pub(super) udp_verdict: String,
    pub(super) udp_open_after_secs: i64,
    /// The ADR-0058 TCP verdict as the last snapshot read it (`open`,
    /// `checking`, `firewalled`) — the recruit gate's other half.
    pub(super) tcp_verdict: String,
    /// Whether a full counters snapshot ([`snapshot`]) ever arrived. Every
    /// counter only it fills is written `-1` when none did: a zero there is a
    /// count nobody took, not a role's honest zero.
    pub(super) snapshot_read: bool,
}

/// Ask for and read back one diagnostics snapshot into `row`.
///
/// Every value here is rmule's own account of its own surfaces, so every claim
/// drawn from it is scored `rmule-only` (ADR-0045's 2026-09-16 amendment).
///
/// # Errors
/// If the command cannot be sent. A snapshot that never arrives leaves the row
/// at the values it already held — a driver that failed to observe itself is
/// not a reason to lose the observation it already made.
pub(super) async fn snapshot(core: &mut Core, row: &mut BuddyRow) -> Result<()> {
    let Some(snapshot) = super::await_snapshot(core, row).await? else {
        return Ok(());
    };
    row.snapshot_read = true;
    if let Some(kad) = snapshot.kad.as_ref() {
        row.udp_verdict = udp_verdict_name(kad.udp).to_owned();
        row.tcp_verdict = tcp_verdict_name(kad.firewall).to_owned();
    }
    let session = &snapshot.session;
    row.buddy_dials_failed = session.buddy_dials_failed_total;
    row.relayed_callbacks_dialed = session.relayed_callbacks_dialed_total;
    row.relayed_callbacks_dropped = session.relayed_callbacks_dropped_total;
    row.relayed_callbacks_no_buddy = session.relayed_callbacks_no_buddy_total;
    row.relayed_callbacks_swapped_spelling = session
        .buddy_hash_spelling
        .relayed_callbacks_swapped_spelling_total;
    row.buddy_state = format!("{:?}", session.buddy_state);
    row.buddy_links_held = session.buddy_links_held_total;
    row.buddy_links_lost = session.buddy_links_lost_total;
    row.buddy_last_recruit_refusal = session
        .buddy_last_recruit_refusal
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_default();
    row.acting_punches = session.acting_punches_total;
    row.acting_refusals = session.acting_refusals_total;
    row.acting_last_refusal = session
        .acting_last_refusal
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_default();
    row.relays_forwarded = session.natt_relays_forwarded_total;
    row.relays_refused = session.natt_relays_refused_total;
    row.rendezvous_emitted = session.natt_rendezvous_emitted_total;
    row.server_requests_emitted = session.natt_server_requests_emitted_total;
    row.attempts_buddy = session.natt_attempts_buddy_total;
    row.attempts_server = session.natt_attempts_server_total;
    row.dials = session.natt_dials_total;
    row.last_attempt_dials = session
        .natt_last_attempt_dials
        .map(|dials| dials.to_string())
        .unwrap_or_default();
    row.tunnels_dialed = session.natt_tunnels_dialed_total;
    row.tunnels_accepted = session.natt_tunnels_accepted_total;
    row.last_transport = session
        .natt_last_tunnel_transport
        .map(|transport| format!("{transport:?}"))
        .unwrap_or_default();
    row.hint_refusals = session.natt_hint_refusals_total;
    row.last_hint_refusal = session
        .natt_last_hint_refusal
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_default();
    row.unexpected_holepunches = session.natt_unexpected_holepunches_total;
    row.download_fallbacks = session.natt_download_fallbacks_total;
    row.download_fallbacks_unclaimable = session.natt_download_fallbacks_unclaimable_total;
    row.download_adoptions = session.natt_download_adoptions_total;
    Ok(())
}

/// Re-read the buddy slot into `row` — the **Readiness Gate** the target's
/// recruit is watched through, and the refusal that says why it is still shut.
///
/// Both, not just the state: a gate that reported `None` without the refusal
/// beside it cannot tell "the walk has not run yet" from "the walk can never
/// run", and those are the two outcomes this flow has to distinguish.
///
/// # Errors
/// If the diagnostics command cannot be sent.
pub(super) async fn poll_buddy(core: &mut Core, row: &mut BuddyRow) -> Result<()> {
    let Some(snapshot) = super::await_snapshot(core, row).await? else {
        return Ok(());
    };
    row.buddy_state = format!("{:?}", snapshot.session.buddy_state);
    row.buddy_last_recruit_refusal = snapshot
        .session
        .buddy_last_recruit_refusal
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_default();
    Ok(())
}

/// Print the one-line summary and write the row.
///
/// # Errors
/// If the row file cannot be written.
pub(super) fn write(path: &Path, row: &BuddyRow) -> Result<()> {
    crate::driver_row::write_row(path, render(row))
}

/// The row as the harness reads it.
fn render(row: &BuddyRow) -> Row {
    println!(
        "natt-buddy-rendezvous role={} serving={} kad={} buddy_state={} relays={}/{} \
         acting={} tunnels={}/{}",
        row.role,
        row.serving,
        row.kad_enabled,
        row.buddy_state,
        row.relays_forwarded,
        row.relays_refused,
        row.acting_punches,
        row.tunnels_dialed,
        row.tunnels_accepted,
    );
    let mut out = Row::new(
        "rmule-tools natt buddy-rendezvous — ADR-0091 rung 1 through its SECOND\n\
         coordinator: a firewalled target recruits a serving buddy over a live Kad\n\
         FINDBUDDY walk, and a second firewalled node reaches it by embedding an\n\
         OP_RENDEZVOUS in an OP_REASKCALLBACKUDP addressed to that buddy. Only\n\
         `--login` asks for an eD2k session, so `connected` is false without it and\n\
         the serve listener is what every body needs from `StartServing`. Every value\n\
         here is rmule's own account of its own surfaces, and is never a\n\
         counterparty's.",
    );
    // A counter only the counters snapshot fills, or `-1` when none arrived.
    let counted = |value: u64| if row.snapshot_read { as_i64(value) } else { -1 };
    out.str("role", row.role)
        .bool("snapshot_read", row.snapshot_read)
        .bool("serving", row.serving)
        .bool("connected", row.connected)
        .int("client_id", i64::from(row.client_id))
        .str("login_failure", &row.login_failure)
        .bool("kad_enabled", row.kad_enabled)
        .str("kad_id", &row.kad_id)
        .int("seeded_contacts", i64::from(row.seeded_contacts))
        .str("buddy_state", &row.buddy_state)
        .int("buddy_links_held", counted(row.buddy_links_held))
        .int("buddy_links_lost", counted(row.buddy_links_lost))
        .str(
            "buddy_last_recruit_refusal",
            &row.buddy_last_recruit_refusal,
        )
        .int("buddy_held_after_secs", row.buddy_held_after_secs)
        .int("buddy_dials_failed", counted(row.buddy_dials_failed))
        .int(
            "relayed_callbacks_dialed",
            counted(row.relayed_callbacks_dialed),
        )
        .int(
            "relayed_callbacks_dropped",
            counted(row.relayed_callbacks_dropped),
        )
        .int(
            "relayed_callbacks_no_buddy",
            counted(row.relayed_callbacks_no_buddy),
        )
        .int(
            "relayed_callbacks_swapped_spelling",
            counted(row.relayed_callbacks_swapped_spelling),
        )
        .int("acting_punches", counted(row.acting_punches))
        .int("acting_refusals", counted(row.acting_refusals))
        .str("acting_last_refusal", &row.acting_last_refusal)
        .int("relays_forwarded", counted(row.relays_forwarded))
        .int("relays_refused", counted(row.relays_refused))
        .int("rendezvous_emitted", counted(row.rendezvous_emitted))
        .int(
            "server_requests_emitted",
            counted(row.server_requests_emitted),
        )
        .int("attempts_buddy", counted(row.attempts_buddy))
        .int("attempts_server", counted(row.attempts_server))
        .str("routed", &row.routed)
        .int("dials", counted(row.dials))
        .str("last_attempt_dials", &row.last_attempt_dials)
        .int("tunnels_dialed", counted(row.tunnels_dialed))
        .int("tunnels_accepted", counted(row.tunnels_accepted))
        .str("last_tunnel_transport", &row.last_transport)
        .int("hint_refusals", counted(row.hint_refusals))
        .str("last_hint_refusal", &row.last_hint_refusal)
        .int(
            "unexpected_holepunches",
            counted(row.unexpected_holepunches),
        )
        .bool("published", row.published)
        .bool("download_started", row.download_started)
        .bool("download_completed", row.download_completed)
        .str("download_failure", &row.download_failure)
        .int("output_bytes", as_i64(row.output_bytes))
        .str("output_ed2k_hash", &row.output_ed2k_hash)
        .int("download_fallbacks", counted(row.download_fallbacks))
        .int(
            "download_fallbacks_unclaimable",
            counted(row.download_fallbacks_unclaimable),
        )
        .int("download_adoptions", counted(row.download_adoptions))
        .str("udp_verdict", &row.udp_verdict)
        .int("udp_open_after_secs", row.udp_open_after_secs)
        .str("tcp_verdict", &row.tcp_verdict);
    out
}

/// The row's name for an ADR-0058 UDP verdict.
pub(super) fn udp_verdict_name(verdict: rmule_core::diagnostics::KadUdpVerdict) -> &'static str {
    match verdict {
        rmule_core::diagnostics::KadUdpVerdict::Open { .. } => "open",
        rmule_core::diagnostics::KadUdpVerdict::Firewalled => "firewalled",
        rmule_core::diagnostics::KadUdpVerdict::Unverified => "unverified",
    }
}

/// The row's name for an ADR-0058 TCP verdict.
pub(super) fn tcp_verdict_name(
    verdict: rmule_core::diagnostics::KadFirewallVerdict,
) -> &'static str {
    match verdict {
        rmule_core::diagnostics::KadFirewallVerdict::Open => "open",
        rmule_core::diagnostics::KadFirewallVerdict::Checking => "checking",
        rmule_core::diagnostics::KadFirewallVerdict::Firewalled => "firewalled",
    }
}

/// Record the one event every role reads the same way.
pub(super) fn observe(event: &CoreEvent, row: &mut BuddyRow) {
    match event {
        CoreEvent::Serve(rmule_core::ServeEvent::ServingStarted { .. }) => row.serving = true,
        CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::Connected {
            client_id,
            ..
        }) => {
            row.connected = true;
            row.client_id = client_id.as_u32();
        }
        CoreEvent::ServerConnection(rmule_core::ServerConnectionEvent::ConnectFailed {
            reason,
            ..
        }) => {
            if row.login_failure.is_empty() {
                row.login_failure = format!("{reason:?}");
            }
        }
        CoreEvent::PeerReachRouted { route, .. } => {
            row.routed = crate::natt::route_code(route).to_owned()
        }
        CoreEvent::Download(rmule_core::DownloadEvent::DownloadCompleted { .. }) => {
            row.download_completed = true;
        }
        CoreEvent::Download(rmule_core::DownloadEvent::DownloadFailed { reason, .. }) => {
            row.download_failure = reason.to_string();
        }
        _ => {}
    }
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{BuddyRow, render};

    /// A body whose counters snapshot never arrived writes `-1`, not the
    /// default `0` a negative row would read as "no Tunnel rose".
    #[test]
    fn a_missed_snapshot_writes_no_measured_zero() {
        let text = render(&BuddyRow::default()).finish();
        assert!(text.contains("snapshot_read = false"), "{text}");
        for key in ["tunnels_dialed", "tunnels_accepted", "relays_forwarded"] {
            assert!(text.contains(&format!("{key} = -1")), "{key}: {text}");
        }
    }
}
