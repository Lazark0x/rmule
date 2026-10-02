//! The ADR-0061 recruit trigger, on the pump's tick: whether this node,
//! firewalled, should look for a buddy now, and the walk that looks.

use std::time::Instant;

use crate::adapters::peer_transfer::buddy_serve_posture;

/// ADR-0061 firewalled-node recruitment. The gate reads *both* verdicts and
/// the recheck clock, all of which live in the store this pump owns — which
/// is why the trigger runs here and not in the front that enacts it. On a
/// decision to recruit, the node runs the FINDBUDDY walk toward `~ourKadID`
/// and picks the convergence contact itself.
pub(super) fn consider(
    handle: &rmule_net::kad::KadNetHandle,
    reach: &crate::reachability::SharedSelfReach,
    last_recheck: Option<Instant>,
    firewalled_slot: &crate::firewalled::link::SharedFirewalledSlot,
    crypt_required: bool,
) {
    let ctx = crate::firewalled::recruit::RecruitContext {
        // The pump only runs while a node does.
        kad_connected: true,
        tcp: reach.kad_tcp(),
        udp: buddy_serve_posture(reach).udp,
        last_recheck,
        crypt_required,
    };
    if let crate::firewalled::recruit::RecruitDecision::Recruit { walk_target } =
        firewalled_slot.consider_recruitment(&ctx, Instant::now())
    {
        // Non-blocking: this pump is the handle's sole
        // event drainer, so an awaited command can
        // deadlock against a driver blocked emitting
        // events. A full inbox costs one walk; the next
        // tick re-decides, and the pacing clock already
        // stamped means it waits out the interval.
        match handle.try_command(rmule_kad::KadCommand::FindBuddyWalk {
            target: walk_target,
        }) {
            Ok(true) => tracing::debug!("firewalled node: FINDBUDDY walk started (ADR-0061)"),
            Ok(false) | Err(_) => firewalled_slot.on_walk_ended(),
        }
    }
}
