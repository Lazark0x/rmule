//! A served link's `OP_CALLBACK` (`0x99`), enacted.
//!
//! aMule's `case OP_CALLBACK:` (`ClientTCPSocket.cpp:1743-1772`, kno
//! `ab483654`) runs on whichever client socket the frame arrives on: Kad
//! running, the check field inverting to this node's own Kad ID and the file
//! known are its only gates, and then it dials the carried endpoint. The rule
//! is [`BuddySlot::consume_callback`](crate::buddy_link::BuddySlot::consume_callback)'s
//! This is the serve bridge's half — reading the live
//! **Kad Presence** and the file-known predicate, and handing a `Dial` to the
//! admit seam exactly as the **Firewalled Front** does its own.
//!
//! The dial-back is plaintext for the wire's reason, not ours: the `0x99`
//! body names no user hash and no connect-options, so no crypt key exists to
//! derive (ADR-0061, "The `0x99` relay cannot be obfuscated").

use rmule_kad::KadId;
use rmule_peer::Callback;
use rmule_primitives::PeerEndpoint;

use super::InboundPeerDeps;
use crate::firewalled::relayed_callback::{CallbackConsume, CallbackVerdict};

/// Consume one `0x99` that arrived on the served connection from `from`:
/// counted either way by the slot, and on `Dial` the requester is dialed back.
pub(super) fn consume(deps: &InboundPeerDeps, from: PeerEndpoint, callback: &Callback) {
    let verdict = deps.buddy_slot.consume_callback(
        deps.kad_presence.running_as(),
        &CallbackConsume {
            check_id: KadId::from_bytes(callback.buddy_id),
            // aMule's `GetFileByID` across shared files and the download
            // queue — the mirrored predicate, read inline, never a round
            // trip through the actor (the firewalled front's rule).
            file_shared_or_downloading: deps.file_known.contains(callback.file_hash),
            requester: callback.requester,
        },
    );
    match verdict {
        CallbackVerdict::Dial { requester, .. } => {
            let requester = PeerEndpoint::V4(requester);
            tracing::info!(
                ?from,
                ?requester,
                "served-link 0x99 callback: dialing the requester back (ADR-0061 route 4)"
            );
            deps.tunnel_admit.spawn_callback_dial_back(requester, None);
        }
        CallbackVerdict::Drop { reason } => {
            tracing::debug!(
                ?from,
                ?reason,
                "served-link 0x99 callback dropped (ADR-0061)"
            );
        }
    }
}

#[cfg(test)]
mod tests;
