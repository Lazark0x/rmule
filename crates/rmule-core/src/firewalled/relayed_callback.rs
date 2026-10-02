//! **Relayed-callback consume**: the `OP_CALLBACK` (`0x99`) a buddy link
//! forwards, asking us to dial a requester that cannot reach us directly.
//!
//! Its refusal matrix, aMule's guarded early returns
//! ([`ClientTCPSocket.cpp#L1630`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1630)):
//! Kad not running → [`KadDown`](CallbackDrop::KadDown) (the mechanism is
//! Kad-scoped); the leading buddy-ID field not inverting to our KadID in
//! either `TAG_BUDDYHASH` spelling →
//! [`NotForUs`](CallbackDrop::NotForUs); the named file neither shared nor
//! downloading → [`FileUnknown`](CallbackDrop::FileUnknown). All three pass and
//! we dial the requester back.
//!
//! **The rule is role-agnostic.** aMule's `case OP_CALLBACK:`
//! arm runs on whichever `CClientTCPSocket` the frame arrives on — it never
//! reads `GetBuddy()`/`IsBuddy` the way the next arm down, `OP_BUDDYPING`
//! (`ClientTCPSocket.cpp#L1774`, `buddy != m_client` → silent drop), does. So
//! a matching `0x99` is acted on whether it rides the link *we* dialed as a
//! firewalled node ([`FirewalledNode::consume_callback`]) or a link *we*
//! serve as the open node buddying for someone else
//! ([`crate::buddy_link::BuddySlot::consume_callback`]) — both call
//! [`apply`], the one rule aMule's source states once. `NoBuddyHeld`
//! stays specific to the firewalled slot: it is *that* slot's
//! own prerequisite (a `0x99` cannot have come from a buddy we never dialed),
//! not part of aMule's ungated rule, so the open side never raises it.
//!
//! The twin `OP_REASKCALLBACKTCP` (`0x9A`) relay needs no gate here: it is
//! answered **directly over UDP** to the requester through the ADR-0057 reask
//! reply matrix, and [`ReaskCallbackTcp`](rmule_peer::ReaskCallbackTcp) already
//! decodes it with the requester endpoint it injects as the answer target.

use rmule_kad::KadId;
use rmule_primitives::Ipv4Endpoint;

use super::{FirewalledNode, inverted};

/// The parsed `OP_CALLBACK` (`0x99`) facts the relay consume reads — the Kad
/// `0x52`→`0x99` decode that supplies them rides the deferred Kad front, exactly
/// as [`broker_dial_back`](crate::reachability::broker_dial_back) reads a parsed
/// dial-back request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallbackConsume {
    /// The callback's leading buddy-ID/check field — XOR-inverted and matched
    /// against our KadID to confirm the callback is for us.
    pub(crate) check_id: KadId,
    /// The named file is one we share or download (aMule `GetFileByID` across
    /// shared files + the download queue) — resolved by the caller.
    pub(crate) file_shared_or_downloading: bool,
    /// The requester's endpoint (its IP + advertised TCP port) — where we dial.
    pub(crate) requester: Ipv4Endpoint,
}

/// What [`consume_callback`](FirewalledNode::consume_callback) decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackVerdict {
    /// Dial the requester's TCP endpoint (an inbound worker/serve dial-back).
    Dial {
        requester: Ipv4Endpoint,
        /// The check matched our Kad ID only under the other `TAG_BUDDYHASH`
        /// spelling — the requester read our aMule-spelled row the eMule
        /// 0.70b / eMuleAI way (source-derived). Counted apart.
        swapped_spelling: bool,
    },
    /// Drop the relayed callback silently — with the precise reason.
    Drop { reason: CallbackDrop },
}

/// Why a relayed `0x99` was dropped (aMule's guarded early returns, plus the
/// prerequisite this node's own [`FirewalledSlot`](super::link::FirewalledSlot)
/// checks before any of them run).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackDrop {
    /// We hold no buddy link at all — our own state, not a counterparty
    /// error: a `0x99` cannot have arrived from a buddy we do not have
    /// Distinct from [`NotForUs`](Self::NotForUs), which is a
    /// genuine wrong-address relay over a link we *do* hold.
    NoBuddyHeld,
    /// Kad is not running — the callback mechanism is Kad-scoped.
    KadDown,
    /// The buddy-ID XOR check failed: the callback did not invert to our KadID
    /// in either spelling.
    NotForUs,
    /// We neither share nor download the named file — nothing to serve/exchange.
    FileUnknown,
}

/// The one `OP_CALLBACK` (`0x99`) rule aMule's source states
/// ([`ClientTCPSocket.cpp#L1630`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1630)),
/// independent of which role's link the frame arrived on — see the module
/// doc. `running_as` is the caller's own KadID while its Kad node runs, `None`
/// while none does: the firewalled node's and the open node's alike, since
/// both check the same field against themselves.
pub(crate) fn apply(running_as: Option<KadId>, req: &CallbackConsume) -> CallbackVerdict {
    let Some(our_kad_id) = running_as else {
        return CallbackVerdict::Drop {
            reason: CallbackDrop::KadDown,
        };
    };
    // Our row names us in aMule's spelling of `TAG_BUDDYHASH`,
    // and an eMule 0.70b / eMuleAI requester reads it per-word swapped
    // (`GetData()`), so either spelling of our own ID is us. The swap is a
    // byte permutation, so it commutes with the XOR inversion.
    let addressed = inverted(&req.check_id);
    let swapped_spelling = if addressed == our_kad_id {
        false
    } else if addressed.word_swapped() == our_kad_id {
        true
    } else {
        return CallbackVerdict::Drop {
            reason: CallbackDrop::NotForUs,
        };
    };
    if !req.file_shared_or_downloading {
        return CallbackVerdict::Drop {
            reason: CallbackDrop::FileUnknown,
        };
    }
    if swapped_spelling {
        tracing::info!(
            requester = ?req.requester,
            "relayed 0x99 addressed our Kad ID in the other TAG_BUDDYHASH spelling \
             (eMule-family reading); dialing back"
        );
    }
    CallbackVerdict::Dial {
        requester: req.requester,
        swapped_spelling,
    }
}

impl FirewalledNode {
    /// Consume an `OP_CALLBACK` (`0x99`) our buddy relayed: dial the requester
    /// only with Kad running, the buddy-ID XOR check passing, and the file
    /// shared-or-downloading; else drop with the precise reason.
    pub(crate) fn consume_callback(
        &self,
        req: &CallbackConsume,
        kad_running: bool,
    ) -> CallbackVerdict {
        apply(kad_running.then_some(self.our_kad_id), req)
    }
}
