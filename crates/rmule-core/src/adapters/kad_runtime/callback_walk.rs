//! The core's half of the **Callback Walk**: the download whose candidate
//! named its buddy by ID alone hands the Kad pump a walk and a place to report
//! its verdict. Who waits on which walk is the **Kad Pump State**'s to
//! remember (`pump_state/callback_walks.rs`).

use std::time::Duration;

use rmule_kad::KadId;
use tokio::sync::mpsc;

use crate::adapters::CallbackKey;
use crate::diagnostics::NattRetirement;

/// Where a download hears that the **Callback Pace** holds its `0x52`, and how
/// long for (ADR-0061).
pub(crate) type HeldSender = mpsc::Sender<(CallbackKey, Duration)>;

/// Where the fate of a `0x52` is reported, under the candidate's key: the
/// download's retire channel, the one a retired punch rides, when no `0x52`
/// will leave, and its held channel when one leaves late.
#[derive(Clone, Debug)]
pub(crate) struct CallbackReply {
    /// The candidate the `0x52` is for.
    pub(crate) key: CallbackKey,
    /// The download's retire channel.
    pub(crate) retire_tx: mpsc::Sender<(CallbackKey, NattRetirement)>,
    /// The download's held channel.
    pub(crate) held_tx: HeldSender,
}

/// Two replies are equal when they report the same candidate to the same
/// download.
impl PartialEq for CallbackReply {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.retire_tx.same_channel(&other.retire_tx)
    }
}

/// A Callback Walk as the core actor resolved it: the `0x52`'s three fields,
/// and who hears if no `0x52` leaves.
#[derive(Clone, Debug)]
pub(crate) struct CallbackWalkAsk {
    /// The buddy relationship ID the row named — the walk's target.
    pub(crate) buddy_id: KadId,
    /// The file the target must know before it dials us back.
    pub(crate) file_hash: rmule_primitives::FileHash,
    /// Where the target must dial us — our advertised TCP port.
    pub(crate) tcp_port: u16,
    /// Where the walk's fate goes.
    pub(crate) reply: CallbackReply,
}

impl CallbackWalkAsk {
    /// The command a running node is handed for this ask: the walk toward the
    /// buddy ID.
    pub(crate) fn node_command(&self) -> rmule_kad::KadCommand {
        rmule_kad::KadCommand::CallbackWalk {
            buddy_id: self.buddy_id,
            file_hash: self.file_hash,
            tcp_port: self.tcp_port,
        }
    }
}

/// Hand one Callback Walk to the running node, reporting whether a node was
/// there to take it.
pub(crate) fn request_kad_callback_walk(sink: &super::SharedKadPump, ask: CallbackWalkAsk) -> bool {
    sink.send(super::KadPumpCommand::CallbackWalk(ask)).is_ok()
}
