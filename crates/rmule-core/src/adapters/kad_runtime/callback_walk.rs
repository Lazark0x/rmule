//! The core's half of the **Callback Walk**: the download whose candidate
//! named its buddy by ID alone hands the Kad pump a walk and a place to report
//! its verdict. Who waits on which walk is the **Kad Pump State**'s to
//! remember (`pump_state/callback_walks.rs`).

use rmule_kad::KadId;
use tokio::sync::mpsc;

use crate::adapters::CallbackKey;
use crate::diagnostics::NattRetirement;

/// Where a Callback Walk's failure is reported: the download's retire channel,
/// under the candidate's key — the same channel a retired punch rides.
#[derive(Clone, Debug)]
pub(crate) struct CallbackWalkReply {
    /// The candidate the walk is for.
    pub(crate) key: CallbackKey,
    /// The download's retire channel.
    pub(crate) retire_tx: mpsc::Sender<(CallbackKey, NattRetirement)>,
}

/// Two replies are equal when they report the same candidate to the same
/// download.
impl PartialEq for CallbackWalkReply {
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
    /// Where the walk's failure goes.
    pub(crate) reply: CallbackWalkReply,
}

/// Hand one Callback Walk to the running node, reporting whether a node was
/// there to take it.
pub(crate) fn request_kad_callback_walk(sink: &super::SharedKadPump, ask: CallbackWalkAsk) -> bool {
    sink.send(super::KadPumpCommand::CallbackWalk(ask)).is_ok()
}
