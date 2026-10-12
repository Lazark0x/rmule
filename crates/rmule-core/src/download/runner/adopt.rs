//! The fleet's adopt arm (ADR-0039, ADR-0051): the accept-router hands over a
//! called-back Low-ID peer's worker under the key of the callback it answers,
//! the brain names the slot it lands in, and only then is the worker's channel
//! registered there, so its own `Connected` flows the normal assignment path.
//! A connection the brain names no slot for — a live worker already holds its
//! endpoint, or its callback already ended — is dropped with its worker, and
//! the live channel stays.

use std::collections::VecDeque;

use super::enact::{LoopCtx, enact_drain};
use super::now;
use crate::adapters::{CallbackKey, PeerTransferService, PeerWorker, SourceLookupService};
use crate::download::state::Decision;
use crate::error::DownloadFailure;

/// Land `worker`, handed over under `reported`, in the slot the brain names
/// for it, and enact what its landing decided.
pub(super) async fn adopt<S, P>(
    ctx: &mut LoopCtx<'_, S, P>,
    reported: CallbackKey,
    worker: PeerWorker,
) -> Result<(), DownloadFailure>
where
    S: SourceLookupService,
    P: PeerTransferService,
{
    let Some(key) = ctx.state.match_inbound_callback(reported) else {
        return Ok(());
    };
    let peer = worker.peer();
    let landing = ctx.state.on_callback_connected(now(), key, peer);
    if let Some(slot) = landing.worker_slot {
        ctx.worker_pool.register_adopted(
            ctx.download_id,
            peer,
            slot,
            worker,
            &mut ctx.command_channels,
        );
    }
    let mut queue: VecDeque<Decision> = landing.decisions.into();
    enact_drain(&mut queue, ctx).await
}

#[cfg(test)]
mod tests;
