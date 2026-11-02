# Cancel transfer is symmetric: consumed as aMule does, emitted on aMule's triggers

## Context

`OP_CANCELTRANSFER` (`0x56`, protocol `0xE3`, empty payload) is aMule's "stop sending,
I no longer want this transfer". The downloader sends it; the uploader ends the upload
session on receipt
([ClientTCPSocket.cpp#L673](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L673)).
Without it, an aMule that cancels mid-transfer holds one of rmule's upload slots until
the slot's stale timeout fires, and an rmule that cancels can only drop the socket.

aMule's receipt path is `RemoveFromUploadQueue`
([UploadQueue.cpp#L522](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/UploadQueue.cpp#L522)):
the slot is freed, pending block requests are cleared, the connection stays open and the
client is not re-queued. A `0x56` from a client holding no slot returns `false` silently.

aMule sends `0x56` at most once per ask cycle (`m_fSentCancelTransfer`, reset on
disconnect,
[BaseClient.cpp#L1381](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1381),
and on a new ask,
[DownloadClient.cpp#L158](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L158)),
on three triggers: an upload accept for a file no longer wanted
([ClientTCPSocket.cpp#L646](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L646)),
parts arriving for a stopped, paused or errored file
([ClientTCPSocket.cpp#L726](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L726)),
and nothing left to request from this source
([DownloadClient.cpp#L693](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L693),
`DS_NONEEDEDPARTS`).

## Decision

**Consume (rmule as uploader), as aMule does.**

- `PeerPacket::CancelTransfer` is a modelled packet. The session raises
  `ServerEvent::TransferCancelled` only when the peer holds a served slot; a slotless
  `0x56` is a no-op. A body on the packet is ignored and the link kept.
- Serve state runs the release it runs for a disconnect, minus the teardown: the slot is
  released, the next queued peer is promoted and ranks are re-broadcast in the same
  decision batch, the canceller's served ranges are cleared and pending unsent blocks are
  dropped. The connection stays open.
- The canceller is not re-queued. A later ask is a fresh admission at the tail.
- The stale timeout remains only as the backstop for silent peers.

**Emit (rmule as downloader), on aMule's triggers.**

1. **Local-reason teardown.** A worker shut down by cancelling, pausing or completing the
   download while its slot is granted or active sends `0x56` before closing. This covers
   aMule's first two triggers; closing right after is safe because aMule's receipt path
   expects no follow-up.
2. **Nothing to work on a granted slot.** A worker granted a slot whose pipeline has
   drained with no block to be handed and no Duplicate Set (ADR-0117) — at the grant, or
   once its last asked block arrived — sends `0x56` and gives the slot back, as aMule's
   `SendBlockRequests` does when no free block is left (`DownloadClient.cpp:641-693`). A
   worker keeps its slot while a slower worker holds a block it could duplicate: the End
   Game hands it that block, and it gives the slot back only once none is left. One whose
   Advertised Parts still hold a part we lack, every block claimed elsewhere, is retired
   `NoFreePart` and its record waits in the
   RemoteQueued stage on the ordinary cadence (ADR-0057); one advertising no part we
   lack is retired `NoNeededParts` (ADR-0112). Neither stays connected: the record's
   standing, not the socket, brings the source back. Holding one of the counterparty's
   few upload slots while requesting nothing is the incivility aMule's
   `DS_NONEEDEDPARTS` cancel avoids. A worker that holds no granted slot sends no
   `0x56`.
3. **An unasked grant nobody stands for.** An `OP_ACCEPTUPLOADREQ` on a link no download
   asked a slot on — an uploader's promotion by dial-back, or on a link it held (ADR-0057)
   — that no download of the peer takes (ADR-0107, the Awaited Grants) is given back with
   `0x56`, as aMule's downloader cancels an accept for a file it no longer wants
   (`ClientTCPSocket.cpp:646-659`). The link stays up for whatever else holds it. A download
   that takes it opens a worker that takes the grant as its own, asking nothing first (ADR-0107);
   until it takes it, the grant stands on the link for the rider to give back. A worker retired before it — its probe naming no
   part we lack (`NoNeededParts`, ADR-0112), or its run stopping — sends the same `0x56`, so
   the uploader never holds a slot for a source that asks nothing on it. A worker that ends
   silently before its ask — its probe unanswered, its link to the download gone — leaves the
   grant to the link: when its last rider leaves and no waiter takes the link, the link gives
   back an offer still standing with the same `0x56`, whether its serve half or the buddy slot
   then keeps it up (ADR-0107 invariant 9) or it closes. Kept up, the slot would otherwise be
   held until the uploader's 40 s silent-link close (`ClientTCPSocket.cpp:201-229`).
4. **A granted slot that stalls.** A worker whose granted slot delivers no byte for the slot
   budget sends `0x56` and gives the slot back, as aMule's downloader does when a
   `DS_DOWNLOADING` client sends nothing for `DOWNLOADTIMEOUT` (`DownloadClient.cpp:1188-1196`,
   100 s, `Constants.h:64`); its record keeps the source, standing without a rank (ADR-0090).
   rmule's budget is the slot wait's, not aMule's 100 s. A slot wait that times out while
   only queued holds no slot and sends nothing.
5. **At most one `0x56` per ask cycle** per connection, reset by the next ask and by
   teardown.

The codec is the empty `0xE3` frame in `rmule_peer`. The session's serve half raises the
event; its download half owns the emit, and core decides when (the first two triggers end
the worker; the third is the link's, since no worker holds it; the fourth is the worker's own
timeout, which ends it). Core maps the
event onto the serve state's release and promote batch.

## Consequences

- The deterministic tier covers the consume path (release and promotion, connection
  survives, slotless no-op, re-ask at the tail, pending sends dropped) and the emit path
  (`0x56` before close on cancel, pause and completion, a granted slot given back,
  the once-per-cycle latch).
- One capture per direction is enough, because the give-back sends the same bytes as
  the captured teardown emit. Consume is proven by a pinned aMule downloading from
  rmule and cancelling through `amulecmd`; emit by rmule cancelling a download from aMule,
  which logs `Upload session ended due canceled transfer`.

## Considered options

- **Treating an inbound `0x56` as a disconnect.** Rejected: aMule keeps the socket to ask
  again when the pause lifts; closing forces a redial.
- **Closing the socket instead of emitting, or emitting only on teardown.** Rejected:
  close-only leaves rmule unable to say it, and an idle worker that keeps its slot through
  the end-game hogs the counterparty's slot.
- **A slotless standby**: the worker stays connected after its `0x56`, to be handed a
  released part and re-run the ask cycle on the same link. Rejected: aMule has none —
  its `DS_NONEEDEDPARTS` link idles into the uploader's 40 s close
  (`CONNECTION_TIMEOUT`, `Constants.h:34`) — and it holds one of the download's worker
  slots for a source the record's standing already brings back on its reask.
- **Swapping out slow sources** (cancelling a slower source to free blocks for a faster
  one,
  [DownloadClient.cpp#L656](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L656)).
  Not adopted: aMule gates it behind a default-off preference (`GetDropSlowSources`); it
  is an optimization, not citizen behaviour, and changes only when the same bytes are
  sent.
