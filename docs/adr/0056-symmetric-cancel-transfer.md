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
2. **No needed parts.** A worker with a granted slot and no assignable part sends `0x56`,
   gives up the slot and stays connected in a slotless **standby** state. When a part
   frees, it re-runs the full ask cycle from the start-upload request. Holding one of the
   counterparty's few upload slots while requesting nothing is the incivility aMule's
   `DS_NONEEDEDPARTS` cancel avoids.
3. **At most one `0x56` per ask cycle** per connection, reset by the next ask and by
   teardown.

The codec is the empty `0xE3` frame in `rmule_peer`. The session's serve half raises the
event; its download half owns the teardown emit and the standby transition. Core maps the
event onto the serve state's release and promote batch.

## Consequences

- The deterministic tier covers the consume path (release and promotion, connection
  survives, slotless no-op, re-ask at the tail, pending sends dropped) and the emit path
  (`0x56` before close on cancel, pause and completion, the standby transition, the
  once-per-cycle latch).
- One capture per direction is enough, because the standby trigger sends the same bytes
  as the captured teardown emit. Consume is proven by a pinned aMule downloading from
  rmule and cancelling through `amulecmd`; emit by rmule cancelling a download from aMule,
  which logs `Upload session ended due canceled transfer`.

## Considered options

- **Treating an inbound `0x56` as a disconnect.** Rejected: aMule keeps the socket to ask
  again when the pause lifts; closing forces a redial.
- **Closing the socket instead of emitting, or emitting only on teardown.** Rejected:
  close-only leaves rmule unable to say it, and an idle worker that keeps its slot through
  the end-game hogs the counterparty's slot.
- **Swapping out slow sources** (cancelling a slower source to free blocks for a faster
  one,
  [DownloadClient.cpp#L656](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/DownloadClient.cpp#L656)).
  Not adopted: aMule gates it behind a default-off preference (`GetDropSlowSources`); it
  is an optimization, not citizen behaviour, and changes only when the same bytes are
  sent.
