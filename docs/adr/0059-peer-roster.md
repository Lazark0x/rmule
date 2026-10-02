# The Peer Roster: one store of the peers this session already deals with

## Context

The Kad UDP self-check must not test a peer rmule already deals with: aMule's
`DoRequestFirewallCheckUDP` refuses a known client (`ClientList.cpp:1204-1211`), and a
helper biases its answer for a requester it has an active upload, download or chat with
(`BaseClient.cpp:4002-4007`) (ADR-0058). aMule answers from its client list, which a
sweep (`CleanUpClientList`) prunes.

## Decision

`SharedPeerRoster` is the one store the self-check reads for "a peer this session already
deals with". It holds relations keyed by holder and endpoint; an IP is known while any
relation holds it.

| Relation | Added | Removed | aMule |
| --- | --- | --- | --- |
| `Download(DownloadId)` | a live worker's hello completes | the worker's retirement, or every still-live worker at the download's end, however it ends | `SetDownloadState`; `Disconnected` → `RemoveSource` |
| `Queued(DownloadId)` | a source enters the Remote-Queued Pool (ADR-0057) | it leaves the pool, or the download ends | `DS_ONQUEUE`, socket closed |
| Waiter (held as `Upload`) | the serve state queues the peer | purged, cancelled while waiting, or the serve activity ends; a promotion is a transition, not a removal | `US_ONUPLOADQUEUE`, kept across a disconnect |
| `Upload` | a slot is granted | the slot is released, or the serve activity ends | `US_UPLOADING` |

A relation is added and removed by the same owner's paired events, never by a sweep that
guesses, unlike aMule's `CleanUpClientList`. The gate widens no further than these
relations: testing a stranger is what the check is for.

## Consequences

- Every relation has a paired add and remove, so the roster never holds a peer no owner
  still deals with; the deterministic tier covers each relation's pair.
- The self-check's gate and the helper's bias read one store, so neither can disagree
  with the other about who is known.
