# A hello that miscounts its tags is refused by name

## Context

kno's aMule (`ab483654`) counts `CT_MOD_IP_V6` in its hello's tag count and then drops the
tag unwritten (`BaseClient.cpp:1384-1385`, `Tag.cpp:398`), so the frame declares one tag
more than it carries. Stock aMule 2.3.3 and eMule 0.70b both throw on that frame and
disconnect. A generic decode error hides which of these happened, and the peer's name and
mod are lost with the connection.

## Decision

When a hello fails to read, the reader looks for a point where the tags read so far end
exactly at the 6-byte connected-server field (optionally plus the 4-byte trailer). If a
count below the declared one ends there, the error is
`PeerHelloDecodeError::TagCountShort { declared, written }`; otherwise it stays the tag
or truncation error it was. The session raises `PeerEvent::HelloRefused` before closing,
carrying the code and the name and mod the peer supplied, as peer-supplied text. Core
counts `peer_hellos_refused_total` and raises `CoreEvent::PeerHelloRefused`, which
carries no peer address. rmule never reads the short list as if the count were right:
that would take the connected-server endpoint from a guess, and no reference does it.

## Consequences

- A refused hello is named, counted and attributable to the software that sent it.
- The hello tag-count defect lives in kno's aMule fork (`integration/network-parity` at
  `ab483654`): its hello counts `CT_MOD_IP_V6` but never writes the tag.

## Considered options

- **Tolerating a hello whose tag count is short.** Rejected: both references refuse it,
  and the fix belongs upstream.
