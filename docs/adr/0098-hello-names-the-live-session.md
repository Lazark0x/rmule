# Every hello names the live server session

## Context

A hello carries the sender's client id and its connected server's address and port. The
session may switch servers, and a server may re-assign the id mid-session with
`OP_IDCHANGE` (ADR-0047); several roads send hellos — download workers, Kad dial-backs, the
UDP firewall check's helper link (ADR-0058), the listener's accept pump and the dial-backs
it admits.

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**Every hello names the live session.** A hello's server fields name the session it is sent
under — the connected server's address and port, or zeros — as aMule and eMule write
`GetCurrentServer()` or `0` (`BaseClient.cpp:1164-1171`). Its client id is the **Presented Client
ID** Self Reach answers (ADR-0060), aMule's `GetID()` written per hello (`BaseClient.cpp:1026`):
an open, connected Kad's address, else the session's id, else `1` for a connected, firewalled
Kad, else `0`. Every dial reads both at the moment it dials (`live_peer_handshake_context`):
download workers, the Kad TCP dial-back, the UDP firewall check's helper link. The long-lived
surfaces — the listener's accept pump, the tunnel and callback dial-backs it admits, the
firewalled front's buddy dial — read the same owner at each connection through a `HelloSource`,
so a mid-session `OP_IDCHANGE`, a login, a logout or a Kad verdict move is named at once.

## Consequences

- A session switch, a mid-session `OP_IDCHANGE` or a Kad verdict move is named in the next hello
  on every road.
- A serverless, firewalled Kad node names `1`, which aMule reads as a Low ID, so an open aMule
  keeps it as a buddy; a `0` would read as the address it dialed from (`BaseClient.cpp:678`).
- No hello names a server rmule is no longer connected to.
