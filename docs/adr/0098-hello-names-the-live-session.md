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
`GetCurrentServer()` or `0` (`BaseClient.cpp:1621-1628`). Every dial reads the live session's id
and server at the moment it dials (`live_peer_handshake_context`): download workers, the Kad TCP
dial-back, the UDP firewall check's helper link. The long-lived surfaces — the listener's accept
pump, the tunnel and callback dial-backs it admits, the firewalled front's buddy dial — read the
same cell at each connection through a `HelloSource`, so a mid-session `OP_IDCHANGE` is named at
once, as aMule writes `theApp->GetID()` per hello (`BaseClient.cpp:1330`).

## Consequences

- A session switch or a mid-session `OP_IDCHANGE` is named in the next hello on every road.
- No hello names a server rmule is no longer connected to.
