# Typed CloseReason replaces String

## Context

A server session ends for several reasons — the caller asked, the server closed the
socket, the server refused the login, the decoder refused to continue, socket I/O
failed, connect or login timed out — and each tells a consumer something different:
retry, give up, or report a bug. A free-form `String` reason forces consumers to
pattern-match on prose, breaks the typed-errors policy for public APIs (ADR-0010),
and lets every new close path add undocumented strings to the contract.

## Decision

`CloseReason` is a typed, `#[non_exhaustive]` enum in `rmule-ed2k`: `Local`,
`ServerClosed`, `LoginRejected`, `ProtocolViolation(SessionError)`,
`Io(io::ErrorKind)`, `ConnectTimeout` and `LoginTimeout`.

- It rides on `Output::Close(CloseReason)` from `Ed2kSession`, so the driver knows
  how to tear down, and on `Ed2kEvent::Disconnected { reason }`, so consumers see
  exactly why the session ended.
- `Disconnected` is always the last event before `next_event()` returns `None`: the
  typed reason is the session's final fact.
- `LoginRejected` (an `OP_REJECT` answer to the login) stays distinct from
  `ServerClosed` (a bare TCP close), so a consumer can tell "refused" from "dropped"
  without guessing.
- `CloseReason::label()` is the one source of stable discriminant strings for
  diagnostics and capture `meta.toml`; payload-carrying variants report their own
  name, never a stand-in.

## Consequences

- Consumers match on variants, not text, and handle unknown variants defensively
  because the enum is non-exhaustive.
- A new close path is a new variant with a documented meaning, added when the
  evidence for it exists.
