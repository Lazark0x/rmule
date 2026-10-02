# Connecting is the operator's act: nothing else dials a server

## Context

A server login nobody asked for — a restored download's lazy login, with no listener bound
and nothing mapped — lands a Low ID and arms a firewalled Kad join before the operator has
done anything. Downloads, searches, serving and Kad all ride the one server session
(ADR-0032), and a login is worth its High ID only once the listener is bound and mapped
(ADR-0086).

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**Nothing dials a server but the operator's connect. There is one establishment, and it binds
the listener and waits for its mapping first (ADR-0086). The listener is up from attach.**

| Path | Opens a session? |
|---|---|
| `ConnectToServer` (Networks `c`, the row menu) | yes: listen, map, log in |
| Connect at start (Settings) | yes: the same `ConnectToServer`, at attach |
| A download's source lookup (restored, `StartDownload`, `ResumeDownload`, Restart) | no: rides the live session or waits (**No network**) |
| A keyword search | no: rides the live session, or waits and is sent when one comes up |
| A Related-Files Search | no: refused with no session |
| A serve start | no: the serve binds and follows whatever session the operator makes |
| A lost session while the operator's intent stands | yes: re-made through the one establishment (ADR-0096) |
| Callback relay, hole-punch request, `OP_OFFERFILES`, more results | no: they ride the live session |
| Server-UDP status pings and the global sweeps | no session: datagrams |

Every activity asks `SharedServerSession::live_session`, which waits out an operator connect in
flight and then answers the live handle or nothing. It never dials.

- **Connect at start** is a Settings preference, **off by default** (aMule's `Autoconnect` is on,
  `Preferences.cpp:1160`). When on, the TUI sends at attach the same `ConnectToServer` to the
  server the operator last connected to, recorded on every `Connected` edge. With none recorded
  or one no longer listed, nothing is dialed and the status bar says why. An unreachable server
  gets one attempt; rmule does not walk the list as aMule's `ConnectToAnyServer` does
  (`ServerConnect.cpp:55-70`), because each step would dial a server the operator never picked.
- **The listener is up from attach.** A core built with credentials starts the Serve activity at
  attach, before it restores any download, on `0.0.0.0:<the credentials' TCP port>`; its TCP
  bind joins the Desired Mapping Set, so mapping starts at attach too. A Kad-only run therefore
  accepts peers, and the Kad TCP self-check has a port to reach before any login, as aMule listens
  from `OnInit` (`amule.cpp:917`, `:1631`). A failed bind is reported as
  `ServingFailed { Bind(..) }`; the operator's connect retries it, and the login still goes out
  Low ID if it fails again. A core built without credentials binds on its first
  `ConnectToServer` or `StartServing`.
- **The serve follows the session.** With no session a serve answers hellos with client id 0 and
  no connected server, because that is true. Each session the operator establishes refreshes the
  hello context and is told the share set, as aMule re-sends its list on every connect
  (`ServerConnect.cpp:325`, `SharedFileList.cpp:1588`). `StartServing` names no server.
- **Kad after the listener or a mapping appears.** Two events re-check Kad's verdict: a fresh
  Exact mapping grant (ADR-0086) — a trigger within five minutes of the last check is deferred to
  the end of the five minutes, never dropped — and a High ID while Kad TCP reads firewalled, since
  the server has just reached our listener on the port Kad advertises.

## Consequences

- No server session exists that the operator did not ask for, directly or through their
  connect-at-start preference; a Kad-only operator can run without any server.

## Considered options

- **A lazy login for a download's lookup or a search.** Rejected: it dialed a server nobody asked
  for, before any listener or mapping.
- **Walking the server list at start.** Rejected: every step dials a server the operator
  never picked.
