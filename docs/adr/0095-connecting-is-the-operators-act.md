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

- **Connect at start** is a Settings preference, **on by default**, as aMule's `Autoconnect` is
  (`Preferences.cpp:1160`). It repeats the operator's own act: the TUI sends at attach the same
  `ConnectToServer` to the server they last connected to, recorded on every `Connected` edge, and
  a restart of a tool left running for days comes back to work rather than to `No network`. With
  none recorded, a first run, nothing is dialed and nothing is said; with one no longer listed,
  nothing is dialed and the status bar says why. The default is the value an unset key reads, so
  a stored off stays off and no store rung is needed. An unreachable server gets one attempt; rmule does not walk the list as aMule's `ConnectToAnyServer` does
  (`ServerConnect.cpp:55-70`), because each step would dial a server the operator never picked.
- **The listener is up from attach.** A core built to restore at attach starts the Serve activity at
  attach, before it restores any download, on `0.0.0.0:<the Core Settings' TCP port>`; its TCP
  bind joins the Desired Mapping Set, so mapping starts at attach too. A Kad-only run therefore
  accepts peers, and the Kad TCP self-check has a port to reach before any login, as aMule listens
  from `OnInit` (`amule.cpp:917`, `:1631`). A failed bind is reported as
  `ServingFailed { Bind(..) }`; the operator's connect retries it, and the login still goes out
  Low ID if it fails again. A core built without it binds on its first
  `ConnectToServer` or `StartServing`, or on an `EnableKad` whose Core Settings' TCP port is `0`:
  the node presents its port for its whole life, so it waits for the port bound, and is refused
  (`KadUnavailableReason::TcpPortUnbound`) when the listener cannot bind.
- **The serve follows the session.** With no session a serve answers hellos with client id 0 and
  no connected server, because that is true. Each session the operator establishes refreshes the
  hello context and is told the share set, as aMule re-sends its list on every connect
  (`ServerConnect.cpp:325`, `SharedFileList.cpp:1588`). `StartServing` names no server.
- **Kad after the listener or a mapping appears.** Two events re-check Kad's verdict: a fresh
  Exact mapping grant (ADR-0086) — a trigger within five minutes of the last check is deferred to
  the end of the five minutes, never dropped — and a High ID while Kad TCP reads firewalled, since
  the server has just reached our listener on the port Kad advertises.

**A dial is the operator's to end, and it holds nothing.** The slot's lock guards the take of the
old session and the install of the new one, no more: a dial may sit out a silent server for a
minute, and every reader of the slot answers meanwhile, none on the actor waiting. A Disconnect
ends a dial in flight, said as `Disconnected`, with nothing counted against the server. A named
server is resolved through the bounded Name Resolver before its filter gate.

**A dead link.** A server link can die with nothing owed on it, so no write of ours finds out. The
kernel probes every quiet server link (a minute idle, every 15 s, four unanswered; `resolve.rs`).
The actor compares the monotonic clock with the wall every 30 s, and a gap past two minutes on
either is a suspend: the mapper races again, and the session is hung up, for the intent to re-make
as after any lost session (ADR-0096). A re-login rather than a ping: aMule's own ping is an empty
`OP_OFFERFILES` it waits on no answer to (`ServerConnect.cpp:595-609`), so it proves nothing by
itself, and a write on a dead link waits on the kernel's retransmission rather than on keepalive.

## Consequences

- No server session exists that the operator did not ask for, directly or through their
  connect-at-start preference; a Kad-only operator can run without any server.

## Considered options

- **A lazy login for a download's lookup or a search.** Rejected: it dialed a server nobody asked
  for, before any listener or mapping.
- **Walking the server list at start.** Rejected: every step dials a server the operator
  never picked.
