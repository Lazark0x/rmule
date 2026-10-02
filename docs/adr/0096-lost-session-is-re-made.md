# A lost server session is re-made while the operator's intent stands

## Context

A server session ends for reasons the operator did not choose: the server restarts, the
link drops, the server goes away for an hour. Only the operator's connect opens a session
(ADR-0095). aMule reconnects after a fixed 30 s under its `Reconnect` preference and walks
its whole list (`ServerConnect.cpp:433-449`, `ServerConnect.h:53`), and its eD2k and Kad
connect and disconnect separately.

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**A lost session is re-made.** The operator's connect expresses an intent that outlives one TCP
link: the **Server Intent** (`service/actor/server_intent.rs`), *stay connected to this server*.
It ends when the operator disconnects (`DisconnectFromServer`), connects elsewhere, or quits.
While it stands, a lost session is re-made through the one establishment:

| Rule | aMule | rmule |
|---|---|---|
| What counts as lost | `CS_DISCONNECTED` after a login (`ServerConnect.cpp:433-449`) | the session task ends without the operator's switch or disconnect |
| Whether it reconnects | the `Reconnect` preference, on by default | always, while the intent stands |
| Retry timer | fixed 30 s (`ServerConnect.h:53`) | 30 s (`server_reconnect_first`), doubling to 10 minutes (`server_reconnect_ceiling`) |
| When the count starts over | no count | a re-made session that holds for `server_session_holds` (10 minutes) starts it over; one that drops sooner continues from its attempt |
| How many attempts | unbounded | unbounded by default (`server_reconnect_attempts`, `RECONNECT_ATTEMPTS = None`): every 10 minutes once the delay is steady, until the intent ends; `Some(n)` bounds it (`ReconnectEnded { AttemptsSpent }`) |
| Which server | the whole list, by priority | the chosen one only; a server no longer listed ends the tries (`ReconnectEnded { Unlisted }`) |
| The operator's own connect failing | not retried | not retried: `ConnectFailed` is shown and the intent ends |
| Dead-server count | `AddFailedCount`; removed past `DeadServerRetries` | each failed retry counts on the server's tally; no server is removed |
| At start | `Autoconnect` | only through the connect-at-start preference |

The attempts are unbounded so an overnight run does not end disconnected because the server was
down for ninety minutes; the operator ends the intent with Disconnect. Core emits
`ServerConnectionEvent::Reconnecting { server, attempt, bound, next_in, at, steady }` per scheduled
attempt and `ReconnectEnded { server, reason }` when it stops; `at` is a monotonic instant the
front end counts down from with its own clock. The status bar reads "eD2k reconnecting (N)", a
download with no network reads **Reconnecting**, and a waiting search says it waits for the
reconnect.

**Disconnect, and Kad's own switch.** The connected server's row menu offers **Disconnect** where
Connect stands on other rows, and `c` on that row does the same: `DisconnectFromServer` ends the
intent and drops a pending retry (`ReconnectEnded { OperatorDisconnected }`). A connect to another
row replaces the intent; the `Connecting` edge names the server it left (`leaving`), and a
reconnect it cut short ends with `ReconnectEnd::Replaced`. **Disconnecting from a server leaves
Kad running**, as in aMule, where eD2k and Kad connect and disconnect separately
(`ServerWnd.cpp:541-553`, `ServerConnect.cpp:522-541`, `KadDlg.cpp:206-215`). **`K` in Networks
is Kad's switch:** it runs the TUI's Kad join (ADR-0067) when Kad is off and sends `DisableKad`
when it runs; core reports `KadStopped { Stopped }`. Kad's state is core's level,
`DiagnosticsSnapshot::kad_state` (`Off`, `Running`, `Stopping`), never assumed from the command
sent. The TUI starts Kad once per run on the first `Connected` edge unless the operator already
started or stopped it with `K`.

## Consequences

- An overnight run is connected again after a long outage; only the operator's Disconnect
  ends the tries.
- Disconnecting from a server leaves Kad running.

## Considered options

- **Walking the server list on a lost session.** Rejected: every step dials a server the
  operator never picked.
- **A bounded number of reconnect attempts by default.** Rejected: a long outage would leave an
  overnight run disconnected; the count stays one configuration value away.
