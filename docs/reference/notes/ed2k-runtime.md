# ED2K runtime

**Status:** implemented
**Scope:** connection lifecycle for one eD2k server session — TCP connect, login wait, welcome burst arrival, idle behaviour, and disconnect causes — as observed in aMule and cross-checked against the eMule protocol PDF. Wire payloads for the welcome packets themselves live in `ed2k-welcome-packets.md`; this note is about *when* bytes flow, not *what* they contain.

Citations point at the pinned aMule commit `377ec8d9d56618f1059d8705ae53a70fa4ffbe87` (link-only per ADR-0013).

## Connection lifecycle

```
                ConnectToAnyServer()
                       |
                       v
            +---------------------+
            |   CS_NOTCONNECTED   |
            +---------------------+
                       | TryAnotherConnectionrequest -> ConnectToServer
                       v
            +---------------------+
            |    CS_CONNECTING    |    socket open in progress
            +---------------------+
                       | OnConnect() success (ServerSocket.cpp:82-88)
                       v
            +---------------------+
            |   CS_WAITFORLOGIN   |    LoginRequest queued; awaiting IdChange
            +---------------------+
                  |              |
        IdChange  |              |  OnClose / read EOF
                  v              v
        +-----------------+   +---------------------+
        |   CS_CONNECTED  |   |   CS_SERVERFULL     |  (ServerSocket.cpp:356-365 maps
        +-----------------+   +---------------------+   prior-state -> terminal-state)
                  |
                  | OnError / write fail / user disconnect
                  v
        +---------------------+
        |   CS_DISCONNECTED   |
        +---------------------+
```

aMule's per-socket state values: `CS_NOTCONNECTED`, `CS_CONNECTING`, `CS_WAITFORLOGIN`, `CS_CONNECTED`, `CS_SERVERFULL`, `CS_DISCONNECTED`, `CS_SERVERDEAD`, `CS_FATALERROR` (`ServerSocket.cpp:66`, `82-105`, `337`, `356-365`). The terminal state on `OnClose()` depends on the prior state — closing from `CS_WAITFORLOGIN` is reported as `CS_SERVERFULL` (the server hung up mid-login, treated as capacity), closing from `CS_CONNECTED` as `CS_DISCONNECTED`, anything else as `CS_NOTCONNECTED`.

## Timeouts

| What aMule times | Constant | Value | Citation | rmule equivalent |
| --- | --- | --- | --- | --- |
| Pending connection / login age | `CONSERVTIMEOUT` | `25000` ms (25 s) | `src/include/protocol/ed2k/Constants.h:53` | Split into `connect_timeout` (default 10 s) + `login_timeout` (default 15 s) on `ConnectOptions`. Sum stays under aMule's combined budget. |
| Generic TCP connection wait | `CONNECTION_TIMEOUT` | `40000` ms (40 s) | `Constants.h:30` | Not adopted directly. rmule's `connect_timeout` is bounded by the user-visible `ConnectOptions::connect_timeout`. |
| Server re-ask cadence | `SERVERREASKTIME` | `800000` ms (≈ 13.3 min) | `Constants.h:32` | The first session runtime did not implement re-ask: out of its welcome-only scope. |

aMule's `CServerConnect::CheckForTimeout()` (`ServerConnect.cpp:382-409`) sweeps `m_lstOpenSockets` once per tick and destroys any socket whose `m_dwLastTransmission` is older than `CONSERVTIMEOUT`. It is one threshold for both "stuck in `CS_CONNECTING`" and "stuck in `CS_WAITFORLOGIN`". The `m_dwLastTransmission` field is refreshed by `CServerSocket::SendPacket()` (`ServerSocket.cpp:347-350`), which is why writing `OP_LOGINREQUEST` resets the login-wait clock.

rmule splits the two windows because the failure they describe are distinct (DNS / SYN never lands vs. server accepted TCP but is silent at the protocol layer) and the typed `CloseReason::ConnectTimeout` vs. `CloseReason::LoginTimeout` payload (ADR-0023) lets consumers react accordingly. Per ADR-0021 the session is time-free, so the driver owns both timers.

## Disconnect causes

aMule disconnects on:

- **TCP connect failure** — `CServerSocket::OnConnect(nErrorCode)` (`ServerSocket.cpp:82-105`) maps `wxSOCKET_INUSE`, `wxSOCKET_NOHOST`, `wxSOCKET_NOPROTO`, `wxSOCKET_INVADDR`, `wxSOCKET_INVOP`, `wxSOCKET_TIMEDOUT`, and friends to `CS_SERVERDEAD` or `CS_FATALERROR` and calls `DestroySocket()`. → rmule: `Ed2kNetError::ConnectFailed { source }` (or `CloseReason::Io(ErrorKind)` once driving).
- **Read EOF / peer FIN** — `OnClose()` (`ServerSocket.cpp:356-365`) destroys the socket and reports a terminal state derived from the prior state. → rmule: driver synthesizes `CloseReason::ServerClosed`. If the close arrives mid-login it is still `ServerClosed`, not `LoginRejected` — the latter is reserved for an explicit `OP_REJECT` frame.
- **Socket error** — `OnError()` (`ServerSocket.cpp:324-330`) logs and sets `CS_DISCONNECTED`. → rmule: `CloseReason::Io(ErrorKind)`.
- **Receive on a not-yet-connected socket** — `OnReceive()` (`ServerSocket.cpp:111-118`) calls `DestroySocket()` if state is not `CS_CONNECTED` / `CS_CONNECTING`. rmule's sans-I/O session ignores this case structurally (no bytes arrive before `start()`).
- **Pending-attempt timeout** — `CheckForTimeout()` (`ServerConnect.cpp:382-409`) destroys stalled sockets. → rmule: driver-side `ConnectTimeout` / `LoginTimeout` (see table above).
- **Server marked dead / full** — `ConnectionFailed()` (`ServerConnect.cpp:341-450`) logs reasons like "Fatal Error while trying to connect", "Lost connection to %s", "%s appears to be dead", "%s appears to be full" and increments `pServer->AddFailedCount()` (`ServerConnect.cpp:358`). On a successful login it calls `update->ResetFailedCount()` (`ServerConnect.cpp:263`). → rmule: out of scope for the first session runtime; per-server fail tracking belongs to a future server-list policy layer, not to `Ed2kSession`.
- **User-requested disconnect** — `Disconnect()` (`ServerConnect.cpp:453-469`) closes the active connected socket explicitly. → rmule: `Ed2kCommand::Disconnect` -> `CloseReason::Local`.
- **`OP_REJECT` payload** — `ServerSocket::ProcessPacket()` (`ServerSocket.cpp:289-291`) handles only the `OP_REJECT` opcode as a server-side login rejection. → rmule: `Ed2kEvent::LoginRejected` followed by `Disconnected` (the cause is not a `ProtocolViolation`; the server explicitly refused).

## Welcome burst arrival

aMule's `ProcessPacket()` switch (`ServerSocket.cpp:120-318`) has cases for `OP_IDCHANGE` (line 177), `OP_SEARCHRESULT`, `OP_FOUNDSOURCES`, `OP_SERVERSTATUS`, `OP_SERVERIDENT`, `OP_SERVERLIST`, `OP_SERVERMESSAGE`, `OP_CALLBACKREQUESTED`, and `OP_REJECT`. **No ordering is enforced** — each opcode is processed independently as it arrives. The "welcome burst" is therefore a behavioural observation about lugdunum-era servers, not a contract aMule defends.

Practical observations (to be confirmed by the A2 captured fixture):

- `OP_IDCHANGE` is the first server-to-client packet on a successful login; without it no other state changes.
- `OP_SERVERMESSAGE` typically follows immediately and may arrive multiple times (MOTD chunked into separate `OP_SERVERMESSAGE` frames).
- `OP_SERVERSTATUS`, `OP_SERVERIDENT`, `OP_SERVERLIST` follow in **server-specific order**; some servers omit `OP_SERVERLIST` entirely until the client sends `OP_GETSERVERLIST`.
- Per `ed2k-welcome-packets.md`, all five S→C welcome opcodes are well-typed; an unknown well-formed opcode that arrives in the same burst is preserved as `ServerPacket::Unknown` per ADR-0018.

The `Ed2kSession` state machine therefore does not enumerate "expected burst" — it accepts any of those packets in any order while in `LoggedIn`, and emits one `Ed2kEvent` per decoded `ServerPacket`. The captured fixture pins one observed sequence as evidence, not as a contract.

## Idle and keep-alive

aMule's `KeepConnectionAlive()` (`ServerConnect.cpp:510-537`) sends an empty `OP_OFFERFILES` packet whenever the connected socket has been silent longer than `thePrefs::GetServerKeepAliveTimeout()` (a user preference, not a hard-coded value). The default in current sources is 0 (disabled) unless the user opts in.

A2 does not implement keep-alive. The welcome-only slice connects, observes the burst, and disconnects. Idle is the caller's concern — the driver does not arm an idle timer, and `Ed2kSession` has no concept of idle. A future slice that holds the connection open will revisit this; the natural home is a driver-side `tokio::time::sleep` on a `ConnectOptions::keep_alive` field, not session state.

## Sources

Link-only (GPLv2, no in-tree copy; pinned at commit `377ec8d9d56618f1059d8705ae53a70fa4ffbe87`):

- `src/ServerConnect.cpp` — lifecycle entry points: `TryAnotherConnectionrequest` (48-72), `ConnectToAnyServer` (73-113), `ConnectToServer` (115-128), `ConnectionFailed` (341-450), `CheckForTimeout` (382-409), `Disconnect` (453-469), `KeepConnectionAlive` (510-537), `DestroySocket` (498-503), `StopConnectionTry` (215-230).
- `src/ServerSocket.cpp` — socket-side state transitions: constructor (66), `OnConnect` (82-105), `OnReceive` (111-118), `OnError` (324-330), `SetConnectionState` (337), `SendPacket` (347-350), `OnClose` (356-365); welcome-burst dispatch (120-318) including `OP_IDCHANGE` (177) and `OP_REJECT` (289-291).
- `src/include/protocol/ed2k/Constants.h` — `CONNECTION_TIMEOUT` (30), `SERVERREASKTIME` (32), `UDPSERVERREASKTIME` (33), `CONSERVTIMEOUT` (53).

Cached:

- `docs/reference/emule-spec/emule_protocol_specification.pdf` — section 2 "Client server TCP Communication" for the welcome-burst behaviour; section 6.2.16 for `OP_REJECT` semantics ("the receiving client logs the message and discards it").
- `docs/reference/amule-wiki/ed2k_protocol.wikitext` — login walkthrough; does not deepen runtime / timeout coverage.

## Open research gaps

- **`OP_REJECT` vs. early `OP_CLOSE`** — confirmed only from `OP_REJECT`. If a server hangs up before sending any frame after `LoginRequest`, that surfaces as `CloseReason::ServerClosed`, not `LoginRejected`. A captured fixture against a banned-hash scenario would tighten this distinction.
- **Variable-length `OP_SERVERSTATUS`** — aMule's `FIXME` (see `ed2k-welcome-packets.md`) implies some servers emit extra trailing bytes. The runtime capture should record the observed `OP_SERVERSTATUS` size; if > 8 bytes, the extension shape goes here.
- **`SO_KEEPALIVE` use** — aMule's wxSocket layer may set the TCP-level keepalive; not relevant to the protocol session but worth confirming before any future long-lived connection slice.
