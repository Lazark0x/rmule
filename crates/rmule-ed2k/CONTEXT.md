# rmule-ed2k

The offline eD2k server-protocol library: packet decoders, umbrella enums, the sans-I/O session state machine, and the command/event service contract. Runtime-agnostic; no Tokio. The live socket layer lives in `rmule-net`'s `ed2k` module.

## Language

**Ed2k Session**:
The sans-I/O state machine that owns one eD2k connection's protocol state. Pure function of inputs: `start()`, `handle_bytes(&[u8])`, `handle_command(`**eD2k Command**`)` push effects into an internal queue; `poll_output()` drains them as `Write(bytes)`, `Event(`**eD2k Event**`)`, or `Close(`**Close Reason**`)`. No clock, no socket, no async. Drives the entire eD2k protocol so unit tests, replay tests, and the live **Driver** all exercise the same state machine.
_Avoid_: connection, actor, runtime task, session manager

**Welcome Burst**:
The back-to-back sequence of server-pushed packets immediately after `OP_IDCHANGE` on a successful login: typically some subset of `OP_SERVERMESSAGE`, `OP_SERVERSTATUS`, `OP_SERVERIDENT`, and `OP_SERVERLIST`. Servers vary in which subset they send and in what order; captured fixtures pin one observed sequence as evidence rather than as a contract.
_Avoid_: handshake, login response, server greeting

**Id Re-assignment**:
A repeat `OP_IDCHANGE` after login. aMule's dispatcher re-runs the whole handler on every `OP_IDCHANGE` (`ServerSocket.cpp`), so an **Ed2k Session** re-applies the client id and re-projects the server's `SRV_TCPFLG` grants and IDCHANGE-extension facts, then re-emits `LoginAccepted` — it does not `Close`. Legitimate because a server may move a client between LowID and HighID mid-session; a zero id is aMule's smart-id case (flags and ports still apply, but no id or connected transition follows). Replaces the removed `DoubleIdChange` protocol-violation close (ADR-0047).
_Avoid_: double IDCHANGE, protocol violation, reconnect, re-login

**Protocol Violation**:
The one non-recoverable failure an **Ed2k Session** raises against the wire: server bytes it cannot decode into a valid frame or typed packet. Triggers `Close(`**Close Reason**`::ProtocolViolation(_))`, carrying the `SessionError::Frame` (framing) or `SessionError::Packet` (typed-payload) cause, and ends the session. No *structural* sequence rule remains — the welcome burst has no enforced arrival order, and a repeat `OP_IDCHANGE` is **Id Re-assignment**, not a violation (ADR-0047). Distinct from a skippable malformed `OP_SEARCHRESULT` (**Search Result Skipped**) and from server-side rejection (the `LoginRejected` event).
_Avoid_: illegal sequence, double IDCHANGE, out-of-order packet, server bug

**Search Result Skipped**:
An **eD2k Event** emitted when a framed `OP_SEARCHRESULT` packet cannot be projected into valid **Search Results** and the session can continue. It is non-terminal and distinct from malformed **Packet Frames**, which still fail the strict frame parser.
_Avoid_: protocol violation, disconnect, empty result

**Source List Reader**:
The one walk every source list shares — `OP_FOUNDSOURCES`, its obfuscated
`0x44` form, and the UDP `OP_GLOBFOUNDSOURCES`: record by record, each
**Sentinel Source** consuming its sixteen address bytes inline as its record's
last field (emule-qt `DownloadQueue.cpp:786-797`). Consuming them in place is
what keeps a sentinel from shifting the record behind it, and what lets a
packed datagram's next packet start where it really starts. A **Malformed
Tail** costs every record from the first sentinel on and nothing before it.
_Avoid_: source parser, trailing sentinel block (the address is inline)

**Login IPv6 Advert**:
The coupled pair a login carries when rmule holds a Known IPv6 (ADR-0087 §4.1):
`CT_SERVER_FLAGS` bit `0x1000` (`SRVCAP_IPV6`) **and** the `CT_MOD_IP_V6`
(`0xAE`) tag, sent together or not at all. One input decides both, so the
coupling is structural rather than a rule to remember. Which of the two a
server gates on is server-dependent and is not the bit — at least one reads the
tag's presence instead — so a client sending either must be sentinel-safe, and
rmule is unconditionally. The bit deliberately sits outside the capability
registry: it states *where rmule can be found*, not what it can speak.
_Avoid_: IPv6 capability (the bit is not a capability), IPv6 flag alone

**Server IPv6 Verdict**:
What the connected server's `ST_IPV6_STATUS` (`0xAB`) says about reaching us
over IPv6 — `HAVE` / `REACHABLE` / `PROBED`, kept whole and read at any integer
width. Exactly one combination means anything to a client: `PROBED` set with
`REACHABLE` clear suppresses further advertisement. An absent tag, `HAVE`
alone, `HAVE | REACHABLE` accepted on trust, and an unknown bit all leave the
advert standing — so a server that trusts rather than dials back can never
suppress anything, by its own design.
_Avoid_: IPv6 status (too vague), reachability (that is rmule's own verdict)

**Id-Tolerant Server Address**:
How `OP_SERVERIDENT`'s *server's own* IPv6 is read: `CT_MOD_SVR_IP_V6` (`0xAF`)
per the spec, with `CT_MOD_IP_V6` (`0xAE`) accepted as a fallback only when
`0xAF` was absent, because the one server implementing the dialect reports
emitting the field under the other id and no public artefact resolves which it
means. `0xAE` is **never** read as a reflection of rmule's own address: the
field is informational either way, so mistaking the server's address for the
server's costs a log line, while mistaking it for ours would make rmule
advertise an address it does not hold.
_Avoid_: ST_IPV6 (that id is `0x99`, and `server.met` only), server address tag

**IPv6 Callback**:
`OP_CALLBACKREQUESTED_IPV6` (`0x26`) — the same role as `0x35` one family over:
sixteen network-order address bytes then the requester's TCP port,
little-endian, eighteen bytes minimum (ADR-0087 §4.5). No crypt extension
exists for it, so trailing bytes are ignored and a dial-back would be
plaintext. Both opcodes project onto one event carrying the requester as a
`PeerEndpoint`, never a synthesised IPv4. **Decoded, not adopted**: core logs
the event and dials nobody, because the opcode names a peer but no file.
_Avoid_: v6 callback request (rmule never sends one — `0x1C` has no v6 form)

**Server List IPv6 Block**:
`OP_SERVERLIST`'s optional trailing block: a `u8` count then eighteen bytes per
entry, after the self-terminating IPv4 array (ADR-0087 §4.6). A legacy server
sends **nothing** after that array — not even a zero byte — so the tail reads as
three outcomes, not an `Option`: *absent* is a server that said nothing about
IPv6, *present and empty* is a capable one that knows none, and *malformed* is a
declared count that does not measure the bytes after it — short or with bytes
over — and costs the IPv6 half alone. Only a
list that read a block writes one back, so a legacy list re-encodes byte-exact.
_Avoid_: trailing bytes (they are a block now), IPv6 server list

**ST_IPV6 Row**:
A `server.met` entry naming an IPv6 server: header IP written as `0` plus the
`ST_IPV6` (`0x99`) tag as a new-format `TAGTYPE_HASH` (ADR-0087 §4.8). The
pairing is a deliberate compatibility trick — stock eMule drops the unknown tag
and then rejects the resulting `ip == 0` entry, so it *ignores* an IPv6 server
rather than mis-dialling one. First tag wins; the address is judged as a **Tag
Identity**; routability is judged on the 128 bits, never on the `u32`
projection, which is `0` for every such row. A row with a zero header IP and no
tag names no server at all and is dropped rather than installed at `0.0.0.0`.
_Avoid_: IPv6 server.met entry (the format has no such field), ST_IPV6 tag on
the wire (it is on disk only)

## Relationships

- An **Ed2k Session** consumes bytes via repeated `Packet::decode` calls against an internal buffer; it does not require a separate frame reader API.
- An **Ed2k Session** projects every decoded **Server Packet** onto its corresponding **eD2k Event** via `Ed2kEvent::from_server_packet`.
- An **Ed2k Session** may skip malformed `OP_SEARCHRESULT` payloads after frame parsing and emit visible typed **Search Result Skipped** events, but malformed **Packet Frames** remain strict session errors.
- A **Welcome Burst** is a sequence of **Server Packets**; the burst's arrival order is captured per-session, not assumed.
- A repeat `OP_IDCHANGE` drives **Id Re-assignment**: the **Ed2k Session** re-projects grants and facts and re-emits `LoginAccepted` in place rather than `Close`-ing; the former `DoubleIdChange` protocol-violation close is gone (ADR-0047).
- A **Protocol Violation** forces an **Ed2k Session** to `Close` with a **Close Reason**; consumers see `Disconnected` as the last event before `next_event` returns `None`.
- `rmule-ed2k` has no dependency on `tokio`; all runtime concerns live in `rmule-net`'s `ed2k` module.
- A **Login IPv6 Advert** and the **Server IPv6 Verdict** close a loop: the advert names an address, the verdict is the server's answer about it, and a `PROBED`-without-`REACHABLE` answer stops the next advert naming it.
- An **IPv6 Callback** and an **ST_IPV6 Row** both name an address in a place the classic format reserved for 32 bits; both avoid writing `0` there, one by carrying the address in its own opcode and the other by pairing the zero with a tag stock eMule refuses.

**Server Punch Coordination**:
ed2k-server's LowID↔LowID introduction (ADR-0091): the **UDP Ports Advert** at login, `OP_LOWID_HOLEPUNCH_REQUEST 0x60` / `_INFO 0x61` (to both peers) / `_FAIL 0x62` on the server link, and the **NAT-T Keepalive**. The server coordinates only; the punch and **Tunnel** are the peer dialect's. `0x61` is the one rendezvous whose address a third party *observed* — the server writes the UDP port it last saw the peer's keepalive arrive from — so nothing in it is the peer's own claim. Its field order is the trap: **TCP port before UDP port**, and the punch goes to the UDP one. The role byte is advisory; both sides fire. The server re-sends `0x61` about 1.2 s and 3 s later, and the session does not dedupe — it holds no attempt state to dedupe against. `0x62` names its target, so unlike `OP_CALLBACK_FAIL` it is attributable, and says whether asking again could help.
_Avoid_: server relay (it relays no data), server callback (the HighID→LowID family)

**UDP Ports Advert**:
`CT_EMULE_UDPPORTS` (`0xF9`) as a **login** tag — `(kadUDP << 16) | clientUDP`, old length-prefixed format, riding `LoginAdvert` after the **Login IPv6 Advert** so neither moves the other. It is both the server's fallback port and the **capability flag**: ed2k-server refuses to introduce anyone to a client that sent none (`TargetNoUdp`). So it is built only by a caller holding a bound client-UDP socket, an `extra_tags` caller cannot make the claim from outside, and a login without it stays byte for byte aMule 2.3.3's four tags.
_Avoid_: UDP port tag (the hello's tag of the same number is a different surface), NAT-T flag

**NAT-T Keepalive**:
`OP_SERVER_NATT_KEEPALIVE 0x9F` — our user hash, every 60 s from the client-UDP socket to the server's UDP port, so the server keeps observing our post-NAT UDP port (it trusts one for 600 s) and counts us alive. A correctness invariant, not a tuning: a lapsed cadence hands peers a port our NAT never opened.
_Avoid_: ping, heartbeat
