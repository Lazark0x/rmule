# rmule-tools

The protocol diagnostic and capture instrument: a CLI that exists to answer
"what did the counterparty actually send?" — by decoding a recorded frame, or by
going and getting one. It enters at whichever layer the question needs: the wire
crates directly when a frame is the subject, the **Core Orchestrator** when the
question first needs a real download, share, or search running. It is *not* an
**Application Front-End**: it holds no durable state, makes no product
decisions, and its output is evidence rather than user-facing status.

Layout: one module per command family under `ed2k/`, `peer/`, and the harness
driver families `nat/`, `natt/` and `ipv6/`, plus a module
per standalone command (`download`, `search`, `serve`, `register_sources`,
`kad_handoff`, `kad_join_node`, `bootstrap_fetch`). The argument tree lives in
`cli.rs`; `main.rs` installs the process-wide tracing subscriber (ADR-0027) and
routes, and does nothing else.

## Language

**Command Family**:
One coherent group of subcommands owning its arguments, its live workflow, and
its verbose inspectors — link decoding, local file hashing, packet inspection,
the welcome capture, the capability probe, the server's UDP face, the peer
welcome/transfer/reask captures. Each family is one module, and a family that
outgrows one file splits along its own legs, never into a helpers bag.
_Avoid_: handler, service, subsystem

**Operand**:
A value typed on the command line that must be parsed into a protocol type
before use: an endpoint, or one of the 16-byte identities (**User Hash**, Kad
ID, **File Hash**) given as 32 hex characters. Each parse is labelled with the
field it came from, because a Kad ID and a User Hash are the same length and
would otherwise report each other's errors.
_Avoid_: arg, param, input

**Capture**:
Counterparty bytes recorded to disk as evidence. Writing one refuses to
overwrite an existing file — there is no `--force`, because a clobber would
silently destroy the only record of an earlier sitting. Captures are never
re-encoded from a decode: what lands on disk is what arrived (ADR-0045).
_Avoid_: dump, log, output file

**Slice**:
Segmenting a recorded stream into per-packet fixture files, using the capture's
own decoded event sequence as the boundary oracle. A stream walk, never a
re-encode: taking the first frame or mis-summing the walk yields a wrong fixture
that only surfaces at promotion time, after the sitting is over.
_Avoid_: split, extract, parse

**Probe**:
A live capability interrogation: log in to a real server and report, as
`key: value` lines, what it actually honours — compression, UDP obfuscation,
the listener's port geometry. The lines are printed as they are found (so they
show in the container logs the harness collects) and retained for the run
directory's `probe.txt`. Two driver commands borrow the word in another sense:
`nat probe` is a **Reflector Probe**, and `ipv6 server-probe` writes a **Driver
Row** about a server's IPv6 surface; neither is this capability report.
_Avoid_: healthcheck, scan, test

**Driver Row**:
The TOML row a `nat`, `natt` or `ipv6` command writes for the interop harness:
rmule's own account of one leg, which the harness reads to *locate* the
counterparty's statement, never as the counterparty's bytes. A counter the
driver never read (a diagnostics snapshot that did not arrive) is written `-1`,
never `0`, because the harness reads a zero as a measurement.
_Avoid_: report, result file

**Reflector Probe**:
`rmule-tools nat probe` — RFC 5780 mapping and filtering discovery from inside a
gateway's LAN against the bench's `natprobe` reflector. It observes the bench,
not a counterparty: stimulus, never evidence. A change test counts only when its
answer left the endpoint the change names; otherwise the row reads
`change-ignored`, and with Test I unanswered both behaviours read `unknown`.
_Avoid_: STUN client, NAT test

**Status Ping**:
The `0x96` request / `0x97` reply exchange on a server's UDP port, in both its
plain and obfuscated spellings. Its port is found by offset from the TCP port —
plain at +4, crypt at +12, with the TCP port itself as a fallback some server
builds need.
_Avoid_: heartbeat, keepalive

**Kad Stimulus Node**:
`rmule-tools kad join-node` — one live Kad node run inside the interop
harness's private mesh, which bootstraps into an aMule hub, taps every datagram,
and logs every event. It participates and records; all acceptance judgement
lives in the harness on the host.
_Avoid_: kad daemon, test node

## Relationships

- Depends on the protocol crates and `rmule-net` directly, and on `rmule-core`
  wherever a command would otherwise reimplement orchestration: `download`,
  `serve`, `search`, `register_sources` and `bootstrap_fetch` each run a real
  `Core`, while `kad_handoff` and the peer welcome capture take their handshake
  context from `rmule_core::build_peer_handshake_context`. What stays off the
  core is the decoding and slicing half, which needs no session at all. Nothing
  depends on `rmule-tools`.
- The interop harness (`tools/interop-harness`) drives these commands as its
  rmule-side stimulus; the harness owns the verdict, the tools own the wire.
- Contrast `rmule-cli`: a product front-end that always goes through the core.
  When a diagnostic needs to reach past the core, it belongs here instead.
