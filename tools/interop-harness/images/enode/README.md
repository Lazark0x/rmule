# eNode interop image (feasibility spike)

Builds **eNode** ([github.com/petermrg/eNode], MIT) — an independent, native
Node.js eD2k/eMule server — from its **unmodified** sources at a pinned commit.
eNode was evaluated as the ADR-0040/0046 server-replacement candidate for the
server-capability rows Lugdunum 17.15 cannot satisfy (crypt-ping, concurrent
High-ID logins, global UDP search). **Verdict: eNode is not admissible as a server replacement: it crashes on the
first login, and its obfuscated found-sources (`0x44`) is unimplemented. It did
answer an obfuscated crypt-ping, captured as `enode-server-udp-crypt-20260728`.**

[github.com/petermrg/eNode]: https://github.com/petermrg/eNode

## What this image is (and is not)

- **Independent counterparty (ADR-0045).** eNode's protocol code is cloned at
  `ENODE_COMMIT` and run **unmodified** — the repo commits no eNode source
  (same posture as the Lugdunum image: recipe only, binary/source by pinned
  ref). Only bytes from this unmodified build are admissible evidence.
- Base `node:0.10` (eNode's 2013 target runtime) under **amd64 emulation**;
  needs a **MySQL** sidecar (its documented backend). The four pure-JS deps
  (`mysql`, `hexy`, `tinylogger`, `colors`) install from npm — no native build.
- `entrypoint.sh` materialises `enode.config.js` from the environment
  (auto-detects the container IP eNode must bind), waits for MySQL, and runs
  `init-schema.js` (idempotent apply of eNode's own `misc/enode.sql`).
  `init-schema.js` is *harness* glue, not eNode code.

## Usage

```bash
./standup.sh                          # enode-mysql + enode on 203.0.113.0/24
docker logs enode                     # boot: 4 listeners + TCP/UDP flag words
./teardown.sh                         # remove containers + network (keep images)
```

`docker-compose.yml` is an equivalent convenience for hosts that have the
compose plugin; `standup.sh` is the plugin-free path exercised in the spike.

`probe.py` is the spike **stimulus** (a plain eD2k client): it reports the bytes
eNode returns per axis. The formal crypt-ping capture uses `rmule-tools ed2k server
probe` as the client-under-test; `probe.py` only answered the feasibility
question. Run it on the network:

```bash
docker run --rm --network enode-spike-net -v "$PWD":/probe python:3-slim \
  python /probe/probe.py all 203.0.113.10 4661 4665 4677
```

## Environment

| Env | Default | Effect |
|---|---|---|
| `ENODE_ADDRESS` | container IP | address eNode binds its TCP listeners to |
| `ENODE_SUPPORT_CRYPT` / `_REQUEST_CRYPT` / `_REQUIRE_CRYPT` | `true`/`true`/`false` | obfuscation posture (sets the `SRV_*OBFUSCATION` advert bits) |
| `ENODE_TCP_PORT` / `_TCP_PORT_OBF` | `4661` / `4673` | plain / obfuscated TCP |
| `ENODE_UDP_PORT` / `_UDP_PORT_OBF` | `4665` / `4677` | plain / obfuscated UDP |
| `ENODE_MYSQL_HOST` | `enode-mysql` | MySQL sidecar address |

## Known limitation (spike finding)

eNode's **MySQL storage path is broken against its own operations layer** (≥5
`storage.js` API desyncs: `getCount`→`count`, `addSource`→`add`, `getSources`
arity), so the **unmodified server crashes on the first client login**
(`TypeError … 'getCount'` in `serverStatus`). Its login-free surface — the
plain **and obfuscated** status ping (crypt advert + crypt-ping SPEAK) — works;
every login-gated flow (offer / search / concurrent sources) does not. This is
engine-agnostic (MongoDB shares `storage.js`). Do **not** patch eNode to work
around it: a modified server is inadmissible (ADR-0045). See the parity verdict.
