# Top-level architecture

rmule is a library-first Rust implementation of the eD2k and Kad protocols
([ADR-0001](../adr/0001-protocol-behaviour-in-reusable-libraries.md)). The
protocol lives in small crates that own no sockets, no clock and no screen; one
crate owns the network, one owns the application's state, and the two programs
are thin front-ends over it
([ADR-0005](../adr/0005-cargo-workspace-of-small-protocol-crates.md),
[ADR-0081](../adr/0081-crate-topology.md)).

This page is the map. Every decision it mentions is indexed in
[`docs/adr/README.md`](../adr/README.md), and each crate's vocabulary is in its
`CONTEXT.md` (see [`CONTEXT-MAP.md`](../../CONTEXT-MAP.md)).

## Crate map

| Crate | Layer | What it holds | Start at |
| --- | --- | --- | --- |
| `crates/rmule-primitives` | wire values | hashes, eD2k links, identities, endpoints, tags, the packet frame codec, obfuscation and SUI key material, the sans-I/O session spine | `src/lib.rs` |
| `crates/rmule-ed2k` | protocol | client-to-server eD2k: login, search, source lookup, server UDP | `src/session.rs` |
| `crates/rmule-peer` | protocol | client-to-client eD2k: hello, file requests, upload queue, part transfer, AICH, source exchange, Secure User Identification | `src/session.rs` |
| `crates/rmule-kad` | protocol | Kad2: packet envelopes, the `KadNode` and its routing table, keyword and source stores, firewall checks, buddies | `src/node.rs` |
| `crates/rmule-bootstrap` | protocol | `server.met` and `nodes.dat` acquisition behind a `Fetcher` seam, with an optional HTTP fetcher | `src/lib.rs` |
| `crates/rmule-net` | networking | the only sockets and timers: a generic driver for any sans-I/O session, wire capture, the crypt stream, the eD2k, peer and Kad runtimes, NAT traversal, port mapping | `src/driver.rs` |
| `crates/rmule-os` | platform | the operating-system calls std does not expose: the Windows ICMP-reset switch for UDP sockets, the part file's sparse flag, punch and allocated size, the default app for a file-name extension; the workspace's only `unsafe` | `src/lib.rs` |
| `crates/rmule-store` | storage | a domain-free typed layer over one `redb` file: records, tables, schema, version ladder | `src/lib.rs` |
| `crates/rmule-core` | orchestration | the `Core` actor: downloads, uploads, search, the server list, Kad, shared files, every durable fact | `src/service.rs` |
| `apps/rmule` | front-end | the `rmule` terminal client, with the core in-process | `src/main.rs` |
| `apps/rmule-cli` | front-end | the headless client, one command per run | `src/main.rs` |
| `crates/rmule-testkit` | tests only | in-process fake servers and peers, peer scripts, the deterministic Kad mesh | `src/lib.rs` |
| `tools/rmule-tools` | tools | a protocol instrument that probes, captures and slices wire bytes, bypassing the core | `src/main.rs` |
| `tools/interop-harness` | tools | the opt-in live bench against real aMule and eD2k server processes | `README.md` |
| `tools/ed2ksrv-differ` | tools | a separate workspace: a second eD2k server's parser as a bug oracle for rmule's server-facing bytes | `src/main.rs` |

Only `rmule` and `rmule-cli` are released as binaries; no crate is published.

## Layers

```text
Front-ends           apps/rmule · apps/rmule-cli
                             |
Orchestration        crates/rmule-core ------------ crates/rmule-store
                             |         \
Networking           crates/rmule-net --- crates/rmule-os  (platform calls)
                             |
Protocol (sans-I/O)  rmule-ed2k · rmule-peer · rmule-kad · rmule-bootstrap
                             |
Wire values          crates/rmule-primitives
```

Dependencies point down only, and commands travel down while events travel up
([ADR-0011](../adr/0011-layered-command-event-stack.md)). A layer may use the
types of any layer below it, but each kind of I/O has one owner:

- **Sockets and timers** live in `rmule-net`. The one other network client is
  `rmule-bootstrap`'s HTTP fetcher, a feature that `rmule` turns on and the
  core leaves off.
- **Durable state** lives in `rmule-core`, through `rmule-store`, in one
  `rmule.redb` per data directory
  ([ADR-0083](../adr/0083-redb-typed-store.md)). Protocol crates never touch
  storage.
- **Operating-system calls std does not expose** live in `rmule-os`: the
  ICMP-reset switch `rmule-net` sets at each UDP bind, the sparse flag,
  punch and allocated size `rmule-core` uses on its part files
  ([ADR-0111](../adr/0111-sparse-part-file.md)), and the default app for a
  file-name extension that `rmule`'s Preview asks on macOS and Windows
  ([ADR-0114](../adr/0114-preview-action.md)). It holds the workspace's only
  `unsafe` code.
- **Process concerns** (arguments, the data directory, logging, drawing) live
  in the front-ends, which hold no durable state of their own
  ([ADR-0069](../adr/0069-thin-front-ends-over-the-core.md),
  [ADR-0076](../adr/0076-arguments-and-the-data-directory.md)).

Two front-end reach-pasts are admitted by name, and only these two:

- `rmule-cli kad join` drives `rmule_net::kad` directly. It is a manual live
  check against the public Kad network; routing it through the core would give
  the core a command whose purpose is to bypass the core's own policy.
- `rmule` acquires Kad seeds through `rmule_bootstrap`, because the
  acquisition needs an HTTP `Fetcher` and the core links no HTTP client
  ([ADR-0065](../adr/0065-bootstrap-http-acquisition.md)). The seed policy is
  still the core's `acquire_kad_seeds`; the front-end only supplies the fetcher.

## Wire values

`rmule-primitives` holds the values every other crate shares and the codecs
that read them: eD2k file and part hashes, AICH roots, eD2k links, client,
user and server identities, endpoints, tags and the frame codec
([ADR-0053](../adr/0053-frame-and-tag-codecs-in-rmule-primitives.md)), search
and source rows, obfuscation and SUI key material, and the sans-I/O session
spine the protocol sessions are built on
([ADR-0044](../adr/0044-shared-sans-io-session-spine.md)). It has no Tokio, no
clock and no filesystem
([ADR-0007](../adr/0007-runtime-free-protocol-crates.md)).

## Protocol crates

Each protocol crate is a sans-I/O state machine: bytes and commands in, events
and effects out. The whole protocol runs in unit tests over byte slices, with
time passed in by the caller
([ADR-0021](../adr/0021-sans-io-ed2k-session-with-connection-handle.md),
[ADR-0025](../adr/0025-reusable-fully-interleaved-peer-session.md),
[ADR-0043](../adr/0043-kad-full-node-for-source-discovery.md)). Codecs are
written by hand ([ADR-0006](../adr/0006-hand-written-byte-codecs.md)). Links
parse leniently; packets decode strictly, but unknown well-formed packets and
tags survive intact
([ADR-0008](../adr/0008-lenient-links-strict-packets.md),
[ADR-0018](../adr/0018-preserve-unknown-well-formed-packets.md)). Libraries
return typed errors; `anyhow` appears only at tool and CLI edges
([ADR-0010](../adr/0010-typed-library-errors-anyhow-at-edges.md)).

`rmule-bootstrap` runs the `server.met` and `nodes.dat` pipelines over a
`Fetcher` seam with aMule's default URLs, while the decoders live with their
domain types in `rmule-ed2k` and `rmule-kad`
([ADR-0065](../adr/0065-bootstrap-http-acquisition.md),
[ADR-0066](../adr/0066-server-met-and-nodes-dat-codecs.md)).

## Networking

`rmule-net` is the only crate that owns sockets and timers
([ADR-0081](../adr/0081-crate-topology.md)). One generic driver runs any
sans-I/O session; the `ed2k`, `peer` and `kad` modules layer the per-protocol
runtimes on top of it. The driver also owns the two concerns every transport
shares: wire capture
([ADR-0022](../adr/0022-capture-is-a-first-class-library-feature.md),
[ADR-0024](../adr/0024-peer-capture-defaults-to-protocol-only.md)) and the
obfuscation layer
([ADR-0042](../adr/0042-rc4-crypt-layer-below-the-packet-codec.md),
[ADR-0046](../adr/0046-per-datagram-udp-obfuscation-layer.md)). By default
every socket binds IPv4 and IPv6 at one port
([ADR-0085](../adr/0085-family-generic-peer-endpoints.md)). The port-mapping
clients and the NAT-traversal transports live here too, and the core decides
when to use them
([ADR-0086](../adr/0086-port-mapping.md),
[ADR-0091](../adr/0091-nat-traversal-emuleai-dialect.md)). On Windows, each
unconnected UDP socket passes once through `rmule-os` at bind time.

## Orchestration

`rmule-core` is the crate a front-end talks to: a `Core` actor, built with
`CoreBuilder`, that takes `CoreCommand`s and emits `CoreEvent`s. It owns:

- download scheduling across peers, block-level part assembly, and which peer
  owns which source
  ([ADR-0026](../adr/0026-core-owned-download-orchestration.md),
  [ADR-0029](../adr/0029-block-level-cross-peer-part-assembly.md),
  [ADR-0090](../adr/0090-source-ownership-inside-one-download.md));
- the upload queue and the serve side
  ([ADR-0031](../adr/0031-bidirectional-peer-session-and-inbound-listener.md));
- the one shared server session and its reconnects
  ([ADR-0032](../adr/0032-persistent-multiplexed-server-session.md),
  [ADR-0096](../adr/0096-lost-session-is-re-made.md));
- search across the server, server UDP and Kad
  ([ADR-0034](../adr/0034-core-owned-search.md));
- the managed server list
  ([ADR-0080](../adr/0080-managed-server-list.md));
- shared directories, the hash scan and the file watch
  ([ADR-0101](../adr/0101-shared-directories.md),
  [ADR-0102](../adr/0102-directory-scan-and-hash-trust.md),
  [ADR-0103](../adr/0103-directory-watch.md));
- the startup join and the Kad node
  ([ADR-0067](../adr/0067-core-owned-startup-join.md));
- every durable fact: identity, preferences, servers, downloads
  ([ADR-0048](../adr/0048-one-identity-per-node.md),
  [ADR-0094](../adr/0094-durable-download-state.md)).

Activities start, stop and retire under one lifecycle, and quitting stops each
of them in order ([ADR-0093](../adr/0093-activity-lifecycle.md)). Nothing
dials a server but the operator
([ADR-0095](../adr/0095-connecting-is-the-operators-act.md)).

## Front-ends

`apps/rmule` builds the `rmule` binary: a terminal UI with the core in the
same process behind a `CoreClient` seam. A bridge task drains the core's
events and polls its diagnostics once a second; the UI folds both into a pure
state that the views draw from
([ADR-0069](../adr/0069-thin-front-ends-over-the-core.md)). `apps/rmule-cli`
is its headless sibling. Both resolve the data directory by one rule in
`rmule-core` before anything touches it
([ADR-0076](../adr/0076-arguments-and-the-data-directory.md)).

## Diagnostics

Three channels, kept apart
([ADR-0027](../adr/0027-tracing-as-third-diagnostic-channel.md),
[ADR-0028](../adr/0028-worker-phase-diagnostics-snapshot.md)):

1. **Typed events**: `CoreEvent`, `Ed2kEvent`, `PeerEvent`, `KadEvent`, the
   domain facts consumers act on.
2. **Capture**: wire bytes recorded per session by the `rmule-net` driver.
3. **Diagnostic trace**: `tracing` spans and the worker-phase snapshot. In
   `rmule`, every `tracing` event lands in the Run Log, `rmule.log`
   ([ADR-0075](../adr/0075-run-log.md)).

Sans-I/O crates emit no traces, so replay tests stay deterministic; subscribers
are installed in the binaries only.

## Compatibility and evidence

aMule's behaviour is the compatibility truth, protocol references supply the
vocabulary, and fixtures are the final evidence
([ADR-0003](../adr/0003-amule-behaviour-is-compatibility-truth.md),
[ADR-0082](../adr/0082-emule-reference-source.md)). eMule and aMule source is
read, never ported
([ADR-0004](../adr/0004-gpl-3-or-later-and-no-ported-source.md),
[ADR-0013](../adr/0013-pinned-local-reference-cache.md)).

Tests come in two tiers. The deterministic tier runs in every CI build against
the in-process fakes of `rmule-testkit`
([ADR-0040](../adr/0040-deterministic-correctness-tier.md)). The live tier is
`tools/interop-harness`, which runs rmule against real aMule and eD2k server
processes on a local bench
([ADR-0033](../adr/0033-local-interop-harness-with-real-counterparties.md)).
Captured bytes become fixtures and golden vectors that the deterministic tier
replays ([`docs/protocol/fixtures.md`](../protocol/fixtures.md)). The parity
matrices in [`docs/protocol/parity/`](../protocol/parity/README.md) say, row by
row, how far each aMule behaviour is matched and on what evidence
([ADR-0045](../adr/0045-evidence-standard-per-parity-disposition.md)).

## Where to start reading

| To understand | Read |
| --- | --- |
| a wire value or a frame | `crates/rmule-primitives/src/lib.rs`, then `packet.rs` and `tag.rs` |
| a server login and search | `crates/rmule-ed2k/src/session.rs`, ADR-0021 |
| one peer conversation | `crates/rmule-peer/src/session.rs`, ADR-0025 |
| Kad | `crates/rmule-kad/src/node.rs`, ADR-0043 |
| how a download runs | `crates/rmule-core/src/download.rs` and `scheduler.rs`, ADR-0026, ADR-0029 |
| uploads | `crates/rmule-core/src/upload_queue.rs` and `serve.rs`, ADR-0031 |
| search | `crates/rmule-core/src/search.rs`, ADR-0034 |
| sockets | `crates/rmule-net/src/driver.rs`, ADR-0081 |
| what is stored | `crates/rmule-core/src/store.rs` and `crates/rmule-store`, ADR-0083 |
| the terminal client | `apps/rmule/src/main.rs`, then `app.rs` and `state.rs`, ADR-0069 |
| tests without a network | `crates/rmule-testkit/src/lib.rs`, ADR-0040 |

## Adding a crate

A crate is created when the work that needs it starts, never as an empty
placeholder: an empty crate makes a boundary look settled before there is
evidence for it. Every workspace member carries a `CONTEXT.md` and a row in
[`CONTEXT-MAP.md`](../../CONTEXT-MAP.md), and `scripts/guards.sh` checks both.
