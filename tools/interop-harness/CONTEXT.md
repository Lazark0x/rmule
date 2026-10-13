# rmule-interop-harness

The opt-in local interoperability harness: a dev tool that stands real, unmodified
eMule-compatible processes up in containers, drives one exchange between them and
rmule, and writes down what actually happened. It proves nothing by assertion — its
output is either a counterparty's own bytes or a recorded absence of them. This is
the only place in the repo that talks about containers, images, and live topologies,
so its language is about *staging and observing*, never about protocol semantics
(those live in the protocol crates' glossaries and the global `CONTEXT.md`).

## Language

**Flow**:
One named end-to-end interop scenario — a topology, a drive sequence, and a verdict.
Each flow is exactly one `*Options` value plus one `run_*` entry point, reachable
from one CLI subcommand, and (for the acceptance-tier ones) known by a letter, A–N.
A flow owns its whole run: it builds images, creates the network, starts every
container, drives the exchange, collects logs, writes its verdict, and tears down.
_Avoid_: test, case, job, pipeline

**Scenario**:
The pre-glossary name for a Flow. It survives in exactly one place: the `scenario`
key of `resolved-config.toml` and of every verdict TOML, which names the Flow that
wrote the file. The key is kept because run-dir artifacts are a read contract (the
CLI and fake-docker suites assert on it); code, comments and docs say Flow. The
`AMULE_SCENARIO_MODE` image knob is an entrypoint contract of the same standing.
_Avoid_: scenario for anything but that key and that knob

**Counterparty**:
A real external process the harness stands up but does not author — a Lugdunum
eserver, a stock or patched aMule. Its bytes and its self-reported state are the only
things a flow may treat as evidence (ADR-0045). A counterparty is never mocked,
stubbed, or patched to make a flow pass; when it cannot be made to do the thing, the
flow records that instead.
_Avoid_: peer, fixture process, test double, mock

**Stimulus**:
rmule's own participation in a flow — the datagrams and dials it emits to provoke the
counterparty into answering. Stimulus is retained for context and is never evidence,
however correct it is. The Kad-specific form of this rule (**Kad Stimulus Node**,
**Core-Pumped Stimulus Node**) is defined in `crates/rmule-kad/CONTEXT.md`; the
harness is where those postures are actually staged.
_Avoid_: probe traffic (a *probe* is a specific read-only rmule-tools run), synthetic
packet, generated evidence

**Bench**:
The live Docker staging a flow runs on: the private network, the volumes, the
container names derived from the run dir, and the guards that tear all of it down.
"The bench" is the fabric; a flow is what is driven *on* it. Flows that need distinct
identities get distinct container IPs, never distinct ports — a Lugdunum eserver
assigns High ID per source address.
In code this is `flow::bench::Bench` (its names are `BenchNames`), one per run:
every container it starts is owned for teardown from the moment the runtime
returns, on every path that leaves the flow.
_Avoid_: environment, fixture, test rig, sandbox

**Run Dir**:
The retained, timestamped directory under `.scratch/interop-runs/` that is a flow's
entire output: the resolved config, the synthetic file, every container's collected
logs, the capture files, and the verdict. Nothing under it is ever auto-promoted into
`tests/fixtures/` — promotion is a deliberate, human act, which is what keeps a
promoted fixture's provenance readable.
_Avoid_: temp dir, output folder, workspace, artifact store

**Synthetic File**:
The deterministic payload a flow shares: bytes the harness generates from a seed, ED2K
-hashed into a link the counterparties are handed. Synthetic because no real
copyrighted content ever touches the bench, and deterministic so a byte-for-byte
completion check is a real assertion.
_Avoid_: test file, sample data, dummy payload

**Registrant**:
A container whose only job is to hold one fabricated High-ID identity and offer one
hash to the eserver, so a flow can stage more sources than it has real clients.
Registrants earn High ID by having distinct static IPs; a registrant lost to a hashing
race directly costs a source row in the capture that needed it.
_Avoid_: fake client, source stub, seeder

**Helper Node**:
An extra stock counterparty added purely to satisfy a *counterparty's own* gate — a
second agreeing reporter so aMule's extern-port probe can settle, open peers so its
firewall self-check can run a connect-back, a TCP-open witness for its autonomous
keyword publisher. A helper is never driven and never observed; it exists so the node
under observation will behave normally.
_Avoid_: filler, padding node, decoy

**Readiness Gate**:
A bounded poll on a signal the container itself emits — an aMule log line, rmule's
`files_announced` marker, `amulecmd Status` reporting Kad connected. Every wait in the
harness is a gate against a deadline; a blind sleep is never an acceptable substitute,
because a gate that times out surfaces the collected logs that explain why.
_Avoid_: sleep, delay, settle time, wait loop

**Tap**:
rmule's own datagram capture — the `datagrams.toml` rows plus the `datagrams.bin`
frames its runners write. The tap is how a flow reads what a counterparty sent
*rmule*, including obfuscated frames it can decrypt with its own derivations.
_Avoid_: log, trace, dump

**Capture Sidecar**:
A passive tcpdump container attached to another container's network namespace, writing
a pcap of everything that crosses it. Passive is load-bearing: the sidecar never
speaks, so its pcap holds only genuine traffic between the real participants.
One builder, `flow::bench::CaptureSidecar`, and one snaplen (`-s 0`, whole
packets), so wire-row counts are comparable across flows and a promoted frame is
byte-complete. A flow with more than one sidecar attached to different network
namespaces (e.g. flow M's rmule-netns tap and its counterparty-netns tap)
gives every **Wire Row** key a `_<role>_tap` suffix (`_rmule_tap`,
`_storer_tap`) naming which sidecar counted it — the same BPF run against two
namespaces counts two different things, and a bare key would leave that
tap-dependent meaning to guesswork. The suffix rides inside the verdict's
existing flat `key = value` TOML; it is not a second schema.
_Avoid_: proxy, interceptor, sniffer container

**Wire Row**:
One named opcode a verdict counts off a pcap, paired with the BPF expression that
finds it. Rows are counted individually so a verdict can be written from what is
absent as precisely as from what is present.
_Avoid_: metric, assertion, check

**Verdict**:
The TOML a flow writes into its run dir (and prints) recording what it observed, leg
by leg. `PASS` means the counterparty did the thing. `OBSERVED` is the honest partial:
the topology stood up and the counterparty engaged, but the target exchange did not
fire in-window. A verdict never reports a number it did not measure.
_Avoid_: result, report, assertion, status

**Documented Absence**:
A zero written down as an observation, with the reason it is zero — a timer that never
armed, a socket rmule does not bind, a relay no third party asked for. The claim carries
the measured count of the thing it names and holds only when that count is zero; a
non-zero count, or one the run never took, fails it. The alternative to a documented
absence is a fabricated row, which ADR-0045 forbids outright.
_Avoid_: skipped, N/A, expected failure, known issue

**Single-Oracle Row**:
A **Wire Row** whose counterparty bytes come from exactly one implementation (ADR-0045, 2026-09-16 amendment) — captured and flagged, never proven at parity; it upgrades on its own when a second pinned body produces the bytes.
_Avoid_: unverified, partial (that is a different scoring word)

**Rmule-Only Row**:
A **Wire Row** for which no external bytes can exist because both ends are rmule (the server-coordinated punch and Tunnel). Scored *exercised* — deterministic tier plus a bench observation behind a proven NAT — never *captured*; rmule never self-certifies.
_Avoid_: self-test, loopback row

**NAT Type Proof**:
What a flow behind a gateway container writes so its NAT claim is evidence, not configuration: the gateway's `nft` ruleset and `conntrack` dump (`-L` *and* `-S`, whose `insert_failed` names a mapping the kernel refused to commit — the one drop `-L` cannot show) in the **Run Dir**, plus a `nat-type.toml` row in RFC 4787 terms; a negative verdict additionally needs an RFC 5780 reflector probe from the same run. In `natgw-selfproof` the row carries two axes RFC 4787 has no names for beside it: the **Pinned-Port Sink** and the **Pinned-Pair Reach**. A punch failure without proof, the outbound conntrack entry and the counterparty's zero is a fabricated row. Every gateway flow judges the proof as well as recording it: `each-gateway-probed-as-its-claimed-nat-type` holds only when every gateway's `agrees` is true, and `natgw-selfproof` writes `FAIL` on a leg that fails an axis.

A topology whose bodies outlive their own punch — the buddy rendezvous flow, whose driver window can start minutes after the burst — takes this dump **twice**: an **in-flight** take, `<tag>-`-prefixed (`natgw-proof`'s optional third argument), triggered while the punch is still live and read while its `[UNREPLIED]` mappings are the claim's evidence; and the **teardown** take every gateway still writes untagged on its own exit, kept as a *second* artifact that now exists to show those same mappings gone — proof the timeout is real, not that the proof is late. A dump taken only at teardown, after a driver's own window has run past `nf_conntrack_udp_timeout` (180 s) and the `restricted` type's `@seen` set's own 3-minute timeout, reads both empty regardless of what the punch did — the failure mode this split exists to rule out.
_Avoid_: NAT config, topology note

**Smoke Verdict**:
`SMOKE` — the only verdict a run against the public network may write: `RMULE_BENCH`-gated, bytes summarised in the **Run Dir**, nothing promoted to a fixture. Defined and not implemented: no flow touches the public network, so none writes it (ADR-0092 as amended 2026-09-25).
_Avoid_: PASS (reserved for pinned counterparties), live capture

**Fork Pin**:
A **Counterparty** pinned to an exact commit on a third party's fork branch — SHA, fork owner and upstream base in the **Image Recipe**, body-specific fixture prefix, re-verified by rebuilding; downgraded to **Stimulus** if the commit can no longer be rebuilt. Admissible: the commit is real and rmule did not author it.
_Avoid_: unreleased build, patched counterparty (that is rmule-authored and inadmissible)

**NAT Gateway**:
The `natgw` container that sits between one client's LAN and the fake-public WAN and translates with a declared `NAT_TYPE` — port-restricted, restricted, full-cone-pinned (exact only for the pinned UDP port, and named so), or symmetric (ADR-0092). One per client; writes its **NAT Type Proof** on teardown. Its default-route change on the client is a **Bench Variant Env** knob.
_Avoid_: router (Docker's `.1` is also a router), NAT container

**Port-Mapping Gateway**:
The `miniupnpd` container that is both a **NAT Gateway** — the same plain
port-preserving SNAT `natgw`'s `port-restricted` branch renders, so it claims a NAT
type `natgw-selfproof` already proved — and the router rmule's own **Port Mapper** (ADR-0086)
talks to, answering UPnP-IGD2, NAT-PMP and PCP (ADR-0092). It is the
**Counterparty** of every port-mapping flow: its own two lease tables (IPv4 redirects and
IPv6 pinholes, different files in different formats) and its own log are the evidence,
and rmule's diagnostics are **Stimulus** read against them.
_Avoid_: UPnP server, router (Docker's `.1` is also a router)

**Reflector Probe**:
The `natprobe` container — two WAN addresses × two UDP ports — and the rmule-tools subcommand that runs RFC 5780's mapping and filtering tests against it, writing the observed behaviour beside the gateway's claim. **Stimulus**, never evidence; mandatory in the same run for any negative verdict.
_Avoid_: STUN server (no STUN wire), NAT detector

**Pinned-Port Sink**:
A third socket on the **Reflector Probe**'s primary address, at the gateway's *pinned* client port, and the one probe test that addresses it. RFC 5780's five tests only ever address the reflector's own two ports, so a gateway rule keyed on the pinned port is invisible to them — which is how an unscoped prerouting DNAT that ate every punch passed `natgw-selfproof` four times. Its result rides `nat-type.toml` as `pinned_port_reachable`, a **separate axis** from `agrees`: a gateway can translate exactly as it claims and still hairpin that one port.
_Avoid_: echo server, port check, folding it into the NAT type

**Pinned-Pair Reach**:
`natgw-selfproof`'s third axis: a **second NAT Gateway** of the same `NAT_TYPE`, with its own LAN and client, and the two clients aiming the pinned port at each other's WAN address (`rmule-tools nat peer-reach`). The **Pinned-Port Sink** answers from an *untranslated* host, so it cannot see the one thing a punch actually does — two gateways pinning the same port toward each other — and the `restricted` gateway's pinned-port drop lived in exactly that blind spot: an unsolicited opener the far gateway kept conntrack state for made the mapping its own client then needed unallocatable. The leg is **staggered on purpose** (one side opens while the other is silent) and expects a crossing on the three types that can and silence on `symmetric`; its `as_expected` is asserted harder than `agrees`, because a gateway that cannot pass a punch between two of its own kind is a bench no NAT-traversal flow can run on.
_Avoid_: punch test (no punch protocol here), ping check, folding it into `pinned_port_reachable`

**Low-ID Buddy Recipe**:
`natt-udp-selfcheck-amule`'s `--low-id-buddy` order of events for getting stock aMule 2.3.3 past its buddy-only publish gate. First, its gateway drops aMule's plaintext `0x60` so the UDP tester never learns its extern port and times out firewalled. Meanwhile an `ed2ksrv`, whose High-ID back-connect is dropped in its own netns, gives the rmule root a real Low ID. aMule recruits the root as its buddy, the drop is released, a helper's `0x62` reads the verdict open, and only then is the **Synthetic File** shared. Each step waits on the counterparty's own log line. The order is the point: 2.3.3 searches for a buddy only while both verdicts read firewalled, and keeps one past an open verdict only if its hello read Low-ID.
_Avoid_: firewall trick, delayed helpers (the helpers run from the start; only the ping is held)

**Fake-Public v6 Plan**:
The IPv6 twin of the fake-public `/24` plan: `3fff:<harness>:<net>::/64` subnets from RFC 9637's documentation block on an `--internal --ipv6` WAN — global-unicast-shaped, unroutable, absent from every counterparty's reject list, and *measured* accepted by `ipv6-net-accept` before any v6 flow trusts it.
_Avoid_: ULA (rejected by every client), documentation prefix `2001:db8` (rejected by emule-qt)

**Per-Attachment Tap**:
One **Capture Sidecar** per network a container is attached to, declared by the flow: the WAN tap yields evidence (counterparty bytes after translation), the LAN tap corroborates the **NAT Type Proof** (the same datagram before it).
_Avoid_: dual capture, mirror

**Bench Doctor**:
The capability gate run before any NAT or IPv6 flow: `nft`, `conntrack` sysctls, `br_netfilter`, daemon `ipv6` + `ip6tables`. A missing capability skips the dependent flows with a documented reason — never a silent pass.
_Avoid_: preflight, healthcheck (that is per-container readiness)

**Exemption**:
A flow that cannot reach its ideal observable because of a *documented counterparty
limitation*, and therefore asserts the strongest honest thing instead — the Low-ID
callback flow asserting rmule's callback capability because the Lugdunum eserver never
surfaces a Low-ID source at all (ADR-0040). An exemption names the limitation and the
tier where the full behavior is proven instead.
_Avoid_: workaround, known failure, soft assert

**Fake-Public Swarm**:
A Kad topology addressed from the RFC 5737 documentation ranges on an `internal`
Docker bridge, so a stock aMule does not classify its peers as LAN and therefore
admits them on its normal, non-LAN-mode paths. "Config A" in the topology doc. The
predecessor recipe — RFC1918 plus a patched `FilterLanIPs` — is retired from evidence
duty precisely because LAN mode falsifies the firewall self-check and the publish
tolerance zone.
_Avoid_: public Kad, real network, internet swarm

**Kad Mesh**:
The private Kad topology a Kad flow plans *before* it starts anything: every node's
identity, static IP, UDP port and bootstrap edges. Planning first is what makes a
seeded bootstrap deterministic, since a `nodes.dat` has to name peer addresses that do
not exist yet.
In code the mesh's names are `KadMeshNames` and its guard `KadResources`.
_Avoid_: cluster, network, DHT

**Settle Window**:
The one bounded wait a Kad flow sits *before* its stimulus fires, so the
counterparty's own timers have run: the publisher's `NODECOMPLETE`-gated source
publish (source lookup), the responder's HELLO-verification of its seeded contacts
(distance ordering). Clamped to `--timeout`; `RMULE_KAD_SETTLE_WINDOW_SECS`
overrides it (the fake-docker suite sets `0`). Not a Readiness Gate — nothing is
polled — and not a Tap window, which is observation after the stimulus.
_Avoid_: publish window, sleep, warm-up

**Run Record**:
The `run.toml` the harness itself writes into every Run Dir: when the run began and
ended, the commit and dirty state of the harness workspace, the hash of the `rmule-tools`
binary (or the id of the Driver Image) under test, the ids of the images the run started,
and how it ended. It is what lets "mine before running" tell an unchanged build from a
changed one; a re-score only appends `rescored_at`.
_Avoid_: run metadata, resolved config (that is the flow's options only)

**Driver Image**:
The `rmule-tools` image every UDP or in-network driver runs from. It is not compiled
by `docker build`: the binary comes from the shared target cache (the warm
host-persisted prebuild the Kad flows also run from), is staged beside the recipe, and
is `COPY`d into a thin runtime. An unchanged tree therefore rebuilds nothing, and the
Bench Doctor's own image is the only one built before a flow decides to skip.
_Avoid_: tools build, release compile

**Search Schedule**:
The bounded cadence of the requester's repeated Kad source searches (`Cancel` +
re-`Add`, four attempts, a 2 s gap inside each, 25 s between). Resolved once per run
and clamped so its total never exceeds `--timeout`;
`RMULE_KAD_SEARCH_CANCEL_GAP_SECS` and `RMULE_KAD_SEARCH_RETRY_INTERVAL_SECS`
override the two pauses (the fake-docker suite sets both `0`). Live runs keep the
defaults.
_Avoid_: retry loop, sleep

**Seeded Bootstrap**:
The harness-generated `preferencesKad.dat` (pinning a node's Kad ID) and `nodes.dat`
(naming its starting contacts) dropped into a container before it starts. Seeding is
configuration, not patching: it pins *who a node is and who it knows*, never how it
behaves.
_Avoid_: preload, injection, patch

**Golden-Author Flush**:
Shutting an aMule down cleanly so it writes its own `server.met` / `nodes.dat`, then
copying those out of the container into the run dir. The only trustworthy source of
those file formats is the client that authors them, so the flush exists to obtain
aMule-authored bytes rather than harness-authored lookalikes.
_Avoid_: export, dump, generate goldens

**Image Recipe**:
The checked-in Dockerfile, entrypoint and config templates under `images/` that build a
counterparty image, plus pinned upstream URLs and checksums. The repo commits recipes;
it never commits the downloaded server binaries, source archives, image layers, or run
artifacts they produce. The root `.dockerignore` keeps every build context to the repo
sources: `.scratch/`, the harness's own run root, is excluded as `**/.scratch` so the
pattern matches wherever the harness's cwd puts it, not only at the repo root (a
root-only `.scratch` pattern once let a `tools/interop-harness/.scratch/` run tree
ride into the context and break the `COPY` cache every build); `target/` (which holds
`target/bench-runs/`) stays a root-only pattern since only one `target/` exists. The
legacy (non-BuildKit) builder's image export also flakes on colima; `Bench::build_rmule_tools_image`
retries that one build exactly once on the failure class (`Docker::is_retriable_build_export_failure`).
_Avoid_: image, container build, docker config

**Bench Variant Env**:
The `AMULE_*` environment knobs an image entrypoint reads to select a counterparty
variant — crypt posture, forced Low ID, a firewalled port, a fresh identity, a queue
preference. Every knob must be a *legal user preference or a legal network condition*;
a knob that changed aMule's protocol behavior would make the capture worthless.
_Avoid_: test flag, override, patch, hack

**Bench Tier**:
The acceptance layer in `tests/harness/acceptance.rs`: thin `#[test]` wrappers
that drive a flow through its CLI subcommand and assert the run-dir artifacts. Every wrapper is
`#[ignore]`d *and* skips unless `RMULE_BENCH=1`, so a plain `cargo test` never reaches
for Docker. The wrappers hold no orchestration — the flows stay library functions.
`RMULE_BENCH_VERDICT_DIR=<run dir or verdict file>` skips driving the flow and
scores that already-driven run instead, a sub-second re-check.
_Avoid_: integration tests, e2e suite, smoke tests

**Fake Docker**:
A stub container runtime — a script the default test suite points `--container-runtime`
at — that records the argv it was handed and replays canned output. It is how the
harness's own orchestration is tested without a container runtime present. It proves
orchestration shape only; it can never stand in for a counterparty.
_Avoid_: mock docker, docker double, test runtime (it is the runtime, faked)

## Relationships

- A **Flow** is staged on a **Bench** (and, for Kad, a **Kad Mesh**), held by
  **Readiness Gates** until the **Counterparty** is genuinely up, observed through a
  **Tap** and/or a **Capture Sidecar**, and concluded in a **Verdict** written into the
  **Run Dir**.
- Evidence flows one way: counterparty bytes prove things, **Stimulus** never does. A
  flow that cannot draw the bytes it wanted writes a **Documented Absence**, or — when
  the cause is a known counterparty defect — an **Exemption**.
- The harness never patches a **Counterparty** to make a flow succeed. The two legal
  levers are a **Bench Variant Env** knob (a user preference or a network condition) and
  a **Seeded Bootstrap** (an identity and a contact list). A **Helper Node** is the
  topological lever for the same problem.
- Nothing under the **Run Dir** is a fixture. Promotion out of a run dir into
  `tests/fixtures/` is deliberate and human; a **Golden-Author Flush** exists so the
  bytes that get promoted were authored by the real client, not by the harness.
