# aMule Interop Image

This directory contains the default local aMule/amuled image build context.

The image installs Ubuntu's `amule-daemon` and `amule-utils` packages and runs
`amuled` under external control via `amulecmd`. The entrypoint selects a scenario
mode with `AMULE_SCENARIO_MODE`.

`entrypoint.sh` is also the `amule-kno` image's scenario layer: that image builds
from the parent `images/` directory, copies this file in, and execs it whenever
`AMULE_SCENARIO_MODE` is set. Every mode and knob below therefore means
the same thing on kno's fork, and the script stays POSIX-portable across both
bases. `ed2k-server-kad` also takes `AMULE_KAD_PREFS_DAT`, the pinned Kad ID.

## Modes

### `AMULE_SCENARIO_MODE=ed2k-server` (default)

Original behavior. Requires `ED2K_SERVER_HOST`, connects `amuled` to the
harness-provided local eD2k server, and prints `rmule-amule-ready` after the
eD2k connection succeeds. Unchanged for existing interop scenarios.

### `AMULE_SCENARIO_MODE=kad-node`

Runs `amuled` as a **private** Kad node. Enables Kad (`ConnectToKad=1`),
disables eD2k (`ConnectToED2K=0`), and does **not** require `ED2K_SERVER_HOST`.

Roles via `AMULE_KAD_ROLE`:

- `publisher` — shares `AMULE_SHARED_DIR`, joins the private Kad nodes, and stays
  running long enough to advertise sources.
- `requester` — joins the private Kad nodes and waits idle for the harness to
  inject the synthetic ED2K link (after packet capture starts). Prints
  `rmule-kad-source-search-active` once a source lookup is in progress.
- `routing` — joins the private Kad nodes and stays available as routing
  evidence, without sharing or downloading the synthetic file.

Each role prints `rmule-kad-<role>-ready` after the private Kad network is
joined.

## Environment

- `AMULE_SCENARIO_MODE` — `ed2k-server` (default) or `kad-node`.
- `AMULE_TCP_PORT` — TCP port (default `4662`).
- `AMULE_UDP_PORT` — UDP/Kad port (default `4672`).
- `AMULE_EC_PORT` — external-control port (default `4712`).
- `AMULE_EC_PASSWORD` / `AMULE_EC_PASSWORD_MD5` — external-control password the
  harness uses to drive `amulecmd` (default `rmule`).
- `AMULE_KAD_ROLE` — `publisher` / `requester` / `routing` (kad-node mode).
- `AMULE_KAD_NODES_DAT` — path to a **harness-generated private** `nodes.dat`
  used as the only Kad bootstrap input.
- `ED2K_SERVER_HOST` / `ED2K_SERVER_PORT` — eD2k-server mode only.

## Private-only Kad rule

Kad mode never uses a public bootstrap URL or a public `nodes.dat`. The only
bootstrap input is a harness-generated private `nodes.dat` whose contacts are
all harness-owned containers. If private bootstrap cannot be made reliable, the
opt-in real-container smoke must fail with retained diagnostics rather than
falling back to public Kad.

## Debugging

`docker run --rm -e AMULE_SCENARIO_MODE=kad-node rmule/interop-amule:local --print-config`
prints the selected mode and key config values (`ConnectToKad=1`,
`ConnectToED2K=0`) and exits before starting `amuled`.

## Debug variant

The default image installs Ubuntu's `amule-daemon` package, which is a
**release** build: aMule compiles the loading of its debug categories
(`Preferences.cpp`) and `CLogger::IsEnabled` itself (`Logger.h`) out under
`#ifdef __DEBUG__`, so `AMULE_KAD_VERBOSE=1` cannot unlock a single `logKad*`
line — a Kad publish (or anything else) that never fired is indistinguishable
on that log from one fired off-tap.

```bash
docker build --build-arg AMULE_DEBUG=1 \
  -t rmule/interop-amule-debug:local \
  tools/interop-harness/images/amule
```

builds `amuled`/`amulecmd` from source instead — the **exact same Debian
source package** the release build installs (`apt-get source amule-daemon`,
pinned by `AMULE_SRC_VERSION`; the pristine upstream tree
`amule-project/amule`'s `2.3.3` tag / commit
`4e8f2b3c3f90cda23765730546b04c684a92e4f5` resolves to, plus Debian's own
small, non-protocol build patches), with `debian/rules`' own `confflags`, ONE
flag flipped: `--disable-debug` -> `--enable-debug` (`acinclude.m4`:
`MULE_ARG_ENABLE([debug], [yes], ...)` — enabled is upstream's own default;
Debian's packaging is what turns it off). Same source, same packaging, the
one bit the packager disables. The default build (`AMULE_DEBUG=0`, unset) is
byte-for-byte unchanged; the debug variant is only produced when a caller
opts in with the build arg and a distinct image tag.

(A raw `git clone` of the tag and a CMake build were both tried and rejected:
the git checkout ships no pre-generated `configure` and Ubuntu 24.04's
Autoconf 2.71 is explicitly refused by `configure.ac` — the packaged source's
`configure` is already 2.69-generated; aMule's CMake `cmake/wx.cmake`
unconditionally links a `wxWidgets::CORE` target a GUI-less build never
creates, a genuine upstream defect in the daemon-only CMake path.)

`AMULE_KAD_VERBOSE=1` is unchanged, but on this image it now does what it
always promised: the entrypoint's `enable_kad_debug_categories` writes the
`/Debug/Cat_*` keys `CLogger::IsEnabled` ANDs with the global `VerboseDebug`
flag (`Logger.cpp`) — `VerboseDebug` alone is not sufficient — so the lifted
`logfile` (`flow::logs::collect_amule_logfile`) carries a genuine `logKad*`
trail: `Kademlia Search`, `Kademlia Routing`, `Kademlia Indexing`, `Kademlia
Main Thread`, `Kademlia Preferences`, `Client Kademlia UDP`, `Kademlia UDP
Firewall Tester`, `Kademlia Packet Tracking`, `Kademlia Entry Tracking` — the
full `g_debugcats` set of Kad-named categories (`Logger.cpp`). There is no
separate `logKadPublish` category; `CSharedFileList::Publish`'s gates are
reasoned about under `logKadSearch` (the `NODECOMPLETE` self-lookup that
flips `Kademlia::CKademlia::GetPublish()`) and `logKadPrefs` (the
external-port / firewall verdicts feeding it).

`AMULE_DEBUG_PEER_CATEGORIES=1` adds the peer-TCP trail on top:
`ED2k Client`, `Local Client Protocol`, `Remote Client Protocol` and `Packet
Parsing Errors` — the categories a buddy relay (`Local Client: OP_CALLBACK
to`), a relayed callback (`Remote Client: OP_CALLBACK from`) and a refused
packet (`caused an error (…). Disconnecting client!`) write under. Flow M's
`--callback-downloader` sets it. In the download scenario (flow C, `--amule-env
AMULE_DEBUG_PEER_CATEGORIES=1`) it also unlocks those categories without
`AMULE_KAD_VERBOSE`. On completion it prints the logfile's SUI trail
(`OP_SECIDENTSTATE`/`OP_PUBLICKEY`/`OP_SIGNATURE` and aMule's `has passed` /
`has failed the secure identification` verdict) as `rmule-amule-sui:` lines
before the completion marker, since amuled's own stdout is cut when the script
exits.

`AMULE_DEBUG_SOURCE_CATEGORIES=1` adds `DownloadQueue`, `PartFiles` and `Asio
Sockets` to that set, and implies the peer set. These are the categories that
show a source's fate: a sources request going out, a server source attached to
a client already known, and the socket layer seeing a peer's close
(`HandleReadError nothing available` / `LibSocketLost`). `peer-hello-surface`
sets it on its stock aMule body. Asio writes a line per read, so
the knob is off by default. It is an entrypoint change only: a debug image
built before it gains the knob from a thin rebuild over the old binary
(`FROM rmule/interop-amule-debug:local`, `COPY entrypoint.sh`), with no
recompile.

Drive a flow against it with the harness's generic image-override flags —
no new CLI flag exists or is needed, since the debug variant is a different
build of the SAME Dockerfile, selected by a build arg and named by its own
tag:

```bash
docker build --build-arg AMULE_DEBUG=1 \
  -t rmule/interop-amule-debug:local \
  tools/interop-harness/images/amule

cargo run -p rmule-interop-harness -- \
  kad-core-buddy --publish-source --mesh-members 3 --window 1500 \
  --amule-image rmule/interop-amule-debug:local \
  --amule-build-context tools/interop-harness/images/amule \
  --skip-build
```

`--skip-build` is load-bearing: the harness's own `docker build` for a flow's
images does **not** pass `--build-arg AMULE_DEBUG=1` (the harness has no
opinion on build args), so `--build-images` with `--amule-image` pointed at
the debug tag would silently rebuild it as a plain release image UNDER the
debug tag — the debug image must be built by hand first, as above, and the
flow told to reuse it.
