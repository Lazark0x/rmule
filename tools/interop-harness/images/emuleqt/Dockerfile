# Runtime image for the Stimulus Counterparty (ADR-0082): emule-qt's headless
# `emulecored`, pinned at `73fff7146d2eec3e8426251ec4959238bae3479a`.
#
# Build context is THIS directory; the compiled binary comes from the image that
# `Dockerfile.build` produces. Use `build.sh`, which verifies the pin and runs
# both stages:
#
#   tools/interop-harness/images/emuleqt/build.sh
#
# or, by hand, from the repo root:
#
#   docker build -t rmule/interop-emuleqt-build:local \
#     -f tools/interop-harness/images/emuleqt/Dockerfile.build \
#     docs/reference/emule-qt/emule-qt
#   docker build -t rmule/interop-emuleqt:local \
#     tools/interop-harness/images/emuleqt
#
# Why two builds: the entrypoint is version-controlled here and the source is a
# gitignored cache over there, and a plain `docker build` (the legacy builder
# the harness invokes) sees exactly one context.

ARG EMULEQT_BUILD_IMAGE=rmule/interop-emuleqt-build:local
FROM ${EMULEQT_BUILD_IMAGE} AS build

FROM debian:trixie-slim
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

ENV DEBIAN_FRONTEND=noninteractive
# Qt refuses a non-UTF-8 locale and prints a warning on every start otherwise.
ENV LANG=C.UTF-8
ENV HOME=/root

# Exactly the packages owning the binary's DT_NEEDED set; apt pulls the
# transitive rest. Derived from the build image rather than guessed:
#
#   objdump -p .../emulecored | awk '/NEEDED/{print $2}'
#
# then each resolved .so mapped through `dpkg -S`. Worth re-deriving after a pin
# bump — the `t64` suffixes are from Debian's 64-bit-time_t transition and are
# NOT uniform, which is a real trap: libqt6core6t64 carries it, libqt6network6
# and libqt6gui6 do not.
#
# Qt Gui is required even though this is a headless daemon: the core library
# links it, so a Core+Network-only runtime will not start.
#
# miniupnpc is absent on purpose — the top-level CMakeLists links it statically.
# `iptables` is here for the same reason as in the aMule image: a firewalled
# variant (drop inbound on the peer port) needs it, and installing it later would
# mean a rebuild mid-scenario.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        libarchive13t64 \
        libqt6core6t64 \
        libqt6gui6 \
        libqt6httpserver6 \
        libqt6multimedia6 \
        libqt6network6 \
        libssl3t64 \
        libyaml-cpp0.8 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/src/daemon/emulecored /usr/local/bin/emulecored

# Fail the build, not a scenario, if the runtime package set drifts away from
# what the binary links against.
RUN ldd /usr/local/bin/emulecored | grep 'not found' && exit 1 || true
RUN emulecored --version

# NOT copied: the upstream `data/config` bundle. It carries a server.met of
# PUBLIC eD2k servers and a public nodes.dat, and a bench counterparty must
# never have either within reach. (On a Release Linux build
# AppConfig::seedBundledData finds no bundle directory and seeds nothing, so
# leaving it out is belt and braces.) The entrypoint writes the single-server
# server.met the bench actually wants.

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 4662/tcp + 4672/udp are the peer ports; 4712 is the IPC control port the CLI
# verbs talk to, bound to loopback so it is reachable via `docker exec` only.
EXPOSE 4662/tcp 4672/udp

ENTRYPOINT ["/entrypoint.sh"]
