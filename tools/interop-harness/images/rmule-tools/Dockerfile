# `rmule-tools` inside the bench network — the **UDP** driver image.
#
# Build context is the REPO ROOT (the workspace sources are needed):
#   docker build -f tools/interop-harness/images/rmule-tools/Dockerfile \
#     -t rmule/interop-rmule-tools:local .
#
# ## Why this image has to exist
#
# On macOS + colima the docker engine lives in a Linux VM and published ports
# reach the host through an **SSH forward, which carries TCP only**. A published
# `-p 127.0.0.1:14665:4665/udp` therefore silently swallows every datagram: the
# host's `sendto` succeeds, the container's listener never wakes. Verified
# directly (a `socat -u UDP4-RECV` in the bench network received 0 bytes from a
# host `nc -u`), so any server-UDP capture — status `0x96`/`0x97`, desc
# `0xA2`/`0xA3`, global search `0x98`/`0x99`, the crypt-ping on TCP+12 — must be
# driven from a process that is *itself* on the bench network. TCP-only rows
# (login, `0x1C`/`0x35`/`0x36`) do not need this image; a host binary reaching a
# published TCP port works fine for those.
#
# Bridging UDP over the TCP forward with socat was rejected on purpose: a TCP
# hop does not preserve datagram boundaries, so two `0x99` replies could arrive
# coalesced and a fixture would then hold bytes no counterparty ever sent as one
# datagram. Evidence integrity (ADR-0045 point 2) outranks the convenience.
#
# Running the driver in-network is also what earns a **fake-public source
# address**: the container gets a real `203.0.113.0/24` IP, so the server's
# `is_routable` check and its High-ID back-connect probe both see a genuine
# routable peer rather than the bridge gateway.
#
# No BuildKit cache mounts — the harness invokes the plain `docker build` and
# colima's engine defaults to the legacy builder. That builder commits every
# stage as its own image, and only the final stage below gets `-t`, so the
# `build` stage is dangling the instant this succeeds. `org.rmule.bench.stage`
# marks it for the label- and dangling-scoped `docker image prune` that
# `main()` runs after every harness subcommand — never a manual
# step, and never touching an image on the host without this label.

FROM rust:1-bookworm AS build
LABEL org.rmule.bench.stage=1
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tools ./tools
COPY apps ./apps
RUN cargo build --release -p rmule-tools \
    && cp target/release/rmule-tools /rmule-tools

FROM debian:bookworm-slim
LABEL org.rmule.bench=1
# iproute2 backs the LAN default-route knob the entrypoint applies (ADR-0092):
# a driver on a NAT gateway's LAN has no egress until its default route points
# at the gateway.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /rmule-tools /usr/bin/rmule-tools
COPY tools/interop-harness/images/rmule-tools/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
