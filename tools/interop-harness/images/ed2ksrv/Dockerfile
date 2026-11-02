# Third-party eD2k index server `andrey23127/ed2k-server` (Rust, MIT) for the
# interop bench, rmule's first server counterparty. The pin of record is
# `pin.env`, audited at v0.9.87 (`97f97ff9`); this image is that audit's
# "bench-fit" recipe.
#
# Build context is the SERVER SOURCE TREE, not this directory (the source is not
# vendored into rmule). Build through `build.sh`, which verifies the clone sits
# clean at the pin of record in `pin.env` and labels the image with it:
#
#   tools/interop-harness/images/ed2ksrv/build.sh /path/to/ed2k-server
#
# A bare `docker build` of this file still works, but the image then carries no
# `org.rmule.ed2ksrv.commit` label and the harness refuses to start it unless
# the run sets RMULE_BENCH_ED2KSRV_OFF_PIN=1, which names the pin unverified.
#
# The image bakes the server's own upstream template, which the server refuses to
# start on while `server.name` and `server.this_ip` read CHANGE_ME: the image only
# runs with a config mounted. The bench bind-mounts `config.toml` from this
# directory over `/etc/ed2k-server/config.toml` (see README.md).
#
# Native-arch build: unlike the amule/eserver images this is not amd64-only,
# so no `--platform` and no qemu emulation.

FROM rust:1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder
WORKDIR /src
COPY . .
# `tikv-jemallocator` compiles jemalloc from C source; the rust bookworm image
# already carries gcc/make. `.cargo/config.toml` in the source tree bakes the
# jemalloc malloc_conf and leaves every `target-cpu` flag commented out, so the
# resulting binary is portable.
RUN cargo build --release

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1
# curl is for the admin API, which binds 127.0.0.1 ONLY (`web.rs:136,162`) —
# bench assertions run as `docker exec <container> curl -s 127.0.0.1:8080/api/...`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/ed2k-server /usr/local/bin/ed2k-server
COPY --from=builder /src/config/config.toml /etc/ed2k-server/config.toml
# tcp_port and the four derived UDP listeners: tcp+4 (main), tcp+8 (aux),
# tcp+12 (obf-ping / crypt-ping), tcp+14 (obfuscated datagram channel).
EXPOSE 4661/tcp 4665/udp 4669/udp 4673/udp 4675/udp
ENTRYPOINT ["/usr/local/bin/ed2k-server"]
CMD ["--config", "/etc/ed2k-server/config.toml"]
