# rmule Kad node image for the kad-join interop scenario (ADR-0043).
#
# Build context is the REPO ROOT (the workspace sources are needed):
#   docker build -f tools/interop-harness/images/rmule-node/Dockerfile -t rmule/interop-rmule-node:local .
#
# No BuildKit cache mounts: the harness invokes the plain `docker build`, and
# colima's engine defaults to the legacy builder. That builder commits every
# stage as its own image, and only the final stage below gets `-t`, so the
# `build` stage is dangling the instant this succeeds. `org.rmule.bench.stage`
# marks it for the label- and dangling-scoped `docker image prune` that
# `main()` runs after every harness subcommand. The stimulus
# runner is the `rmule-tools kad join-node` subcommand (the former standalone
# kad-join-node binary, absorbed per ADR-0081), so this image builds the full
# rmule-tools stack; the entrypoint pins the subcommand, and the scenarios'
# bare `--flag` arguments append after it unchanged.

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
# iproute2 backs the LAN default-route knob the entrypoint applies (ADR-0092).
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /rmule-tools /usr/bin/rmule-tools
COPY tools/interop-harness/images/rmule-node/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
