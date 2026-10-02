# RUNTIME image for kno's aMule at its **Fork Pin** (ADR-0092). The binaries come
# from the image `Dockerfile.build` produces; this stage adds the runtime
# libraries, the harness entrypoint and the pin labels.
#
# Build context is the PARENT `images/` directory, with `-f` naming this file:
# the stock image's scenario entrypoint (`amule/entrypoint.sh`) is lifted from
# there verbatim, so the Seeded Bootstrap knobs exist once for both aMule
# bodies instead of drifting as two copies. The whole `images/` tree is a few
# hundred KB of recipes. Use `build.sh`, which runs both stages:
#
#   tools/interop-harness/images/amule-kno/build.sh [--quic]
#
#   Fork owner    kno
#   Branch        integration/network-parity
#   Commit        ab483654f3c975face368184912138513184e3f0  (2026-09-10)
#   Upstream base amule-org/amule @ 1cbc7c50f39e1e940d4dc0257169633f00a71435

ARG AMULE_KNO_BUILD_IMAGE=rmule/interop-amule-kno-build:local
FROM ${AMULE_KNO_BUILD_IMAGE} AS build

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
# amuled refuses non-ASCII paths without a UTF-8 locale.
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# The pin, on the image, so `docker inspect` can always name the source it was
# cut from. build.sh verifies these against the reference clone before building.
ARG AMULE_KNO_COMMIT=ab483654f3c975face368184912138513184e3f0
ARG AMULE_KNO_UPSTREAM_BASE=1cbc7c50f39e1e940d4dc0257169633f00a71435
ARG ENABLE_QUIC=NO
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# The compile stage is a separate image, not a stage of this one.
LABEL org.rmule.bench=1 \
      org.rmule.amule_kno.owner="kno" \
      org.rmule.amule_kno.branch="integration/network-parity" \
      org.rmule.amule_kno.commit="${AMULE_KNO_COMMIT}" \
      org.rmule.amule_kno.upstream_base="${AMULE_KNO_UPSTREAM_BASE}" \
      org.rmule.amule_kno.quic="${ENABLE_QUIC}" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

# No `/usr/share/amule`: that tree is the web UI's assets, and this recipe sets
# BUILD_WEBSERVER=NO — a bench body is driven over EC, never over amuleweb.
COPY --from=build /usr/bin/amulecmd /usr/bin/amuled /usr/bin/ed2k /usr/bin/

# iproute2 backs the LAN default-route knob; iptables is here for the same reason
# as in the stock aMule image (a firewalled variant must not need a rebuild).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcrypto++8t64 libreadline8t64 libgcc-s1 libstdc++6 libpng16-16t64 \
        libwxbase3.2-1t64 libglib2.0-0t64 libupnp17t64 libmaxminddb0 libatomic1 \
        libbinutils ca-certificates iproute2 iptables procps tzdata \
    && if [ "$ENABLE_QUIC" = "YES" ]; then \
        apt-get install -y --no-install-recommends \
            libngtcp2-16 libngtcp2-crypto-gnutls8 libgnutls30t64 ; \
    fi \
    && rm -rf /var/lib/apt/lists/* /usr/share/locale /usr/share/doc/* \
    # Fail the build, not a flow, if the runtime package set drifts from what the
    # binaries link against.
    && for bin in amulecmd amuled ed2k; do \
        if ldd "/usr/bin/$bin" | grep -q "not found"; then \
            echo "ERROR: missing shared libraries in $bin:"; ldd "/usr/bin/$bin"; exit 1; \
        fi; \
    done

COPY amule-kno/entrypoint.sh /entrypoint.sh
COPY amule/entrypoint.sh /usr/local/lib/rmule/amule-scenario.sh
RUN chmod +x /entrypoint.sh /usr/local/lib/rmule/amule-scenario.sh

EXPOSE 4662/tcp 4665/udp 4672/udp 4712/tcp

ENTRYPOINT ["/entrypoint.sh"]
