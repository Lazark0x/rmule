# The **Reflector Probe**'s server half (`natprobe`, ADR-0092): a reflector on
# the fake-public WAN holding TWO addresses × TWO UDP ports, which is the exact
# shape RFC 5780's mapping and filtering discovery needs.
#
# Build:
#   docker build -t rmule/interop-natprobe:local tools/interop-harness/images/natprobe
#
# Two addresses, because Test II ("same mapping toward a different host?") and
# Test III ("…toward a different host AND port?") are what separate
# Endpoint-Independent from Address-Dependent from Address-and-Port-Dependent
# Mapping. Two ports, because the filtering tests ask the reflector to answer
# from a port the client never sent to.
#
# This is **Stimulus, never evidence** (ADR-0045): it proves the bench built the
# NAT it claimed, not that any counterparty did anything. It is mandatory in the
# same run for any negative NAT verdict.
#
# Not a STUN server. RFC 5780's *procedure* is reused; its wire format is not,
# because the harness would then have to vendor a STUN codec to read its own
# bench provenance. The line protocol is documented in README.md.
#
# `--cap-add NET_ADMIN` is required: the second fake-public address is added to
# the interface at start (one container, two addresses on one bridge — cheaper
# than a second network attachment, and it keeps both reflector addresses in the
# same `/24` the counterparties already accept).

FROM debian:trixie-slim
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        python3-minimal \
    && rm -rf /var/lib/apt/lists/*

COPY reflector.py /usr/local/bin/natprobe-reflector
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/natprobe-reflector /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
