# The **NAT Gateway** (`natgw`, ADR-0092): one container per client, sitting
# between that client's LAN bridge and the fake-public WAN, translating with a
# declared `NAT_TYPE`.
#
# Build:
#   docker build -t rmule/interop-natgw:local tools/interop-harness/images/natgw
#
# Debian trixie for one reason: nftables 1.1 with working dynamic sets, which is
# what the `restricted` type's Address-Dependent Filtering is built out of.
# conntrack-tools is the other half of the **NAT Type Proof** — the reply tuple
# in `conntrack -L` names the chosen external port directly, which is what
# distinguishes Endpoint-Independent from Address-and-Port-Dependent Mapping
# without any extra container.
#
# The container needs `--cap-add NET_ADMIN` and these sysctls at `run` time:
#   --sysctl net.ipv4.ip_forward=1
#   --sysctl net.ipv6.conf.all.forwarding=1
#   --sysctl net.netfilter.nf_conntrack_udp_timeout=180
# The last one is not tuning: the Linux default of 30 s violates RFC 4787 REQ-5
# ("a NAT UDP mapping timer MUST NOT expire in less than two minutes") by 4×, so
# a rendezvous→punch gap over 30 s would see the mapping gone and the flow would
# record a protocol failure that was really a bench artefact.
#
# `iptables` is deliberately absent: the whole simulator is one nft table, and a
# second firewall front-end in the image would make `nft list ruleset` an
# incomplete proof.

FROM debian:trixie-slim
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        conntrack \
        iproute2 \
        nftables \
    && rm -rf /var/lib/apt/lists/*

COPY natgw-proof.sh /usr/local/bin/natgw-proof
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/natgw-proof /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
