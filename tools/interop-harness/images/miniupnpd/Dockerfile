# The **Port-Mapping Gateway** (`miniupnpd`, ADR-0092): a NAT gateway that
# also *speaks* the three protocols rmule's **Port Mapper** races — UPnP-IGD2,
# NAT-PMP and PCP — so the mapper can be driven against a real router instead of
# a scripted backend.
#
# Build:
#   docker build -t rmule/interop-miniupnpd:local tools/interop-harness/images/miniupnpd
#
# ## Pin
#
# `alpine:edge` + `miniupnpd-nftables=2.3.10-r0`, pinned by exact package
# version: 2.3.10 is the release ADR-0092 names and Alpine 3.22 carries only
# 2.3.7. The `=2.3.10-r0` is load-bearing — edge moves, and an unpinned `apk add`
# would silently re-base the gateway a captured row was taken against. A build
# that fails here is edge having moved on, which is a pin to bump deliberately.
#
# ## Why the nftables flavour
#
# Alpine ships two builds: the default `miniupnpd` links `libip4tc`/`libip6tc`
# (the iptables backend) and `miniupnpd-nftables` links `libnftnl`. The whole
# bench's **NAT Type Proof** is `nft list ruleset` (see the `natgw` image
# header), and a gateway whose forwarding lived half in iptables would make that
# dump an incomplete proof — so this image carries nftables only, exactly like
# `natgw`, and miniupnpd's own dynamically-added rules land in the same ruleset
# the proof captures.
#
# The package's `nft_init.sh` creates the chains miniupnpd updates
# (`filter/miniupnpd`, `filter/prerouting_miniupnpd`,
# `filter/postrouting_miniupnpd`); the entrypoint runs it before the daemon and
# adds the plain SNAT that makes this a `port-restricted` NAT in RFC 4787 terms.
#
# ## What the build already carries
#
# `miniupnpd -h` on this package advertises `-N` (NAT-PMP **and** PCP), `-1`
# ("force reporting IGDv1 *use with care*" — so IGD2 is the default, i.e. built
# `--igd2`) and `-4` ("disable IPv6" — so IPv6 is compiled in, i.e. built
# `--ipv6`). ADR-0092's `--ipv6 --igd2 enable_pcp_pmp=yes` gateway is therefore
# this package with `-N` and neither `-1` nor `-4`.
#
# Run-time requirements: `--cap-add NET_ADMIN` and
#   --sysctl net.ipv4.ip_forward=1
#   --sysctl net.ipv6.conf.all.forwarding=1
#   --sysctl net.netfilter.nf_conntrack_udp_timeout=180
# (the last for the same RFC 4787 REQ-5 reason the `natgw` image documents).

FROM alpine:edge
# `org.rmule.bench=1` scopes the bench-image cleanup to harness images
# Every harness final stage carries it.
LABEL org.rmule.bench=1

RUN apk add --no-cache \
        conntrack-tools \
        iproute2 \
        miniupnpc=2.3.3-r2 \
        miniupnpd-nftables=2.3.10-r0 \
        nftables

COPY miniupnpd-proof.sh /usr/local/bin/miniupnpd-proof
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/miniupnpd-proof /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
