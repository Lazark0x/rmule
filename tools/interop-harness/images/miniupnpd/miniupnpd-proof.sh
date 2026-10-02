#!/bin/sh
# The **NAT Type Proof** dump for the **Port-Mapping Gateway** (ADR-0045 as
# amended 2026-09-16, ADR-0092).
#
#   miniupnpd-proof [proof-dir]
#
# The same three files `natgw-proof` writes, under the same names, so a port-mapping
# verdict's proof directory reads exactly like a `natgw-selfproof` one — plus the two this
# gateway alone can produce:
#
#   nft-ruleset.txt   `nft list ruleset`. For this gateway that is BOTH halves:
#                     the entrypoint's SNAT *and* every rule miniupnpd added
#                     dynamically for a granted mapping. The DNAT rule naming a
#                     LAN address and port is the router's own statement that
#                     the mapping exists.
#   conntrack.txt     `conntrack -L`, as on `natgw`.
#   upnp6.leases      the IPv6 **pinhole** table (`lease_file6`). A PCP MAP
#                     over IPv6 is a firewall pinhole rather than a redirect, so
#                     it never appears in `upnp.leases`; a flow asserting a
#                     pinhole reads this one.
#   upnp.leases       miniupnpd's own lease table, in its own format
#                     (`proto:eport:iaddr:iport:timestamp:desc`). This is the
#                     gateway table a flow asserts against: it is written by the
#                     daemon, names the external port it chose, and survives the
#                     daemon's own restart.
#   miniupnpd.conf    the configuration the entrypoint generated, so a row can
#                     be read against the lifetime clamps that were in force.
set -u

PROOF_DIR="${1:-/proof}"
mkdir -p "$PROOF_DIR"

{
    printf '# miniupnpd gateway proof — taken=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    nft list ruleset 2>&1
} >"$PROOF_DIR/nft-ruleset.txt"

{
    printf '# conntrack -L\n'
    conntrack -L 2>&1
    printf '\n# conntrack -L -p udp\n'
    conntrack -L -p udp 2>&1
    printf '\n# nf_conntrack_udp_timeout\n'
    cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>&1
} >"$PROOF_DIR/conntrack.txt"

# The lease file is the daemon's, written as it grants; copy it under a stable
# name even when empty so an absence is recorded rather than missing.
if [ -f "$PROOF_DIR/upnp.leases" ]; then
    cp "$PROOF_DIR/upnp.leases" "$PROOF_DIR/gateway-table.txt"
else
    printf '# no lease file: miniupnpd granted nothing\n' >"$PROOF_DIR/gateway-table.txt"
fi
if [ -f "$PROOF_DIR/upnp6.leases" ]; then
    cp "$PROOF_DIR/upnp6.leases" "$PROOF_DIR/gateway-table6.txt"
else
    printf '# no v6 lease file: miniupnpd opened no pinhole\n' \
        >"$PROOF_DIR/gateway-table6.txt"
fi

echo "rmule-miniupnpd-proof-written dir=$PROOF_DIR"
