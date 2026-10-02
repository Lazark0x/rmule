#!/bin/sh
# The **NAT Type Proof** dump (ADR-0045 as amended 2026-09-16, ADR-0092).
#
#   natgw-proof [proof-dir] [nat-type] [tag]
#
# Writes the gateway's own provenance into the mounted proof directory, which is
# a **Run Dir** subdirectory on the host. `tag`, when given, prefixes every
# filename (`<tag>-nft-ruleset.txt`, ...) so a flow can take this dump more
# than once in a run and keep every take as a distinct artifact — an
# **in-flight** dump, still inside `nf_conntrack_udp_timeout` and the `@seen`
# set's own timeout, beside the untagged **teardown** one every caller already
# took, which now exists to prove the mappings this script caught in flight
# are gone by the time the driver exits. Omitted, filenames are
# exactly what every existing caller already reads.
#
#   nft-ruleset.txt   `nft list ruleset` — what was actually installed, not what
#                     the entrypoint meant to install.
#   nft-seen-set.txt  the `restricted` type's dynamic set, with the peer
#                     addresses the client really did send to. Empty for the
#                     other three types, which have no set to populate. Also
#                     the first thing to empty on its own 3-minute set
#                     timeout, which is why a late dump reads it empty too.
#   conntrack.txt     `conntrack -L` — the mappings themselves. Two entries from
#                     the same client sport to two destinations sharing ONE
#                     external port is Endpoint-Independent Mapping; two
#                     different external ports is Address-and-Port-Dependent.
#                     `[UNREPLIED]` is the honest record that a punch never
#                     landed, and is what separates "the mapping existed and
#                     nothing came back" from "the bench was misconfigured".
#                     `conntrack -S` rides in the same file for one counter,
#                     `insert_failed`: a mapping the kernel REFUSED to commit
#                     because some other entry already owns its reply tuple is
#                     invisible in `-L` — the datagram is dropped and nothing is
#                     listed — and that is exactly how a gateway drop once read
#                     as a product defect for a session. Non-zero on a gateway whose
#                     SNAT is pinned to one port, it names the cause outright.
#
# The claim in `nat-type.toml` is written by the flow, not here: a gateway
# asserting its own type would be configuration restating itself. This script
# only produces the bytes that claim has to survive.
set -u

PROOF_DIR="${1:-/proof}"
NAT_TYPE="${2:-${NAT_TYPE:-unknown}}"
TAG="${3:-}"
FILE_PREFIX="${TAG:+${TAG}-}"

mkdir -p "$PROOF_DIR"

{
    printf '# natgw proof — nat_type=%s tag=%s taken=%s\n' "$NAT_TYPE" "${TAG:-teardown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    nft list ruleset 2>&1
} >"$PROOF_DIR/${FILE_PREFIX}nft-ruleset.txt"

{
    printf '# nft list set ip natsim seen — nat_type=%s tag=%s\n' "$NAT_TYPE" "${TAG:-teardown}"
    nft list set ip natsim seen 2>&1
} >"$PROOF_DIR/${FILE_PREFIX}nft-seen-set.txt"

{
    printf '# conntrack -L — nat_type=%s tag=%s\n' "$NAT_TYPE" "${TAG:-teardown}"
    conntrack -L 2>&1
    printf '\n# conntrack -L -p udp\n'
    conntrack -L -p udp 2>&1
    printf '\n# conntrack -S\n'
    conntrack -S 2>&1
    printf '\n# nf_conntrack_udp_timeout\n'
    cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>&1
} >"$PROOF_DIR/${FILE_PREFIX}conntrack.txt"

echo "rmule-natgw-proof-written dir=$PROOF_DIR nat_type=$NAT_TYPE tag=${TAG:-teardown}"
