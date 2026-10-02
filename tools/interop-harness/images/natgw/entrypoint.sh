#!/bin/sh
# Harness entrypoint for the **NAT Gateway** (ADR-0092).
#
# Builds one of four nftables rulesets, named by `NAT_TYPE`, and then does
# nothing else — a gateway has no protocol behaviour to drive, it either
# translates the way it claims or it does not, and the **NAT Type Proof**
# (`natgw-proof`) is what settles which.
#
# The recipes, and the reasoning behind each:
#
#   port-restricted   EIM + APDF  plain port-preserving SNAT; conntrack is the
#                                 only return path. This is what netfilter and
#                                 Docker do with no rules at all.
#   restricted        EIM + ADF   port-pinned SNAT + a prerouting DNAT gated on
#                                 an nft dynamic set of the peer ADDRESSES the
#                                 client has sent to. conntrack alone cannot
#                                 express this: its reverse tuple is the full
#                                 5-tuple, so it can only ever do APDF.
#   full-cone-pinned  EIM + EIF   port-pinned SNAT + a DNAT of the one pinned
#                                 UDP port that admits any WAN source. Stateful
#                                 NAT has no general Endpoint-Independent
#                                 Filtering — a rule that admits any source for
#                                 a port IS a static port-forward — so this is
#                                 full cone *for that port* and is named so. A
#                                 flow may not claim a general full cone from
#                                 it. "Any source" means any source *arriving
#                                 on the WAN*: see `filter_rules` for why the
#                                 interface scope is load-bearing.
#   symmetric         APDM + APDF `snat … fully-random`: the kernel skips its
#                                 "reuse an existing mapping" step and draws a
#                                 fresh random port per connection.
#
# Address-Dependent Mapping ("hard" NAT) is absent on purpose: no netfilter mode
# keys a mapping on the destination address alone, so it cannot be built here
# and is not offered.
#
# All four also carry the shared `input` drop of `input_rules`: an unsolicited
# inbound UDP datagram must leave no conntrack state behind, or it poisons the
# very mapping the client is about to need. See that function for the two ways
# it broke the bench.
set -eu

NAT_TYPE="${NAT_TYPE:-port-restricted}"
WAN_IF="${NAT_WAN_IF:-eth0}"
LAN_IF="${NAT_LAN_IF:-eth1}"
# No apostrophe in the message: a lone `'` inside `${...:?...}` is a parse error
# in some `sh` implementations (bash 3.2 reads it as an unterminated quote), and
# this file is rendered by whatever shell a host happens to have.
LAN_CLIENT="${NAT_LAN_CLIENT:?NAT_LAN_CLIENT names the LAN address of the client and is required}"
CLIENT_PORT="${NAT_CLIENT_PORT:-4672}"
PUBLIC_PORT="${NAT_PUBLIC_PORT:-$CLIENT_PORT}"
PROOF_DIR="${NAT_PROOF_DIR:-/proof}"
# The LAN attachment is made with `docker network connect` AFTER `docker run`,
# so the interface does not exist yet when this starts. Gate on it rather than
# sleeping — a gate that times out says which interface never appeared.
LAN_WAIT_SECS="${NAT_LAN_WAIT_SECS:-60}"

PRINT_CONFIG=0
if [ "${1:-}" = "--print-config" ]; then
    PRINT_CONFIG=1
fi

wait_for_interface() {
    interface="$1"
    waited=0
    while [ "$waited" -lt "$LAN_WAIT_SECS" ]; do
        if ip -o link show "$interface" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "rmule-natgw-error: interface $interface never appeared within ${LAN_WAIT_SECS}s" >&2
    ip -o link show >&2
    return 1
}

# The gateway's own fake-public address. Read off the WAN interface rather than
# passed in, so the SNAT target cannot drift from what the bridge actually
# assigned — a mismatch there would translate to an address nobody answers.
wan_address() {
    ip -4 -o addr show dev "$WAN_IF" \
        | awk '{ split($4, parts, "/"); print parts[1]; exit }'
}

# `--sysctl` at container create is the primary path (see the Dockerfile header);
# these are the belt-and-braces re-assert for a runtime that dropped one. Failure
# is not fatal here: bench-doctor measures the values that actually took, and a
# silent partial apply would be worse than a loud one.
apply_sysctls() {
    for setting in \
        net.ipv4.ip_forward=1 \
        net.ipv6.conf.all.forwarding=1 \
        net.ipv4.conf.all.rp_filter=0 \
        net.ipv4.conf.default.rp_filter=0
    do
        sysctl -w "$setting" >/dev/null 2>&1 \
            || echo "rmule-natgw-warn: could not set $setting" >&2
    done
}

# The SNAT half, per type. `$1` is the gateway's WAN address.
snat_rules() {
    wan="$1"
    case "$NAT_TYPE" in
        symmetric)
            # A fresh random external port per (src, sport, dst, dport): the
            # kernel skips its find_appropriate_src() reuse step whenever
            # NF_NAT_RANGE_PROTO_RANDOM_ALL is set.
            printf '        oifname "%s" snat to %s fully-random\n' "$WAN_IF" "$wan"
            ;;
        restricted|full-cone-pinned)
            # Pin the client's own UDP port so the DNAT target below is static.
            # A single-port SNAT range is deterministic: the kernel early-returns
            # when min_proto == max_proto.
            printf '        oifname "%s" ip saddr %s udp sport %s snat to %s : %s\n' \
                "$WAN_IF" "$LAN_CLIENT" "$CLIENT_PORT" "$wan" "$PUBLIC_PORT"
            printf '        oifname "%s" snat to %s\n' "$WAN_IF" "$wan"
            ;;
        port-restricted)
            # No flags: port-preserving SNAT, which IS Endpoint-Independent
            # Mapping — the kernel reuses an existing mapping keyed on
            # (proto, saddr, sport) with the destination excluded from the key.
            printf '        oifname "%s" snat to %s\n' "$WAN_IF" "$wan"
            ;;
        *)
            echo "rmule-natgw-error: unknown NAT_TYPE '$NAT_TYPE'" >&2
            return 1
            ;;
    esac
}

# The filtering half, per type: the prerouting DNAT that admits an unsolicited
# inbound datagram, and (for ADF) the forward-hook recorder that decides which
# ones count. Empty for port-restricted and symmetric — there conntrack IS the
# filter, and its reverse tuple is the full 5-tuple, i.e. APDF by construction.
#
# **Every DNAT here is scoped `iifname "$WAN_IF"`, and that scope is the rule's
# meaning, not a refinement of it.** `prerouting` sees LAN-to-WAN traffic too,
# so an unscoped `udp dport $PUBLIC_PORT dnat to $LAN_CLIENT` also matches the
# client's OWN outbound datagrams whenever it addresses the pinned port — which
# is exactly what a punch and the uTP dial that follows it do. Those get their
# destination rewritten to the client itself and are routed straight back down
# the LAN, so nothing reaches the WAN and the peer's gateway never sees a
# packet. Measured that way in run `1790028867`: peer A's single
# `ST_SYN` left its socket, came back DNAT'd to its own address, and the WAN tap
# counted zero — the conntrack reply tuple read
# `src=10.77.0.3 dst=10.77.0.3`. The RFC 5780 reflector never caught it because
# the probe addresses the reflector's own ports, never the pinned one.
filter_rules() {
    case "$NAT_TYPE" in
        restricted)
            cat <<NFT

    chain record {
        type filter hook forward priority filter; policy accept;
        iifname "$LAN_IF" ip saddr $LAN_CLIENT udp sport $CLIENT_PORT update @seen { ip daddr }
    }

    chain pre {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "$WAN_IF" udp dport $PUBLIC_PORT ip saddr @seen dnat to $LAN_CLIENT : $CLIENT_PORT
    }
NFT
            ;;
        full-cone-pinned)
            cat <<NFT

    chain pre {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "$WAN_IF" udp dport $PUBLIC_PORT dnat to $LAN_CLIENT : $CLIENT_PORT
    }
NFT
            ;;
        *)
            ;;
    esac
}

# The rule every type carries: **an unsolicited inbound UDP datagram must leave
# no trace.** A NAT gateway hosts no UDP service of its own, so every datagram
# it legitimately handles is forwarded — either translated back onto an existing
# mapping, or DNAT'd by the rules above, both of which traverse `forward` and
# never `input`. A datagram that reaches `input` is by definition one no mapping
# claimed, and a real NAT discards it. Letting the local stack have it instead
# costs a conntrack entry, and that entry is a loaded gun:
#
#   Peer B opens toward us at the pinned port before our own client has sent to
#   B. Nothing DNATs it (on `restricted` B is not in @seen yet; on
#   `port-restricted` and `symmetric` there is no DNAT at all), so it is
#   delivered locally and `__nf_conntrack_confirm` commits an entry whose
#   ORIGINAL tuple is `B:4672 -> us:4672`. Moments later our own client sends to
#   B and needs a mapping whose REPLY tuple is that same `B:4672 -> us:4672`.
#   The two collide:
#
#     restricted / full-cone-pinned — the SNAT range is one pinned port, so the
#       kernel has nowhere else to go: the clash is fatal and the datagram is
#       dropped at confirmation. Measured on the bench at `conntrack -S`
#       `insert_failed=23 drop=23`, one per send, while the ±16
#       sweep ports — whose reply tuples differ — crossed untouched. That is
#       exactly the shape run `1790070327` recorded: 357 sweep datagrams off the
#       requester's WAN tap and not one aimed at 4672.
#     port-restricted — the SNAT range is the whole port space, so the kernel
#       quietly picks another: the mapping's reply tuple came back
#       `dport=50982`. No drop, no counter, and Endpoint-Independent Mapping —
#       the one behaviour this type exists to provide — is violated for exactly
#       the peer a punch is aimed at, so the far side's openers land on a port
#       nothing is mapped to.
#
# Hence the drop is generic and not a `restricted` patch: two of the four types
# are broken by it outright, by two different mechanisms, and `full-cone-pinned`
# escapes only because its unconditional DNAT happens to catch the pinned port
# before the local stack can. `symmetric` carries it for the model's sake — a
# gateway that answers datagrams addressed to itself is not the NAT it claims.
#
# `ct state new` rather than a blanket drop: a reply to the gateway's OWN
# outbound UDP (a resolver query, say) is `established` and must still arrive.
# Only the unsolicited half is discarded — and it is discarded in `filter input`
# at priority 0, which runs BEFORE conntrack confirmation at `LOCAL_IN`, so no
# entry is ever committed. A `raw prerouting notrack` would also work and is
# strictly worse: it would have to re-state the DNAT's own match to avoid
# untracking the traffic the gateway must translate.
input_rules() {
    cat <<NFT
    chain in {
        type filter hook input priority filter; policy accept;
        iifname "$WAN_IF" meta l4proto udp ct state new drop
    }
NFT
}

render_ruleset() {
    wan="$1"
    printf 'table ip natsim {\n'
    # The filtering-behaviour state. Address-keyed, so a hit means "the client
    # has sent something to this HOST", which is exactly Address-Dependent
    # Filtering; keying it on `ipv4_addr . inet_service` instead would collapse
    # it back to the APDF conntrack already gives.
    printf '    set seen {\n'
    printf '        type ipv4_addr\n'
    printf '        flags dynamic, timeout\n'
    printf '        timeout 3m\n'
    printf '        size 65536\n'
    printf '    }\n\n'
    input_rules
    filter_rules
    printf '\n    chain post {\n'
    printf '        type nat hook postrouting priority srcnat; policy accept;\n'
    snat_rules "$wan"
    printf '    }\n'
    printf '}\n'
}

if [ "$PRINT_CONFIG" -eq 1 ]; then
    render_ruleset "${NAT_WAN_ADDR:-0.0.0.0}"
    exit 0
fi

wait_for_interface "$WAN_IF"
wait_for_interface "$LAN_IF"
apply_sysctls

WAN_ADDR="${NAT_WAN_ADDR:-$(wan_address)}"
if [ -z "$WAN_ADDR" ]; then
    echo "rmule-natgw-error: no IPv4 address on $WAN_IF" >&2
    ip -o addr show >&2
    exit 1
fi

mkdir -p "$PROOF_DIR"
RULESET_FILE=/tmp/natsim.nft
render_ruleset "$WAN_ADDR" >"$RULESET_FILE"
nft -f "$RULESET_FILE"

# The dump is taken on demand (`docker exec <gw> natgw-proof`) because the
# harness tears containers down with `rm -f`, which is SIGKILL and runs no trap.
# The trap is still here for an operator's `docker stop`.
trap 'natgw-proof "$PROOF_DIR" "$NAT_TYPE"; exit 0' TERM INT

echo "rmule-natgw-ready nat_type=$NAT_TYPE wan=$WAN_ADDR lan_client=$LAN_CLIENT pinned_port=$PUBLIC_PORT"
nft list ruleset

# Idle in the foreground. `wait` is what lets the trap run promptly.
while true; do
    sleep 3600 &
    wait $!
done
