#!/bin/sh
# Harness entrypoint for the **Port-Mapping Gateway** (ADR-0092).
#
# Two jobs, in order, because the second depends on the first:
#
#  1. **Be a NAT.** A plain port-preserving SNAT of the LAN out of the WAN
#     interface — Endpoint-Independent Mapping + Address-and-Port-Dependent
#     Filtering, i.e. the `port-restricted` type in the `natgw` image's
#     vocabulary and what netfilter does with no flags. The flow claims exactly
#     that and the **Reflector Probe** checks the claim, so this recipe is
#     deliberately the same one `natgw`'s `port-restricted` branch renders.
#  2. **Speak the three protocols.** miniupnpd with `-N` (NAT-PMP + PCP), IGD2
#     (no `-1`) and IPv6 (no `-4`), listening on the LAN interface only — a
#     gateway that answered SSDP on its WAN would let a counterparty on the
#     fake-public bridge map ports it does not own.
#
# The knobs:
#
#   MINIUPNPD_LAN_ADDR   this gateway's own LAN address. When set, the LAN and
#                        WAN interfaces are resolved from the ADDRESSES rather
#                        than assumed to be `eth1` and `eth0`. Docker does not
#                        promise a stable interface order for a multi-homed
#                        container — a restart can swap the two — and miniupnpd
#                        refuses to start at all when it resolves its
#                        `listening_ip` to the public side ("LAN address
#                        contains public IP address"). Measured here.
#   MINIUPNPD_WAN_IF     WAN interface, when not resolved from an address
#                        (default `eth0`)
#   MINIUPNPD_LAN_IF     LAN interface, when not resolved (default `eth1`)
#   MINIUPNPD_LAN_CIDR   the LAN the `allow` rule admits (default 10.77.0.0/24)
#   MINIUPNPD_MIN_LIFETIME / _MAX_LIFETIME
#                        the PCP lifetime clamps. The default `min_lifetime` is
#                        120 s, which would silently turn a flow's deliberately
#                        short lease into a two-minute one and make the renewal
#                        it is trying to observe fall outside the window — so the
#                        harness lowers it and the value is recorded in the conf
#                        this writes into the proof dir.
#   MINIUPNPD_SECURE_MODE  `yes` (default) refuses a mapping requested *for*
#                        another host; `no` passes `-S0`.
#   MINIUPNPD_EXTRA_ARGS extra argv for the daemon.
#   NAT_PROOF_DIR        where `miniupnpd-proof` writes (default `/proof`).
#
# Like `natgw`, the dump is taken on demand by `docker exec` (the harness tears
# containers down with `rm -f`, which is SIGKILL and runs no trap).
set -eu

WAN_IF="${MINIUPNPD_WAN_IF:-eth0}"
LAN_IF="${MINIUPNPD_LAN_IF:-eth1}"
LAN_CIDR="${MINIUPNPD_LAN_CIDR:-10.77.0.0/24}"
PROOF_DIR="${NAT_PROOF_DIR:-/proof}"
MIN_LIFETIME="${MINIUPNPD_MIN_LIFETIME:-4}"
MAX_LIFETIME="${MINIUPNPD_MAX_LIFETIME:-86400}"
SECURE_MODE="${MINIUPNPD_SECURE_MODE:-yes}"
LAN_WAIT_SECS="${MINIUPNPD_LAN_WAIT_SECS:-60}"
CONF=/etc/miniupnpd/miniupnpd.conf

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
    echo "rmule-miniupnpd-error: interface $interface never appeared within ${LAN_WAIT_SECS}s" >&2
    ip -o link show >&2
    return 1
}

# The interface holding `$1`, or empty. The LAN attachment is made with
# `docker network connect` after `docker run`, so this is also the gate: the
# address exists exactly when the attachment is complete.
interface_for_address() {
    ip -4 -o addr show \
        | awk -v want="$1" '{ split($4, parts, "/"); if (parts[1] == want) { print $2; exit } }'
}

wait_for_address() {
    want="$1"
    waited=0
    while [ "$waited" -lt "$LAN_WAIT_SECS" ]; do
        found=$(interface_for_address "$want")
        if [ -n "$found" ]; then
            echo "$found"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "rmule-miniupnpd-error: no interface holds $want within ${LAN_WAIT_SECS}s" >&2
    ip -4 -o addr show >&2
    return 1
}

# Read off the interface rather than passed in, for the same reason `natgw`
# does: a SNAT target that drifted from what the bridge assigned would translate
# to an address nobody answers.
wan_address() {
    ip -4 -o addr show dev "$WAN_IF" \
        | awk '{ split($4, parts, "/"); print parts[1]; exit }'
}

apply_sysctls() {
    for setting in \
        net.ipv4.ip_forward=1 \
        net.ipv6.conf.all.forwarding=1 \
        net.ipv4.conf.all.rp_filter=0 \
        net.ipv4.conf.default.rp_filter=0
    do
        sysctl -w "$setting" >/dev/null 2>&1 \
            || echo "rmule-miniupnpd-warn: could not set $setting" >&2
    done
}

# Resolve the two sides from their addresses when the harness named the LAN
# one: an interface-order assumption is what makes a restarted gateway listen
# on its public side and refuse to start.
if [ -n "${MINIUPNPD_LAN_ADDR:-}" ]; then
    LAN_IF=$(wait_for_address "$MINIUPNPD_LAN_ADDR")
    if [ -n "${NAT_WAN_ADDR:-}" ]; then
        WAN_IF=$(wait_for_address "$NAT_WAN_ADDR")
    else
        WAN_IF=$(ip -4 -o addr show \
            | awk -v lan="$LAN_IF" '$2 != "lo" && $2 != lan { print $2; exit }')
    fi
    if [ -z "$WAN_IF" ]; then
        echo "rmule-miniupnpd-error: no WAN interface beside $LAN_IF" >&2
        ip -4 -o addr show >&2
        exit 1
    fi
else
    wait_for_interface "$WAN_IF"
    wait_for_interface "$LAN_IF"
fi
apply_sysctls
mkdir -p "$PROOF_DIR"

WAN_ADDR="${NAT_WAN_ADDR:-$(wan_address)}"
if [ -z "$WAN_ADDR" ]; then
    echo "rmule-miniupnpd-error: no IPv4 address on $WAN_IF" >&2
    ip -o addr show >&2
    exit 1
fi

# (1) The NAT itself. `snat to <wan>` with no flags is port-preserving, which IS
# Endpoint-Independent Mapping: the kernel reuses a mapping keyed on
# (proto, saddr, sport) with the destination excluded. conntrack is then the
# only return path, i.e. Address-and-Port-Dependent Filtering.
#
# `chain in` is `natgw`'s own rule, and for its reason (spelled out in images/natgw/entrypoint.sh):
# an unsolicited WAN datagram the gateway
# delivers locally commits a conntrack entry whose original tuple can collide
# with the reply tuple a LAN client's later mapping needs, and on a
# port-preserving SNAT the kernel then silently remaps that client — breaking
# the Endpoint-Independent Mapping this recipe claims. Only WAN-side input is
# dropped: miniupnpd listens on the LAN, and a DNAT'd forward never reaches
# `input`.
nft -f - <<NFT
table ip natsim {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IF" ip saddr $LAN_CIDR snat to $WAN_ADDR
    }
    chain in {
        type filter hook input priority filter; policy accept;
        iifname "$WAN_IF" meta l4proto udp ct state new drop
    }
}
NFT

# (2) miniupnpd's own chains. `nft_init.sh` creates `inet filter` with a
# forward chain whose policy is DROP and a `jump miniupnpd` at its head — the
# pinhole table. Everything else the gateway must still forward has to be
# spelled out, so the two accepts below are appended *after* that jump: the
# conntrack return path, and the LAN's own egress.
sh /etc/miniupnpd/nft_init.sh
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward iifname "$LAN_IF" oifname "$WAN_IF" accept

UUID="${MINIUPNPD_UUID:-$(uuidgen)}"
{
    printf '# written by the rmule harness entrypoint (ADR-0092)\n'
    printf 'ext_ifname=%s\n' "$WAN_IF"
    printf 'listening_ip=%s\n' "$LAN_IF"
    printf 'enable_natpmp=yes\n'
    # ADR-0092's literal knob. This build carries both spellings (`strings` on
    # the binary shows `enable_natpmp` and `enable_pcp_pmp`); setting both is
    # what makes the config say the same thing the ADR does.
    printf 'enable_pcp_pmp=yes\n'
    printf 'enable_upnp=yes\n'
    printf 'system_uptime=yes\n'
    printf 'notify_interval=60\n'
    # Never reap: the flow reads the lease table as the gateway's own record of
    # what it granted, and a sweeper racing that read would turn an observation
    # into a coin flip.
    printf 'clean_ruleset_interval=0\n'
    printf 'lease_file=%s/upnp.leases\n' "$PROOF_DIR"
    # The IPv6 pinhole table. A PCP MAP over IPv6 is a firewall pinhole, not a
    # redirect, so it never reaches `lease_file` — the daemon keeps the two
    # tables apart and so must the flow that reads them.
    printf 'lease_file6=%s/upnp6.leases\n' "$PROOF_DIR"
    printf 'uuid=%s\n' "$UUID"
    # Measured (ADR-0092): this lowers the UPnP floor — an
    # `AddPortMapping` for 12 s is honoured verbatim — but a **PCP** MAP is
    # still answered with a 120 s lifetime whatever this says. So a flow that
    # needs a renewal inside a short window drives it over UPnP, and a PCP row's
    # `lease_secs = 120` is the gateway's clamp rather than the request.
    printf 'min_lifetime=%s\n' "$MIN_LIFETIME"
    printf 'max_lifetime=%s\n' "$MAX_LIFETIME"
    printf 'allow 1024-65535 %s 1024-65535\n' "$LAN_CIDR"
    printf 'deny 0-65535 0.0.0.0/0 0-65535\n'
} >"$CONF"
cp "$CONF" "$PROOF_DIR/miniupnpd.conf"

set -- -f "$CONF" -d
if [ "$SECURE_MODE" = "no" ]; then
    set -- "$@" -S0
fi
# `-N` is ADR-0092's `enable_pcp_pmp=yes`: this build's own help spells the flag
# "enables NAT-PMP and PCP functionality", and both ride UDP 5351.
set -- "$@" -N
# shellcheck disable=SC2086
[ -n "${MINIUPNPD_EXTRA_ARGS:-}" ] && set -- "$@" $MINIUPNPD_EXTRA_ARGS

echo "rmule-miniupnpd-ready wan=$WAN_ADDR wan_if=$WAN_IF lan_if=$LAN_IF lan=$LAN_CIDR uuid=$UUID"
miniupnpd --version 2>&1 | sed 's/^/rmule-miniupnpd-version /'
nft list ruleset

trap 'miniupnpd-proof "$PROOF_DIR"; exit 0' TERM INT
exec miniupnpd "$@"
