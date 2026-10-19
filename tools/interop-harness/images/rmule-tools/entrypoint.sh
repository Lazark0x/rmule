#!/bin/sh
# Entrypoint for the `rmule-tools` driver image.
#
# Its only job beyond `exec`ing the binary is the **LAN default-route knob**: a
# container placed on a NAT gateway's LAN bridge has no egress of its own (the
# bridge is created with `enable_ip_masquerade=false`), so its way out is a
# default route through the gateway. Pointing that route is a *network
# condition*, which is a legal Bench Variant Env lever — the same class as
# `AMULE_FORCE_LOW_ID`'s inbound DROP — and never a patch to the driver.
#
#   RMULE_DEFAULT_ROUTE_VIA    IPv4 gateway for `ip route replace default via …`
#   RMULE_DEFAULT_ROUTE_VIA6   IPv6 gateway for `ip -6 route replace default via …`
#   RMULE_DEFAULT_ROUTE_DEV6   the interface that route goes out of — required
#                              when the v6 gateway is link-local (`fe80::…`),
#                              the shape a Router Advertisement always gives
#
# Unset means untouched, which is what every pre-NAT flow relies on.
#
# The second knob is the **Source Sink** plan of the sentinel stimulus
# (ADR-0092): a source list names addresses, and a dial at an address nothing holds
# dies at ARP instead of putting a SYN on the wire — so the counterparty's read
# of the record would be unobservable. Holding the addresses on this container's
# own interface is a network condition of rmule's own stimulus, not a change to
# any counterparty.
#
#   RMULE_EXTRA_ADDRS          space-separated CIDRs for `ip addr add … dev eth0`
#   RMULE_EXTRA_ADDRS_DEV      the interface they land on (default `eth0`)
#
# The third is the **forced Low ID**, `AMULE_FORCE_LOW_ID`'s twin: inbound TCP
# to rmule's listener is dropped, so the server's High-ID probe fails and no
# peer can dial it, while every connection rmule opens itself still runs. It
# needs `NET_ADMIN`.
#
#   RMULE_FORCE_LOW_ID_TCP_PORT   the listener port whose inbound TCP is dropped
#   RMULE_TCP_ACCEPT_FROM         space-separated source addresses still
#                                 admitted to that port ahead of the drop: a
#                                 server's High-ID probe and one peer's
#                                 dial-back reach the listener, and no Kad
#                                 contact can acknowledge its TCP check
set -eu

if [ -n "${RMULE_FORCE_LOW_ID_TCP_PORT:-}" ]; then
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for source in ${RMULE_TCP_ACCEPT_FROM:-}; do
        iptables -A INPUT -p tcp --dport "$RMULE_FORCE_LOW_ID_TCP_PORT" -s "$source" -j ACCEPT
        echo "rmule-tools-tcp-accept-from source=$source"
    done
    iptables -A INPUT -p tcp --dport "$RMULE_FORCE_LOW_ID_TCP_PORT" -j DROP
    echo "rmule-tools-low-id-firewall-installed port=$RMULE_FORCE_LOW_ID_TCP_PORT"
fi

if [ -n "${RMULE_DEFAULT_ROUTE_VIA:-}" ]; then
    ip route replace default via "$RMULE_DEFAULT_ROUTE_VIA"
    echo "rmule-tools-default-route via=$RMULE_DEFAULT_ROUTE_VIA"
fi
if [ -n "${RMULE_DEFAULT_ROUTE_VIA6:-}" ]; then
    if [ -n "${RMULE_DEFAULT_ROUTE_DEV6:-}" ]; then
        ip -6 route replace default via "$RMULE_DEFAULT_ROUTE_VIA6" dev "$RMULE_DEFAULT_ROUTE_DEV6"
    else
        ip -6 route replace default via "$RMULE_DEFAULT_ROUTE_VIA6"
    fi
    echo "rmule-tools-default-route6 via=$RMULE_DEFAULT_ROUTE_VIA6 dev=${RMULE_DEFAULT_ROUTE_DEV6:-}"
fi

if [ -n "${RMULE_EXTRA_ADDRS:-}" ]; then
    dev="${RMULE_EXTRA_ADDRS_DEV:-eth0}"
    for cidr in $RMULE_EXTRA_ADDRS; do
        ip addr add "$cidr" dev "$dev"
        echo "rmule-tools-extra-addr addr=$cidr dev=$dev"
    done
fi

exec /usr/bin/rmule-tools "$@"
