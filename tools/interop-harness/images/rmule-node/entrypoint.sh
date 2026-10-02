#!/bin/sh
# Entrypoint for the rmule Kad node image (`rmule-tools kad join-node`).
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
#
# Unset means untouched, which is what every pre-NAT flow relies on.
set -eu

if [ -n "${RMULE_DEFAULT_ROUTE_VIA:-}" ]; then
    ip route replace default via "$RMULE_DEFAULT_ROUTE_VIA"
    echo "rmule-node-default-route via=$RMULE_DEFAULT_ROUTE_VIA"
fi
if [ -n "${RMULE_DEFAULT_ROUTE_VIA6:-}" ]; then
    ip -6 route replace default via "$RMULE_DEFAULT_ROUTE_VIA6"
    echo "rmule-node-default-route6 via=$RMULE_DEFAULT_ROUTE_VIA6"
fi

exec /usr/bin/rmule-tools kad join-node "$@"
