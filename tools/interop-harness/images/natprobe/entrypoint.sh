#!/bin/sh
# Harness entrypoint for the **Reflector Probe**'s server half.
#
# Docker assigns one address per network attachment, and RFC 5780's mapping
# discovery needs two. The second is added to the same interface here, under
# NET_ADMIN, rather than by attaching the container to a second network: both
# reflector addresses then live in the one fake-public `/24` the counterparties
# already accept, and a probe that walks between them never leaves the WAN.
set -eu

PRIMARY_ADDR="${NATPROBE_PRIMARY_ADDR:?NATPROBE_PRIMARY_ADDR is required}"
SECONDARY_ADDR="${NATPROBE_SECONDARY_ADDR:?NATPROBE_SECONDARY_ADDR is required}"
IFACE="${NATPROBE_IFACE:-eth0}"
PREFIX_LEN="${NATPROBE_PREFIX_LEN:-24}"

if [ "${1:-}" = "--print-config" ]; then
    printf 'primary=%s\nsecondary=%s\niface=%s\nprimary_port=%s\nsecondary_port=%s\npinned_port=%s\n' \
        "$PRIMARY_ADDR" "$SECONDARY_ADDR" "$IFACE" \
        "${NATPROBE_PRIMARY_PORT:-3478}" "${NATPROBE_SECONDARY_PORT:-3479}" \
        "${NATPROBE_PINNED_PORT:--}"
    exit 0
fi

# Idempotent: a restarted container finds the address already there.
if ! ip -4 -o addr show dev "$IFACE" | grep -q " $SECONDARY_ADDR/"; then
    ip addr add "$SECONDARY_ADDR/$PREFIX_LEN" dev "$IFACE"
fi
ip -4 -o addr show dev "$IFACE"

exec /usr/local/bin/natprobe-reflector
