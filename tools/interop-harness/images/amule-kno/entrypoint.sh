#!/bin/sh
# Harness entrypoint for kno's aMule at its **Fork Pin** (ADR-0092).
#
# Deliberately much smaller than the stock `amule` image's entrypoint: this body
# exists for the IPv6, uTP and NAT-T rows, and the knobs those need are either
# compile-time (ENABLE_UTP, ENABLE_QUIC) or plain `amule.conf` values. Only
# knobs a real user could set appear here, which is the Bench Variant Env rule.
#
# The daemon's own log is the flow's evidence surface — `ipv6-net-accept` reads
# what this body says about its address — so the logfile is tailed onto stdout
# rather than left inside the container.
#
# **Seeded Bootstrap.** With AMULE_SCENARIO_MODE set, this script bootstraps the
# fork's own `amule.conf`, applies the knobs only this fork has, and then execs
# the stock `amule` image's scenario entrypoint — the same file, lifted in at
# build time rather than copied into this tree — so every scenario mode and its
# knobs (`kad-node`, `ed2k-server-kad`, AMULE_KAD_PREFS_DAT, AMULE_KAD_NODES_DAT,
# AMULE_USER_HASH's `preferences.dat` pin, AMULE_KAD_FILTER_LAN_IPS for the
# fake-public `/24`) mean exactly what they mean on stock aMule 2.3.3. Unset,
# the behaviour below is unchanged.
set -eu

SCENARIO_ENTRYPOINT=/usr/local/lib/rmule/amule-scenario.sh

CONFIG_DIR="${AMULE_CONFIG_DIR:-/root/.aMule}"
INCOMING_DIR="${AMULE_SHARED_DIR:-/incoming}"
TEMP_DIR="${AMULE_TEMP_DIR:-/tmp/amule-temp}"
EC_PASSWORD="${AMULE_EC_PASSWORD:-rmule}"
EC_PASSWORD_MD5="${AMULE_EC_PASSWORD_MD5:-6a30721f062fac4590247952165a57bc}"
TCP_PORT="${AMULE_TCP_PORT:-4662}"
UDP_PORT="${AMULE_UDP_PORT:-4672}"
EC_PORT="${AMULE_EC_PORT:-4712}"

PRINT_CONFIG=0
if [ "${1:-}" = "--print-config" ]; then
    PRINT_CONFIG=1
fi

mkdir -p "$CONFIG_DIR" "$INCOMING_DIR" "$TEMP_DIR"

# LAN default-route knob (ADR-0092): a body on a NAT gateway's masquerade-free
# LAN has no egress until its default route points at the gateway. A route is a
# network condition, not a patch.
if [ -n "${AMULE_DEFAULT_ROUTE_VIA:-}" ]; then
    ip route replace default via "$AMULE_DEFAULT_ROUTE_VIA"
    echo "rmule-amule-kno-default-route via=$AMULE_DEFAULT_ROUTE_VIA"
fi
if [ -n "${AMULE_DEFAULT_ROUTE_VIA6:-}" ]; then
    ip -6 route replace default via "$AMULE_DEFAULT_ROUTE_VIA6"
    echo "rmule-amule-kno-default-route6 via=$AMULE_DEFAULT_ROUTE_VIA6"
fi

if [ ! -f "$CONFIG_DIR/amule.conf" ]; then
    timeout 20s amuled -c "$CONFIG_DIR" -o >/tmp/amule-bootstrap.log 2>&1 || true
fi

set_config() {
    key="$1"
    value="$2"
    file="$CONFIG_DIR/amule.conf"
    if grep -q "^${key}=" "$file" 2>/dev/null; then
        escaped=$(printf '%s' "$value" | sed 's/[\\&|]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >>"$file"
    fi
}

# The address-family policy is this fork's whole reason for being here. Its
# `AddressFamilyPolicy::Configured()` already defaults to DualStack on the pinned
# branch; the knob is written anyway so the run dir records what was asked for.
if [ -n "${AMULE_ADDRESS_FAMILY:-}" ]; then
    set_config AddressFamily "$AMULE_ADDRESS_FAMILY"
fi

if [ -n "${AMULE_SCENARIO_MODE:-}" ]; then
    # The version check and GeoIP fetch are the only public fetches the stock
    # scenario modes leave on; the bench network is internal anyway.
    set_config NewVersionCheck 0
    set_config GeoIPAutoUpdate 0
    if [ "$PRINT_CONFIG" -eq 0 ]; then
        rm -f "$CONFIG_DIR/logfile"
        touch "$CONFIG_DIR/logfile"
        tail -F "$CONFIG_DIR/logfile" 2>/dev/null &
    fi
    echo "rmule-amule-kno-scenario mode=$AMULE_SCENARIO_MODE"
    ip -o addr show 2>/dev/null || true
    exec "$SCENARIO_ENTRYPOINT" "$@"
fi

touch "$CONFIG_DIR/amule.conf"
set_config Port "$TCP_PORT"
set_config UDPPort "$UDP_PORT"
set_config ECPort "$EC_PORT"
set_config ECPassword "$EC_PASSWORD_MD5"
set_config AcceptExternalConnections 1
set_config IncomingDir "$INCOMING_DIR"
set_config TempDir "$TEMP_DIR"
# A zero upload limit makes aMule's throttler hold control packets; every Kad and
# peer flow in this harness has learned that the hard way.
set_config MaxUpload "${AMULE_MAX_UPLOAD:-1000}"
set_config MaxDownload "${AMULE_MAX_DOWNLOAD:-1000}"
# No bench body ever reaches the public network: no server list to fetch, no
# nodes.dat to download, no version check, nothing auto-connected. The URLs are
# blanked rather than just disabled because aMule fetches them on start
# regardless of the list-update preference.
set_config UpdateServerList 0
set_config Autoconnect 0
set_config AutoConnectStaticOnly 1
set_config Ed2kServersUrl ""
set_config KadNodesUrl ""
set_config NewVersionCheck 0
set_config GeoIPAutoUpdate 0
if [ "$PRINT_CONFIG" -eq 1 ]; then
    cat "$CONFIG_DIR/amule.conf"
    exit 0
fi

echo "rmule-amule-kno-config-ready tcp=$TCP_PORT udp=$UDP_PORT ec=$EC_PORT"
ip -o addr show 2>/dev/null || true

rm -f "$CONFIG_DIR/logfile"
touch "$CONFIG_DIR/logfile"
# The daemon's own logfile is the flow's evidence surface for `ipv6-net-accept`,
# and amuled's `-o` stream does not carry every line it writes there, so both are
# on stdout.
tail -F "$CONFIG_DIR/logfile" 2>/dev/null &

# NOT `-f`: in aMule `--full-daemon` means *fork to background*, which would end
# this script and stop the container the moment the daemon detached. `-o` puts
# log messages on stdout, `-i` leaves stdin alone.
amuled -c "$CONFIG_DIR" -o -i &
AMULE_PID=$!
echo "rmule-amule-kno-ready pid=$AMULE_PID"
wait "$AMULE_PID"
