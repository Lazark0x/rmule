#!/bin/sh
# Harness entrypoint for the Stimulus Counterparty (ADR-0082): emule-qt's
# headless `emulecored`.
#
# Shape follows images/amule/entrypoint.sh — a scenario-mode switch, env-var
# knobs, a `--print-config` dry run, and a `rmule-emuleqt-*-ready` marker on
# stdout that `wait_for_container_log` in the harness blocks on. Two things
# differ, both forced by the daemon:
#
#   1. Config is YAML (src/core/prefs/Preferences.cpp), not aMule's flat ini,
#      so this writes a whole preferences.yml rather than sed-ing keys.
#   2. There is no `amulecmd`. The daemon's control surface is the five CLI
#      verbs (`--connect`, `--disconnect`, `--connect-kad`, `--disconnect-kad`,
#      `--add-link`), which are one-shot IPC clients against the running daemon
#      — they print OK/Failed and exit, they do NOT report status. So readiness
#      is read out of the daemon's own log stream instead of polled over IPC.
#
# The daemon runs with autoConnect=false in every mode: nothing connects itself,
# every connection in a scenario is an explicit CLI verb. That is the stimulus
# lever the harness drives, so the entrypoint exercises it rather than working
# around it.
set -eu

EMULEQT_SCENARIO_MODE="${EMULEQT_SCENARIO_MODE:-ed2k-server}"

CONFIG_DIR="${EMULEQT_CONFIG_DIR:-/config}"
INCOMING_DIR="${EMULEQT_SHARED_DIR:-/incoming}"
TEMP_DIR="${EMULEQT_TEMP_DIR:-/tmp/emuleqt-temp}"
TCP_PORT="${EMULEQT_TCP_PORT:-4662}"
UDP_PORT="${EMULEQT_UDP_PORT:-4672}"
IPC_PORT="${EMULEQT_IPC_PORT:-4712}"
IPC_TOKEN="${EMULEQT_IPC_TOKEN:-rmule}"
NICK="${EMULEQT_NICK:-rmule-stimulus}"
USER_HASH="${EMULEQT_USER_HASH:-}"
MAX_UPLOAD="${EMULEQT_MAX_UPLOAD:-1000}"
MAX_DOWNLOAD="${EMULEQT_MAX_DOWNLOAD:-1000}"
READY_TIMEOUT="${EMULEQT_READY_TIMEOUT:-120}"

LOG_FILE=/tmp/emulecored.log

PRINT_CONFIG=0
if [ "${1:-}" = "--print-config" ]; then
    PRINT_CONFIG=1
fi

# LAN default-route knob (ADR-0092). A counterparty placed on a NAT gateway's
# LAN bridge has no egress of its own — the bridge is created with
# `enable_ip_masquerade=false` — so its way out is a default route through the
# gateway. Repointing a route is a *network condition*, the same legal Bench
# Variant Env class as the aMule image's `AMULE_DEFAULT_ROUTE_VIA`,
# and changes nothing about how the client speaks the protocol.
if [ -n "${EMULEQT_DEFAULT_ROUTE_VIA:-}" ]; then
    ip route replace default via "$EMULEQT_DEFAULT_ROUTE_VIA"
    echo "rmule-emuleqt-default-route via=$EMULEQT_DEFAULT_ROUTE_VIA"
fi
if [ -n "${EMULEQT_DEFAULT_ROUTE_VIA6:-}" ]; then
    ip -6 route replace default via "$EMULEQT_DEFAULT_ROUTE_VIA6"
    echo "rmule-emuleqt-default-route6 via=$EMULEQT_DEFAULT_ROUTE_VIA6"
fi

# ---------------------------------------------------------------------------
# preferences.yml
#
# Only the sections the loader actually reads (Preferences::load) are written;
# an unknown key is silently ignored, so a typo here fails open into a default
# and that is exactly what the --print-config path exists to catch.
#
# Bench-critical settings, and why:
#   general.autoConnect      false — see the header. Everything is CLI-driven.
#   general.filterLANIPs     false — the harness bridge is RFC1918.
#   serverConnection.*       every "learn about more servers" and "fetch a
#                            server list over HTTP" path off. A bench
#                            counterparty must reach exactly one server, the
#                            one in the server.met written below, and must
#                            never touch the public network.
#   serverConnection.smartLowIdCheck
#                            false — the smart-LowID bounce refuses the first
#                            LowID and tries the next server, which on a
#                            one-server bench is a connect loop.
#   upnp.enableUPnP          false — no port mapping against the host's router.
#   webserver.enabled        false — the daemon's HTTP surface is not wanted.
#   ipc.listenAddress        127.0.0.1 — the CLI verbs run inside the container
#                            (docker exec), and a handshake from loopback needs
#                            no token (IpcClientHandler::handleHandshake). A
#                            token is still configured so a non-local client
#                            could be added later without a rebuild.
#   logging.verbose/serverVerboseLog/kadVerboseLog
#                            on — the log stream IS the readiness probe.
# ---------------------------------------------------------------------------
write_preferences() {
    network_ed2k="$1"
    kad_enabled="$2"

    mkdir -p "$CONFIG_DIR" "$INCOMING_DIR" "$TEMP_DIR"

    {
        printf 'general:\n'
        printf '  nick: "%s"\n' "$NICK"
        if [ -n "$USER_HASH" ]; then
            printf '  userHash: "%s"\n' "$USER_HASH"
        fi
        printf '  autoConnect: false\n'
        printf '  reconnect: false\n'
        printf '  filterLANIPs: false\n'
        printf '  skipFirewalledChecksInLanMode: false\n'
        printf '  versionCheckEnabled: false\n'
        printf '  enableOnlineSignature: false\n'
        printf '\n'
        printf 'serverConnection:\n'
        printf '  safeServerConnect: false\n'
        printf '  autoConnectStaticOnly: false\n'
        printf '  addServersFromServer: false\n'
        printf '  addServersFromClients: false\n'
        printf '  autoUpdateServerList: false\n'
        printf '  serverListURL: ""\n'
        printf '  filterServerByIP: false\n'
        printf '  smartLowIdCheck: false\n'
        printf '  deadServerRetries: 0\n'
        printf '\n'
        printf 'network:\n'
        printf '  port: %s\n' "$TCP_PORT"
        printf '  udpPort: %s\n' "$UDP_PORT"
        printf '  networkED2K: %s\n' "$network_ed2k"
        printf '  maxConnections: 200\n'
        printf '  maxHalfConnections: 9\n'
        printf '\n'
        printf 'bandwidth:\n'
        printf '  maxUpload: %s\n' "$MAX_UPLOAD"
        printf '  maxDownload: %s\n' "$MAX_DOWNLOAD"
        printf '\n'
        printf 'encryption:\n'
        printf '  cryptLayerSupported: %s\n' "${EMULEQT_CRYPT_SUPPORTED:-false}"
        printf '  cryptLayerRequested: %s\n' "${EMULEQT_CRYPT_REQUESTED:-false}"
        printf '  cryptLayerRequired: %s\n' "${EMULEQT_CRYPT_REQUIRED:-false}"
        printf '\n'
        printf 'directories:\n'
        printf '  configDir: "%s"\n' "$CONFIG_DIR"
        printf '  incomingDir: "%s"\n' "$INCOMING_DIR"
        printf '  tempDirs:\n'
        printf '    - "%s"\n' "$TEMP_DIR"
        printf '  sharedDirs:\n'
        printf '    - "%s"\n' "$INCOMING_DIR"
        printf '\n'
        printf 'upnp:\n'
        printf '  enableUPnP: false\n'
        printf '\n'
        printf 'security:\n'
        printf '  ipFilterLevel: 0\n'
        printf '  useSecureIdent: %s\n' "${EMULEQT_SECURE_IDENT:-true}"
        printf '\n'
        printf 'logging:\n'
        printf '  verbose: true\n'
        printf '  serverVerboseLog: true\n'
        printf '  kadVerboseLog: %s\n' "${EMULEQT_KAD_VERBOSE:-true}"
        printf '  logToDiskCore: false\n'
        printf '\n'
        printf 'ipc:\n'
        printf '  enabled: true\n'
        printf '  port: %s\n' "$IPC_PORT"
        printf '  listenAddress: "127.0.0.1"\n'
        printf '  tokens:\n'
        printf '    - "%s"\n' "$IPC_TOKEN"
        printf '\n'
        printf 'webserver:\n'
        printf '  enabled: false\n'
        printf '\n'
        printf 'kademlia:\n'
        printf '  enabled: %s\n' "$kad_enabled"
    } >"$CONFIG_DIR/preferences.yml"
}

# Minimal one-server server.met so the daemon's ServerList has exactly the bench
# eserver in it and `--connect` (which maps to connectToAnyServer) can only pick
# that one. Layout is stock, and identical to the aMule image's seed:
# [u8 0xE0][u32 count][per server: 4 IP octets a.b.c.d][u16 port LE][u32 tagcount].
# emule-qt reads it at ServerList::addServerMetToList and accepts a zero-tag
# entry; the live connection supplies the name and counts afterwards.
seed_server_met() {
    seed_ip="$1"
    seed_port="$2"
    seed_out="$3"
    old_ifs="$IFS"
    IFS='.'
    # shellcheck disable=SC2086
    set -- $seed_ip
    IFS="$old_ifs"
    o1="$1"; o2="$2"; o3="$3"; o4="$4"
    plo=$(( seed_port & 255 ))
    phi=$(( (seed_port >> 8) & 255 ))
    {
        printf '\340\001\000\000\000'
        printf "\\$(printf '%03o' "$o1")\\$(printf '%03o' "$o2")\\$(printf '%03o' "$o3")\\$(printf '%03o' "$o4")"
        printf "\\$(printf '%03o' "$plo")\\$(printf '%03o' "$phi")"
        printf '\000\000\000\000'
    } >"$seed_out"
}

print_selected_config() {
    printf 'mode=%s\n' "$EMULEQT_SCENARIO_MODE"
    printf 'configDir=%s\n' "$CONFIG_DIR"
    printf 'emulecored=%s\n' "$(emulecored --version 2>/dev/null | tr -d '\r')"
    cat "$CONFIG_DIR/preferences.yml"
}

# Start the daemon, relay its log to stdout (so `docker logs` sees it) and keep
# it in a file the readiness waits can grep. The daemon is backgrounded directly
# rather than piped so "$!" is emulecored's own pid and the TERM trap reaches it.
#
# `stdbuf -oL -eL`: stdout redirected to a file, not a tty, makes
# glibc pick fully-buffered rather than line-buffered — emulecored's own
# writes can sit in its libc buffer well past when a line is logically
# emitted, and both readers of $LOG_FILE (this script's own `wait_for_log`
# grep and the `tail -f` relay `docker logs` sees) only see bytes once that
# buffer flushes. `stdbuf` forces line buffering on the child from outside
# it — no source change, no daemon restart needed on a rebuild — so a line
# reaches the file, and `docker logs`, as soon as emulecored writes it.
start_daemon() {
    : >"$LOG_FILE"
    stdbuf -oL -eL emulecored --config "$CONFIG_DIR" --port "$IPC_PORT" >"$LOG_FILE" 2>&1 &
    daemon_pid="$!"
    tail -n +1 -f "$LOG_FILE" &
    tail_pid="$!"
    trap 'kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; kill "$tail_pid" 2>/dev/null || true' INT TERM
}

# Block until PATTERN shows up in the daemon log, or the deadline passes.
# Returns 1 on timeout rather than exiting, so each caller decides whether the
# missing line is fatal (a failed server login) or merely unreached (a lone Kad
# node that nobody has bootstrapped yet).
wait_for_log() {
    pattern="$1"
    seconds="$2"
    i=0
    while [ "$i" -lt "$seconds" ]; do
        if grep -q "$pattern" "$LOG_FILE" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$daemon_pid" 2>/dev/null; then
            echo "emulecored exited before matching ${pattern}" >&2
            return 1
        fi
        sleep 1
        i=$(( i + 1 ))
    done
    return 1
}

wait_for_ipc() {
    if ! wait_for_log 'IPC listening on' "${EMULEQT_IPC_TIMEOUT:-60}"; then
        echo "emulecored IPC did not come up" >&2
        cat "$LOG_FILE" >&2 || true
        exit 1
    fi
}

resolve_server() {
    SERVER_HOST="${ED2K_SERVER_HOST:?ED2K_SERVER_HOST is required}"
    SERVER_PORT="${ED2K_SERVER_PORT:-4661}"
    SERVER_ADDR="$(getent hosts "$SERVER_HOST" | awk '{ print $1; exit }')"
    if [ -z "$SERVER_ADDR" ]; then
        echo "could not resolve ED2K_SERVER_HOST=${SERVER_HOST}" >&2
        exit 1
    fi
}

# Drive the eD2k connect verb and block until the server has answered the login
# with an ID. "Connected to" is logged when the TCP session is up and the login
# has been sent; the serverVerbose "onLoginReceived" line is the server's
# answer, which is the one that proves a real login rather than a live socket.
connect_to_server() {
    emulecored --config "$CONFIG_DIR" --port "$IPC_PORT" --connect
    if ! wait_for_log 'Connected to' "$READY_TIMEOUT"; then
        echo "emulecored did not connect to ${SERVER_ADDR}:${SERVER_PORT}" >&2
        cat "$LOG_FILE" >&2 || true
        exit 1
    fi
    if wait_for_log 'onLoginReceived: clientID=' 30; then
        grep 'onLoginReceived: clientID=' "$LOG_FILE" | head -n 1
    fi
}

idle() {
    wait "$daemon_pid"
}

# ---------------------------------------------------------------------------
# eD2k server mode (default): connect to the bench eserver, then idle as a
# third body on the wire.
# ---------------------------------------------------------------------------
run_ed2k_server_mode() {
    write_preferences true false
    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi
    resolve_server
    seed_server_met "$SERVER_ADDR" "$SERVER_PORT" "$CONFIG_DIR/server.met"
    echo "rmule-emuleqt-serverlist-seeded ip=${SERVER_ADDR} port=${SERVER_PORT} bytes=$(wc -c <"$CONFIG_DIR/server.met")"

    start_daemon
    wait_for_ipc
    connect_to_server

    if [ -n "${EMULEQT_DOWNLOAD_LINK:-}" ]; then
        emulecored --config "$CONFIG_DIR" --port "$IPC_PORT" \
            --add-link "$EMULEQT_DOWNLOAD_LINK"
        echo "rmule-emuleqt-link-added"
    fi

    echo "rmule-emuleqt-ready"
    idle
}

# ---------------------------------------------------------------------------
# Direct-peer mode: no server, no Kad. The daemon just listens on its peer port
# and shares $EMULEQT_SHARED_DIR, for scenarios that dial it directly.
# ---------------------------------------------------------------------------
run_direct_peer_mode() {
    write_preferences false false
    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi
    start_daemon
    wait_for_ipc
    if ! wait_for_log 'TCP listen socket bound on port' 30; then
        echo "emulecored did not bind its peer TCP port" >&2
        cat "$LOG_FILE" >&2 || true
        exit 1
    fi
    echo "rmule-emuleqt-direct-peer-ready"
    idle
}

# ---------------------------------------------------------------------------
# Kad-node mode: Kad only, bootstrapped from a harness-generated private
# nodes.dat. Never a public bootstrap — serverListURL and autoUpdate are off in
# every mode, and the only routing input is the seeded file.
#
# Readiness is "Kad started", not "Kad connected": a node whose seeds have
# not answered yet never reaches connected on its own, exactly as the aMule
# kad-node image's publisher/routing roles do. The marker is
# `Kad: Started with ID`, which `Kademlia::start` logs on every start
# (src/core/kademlia/Kademlia.cpp:139). The daemon's `Kademlia started.` line
# is logged only on the autoConnect start path (src/core/app/CoreSession.cpp:1160-1163),
# which this image never takes, so a `--connect-kad` start never prints it
# (run 1790247348).
# ---------------------------------------------------------------------------
run_kad_node_mode() {
    write_preferences false true
    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi

    if [ -n "${EMULEQT_KAD_NODES_DAT:-}" ]; then
        if [ ! -f "$EMULEQT_KAD_NODES_DAT" ]; then
            echo "EMULEQT_KAD_NODES_DAT=${EMULEQT_KAD_NODES_DAT} does not exist" >&2
            exit 1
        fi
        cp "$EMULEQT_KAD_NODES_DAT" "$CONFIG_DIR/nodes.dat"
        echo "rmule-emuleqt-kad-nodes-seeded bytes=$(wc -c <"$CONFIG_DIR/nodes.dat")"
    fi
    if [ -n "${EMULEQT_KAD_PREFS_DAT:-}" ]; then
        if [ ! -f "$EMULEQT_KAD_PREFS_DAT" ]; then
            echo "EMULEQT_KAD_PREFS_DAT=${EMULEQT_KAD_PREFS_DAT} does not exist" >&2
            exit 1
        fi
        cp "$EMULEQT_KAD_PREFS_DAT" "$CONFIG_DIR/preferencesKad.dat"
    fi

    start_daemon
    wait_for_ipc
    emulecored --config "$CONFIG_DIR" --port "$IPC_PORT" --connect-kad
    if ! wait_for_log 'Kad: Started with ID' "$READY_TIMEOUT"; then
        echo "emulecored did not start Kademlia" >&2
        cat "$LOG_FILE" >&2 || true
        exit 1
    fi
    echo "rmule-emuleqt-kad-node-ready"
    idle
}

# ---------------------------------------------------------------------------
# eD2k + Kad mode: both networks live, for handoff scenarios where the peer
# hello has to carry a real Kad half.
# ---------------------------------------------------------------------------
run_ed2k_server_kad_mode() {
    write_preferences true true
    if [ "$PRINT_CONFIG" -eq 1 ]; then
        print_selected_config
        return 0
    fi
    resolve_server
    seed_server_met "$SERVER_ADDR" "$SERVER_PORT" "$CONFIG_DIR/server.met"
    if [ -n "${EMULEQT_KAD_NODES_DAT:-}" ]; then
        cp "$EMULEQT_KAD_NODES_DAT" "$CONFIG_DIR/nodes.dat"
    fi

    start_daemon
    wait_for_ipc
    connect_to_server
    emulecored --config "$CONFIG_DIR" --port "$IPC_PORT" --connect-kad
    wait_for_log 'Kad: Started with ID' 30 || true
    echo "rmule-emuleqt-server-kad-ready"
    idle
}

case "$EMULEQT_SCENARIO_MODE" in
    ed2k-server)     run_ed2k_server_mode ;;
    ed2k-server-kad) run_ed2k_server_kad_mode ;;
    direct-peer)     run_direct_peer_mode ;;
    kad-node)        run_kad_node_mode ;;
    *)
        echo "unknown EMULEQT_SCENARIO_MODE=${EMULEQT_SCENARIO_MODE}" >&2
        exit 1
        ;;
esac
