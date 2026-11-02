# Shared staging for the rigs: a fake-public network, ed2k-server, and helpers.
RIGS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${RIG_ROOT:-$HOME/Projects/rmule-bench-runs/h-bench}"
NET=rig-net
SUB=198.51.100
SERVER=$SUB.200
TOOLS=rmule/interop-rmule-tools:local
SEED_IMAGE=rmule/interop-amule-debug:local

wait_log() { # container pattern seconds
    local end=$((SECONDS + $3))
    while [ $SECONDS -lt $end ]; do
        docker logs "$1" 2>&1 | grep -q -- "$2" && return 0
        sleep 1
    done
    echo "rig: no '$2' in $1 inside $3 s" >&2
    return 1
}

teardown() {
    for c in "$@"; do docker rm -f "$c" >/dev/null 2>&1; done
    docker rm -f rig-srv >/dev/null 2>&1
    docker network rm $NET >/dev/null 2>&1
}

stage_server() { # run dir
    docker network create --subnet $SUB.0/24 $NET >/dev/null
    sed "s/^this_ip = .*/this_ip = \"$SERVER\"/" "$RIGS/../images/ed2ksrv/config.toml" >"$1/ed2ksrv-config.toml"
    docker run -d --name rig-srv --network $NET --ip $SERVER \
        -v "$1/ed2ksrv-config.toml":/etc/ed2k-server/config.toml:ro \
        rmule/interop-ed2ksrv:local --config /etc/ed2k-server/config.toml >/dev/null
    wait_log rig-srv 'TCP listener ready' 30
}

amule_up() { # name ip extra-docker-args...
    local name=$1 ip=$2
    shift 2
    docker run -d --name "$name" --network $NET --ip "$ip" \
        -e ED2K_SERVER_HOST=rig-srv -e ED2K_SERVER_PORT=4661 \
        -e AMULE_SCENARIO_MODE=ed2k-server -e AMULE_DEBUG_PEER_CATEGORIES=1 \
        "$@" $SEED_IMAGE >/dev/null
    wait_log "$name" 'rmule-amule-ready' 90
}

amulecmd() { # container command
    docker exec "$1" amulecmd -P rmule -c "$2"
}

amule_log() { # container
    docker exec "$1" sh -c 'cat "${AMULE_CONFIG_DIR:-$HOME/.aMule}/logfile"' 2>/dev/null
}
