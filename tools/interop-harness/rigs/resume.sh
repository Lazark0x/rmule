#!/bin/bash
# A first-class download from a stock aMule, interrupted once and finished.
#   resume.sh <pause|restart|paused-restart|kill9|forged>
# A tap on each seed holds every block, so a byte sent twice is a refetch. A
# second stock seed joins during the interruption: a stock-shaped client asks a
# source it has just asked again only after the reask period, as stock does.
# Writes <root>/resume/<mode>/ and prints `resume <mode> ...`.
mode=$1
. "$(dirname "$0")/common.sh"
R=$ROOT/resume/$mode
rm -rf "$R"
mkdir -p "$R/seed/in" "$R/seed/temp" "$R/cap"
SIZE=${RIG_SIZE:-48640000}
CAP=${RIG_CAP:-500}
HOLD=${RIG_HOLD:-45}
bail() {
    for c in rig-rmule rig-rmule2 rig-seed rig-srv; do docker logs "$c" >"$R/at-exit-$c.log" 2>&1; done
    teardown rig-seed rig-seed2 rig-tap rig-tap2 rig-rmule rig-rmule2
}
trap bail EXIT
link=$(cd "$RIGS" && python3 -I -c "
import sys; sys.path.insert(0, '.')
from evil_source import File
print(File('$R/seed/in/stream.bin', $SIZE).link())")
stage_server "$R" || exit 3
amule_up rig-seed $SUB.2 -e AMULE_SHARED_DIR=/seed/incoming -e AMULE_TEMP_DIR=/seed/temp \
    -v "$R/seed/in":/seed/incoming -v "$R/seed/temp":/seed/temp -e AMULE_MAX_UPLOAD=$CAP || exit 3
end=$((SECONDS + 60))
until amulecmd rig-seed 'Show shared' 2>/dev/null | grep -q stream.bin; do
    [ $SECONDS -lt $end ] || { echo "rig: seed never shared"; exit 3; }
    sleep 1
done
tap() { # tap-container seed-container pcap
    docker run -d --name "$1" --network "container:$2" --cap-add NET_RAW --cap-add NET_ADMIN \
        -v "$R/cap":/cap rmule/interop-capture:local tcpdump -i eth0 --immediate-mode -U -s 0 -B 262144 \
        -w "/cap/$3" -- 'tcp port 4662' >/dev/null
    wait_log "$1" 'listening on' 20
}
second_seed() {
    mkdir -p "$R/seed2/in" "$R/seed2/temp"
    ln "$R/seed/in/stream.bin" "$R/seed2/in/stream.bin"
    amule_up rig-seed2 $SUB.3 -e AMULE_SHARED_DIR=/seed/incoming -e AMULE_TEMP_DIR=/seed/temp \
        -v "$R/seed2/in":/seed/incoming -v "$R/seed2/temp":/seed/temp -e AMULE_MAX_UPLOAD=$CAP || exit 3
    local end=$((SECONDS + 60))
    until amulecmd rig-seed2 'Show shared' 2>/dev/null | grep -q stream.bin; do
        [ $SECONDS -lt $end ] || { echo "rig: second seed never shared"; exit 3; }
        sleep 1
    done
    tap rig-tap2 rig-seed2 seed2-tap.pcap
    # ed2k-server answers a file's sources from a cache of 120 s.
    while [ $SECONDS -lt $((first_ask + 130)) ]; do sleep 1; done
}
tap rig-tap rig-seed seed-tap.pcap || exit 3
docker run -d --name rig-rmule --network $NET --ip $SUB.10 -e RMULE_LOG=info -v "$R":/w $TOOLS \
    ed2k download start --data-dir /w/rmule --server $SERVER:4661 --file "$link" \
    --out /w/rmule/output.bin --tcp-port 4663 --serve --max-seconds 900 --streaming-window 0 \
    --report-parts-every-ms 1000 --pause-gate /w/pause.gate --pause-toggle --stop-gate /w/stop.gate >/dev/null
first_ask=$SECONDS
wait_log rig-rmule 'parts=.*I' 60 || exit 3
sleep "$HOLD"
part_files() { find "$R/rmule" -type f ! -name '*.redb' ! -name '*.lock' -size +0 | head -5; }
resume() {
    docker logs rig-rmule >"$R/rmule-first.log" 2>&1
    docker run --rm --network $NET -v "$R":/w --entrypoint /usr/bin/rmule-tools $TOOLS \
        ed2k download status --data-dir /w/rmule >"$R/status.txt" 2>&1
    id=$(sed -n 's/^download id=\([0-9]*\).*/\1/p' "$R/status.txt" | head -1)
    id=${id:-1}
    docker rm rig-rmule >/dev/null
    docker run -d --name rig-rmule2 --network $NET --ip $SUB.10 -e RMULE_LOG=info -v "$R":/w $TOOLS \
        ed2k download resume --data-dir /w/rmule --download-id "$id" --server $SERVER:4661 >/dev/null
}
case $mode in
pause)
    touch "$R/pause.gate"
    sleep 5
    second_seed
    rm "$R/pause.gate"
    box=rig-rmule
    ;;
restart | paused-restart | forged)
    if [ "$mode" != restart ]; then
        # A pause stops the run, which is what writes its closing checkpoint.
        touch "$R/pause.gate"
        sleep 4
    fi
    touch "$R/stop.gate"
    docker wait rig-rmule >/dev/null
    second_seed
    if [ "$mode" = forged ]; then
        part=$(part_files | head -1)
        cp "$R/cap/seed-tap.pcap" "$R/cap/before.pcap"
        python3 -I "$RIGS/wire_ranges.py" "$R/cap/before.pcap:$SUB.2" --json "$R/cap/before.json" >"$R/before.txt"
        python3 -I - "$R/cap/before.json" "$part" "$SIZE" >"$R/forged.txt" <<'PY'
import json, os, sys
ranges = sorted(tuple(r) for r in json.load(open(sys.argv[1]))["delivered"])
part_size = 9_728_000
# The last delivered cell sits in the part still being filled, so it is unverified.
a, b = ranges[-1]
cell = a + (b - a) // 2 - 256
with open(sys.argv[2], "r+b") as f:
    f.seek(cell)
    f.write(os.urandom(512))
print(f"forged_at={cell} len=512 part={cell // part_size} file={sys.argv[2]}")
PY
    fi
    resume
    box=rig-rmule2
    ;;
kill9)
    docker kill -s KILL rig-rmule >/dev/null
    mkdir -p "$R/at-kill"
    for f in $(part_files); do cp "$f" "$R/at-kill/"; done
    cp "$R/rmule/rmule.redb" "$R/at-kill/"
    second_seed
    resume
    box=rig-rmule2
    ;;
esac
pattern='download finalized'
[ "$box" = rig-rmule2 ] && pattern='download completed\|finalized\|download.completed'
wait_log "$box" "$pattern" "${RIG_FINISH:-400}"
docker logs "$box" >"$R/rmule-last.log" 2>&1
sleep 2
docker logs rig-srv >"$R/server.log" 2>&1
docker logs rig-seed >"$R/seed-stdout.log" 2>&1
amule_log rig-seed >"$R/seed-logfile.log"
docker stop rig-tap rig-tap2 >/dev/null
python3 -I "$RIGS/wire_ranges.py" "$R/cap/seed-tap.pcap:$SUB.2" "$R/cap/seed2-tap.pcap:$SUB.3" --json "$R/cap/ranges.json" >"$R/wire.txt"
if [ "$mode" = kill9 ]; then
    python3 -I "$RIGS/wire_ranges.py" "$R/cap/seed2-tap.pcap:$SUB.3" --json "$R/cap/after.json" >"$R/after.txt"
    python3 -I "$RIGS/kill_check.py" "$R/seed/in/stream.bin" "$R/at-kill/$(ls "$R/at-kill" | grep -v redb | grep -v link | head -1)" "$R/cap/after.json" | tee "$R/kill-check.txt"
fi
final=$(find "$R/rmule" -type f -size "+$((SIZE / 1024 - 1))k" ! -name '*.redb' | head -3 | tr '\n' ' ')
same=no
for f in $final; do cmp -s "$f" "$R/seed/in/stream.bin" && same="$f"; done
echo "resume $mode $(cat "$R/wire.txt") byte_equal=$same corrupt_lines=$(grep -c part_corrupt "$R/rmule-last.log")"
