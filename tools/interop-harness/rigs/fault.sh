#!/bin/bash
# One downloader in front of evil_source.py, one fault.
#   fault.sh <control|late-block|hashset-corrupt|hashset-count> <stock|rmule>
# Writes <root>/fault/<mode>-<who>/ and prints `fault <mode> <who> ...`.
mode=$1 who=$2
. "$(dirname "$0")/common.sh"
R=$ROOT/fault/$mode-$who
rm -rf "$R"
mkdir -p "$R/src" "$R/dl/in" "$R/dl/temp"
SIZE=12000000
trap 'teardown rig-evil rig-dl' EXIT
stage_server "$R" || exit 3
docker run -d --name rig-evil --network $NET --ip $SUB.5 \
    -v "$R/src":/w -v "$RIGS":/rig:ro python:3.12-alpine \
    python3 -u /rig/evil_source.py "$mode" 150 $SERVER:4661 $SUB.5 /w $SIZE >/dev/null
wait_log rig-evil '"offered"' 60 || exit 3
docker logs rig-evil 2>&1 | grep -q '"high_id": true' || { echo "rig: evil source is Low ID"; exit 3; }
if [ "$who" = stock ]; then
    amule_up rig-dl $SUB.10 -e AMULE_SHARED_DIR=/dl/in -e AMULE_TEMP_DIR=/dl/temp -v "$R/dl":/dl || exit 3
    while read -r link; do amulecmd rig-dl "Add $link" >>"$R/dl/add.log" 2>&1; done <"$R/src/links.txt"
else
    a=$(sed -n 1p "$R/src/links.txt") b=$(sed -n 2p "$R/src/links.txt")
    docker run -d --name rig-dl --network $NET --ip $SUB.10 -e RMULE_LOG=info -v "$R/dl":/w $TOOLS \
        ed2k download start --data-dir /w/rmule --server $SERVER:4661 \
        --file "$a" --out /w/rmule/a.bin --file "$b" --out /w/rmule/b.bin \
        --tcp-port 4663 --max-seconds 140 --streaming-window 0 >/dev/null
fi
end=$((SECONDS + 140))
while [ $SECONDS -lt $end ]; do
    docker logs rig-evil 2>&1 | grep -q '"event": "closed".*"after_stimulus_s": [0-9]' && break
    if [ "$mode" = control ]; then
        [ "$who" = stock ] && [ -f "$R/dl/in/a.bin" ] && [ -f "$R/dl/in/b.bin" ] && break
        [ "$who" = rmule ] && docker logs rig-dl 2>&1 | grep -c 'download finalized' | grep -q 2 && break
    fi
    sleep 1
done
sleep 3
docker logs rig-evil >"$R/evil.jsonl" 2>&1
docker logs rig-srv >"$R/server.log" 2>&1
docker logs rig-dl >"$R/downloader.log" 2>&1
[ "$who" = stock ] && amule_log rig-dl >"$R/amule-logfile.log"
docker exec rig-evil kill 1 2>/dev/null
python3 - "$R" "$mode" "$who" <<'PY'
import json, sys
R, mode, who = sys.argv[1:4]
rows = [json.loads(l) for l in open(R + "/evil.jsonl") if l.startswith("{")]
stim = [r for r in rows if r["event"] == "stimulus"]
closed = [r for r in rows if r["event"] == "closed" and r.get("after_stimulus_s") is not None]
frames = sorted({r["frame"] for r in rows if r["event"] == "received"})
print("fault", mode, who, "stimulus", len(stim), "closed_after_s", closed[0]["after_stimulus_s"] if closed else None, "frames", frames)
PY
