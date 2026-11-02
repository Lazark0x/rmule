#!/bin/bash
# How long each downloader leaves a source that reset the link with no queue word.
# One source, one stock aMule and one rmule in front of it, one window of
#   RIG_WATCH seconds. Writes <root>/reset/ and prints each peer's next link.
. "$(dirname "$0")/common.sh"
R=$ROOT/reset
rm -rf "$R"
mkdir -p "$R/src" "$R/dl/in" "$R/dl/temp"
WATCH=${RIG_WATCH:-2100}
trap 'teardown rig-evil rig-dl rig-rmule' EXIT
stage_server "$R" || exit 3
docker run -d --name rig-evil --network $NET --ip $SUB.5 \
    -v "$R/src":/w -v "$RIGS":/rig:ro python:3.12-alpine \
    python3 -u /rig/evil_source.py reset-after-ask "$WATCH" $SERVER:4661 $SUB.5 /w 12000000 >/dev/null
wait_log rig-evil '"offered"' 90 || exit 3
amule_up rig-dl $SUB.10 -e AMULE_SHARED_DIR=/dl/in -e AMULE_TEMP_DIR=/dl/temp -v "$R/dl":/dl || exit 3
amulecmd rig-dl "Add $(sed -n 1p "$R/src/links.txt")" >"$R/add.log" 2>&1
docker run -d --name rig-rmule --network $NET --ip $SUB.11 -e RMULE_LOG=info -v "$R":/w $TOOLS \
    ed2k download start --data-dir /w/rmule --server $SERVER:4661 --file "$(sed -n 1p "$R/src/links.txt")" \
    --out /w/rmule/a.bin --tcp-port 4663 --max-seconds "$WATCH" --streaming-window 0 \
    --report-parts-every-ms 10000 >/dev/null
end=$((SECONDS + WATCH))
while [ $SECONDS -lt $end ]; do
    n=$(docker logs rig-evil 2>&1 | grep -c '"event": "connected"')
    [ "$n" -ge 4 ] && break
    sleep 5
done
sleep 20
docker logs rig-evil >"$R/evil.jsonl" 2>&1
docker logs rig-rmule >"$R/rmule.log" 2>&1
amule_log rig-dl >"$R/amule-logfile.log"
python3 -I - "$R/evil.jsonl" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
for peer in sorted({r["peer"] for r in rows if "peer" in r}):
    marks = [r for r in rows if r.get("peer") == peer and r["event"] in ("connected", "reset")]
    t0 = next((r["t"] for r in marks if r["event"] == "reset"), None)
    print("reset", peer, [(r["event"], round(r["t"] - t0, 1) if t0 else None) for r in marks])
PY
