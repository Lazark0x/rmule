#!/bin/bash
# rmule and emule-qt through a whole transfer each way, under the frame gate.
# A tap holds every frame; rmule's log says why each link closed. Writes
# <root>/stay/ and prints `stay <direction> ...`.
. "$(dirname "$0")/common.sh"
R=$ROOT/stay
rm -rf "$R"
mkdir -p "$R/seed/in" "$R/peer/in" "$R/cap"
SIZE=20000000
QT=rmule/interop-emuleqt:local
trap 'teardown rig-qt rig-qt2 rig-tap rig-rmule rig-rmule2' EXIT
link=$(cd "$RIGS" && python3 -I -c "
import sys; sys.path.insert(0, '.')
from evil_source import File
print(File('$R/seed/in/stream.bin', $SIZE).link())")
stage_server "$R" || exit 3
docker run -d --name rig-qt --network $NET --ip $SUB.3 --cap-add NET_ADMIN \
    -e EMULEQT_SCENARIO_MODE=ed2k-server -e ED2K_SERVER_HOST=$SERVER -e ED2K_SERVER_PORT=4661 \
    -v "$R/seed/in":/incoming $QT >/dev/null
wait_log rig-qt 'rmule-emuleqt-ready' 90 || exit 3
docker exec rig-qt sh -c 'until grep -q "Hashed OK" /tmp/emulecored.log; do sleep 1; done'
docker run -d --name rig-tap --network container:rig-qt --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$R/cap":/cap rmule/interop-capture:local tcpdump -i eth0 --immediate-mode -U -s 0 -B 262144 \
    -w /cap/qt-tap.pcap -- 'tcp port 4662 or tcp port 4663' >/dev/null
wait_log rig-tap 'listening on' 20 || exit 3
docker run -d --name rig-rmule --network $NET --ip $SUB.10 -e RMULE_LOG=info -v "$R":/w $TOOLS \
    ed2k download start --data-dir /w/rmule --server $SERVER:4661 --file "$link" \
    --out /w/rmule/output.bin --tcp-port 4663 --max-seconds 200 --streaming-window 0 >/dev/null
wait_log rig-rmule 'download finalized' 200
docker logs rig-rmule >"$R/rmule-download.log" 2>&1
docker rm -f rig-rmule >/dev/null
cmp -s "$R/rmule/output.bin" "$R/seed/in/stream.bin" && down=yes || down=no
echo "stay down byte_equal=$down closes=$(grep -o 'peer connection closed reason=[A-Za-z()]*' "$R/rmule-download.log" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
docker run -d --name rig-rmule2 --network $NET --ip $SUB.10 -e RMULE_LOG=info -v "$R":/w $TOOLS \
    ed2k serve start --server $SERVER:4661 --file /w/seed/in/stream.bin --tcp-port 4663 --max-seconds 170 >/dev/null
wait_log rig-rmule2 'files_announced' 30 || exit 3
docker run -d --name rig-qt2 --network $NET --ip $SUB.4 --cap-add NET_ADMIN \
    -e EMULEQT_SCENARIO_MODE=ed2k-server -e ED2K_SERVER_HOST=$SERVER -e ED2K_SERVER_PORT=4661 \
    -e EMULEQT_NICK=rmule-stimulus-2 -e "EMULEQT_DOWNLOAD_LINK=$link" -v "$R/peer/in":/incoming $QT >/dev/null
end=$((SECONDS + 150))
until [ -f "$R/peer/in/stream.bin" ] && cmp -s "$R/peer/in/stream.bin" "$R/seed/in/stream.bin"; do
    [ $SECONDS -lt $end ] || break
    sleep 2
done
docker logs rig-rmule2 >"$R/rmule-serve.log" 2>&1
docker exec rig-qt2 cat /tmp/emulecored.log >"$R/qt2.log" 2>/dev/null
docker exec rig-qt cat /tmp/emulecored.log >"$R/qt.log" 2>/dev/null
docker stop rig-tap >/dev/null
cmp -s "$R/peer/in/stream.bin" "$R/seed/in/stream.bin" && up=yes || up=no
echo "stay up byte_equal=$up closes=$(grep -o 'peer connection closed reason=[A-Za-z()]*' "$R/rmule-serve.log" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
python3 -I "$RIGS/wire_ranges.py" "$R/cap/qt-tap.pcap:$SUB.3" --json "$R/cap/ranges.json"
