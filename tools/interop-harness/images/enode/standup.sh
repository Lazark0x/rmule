#!/bin/sh
# Proven eNode-spike standup via plain `docker run` — the path
# the feasibility spike exercised (works without the compose
# plugin). Brings up MySQL + an unmodified eNode on a Config-A fake-public /24.
# Tear down with teardown.sh.
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NET=enode-spike-net

docker network inspect "$NET" >/dev/null 2>&1 \
  || docker network create --subnet 203.0.113.0/24 "$NET"

docker rm -f enode-mysql enode >/dev/null 2>&1 || true

docker run -d --name enode-mysql --network "$NET" --ip 203.0.113.5 \
  --platform linux/amd64 \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=enode \
  -e MYSQL_USER=enode -e MYSQL_PASSWORD=password \
  mysql:5.7 --default-authentication-plugin=mysql_native_password

docker build --platform linux/amd64 -t rmule/interop-enode:local "$DIR"

docker run -d --name enode --network "$NET" --ip 203.0.113.10 \
  --platform linux/amd64 \
  -e ENODE_MYSQL_HOST=203.0.113.5 \
  rmule/interop-enode:local

echo "eNode standup started. Boot log: docker logs -f enode"
echo "Probe:  docker run --rm --network $NET -v \"$DIR\":/probe python:3-slim \\"
echo "          python /probe/probe.py all 203.0.113.10 4661 4665 4677"
