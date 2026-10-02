#!/bin/sh
# Tear down the eNode spike standup. Keeps the built images.
docker rm -f enode enode-mysql >/dev/null 2>&1 || true
docker network rm enode-spike-net >/dev/null 2>&1 || true
echo "eNode spike torn down (images kept)."
