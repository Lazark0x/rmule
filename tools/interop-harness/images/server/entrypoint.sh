#!/bin/sh
set -eu

echo "starting Lugdunum eserver on tcp/4661" >&2
exec tail -f /dev/null | /usr/local/bin/eserver
