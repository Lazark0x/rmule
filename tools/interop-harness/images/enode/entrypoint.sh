#!/bin/sh
# eNode entrypoint: materialise enode.config.js from the environment, wait for
# the MySQL sidecar, ensure the schema, then run eNode's own unmodified server.
#
# eNode binds its TCP listeners to a single configured address (tcpserver.js
# `server.listen(port, conf.address)`) and panics EADDRNOTAVAIL otherwise, so
# the address is auto-detected as this container's own IP unless ENODE_ADDRESS
# is set. All protocol behaviour is eNode's — this script only wires config.
set -eu

ENODE_DIR=/opt/enode/src
CONFIG="${ENODE_DIR}/enode.config.js"

ADDRESS="${ENODE_ADDRESS:-$(hostname -i | awk '{print $1}')}"
SUPPORT_CRYPT="${ENODE_SUPPORT_CRYPT:-true}"
REQUEST_CRYPT="${ENODE_REQUEST_CRYPT:-true}"
REQUIRE_CRYPT="${ENODE_REQUIRE_CRYPT:-false}"

TCP_PORT="${ENODE_TCP_PORT:-4661}"
TCP_PORT_OBF="${ENODE_TCP_PORT_OBF:-4673}"
UDP_PORT="${ENODE_UDP_PORT:-4665}"
UDP_PORT_OBF="${ENODE_UDP_PORT_OBF:-4677}"

MYSQL_HOST="${ENODE_MYSQL_HOST:-enode-mysql}"
MYSQL_DB="${ENODE_MYSQL_DB:-enode}"
MYSQL_USER="${ENODE_MYSQL_USER:-enode}"
MYSQL_PASS="${ENODE_MYSQL_PASS:-password}"

echo "eNode entrypoint: address=${ADDRESS} tcp=${TCP_PORT}/${TCP_PORT_OBF} udp=${UDP_PORT}/${UDP_PORT_OBF} mysql=${MYSQL_HOST}/${MYSQL_DB}" >&2

cat > "${CONFIG}" <<EOF
exports.config = {
  name: 'rmule-interop-eNode',
  description: 'eNode (feasibility spike): experimental ed2k server written in node.js',
  address: '${ADDRESS}',
  dynIp: '',
  messageLowID: 'You have LowID.',
  messageLogin: 'Welcome to eNode (rmule interop spike)!',
  noAssert: false,
  supportCrypt: ${SUPPORT_CRYPT},
  requestCrypt: ${REQUEST_CRYPT},
  requireCrypt: ${REQUIRE_CRYPT},
  auxiliarPort: false,
  IPinLogin: false,
  tcp: {
    port: ${TCP_PORT},
    portObfuscated: ${TCP_PORT_OBF},
    maxConnections: 1000000,
    connectionTimeout: 2000,
    allowLowIDs: true,
    minLowID: 1,
    maxLowID: 0xffffff,
  },
  udp: {
    port: ${UDP_PORT},
    portObfuscated: ${UDP_PORT_OBF},
    getSources: true,
    getFiles: true,
    serverKey: 0x12345678,
  },
  storage: {
    engine: 'mysql',
    mysql: {
      database: '${MYSQL_DB}',
      host: '${MYSQL_HOST}',
      user: '${MYSQL_USER}',
      pass: '${MYSQL_PASS}',
      log: false,
      fullLog: false,
      connections: 4,
      deadlockDelay: 100,
    },
    mongodb: { host: '127.0.0.1', port: '27017' },
  },
};
EOF

echo "eNode entrypoint: waiting for MySQL at ${MYSQL_HOST} and loading schema..." >&2
ENODE_MYSQL_HOST="${MYSQL_HOST}" ENODE_MYSQL_DB="${MYSQL_DB}" \
ENODE_MYSQL_USER="${MYSQL_USER}" ENODE_MYSQL_PASS="${MYSQL_PASS}" \
  node /opt/enode/init-schema.js

echo "eNode entrypoint: starting eNode server" >&2
cd "${ENODE_DIR}"
exec node enode.js
