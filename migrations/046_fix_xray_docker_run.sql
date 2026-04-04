-- Fix X-Ray install script: 
-- 1) Use single-line docker run (backslash continuations break in MySQL)
-- 2) Handle new xray x25519 output format (Password instead of Public key)
UPDATE protocols
SET install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"
XRAY_PORT=${SERVER_PORT:-443}

docker pull teddysun/xray >/dev/null 2>&1 || true

GEN=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 2>/dev/null || true)
PRIVATE_KEY=$(printf "%s\n" "$GEN" | sed -n -E "s/^[Pp]rivate[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")
if [ -z "$PRIVATE_KEY" ]; then
  PRIVATE_KEY=$(printf "%s\n" "$GEN" | grep -i "private" | head -1 | sed "s/.*:[[:space:]]*//" | tr -d " \\t\\r\\n")
fi
PUBLIC_KEY=$(printf "%s\n" "$GEN" | sed -n -E "s/^[Pp]ublic[[:space:]]*[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")
if [ -z "$PUBLIC_KEY" ]; then
  PUBLIC_KEY=$(printf "%s\n" "$GEN" | sed -n -E "s/^[Pp]assword:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")
fi
if [ -z "$PUBLIC_KEY" ] && [ -n "$PRIVATE_KEY" ]; then
  PUBLIC_KEY=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null | sed -n -E "s/^[Pp]assword:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n" || true)
fi

SHORT_ID=$(od -An -tx1 -N8 /dev/urandom | tr -d " \\n")
CLIENT_ID=$(cat /proc/sys/kernel/random/uuid)
SERVER_NAME="${SERVER_NAME:-www.googletagmanager.com}"
FINGERPRINT="${FINGERPRINT:-chrome}"
SPIDER_X="${SPIDER_X:-/}"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
mkdir -p /opt/amnezia/xray

cat > /opt/amnezia/xray/server.json <<EOJSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${XRAY_PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${CLIENT_ID}", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "${SERVER_NAME}:443",
        "xver": 0,
        "serverNames": ["${SERVER_NAME}"],
        "privateKey": "${PRIVATE_KEY}",
        "shortIds": ["${SHORT_ID}"],
        "fingerprint": "${FINGERPRINT}",
        "spiderX": "${SPIDER_X}"
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOJSON

docker run -d --name "$CONTAINER_NAME" --restart always -p "${XRAY_PORT}:${XRAY_PORT}" -v /opt/amnezia/xray:/opt/amnezia/xray teddysun/xray xray run -c /opt/amnezia/xray/server.json

sleep 2

echo "XrayPort: ${XRAY_PORT}"
echo "Port: ${XRAY_PORT}"
echo "ClientID: ${CLIENT_ID}"
echo "PublicKey: ${PUBLIC_KEY}"
echo "PrivateKey: ${PRIVATE_KEY}"
echo "ShortID: ${SHORT_ID}"
echo "ServerName: ${SERVER_NAME}"
echo "ContainerName: ${CONTAINER_NAME}"'
WHERE slug = 'xray-vless';
