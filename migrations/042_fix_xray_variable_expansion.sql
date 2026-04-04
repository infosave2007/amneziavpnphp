-- Fix X-Ray install script variable substitution
-- The heredoc was preserving ${VAR} as literals instead of expanding them
UPDATE protocols
SET install_script = '#!/bin/bash

set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
XRAY_PORT=${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}

# Ensure image present
docker pull teddysun/xray >/dev/null 2>&1 || true

# Generate keys
GEN=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 2>/dev/null || true)
PRIVATE_KEY=$(printf "%s\\n" "$GEN" | sed -n -E "s/^[Pp]rivate[[:space:]]*[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")
PUBLIC_KEY=$(printf "%s\\n" "$GEN" | sed -n -E "s/^[Pp]ublic[[:space:]]*[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")

if [ -z "$PUBLIC_KEY" ] && [ -n "$PRIVATE_KEY" ]; then
  PUBLIC_KEY=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null | sed -n -E "s/^[Pp]ublic[[:space:]]*[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n" || true)
fi

SHORT_ID=$(od -An -tx1 -N8 /dev/urandom | tr -d " \\n")
CLIENT_ID=$(cat /proc/sys/kernel/random/uuid)

SERVER_NAME="${SERVER_NAME:-www.googletagmanager.com}"
FINGERPRINT="${FINGERPRINT:-chrome}"
SPIDER_X="${SPIDER_X:-/}"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
mkdir -p /opt/amnezia/xray

# Write config using printf to ensure variable expansion
printf ''%s\\n'' "{
  \"log\": { \"loglevel\": \"warning\" },
  \"inbounds\": [
    {
      \"listen\": \"0.0.0.0\",
      \"port\": $XRAY_PORT,
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [ { \"id\": \"$CLIENT_ID\" } ],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"tcp\",
        \"security\": \"reality\",
        \"realitySettings\": {
          \"show\": false,
          \"dest\": \"$SERVER_NAME:443\",
          \"xver\": 0,
          \"serverNames\": [ \"$SERVER_NAME\" ],
          \"privateKey\": \"$PRIVATE_KEY\",
          \"shortIds\": [ \"$SHORT_ID\" ],
          \"fingerprint\": \"$FINGERPRINT\",
          \"spiderX\": \"$SPIDER_X\"
        }
      }
    }
  ],
  \"outbounds\": [ { \"protocol\": \"freedom\", \"tag\": \"direct\" } ]
}" > /opt/amnezia/xray/server.json

# Start container
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart always \
  -p "${XRAY_PORT}:${XRAY_PORT}" \
  -v /opt/amnezia/xray:/opt/amnezia/xray \
  teddysun/xray xray run -c /opt/amnezia/xray/server.json

sleep 2

# Output configuration
echo "XrayPort: ${XRAY_PORT}"
echo "Port: ${XRAY_PORT}"
echo "ClientID: ${CLIENT_ID}"
echo "PublicKey: ${PUBLIC_KEY}"
echo "PrivateKey: ${PRIVATE_KEY}"
echo "ShortID: ${SHORT_ID}"
echo "ServerName: ${SERVER_NAME}"
echo "ContainerName: ${CONTAINER_NAME}"'
WHERE slug = 'xray-vless';
