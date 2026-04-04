-- Fix X-Ray port to 443 to match Android client and avoid firewall issues.
-- Previous usage of random ports caused connection failures on restricted networks.
UPDATE protocols
SET install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"
# Default to port 443 if SERVER_PORT is not provided
XRAY_PORT=${SERVER_PORT:-443}

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

C="/opt/amnezia/xray/server.json"
echo "{" > "$C"
echo "  \\\"log\\\": { \\\"loglevel\\\": \\\"warning\\\" }," >> "$C"
echo "  \\\"inbounds\\\": [" >> "$C"
echo "    {" >> "$C"
echo "      \\\"listen\\\": \\\"0.0.0.0\\\"," >> "$C"
echo "      \\\"port\\\": $XRAY_PORT," >> "$C"
echo "      \\\"protocol\\\": \\\"vless\\\"," >> "$C"
echo "      \\\"settings\\\": {" >> "$C"
echo "        \\\"clients\\\": [ { \\\"id\\\": \\\"$CLIENT_ID\\\", \\\"flow\\\": \\\"xtls-rprx-vision\\\" } ]," >> "$C"
echo "        \\\"decryption\\\": \\\"none\\\"" >> "$C"
echo "      }," >> "$C"
echo "      \\\"streamSettings\\\": {" >> "$C"
echo "        \\\"network\\\": \\\"tcp\\\"," >> "$C"
echo "        \\\"security\\\": \\\"reality\\\"," >> "$C"
echo "        \\\"realitySettings\\\": {" >> "$C"
echo "          \\\"show\\\": false," >> "$C"
echo "          \\\"dest\\\": \\\"$SERVER_NAME:443\\\"," >> "$C"
echo "          \\\"xver\\\": 0," >> "$C"
echo "          \\\"serverNames\\\": [ \\\"$SERVER_NAME\\\" ]," >> "$C"
echo "          \\\"privateKey\\\": \\\"$PRIVATE_KEY\\\"," >> "$C"
echo "          \\\"shortIds\\\": [ \\\"$SHORT_ID\\\" ]," >> "$C"
echo "          \\\"fingerprint\\\": \\\"$FINGERPRINT\\\"," >> "$C"
echo "          \\\"spiderX\\\": \\\"$SPIDER_X\\\"" >> "$C"
echo "        }" >> "$C"
echo "      }" >> "$C"
echo "    }" >> "$C"
echo "  ]," >> "$C"
echo "  \\\"outbounds\\\": [ { \\\"protocol\\\": \\\"freedom\\\", \\\"tag\\\": \\\"direct\\\" } ]" >> "$C"
echo "}" >> "$C"

docker run -d \
  --name "$CONTAINER_NAME" \
  --restart always \
  -p "${XRAY_PORT}:${XRAY_PORT}" \
  -v /opt/amnezia/xray:/opt/amnezia/xray \
  teddysun/xray xray run -c /opt/amnezia/xray/server.json

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
