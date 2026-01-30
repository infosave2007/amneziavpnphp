-- Enable single IP enforcement for XRay VLESS protocol
-- Adds:
-- 1. statsUserOnline for tracking online connections
-- 2. RoutingService for dynamic IP blocking
-- 3. blocked outbound (blackhole) for dropping unwanted traffic
-- 4. vless-in tag on main inbound for targeting rules

UPDATE protocols SET install_script = '#!/bin/bash
set -eu

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"
XRAY_PORT=${SERVER_PORT:-443}

docker pull teddysun/xray >/dev/null 2>&1 || true

# Use existing keys if provided, otherwise generate new ones
if [ -z "${PRIVATE_KEY:-}" ]; then
  GEN=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 2>/dev/null || true)
  PRIVATE_KEY=$(printf "%s\\n" "$GEN" | sed -n -E "s/^[Pp]rivate[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n")
  if [ -z "$PRIVATE_KEY" ]; then
    PRIVATE_KEY=$(printf "%s\\n" "$GEN" | grep -i "private" | head -1 | sed "s/.*:[[:space:]]*//" | tr -d " \\t\\r\\n")
  fi
fi

# Derive public key from private key
PUBLIC_KEY=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null | sed -n -E "s/^[Pp]ublic[[:space:]]*[Kk]ey:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n" || true)
if [ -z "$PUBLIC_KEY" ]; then
  PUBLIC_KEY=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null | sed -n -E "s/^[Pp]assword:[[:space:]]*(.*)$/\\1/p" | tr -d " \\t\\r\\n" || true)
fi

# Use existing short_id or generate new one
if [ -z "${SHORT_ID:-}" ]; then
  SHORT_ID=$(od -An -tx1 -N8 /dev/urandom | tr -d " \\n")
fi

# Use existing client_id or generate new one
if [ -z "${CLIENT_ID:-}" ]; then
  CLIENT_ID=$(cat /proc/sys/kernel/random/uuid)
fi

SERVER_NAME="${SERVER_NAME:-www.googletagmanager.com}"
FINGERPRINT="${FINGERPRINT:-chrome}"
SPIDER_X="${SPIDER_X:-/}"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
mkdir -p /opt/amnezia/xray

cat > /opt/amnezia/xray/server.json <<EOJSON
{
  "log": { "loglevel": "warning" },
  "stats": {},
  "api": {
    "tag": "api",
    "services": [ "StatsService", "RoutingService" ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": ${XRAY_PORT},
    "protocol": "vless",
    "tag": "vless-in",
    "settings": {
      "clients": [{ "id": "${CLIENT_ID}", "flow": "xtls-rprx-vision", "email": "${CLIENT_ID}", "level": 0 }],
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
  },
  {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "tag": "api",
      "settings": {
        "address": "127.0.0.1"
      }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "rules": [
      {
        "inboundTag": [ "api" ],
        "outboundTag": "api",
        "type": "field"
      }
    ]
  }
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
echo "ContainerName: ${CONTAINER_NAME}"
'
WHERE slug = 'xray-vless';
