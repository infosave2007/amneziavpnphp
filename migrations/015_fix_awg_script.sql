UPDATE protocols SET 
  install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT=${VPN_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}
MTU=${MTU:-1420}

# Ensure host directory exists for persistence
mkdir -p /opt/amnezia/awg

EXISTING=$(docker ps -aq -f "name=$CONTAINER_NAME" 2>/dev/null | head -1)
if [ -z "$EXISTING" ]; then
  # Run container with volume mount and keepalive command
  # Waits for config file to appear before starting WireGuard
  docker run -d --name "$CONTAINER_NAME" \
    --restart always \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    -p "${VPN_PORT}:${VPN_PORT}/udp" \
    -v /lib/modules:/lib/modules \
    -v /opt/amnezia/awg:/opt/amnezia/awg \
    amneziavpn/amnezia-wg:latest \
    sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
  
  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ "$STATUS" != "running" ]; then
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

# Check for existing config
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  # Extract existing configuration
  PORT=$(grep -E "^ListenPort" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  PSK=$(cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true)
  if [ -z "$PSK" ]; then
    PSK=$(grep -E "^PresharedKey" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  fi
  PUBKEY=$(cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || true)
  if [ -z "$PUBKEY" ]; then
    PRIVKEY=$(cat /opt/amnezia/awg/wireguard_server_private_key.key 2>/dev/null || true)
    if [ -n "$PRIVKEY" ]; then
      PUBKEY=$(echo "$PRIVKEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
    fi
  fi
  
  echo "Using existing AmneziaWG configuration"
  echo "Port: ${PORT:-$VPN_PORT}"
  if [ -n "${PUBKEY:-}" ]; then echo "Server Public Key: $PUBKEY"; fi
  if [ -n "${PSK:-}" ]; then echo "PresharedKey = $PSK"; fi
  exit 0
fi

# Generate keys using the container
PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

# Write config to HOST file (mounted to container)
cat > /opt/amnezia/awg/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = 5
Jmin = 100
Jmax = 200
S1 = 50
S2 = 100
S3 = 20
S4 = 10
H1 = 0xDEADBEEF
H2 = 0xCAFEBABE
H3 = 0x12345678
H4 = 0x9ABCDEF0
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.1.2/32
EOF

# Save keys to files on host
echo "$PRIVATE_KEY" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg/wireguard_psk.key
echo "[]" > /opt/amnezia/awg/clientsTable

# Container is already waiting for config (loop), so it should pick it up automatically.
# But we can also force it if needed, or just wait a moment.
# The loop is: while [ ! -f ... ]; do sleep 1; done; wg-quick up ...
# Since we just wrote the file, the loop will exit and run wg-quick up.

echo "AmneziaWG Advanced installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
' 
WHERE slug = 'amnezia-wg-advanced';
