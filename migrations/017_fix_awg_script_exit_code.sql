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

# Function to check if container is healthy
check_container() {
  local status
  status=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "missing")
  if [ "$status" = "running" ]; then
    return 0
  elif [ "$status" = "restarting" ]; then
    return 2 # Restarting loop
  else
    return 1 # Stopped or missing
  fi
}

# Check for existing configuration on HOST first (preferred persistence)
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  echo "Found existing configuration on host."
  
  # Ensure container is running correctly
  STATUS=0
  check_container || STATUS=$?
  
  if [ $STATUS -eq 2 ]; then
    echo "Container is in restart loop. Recreating..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif [ $STATUS -eq 1 ]; then
    # If stopped but exists, remove to recreate with correct flags
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  
  # If container is missing (or we just removed it), create it
  if ! docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
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
      
      # Wait a moment for it to start
      sleep 2
  fi
  
  # Extract config from HOST file
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

# If no host config, check if container exists and try to rescue config
STATUS=0
check_container || STATUS=$?

if [ $STATUS -eq 2 ]; then
  echo "Container is restarting and no host config found. Attempting to rescue config..."
  # Try to copy from container even if restarting (might fail if container is crashing too fast)
  if docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wg0.conf /opt/amnezia/awg/wg0.conf 2>/dev/null; then
     echo "Rescued config from broken container."
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_public_key.key /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || true
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_private_key.key /opt/amnezia/awg/wireguard_server_private_key.key 2>/dev/null || true
     
     # Now recreate container with rescue config
     docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
     HAS_RESCUED=1
  else
     echo "Could not rescue config. Removing broken container."
     docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
     HAS_RESCUED=0
  fi
elif [ $STATUS -eq 0 ]; then
  # Running. Check if it has config inside but not on host (old version)
  if docker exec "$CONTAINER_NAME" [ -f /opt/amnezia/awg/wg0.conf ]; then
     echo "Container running with internal config. Migrating to host..."
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wg0.conf /opt/amnezia/awg/wg0.conf
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_public_key.key /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || true
     docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_private_key.key /opt/amnezia/awg/wireguard_server_private_key.key 2>/dev/null || true
     
     # Recreate to add volume mount
     docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
     HAS_RESCUED=1
  else
     # Running but no config? Weird. Treat as fresh.
     docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
     HAS_RESCUED=0
  fi
else
  HAS_RESCUED=0
fi

# If we rescued config, we need to start the container with mounts
if [ "$HAS_RESCUED" = "1" ]; then
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
  
  # Extract and exit (same logic as top)
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

# FRESH INSTALL
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

PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

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

echo "$PRIVATE_KEY" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg/wireguard_psk.key
echo "[]" > /opt/amnezia/awg/clientsTable

echo "AmneziaWG Advanced installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
' 
WHERE slug = 'amnezia-wg-advanced';
