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

# Validate existing config
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  # Check for unexpanded variables
  if grep -Fq ''$PRIVATE_KEY'' /opt/amnezia/awg/wg0.conf; then
    echo "Detected broken configuration (unexpanded variables). Removing..."
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  # Check for invalid parameters S3/S4
  if grep -Eiq "^S3[[:space:]]*=" /opt/amnezia/awg/wg0.conf || grep -Eiq "^S4[[:space:]]*=" /opt/amnezia/awg/wg0.conf; then
    echo "Detected invalid parameters (S3/S4). Removing config to regenerate..."
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  # Check for hex H-params
  if grep -Eiq "^H[1-4][[:space:]]*=[[:space:]]*0x" /opt/amnezia/awg/wg0.conf; then
    echo "Detected invalid hex parameters (H1-H4). Removing config to regenerate..."
    rm -f /opt/amnezia/awg/wg0.conf
  fi
fi

# Check for existing configuration on HOST first (preferred persistence)
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  echo "Found existing configuration on host."
  
  STATUS=0
  check_container || STATUS=$?
  
  if [ $STATUS -eq 2 ]; then
    echo "Container is in restart loop. Recreating..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  elif [ $STATUS -eq 1 ]; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  
  if ! docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
     # Run container with volume mount - SINGLE LINE
     docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules -v /opt/amnezia/awg:/opt/amnezia/awg amneziavpn/amnezia-wg:latest sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
     sleep 2
  fi
  
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

# Rescue logic
STATUS=0
check_container || STATUS=$?
HAS_RESCUED=0

if [ $STATUS -eq 2 ] || [ $STATUS -eq 0 ]; then
  echo "Checking for config in existing container..."
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  
  if docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wg0.conf /opt/amnezia/awg/wg0.conf 2>/dev/null; then
     # Validate rescued config
     IS_BROKEN=0
     if grep -Fq ''$PRIVATE_KEY'' /opt/amnezia/awg/wg0.conf; then IS_BROKEN=1; fi
     if grep -Eiq "^S3[[:space:]]*=" /opt/amnezia/awg/wg0.conf; then IS_BROKEN=1; fi
     if grep -Eiq "^H[1-4][[:space:]]*=[[:space:]]*0x" /opt/amnezia/awg/wg0.conf; then IS_BROKEN=1; fi
     
     if [ "$IS_BROKEN" = "1" ]; then
        echo "Rescued config is broken. Discarding."
        rm -f /opt/amnezia/awg/wg0.conf
     else
        echo "Rescued config from container."
        docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true
        docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_public_key.key /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || true
        docker cp "$CONTAINER_NAME":/opt/amnezia/awg/wireguard_server_private_key.key /opt/amnezia/awg/wireguard_server_private_key.key 2>/dev/null || true
        HAS_RESCUED=1
     fi
  fi
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# Start container (Fresh or Rescued)
docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules -v /opt/amnezia/awg:/opt/amnezia/awg amneziavpn/amnezia-wg:latest sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"

sleep 2

if [ "$HAS_RESCUED" = "1" ]; then
  # Extract and exit
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

# Generate new config
PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

# Use WG_CONF delimiter to avoid EOF replacement in PHP
cat > /opt/amnezia/awg/wg0.conf << WG_CONF
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
H1 = 1
H2 = 2
H3 = 3
H4 = 4
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.1.2/32
WG_CONF

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
