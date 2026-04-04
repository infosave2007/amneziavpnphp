-- Fix AWG Advanced install script: create container BEFORE generating keys
-- The issue was that the script tried to call docker exec wg genkey before the container existed
UPDATE protocols SET 
  install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT=${VPN_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}
MTU=${MTU:-1420}

mkdir -p /opt/amnezia/awg

# Check if container exists and is running
container_running() {
  docker inspect --format="{{.State.Running}}" "$CONTAINER_NAME" 2>/dev/null | grep -q true
}

# Clean up broken configs
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  if grep -q "PRIVATE_KEY" /opt/amnezia/awg/wg0.conf 2>/dev/null; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  if grep -Eiq "^S3[[:space:]]*=" /opt/amnezia/awg/wg0.conf 2>/dev/null; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  if grep -Eiq "^H[1-4][[:space:]]*=[[:space:]]*0x" /opt/amnezia/awg/wg0.conf 2>/dev/null; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  if grep -Eiq "^H1[[:space:]]*=[[:space:]]*1$" /opt/amnezia/awg/wg0.conf 2>/dev/null; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
fi

# If valid config exists, just ensure container is running
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  echo "Found existing configuration"
  VPN_PORT=$(grep -E "^ListenPort" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " " || echo "$VPN_PORT")
  
  if ! container_running; then
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules -v /opt/amnezia/awg:/opt/amnezia/awg amneziavpn/amnezia-wg:latest sh -c "wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
    sleep 3
    # Force reload interface to apply AWG params
    docker exec "$CONTAINER_NAME" ip link del wg0 2>/dev/null || true
    docker exec "$CONTAINER_NAME" wg-quick up /opt/amnezia/awg/wg0.conf
  fi
  
  PUBKEY=$(cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || echo "")
  PSK=$(cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || echo "")
  JC=$(grep -E "^Jc" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  JMIN=$(grep -E "^Jmin" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  JMAX=$(grep -E "^Jmax" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  S1=$(grep -E "^S1" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  S2=$(grep -E "^S2" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  H1=$(grep -E "^H1" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  H2=$(grep -E "^H2" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  H3=$(grep -E "^H3" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  H4=$(grep -E "^H4" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d " ")
  
  echo "Using existing AmneziaWG configuration"
  echo "Variable: server_port=$VPN_PORT"
  echo "Variable: server_public_key=$PUBKEY"
  echo "Variable: preshared_key=$PSK"
  echo "Variable: container_name=$CONTAINER_NAME"
  echo "Variable: Jc=$JC"
  echo "Variable: Jmin=$JMIN"
  echo "Variable: Jmax=$JMAX"
  echo "Variable: S1=$S1"
  echo "Variable: S2=$S2"
  echo "Variable: H1=$H1"
  echo "Variable: H2=$H2"
  echo "Variable: H3=$H3"
  echo "Variable: H4=$H4"
  exit 0
fi

# FRESH INSTALL
echo "Starting fresh AmneziaWG Advanced installation..."

# Remove old container if exists
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Start container FIRST so we can use wg tools inside it
docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules -v /opt/amnezia/awg:/opt/amnezia/awg amneziavpn/amnezia-wg:latest sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
sleep 3

# Generate keys using the container
PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

# Generate random obfuscation parameters
JC=$((RANDOM % 8 + 3))
JMIN=50
JMAX=$((RANDOM % 500 + 500))
S1=$((RANDOM % 150 + 50))
S2=$((RANDOM % 150 + 50))
H1=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d " ")
H2=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d " ")
H3=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d " ")
H4=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d " ")

# Create config file
cat > /opt/amnezia/awg/wg0.conf << WGCONF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
WGCONF

# Save keys
echo "$PRIVATE_KEY" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg/wireguard_psk.key
echo "[]" > /opt/amnezia/awg/clientsTable

# Restart container and explicitly reload WG interface to apply AWG params
docker restart "$CONTAINER_NAME"
sleep 2

# CRITICAL: Force reload interface to apply AWG obfuscation parameters
docker exec "$CONTAINER_NAME" ip link del wg0 2>/dev/null || true
docker exec "$CONTAINER_NAME" wg-quick up /opt/amnezia/awg/wg0.conf
sleep 1

echo "AmneziaWG Advanced installed successfully"
echo "Variable: server_port=$VPN_PORT"
echo "Variable: server_public_key=$PUBLIC_KEY"
echo "Variable: preshared_key=$PRESHARED_KEY"
echo "Variable: container_name=$CONTAINER_NAME"
echo "Variable: Jc=$JC"
echo "Variable: Jmin=$JMIN"
echo "Variable: Jmax=$JMAX"
echo "Variable: S1=$S1"
echo "Variable: S2=$S2"
echo "Variable: H1=$H1"
echo "Variable: H2=$H2"
echo "Variable: H3=$H3"
echo "Variable: H4=$H4"
' 
WHERE slug = 'amnezia-wg-advanced';
