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
  # Check for broken config
  if grep -Fq ''$PRIVATE_KEY'' /opt/amnezia/awg/wg0.conf; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  if grep -Eiq "^S3[[:space:]]*=" /opt/amnezia/awg/wg0.conf; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  # Check for invalid hex parameters H
  if grep -Eiq "^H[1-4][[:space:]]*=[[:space:]]*0x" /opt/amnezia/awg/wg0.conf; then
    rm -f /opt/amnezia/awg/wg0.conf
  fi
  # Check for insecure defaults (1, 2, 3, 4)
  if grep -Eiq "^H1[[:space:]]*=[[:space:]]*1$" /opt/amnezia/awg/wg0.conf; then
     # Only remove if H2=2 etc also match? Or just safe to regenerate if H1=1 (insecure)
     rm -f /opt/amnezia/awg/wg0.conf
  fi
fi

# Check for existing configuration on HOST first (preferred persistence)
if [ -f /opt/amnezia/awg/wg0.conf ]; then
  echo "Found existing configuration on host."
  
  PORT=$(grep -E "^ListenPort" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  VPN_PORT=${PORT:-$VPN_PORT}
  
  STATUS=0
  check_container || STATUS=$?
  
  if [ $STATUS -ne 0 ]; then
     echo "Starting container..."
     docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules -v /opt/amnezia/awg:/opt/amnezia/awg amneziavpn/amnezia-wg:latest sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; wg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
     sleep 2
  fi
  
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
  echo "Port: $VPN_PORT"
  if [ -n "${PUBKEY:-}" ]; then echo "Server Public Key: $PUBKEY"; fi
  if [ -n "${PSK:-}" ]; then echo "PresharedKey: $PSK"; fi
  
  # Output variables for preview
  echo "Variable: server_port=$VPN_PORT"
  echo "Variable: server_public_key=$PUBKEY"
  echo "Variable: preshared_key=$PSK"
  
  # Extract actual params
  JC=$(grep -E "^Jc" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  H1=$(grep -E "^H1" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  echo "Variable: Jc=${JC:-5}"
  echo "Variable: H1=${H1:-$((RANDOM * 1000 + RANDOM))}"
  
  exit 0
fi

# Generate new config
PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

# Generate Random Obfuscation Params
JC=$(( (RANDOM % 8) + 3 ))
JMIN=50
JMAX=$(( (RANDOM % 500) + 500 ))
S1=$(( (RANDOM % 150) + 50 ))
S2=$(( (RANDOM % 150) + 50 ))
# Using od for larger range 32-bit ints
H1=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d "[:space:]")
H2=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d "[:space:]")
H3=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d "[:space:]")
H4=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d "[:space:]")

cat > /opt/amnezia/awg/wg0.conf << WG_CONF
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
WG_CONF

echo "$PRIVATE_KEY" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg/wireguard_psk.key
echo "[]" > /opt/amnezia/awg/clientsTable

echo "AmneziaWG Advanced installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey: $PRESHARED_KEY"

echo "Variable: server_port=$VPN_PORT"
echo "Variable: server_public_key=$PUBLIC_KEY"
echo "Variable: preshared_key=$PRESHARED_KEY"
echo "Variable: Jc=$JC"
echo "Variable: Jmin=$JMIN"
echo "Variable: H1=$H1"
echo "Variable: H2=$H2"
echo "Variable: H3=$H3"
echo "Variable: H4=$H4"
' 
WHERE slug = 'amnezia-wg-advanced';
