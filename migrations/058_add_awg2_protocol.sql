-- =====================================================================
-- Migration 058: Add AmneziaWG 2.0 protocol (amneziawg-go userspace)
-- Uses amneziawg-go (Go userspace) instead of kernel module
-- https://github.com/amnezia-vpn/amneziawg-go
-- =====================================================================

-- 1. Insert the protocol entry (clone output_template from amnezia-wg-advanced)
INSERT INTO protocols (name, slug, description, install_script, uninstall_script, output_template, ubuntu_compatible, is_active, definition, created_at, updated_at)
SELECT
  'AmneziaWG 2.0',
  'awg2',
  'AmneziaWG 2.0 — userspace Go implementation (amneziawg-go). No kernel module required.',
  '#!/bin/bash
set -euo pipefail

# Use exported variables from panel (SERVER_PORT, SERVER_CONTAINER) or defaults
CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"
MTU=${MTU:-1420}

# Install git if not available
if ! command -v git &> /dev/null; then
  apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
fi

mkdir -p /opt/amnezia/awg2

# Clone amneziawg-go source for Docker build
if [ ! -d /opt/amnezia/awg2/src ]; then
  git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /opt/amnezia/awg2/src
fi

# Build Docker image using the repo Dockerfile (multi-stage: Go compile + tools)
docker build --no-cache -t amnezia-awg2 /opt/amnezia/awg2/src

# Run container (userspace: no SYS_MODULE, no /lib/modules)
EXISTING=$(docker ps -aq -f "name=$CONTAINER_NAME" 2>/dev/null | head -1)
if [ -z "$EXISTING" ]; then
  docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v /opt/amnezia/awg2:/opt/amnezia/awg amnezia-awg2 sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"

  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ \"$STATUS\" != \"running\" ]; then
    docker start \"$CONTAINER_NAME\" >/dev/null 2>&1 || true
  fi
fi

# Check for existing config
if [ -f /opt/amnezia/awg2/wg0.conf ]; then
  PORT=$(grep -E "^ListenPort" /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  PSK=$(cat /opt/amnezia/awg2/wireguard_psk.key 2>/dev/null || true)
  if [ -z "$PSK" ]; then
    PSK=$(grep -E "^PresharedKey" /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  fi
  PUBKEY=$(cat /opt/amnezia/awg2/wireguard_server_public_key.key 2>/dev/null || true)
  if [ -z "$PUBKEY" ]; then
    PRIVKEY=$(cat /opt/amnezia/awg2/wireguard_server_private_key.key 2>/dev/null || true)
    if [ -n "$PRIVKEY" ]; then
      PUBKEY=$(echo "$PRIVKEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
    fi
  fi

  echo "Using existing AmneziaWG 2.0 configuration"
  echo "Port: ${PORT:-$VPN_PORT}"
  if [ -n "${PUBKEY:-}" ]; then echo "Server Public Key: $PUBKEY"; fi
  if [ -n "${PSK:-}" ]; then echo "PresharedKey = $PSK"; fi

  EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
  echo "Server Host: $EXTERNAL_IP"

  # Output AWG params from existing config
  for P in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
    VAL=$(grep -E "^$P " /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
    if [ -n "$VAL" ]; then echo "Variable: $P=$VAL"; fi
  done
  echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"
  exit 0
fi

# Generate keys
PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

# AWG obfuscation parameters
JC=5
JMIN=50
JMAX=1000
S1_VAL=50
S2_VAL=100
S3_VAL=20
S4_VAL=10
# H1-H4: keep numeric values for broad awg-tools compatibility.
H1_VAL=123456789
H2_VAL=223456789
H3_VAL=323456789
H4_VAL=423456789

# Write config
cat > /opt/amnezia/awg2/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1_VAL
S2 = $S2_VAL
S3 = $S3_VAL
S4 = $S4_VAL
H1 = $H1_VAL
H2 = $H2_VAL
H3 = $H3_VAL
H4 = $H4_VAL
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.1.2/32
EOF

echo "$PRIVATE_KEY" > /opt/amnezia/awg2/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg2/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg2/wireguard_psk.key
echo "[]" > /opt/amnezia/awg2/clientsTable

# Get external IP
EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo "AmneziaWG 2.0 installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
echo "Server Host: $EXTERNAL_IP"
echo "Variable: Jc=$JC"
echo "Variable: Jmin=$JMIN"
echo "Variable: Jmax=$JMAX"
echo "Variable: S1=$S1_VAL"
echo "Variable: S2=$S2_VAL"
echo "Variable: S3=$S3_VAL"
echo "Variable: S4=$S4_VAL"
echo "Variable: H1=$H1_VAL"
echo "Variable: H2=$H2_VAL"
echo "Variable: H3=$H3_VAL"
echo "Variable: H4=$H4_VAL"
echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"',
  '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg2}"

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm -fv "$CONTAINER_NAME" 2>/dev/null || true
docker image rm amnezia-awg2 2>/dev/null || true
rm -rf /opt/amnezia/awg2 2>/dev/null || true

echo "{\"success\":true,\"message\":\"AmneziaWG 2.0 uninstalled\"}"',
  p.output_template,
  1,
  1,
  JSON_OBJECT(
    'engine', 'shell',
    'metadata', JSON_OBJECT(
      'container_name', 'amnezia-awg2',
      'vpn_subnet', '10.8.1.0/24',
      'port_range', JSON_ARRAY(30000, 65000),
      'config_dir', '/opt/amnezia/awg2'
    )
  ),
  NOW(),
  NOW()
FROM protocols p
WHERE p.slug = 'amnezia-wg-advanced'
  AND NOT EXISTS (SELECT 1 FROM protocols WHERE slug = 'awg2');

-- 2. Clone protocol variables from amnezia-wg-advanced to awg2
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT 
  (SELECT id FROM protocols WHERE slug = 'awg2' LIMIT 1),
  src.variable_name,
  src.variable_type,
  src.default_value,
  src.description,
  src.required
FROM protocol_variables src
WHERE src.protocol_id = (SELECT id FROM protocols WHERE slug = 'amnezia-wg-advanced' LIMIT 1)
  AND NOT EXISTS (
    SELECT 1 FROM protocol_variables ev
    WHERE ev.protocol_id = (SELECT id FROM protocols WHERE slug = 'awg2' LIMIT 1)
      AND ev.variable_name = src.variable_name
  );

-- 3. Clone protocol templates from amnezia-wg-advanced to awg2
INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT
  (SELECT id FROM protocols WHERE slug = 'awg2' LIMIT 1),
  src.template_name,
  src.template_content,
  src.is_default
FROM protocol_templates src
WHERE src.protocol_id = (SELECT id FROM protocols WHERE slug = 'amnezia-wg-advanced' LIMIT 1)
  AND NOT EXISTS (
    SELECT 1 FROM protocol_templates et
    WHERE et.protocol_id = (SELECT id FROM protocols WHERE slug = 'awg2' LIMIT 1)
      AND et.template_name = src.template_name
  );

-- 4. Update install_script for existing awg2 protocol (in case migration was already run)
UPDATE protocols SET install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"
MTU=${MTU:-1420}

if ! command -v git &> /dev/null; then
  apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
fi

mkdir -p /opt/amnezia/awg2

if [ ! -d /opt/amnezia/awg2/src ]; then
  git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /opt/amnezia/awg2/src
fi

docker build --no-cache -t amnezia-awg2 /opt/amnezia/awg2/src

EXISTING=$(docker ps -aq -f "name=$CONTAINER_NAME" 2>/dev/null | head -1)
if [ -z "$EXISTING" ]; then
  docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v /opt/amnezia/awg2:/opt/amnezia/awg amnezia-awg2 sh -c "while [ ! -f /opt/amnezia/awg/wg0.conf ]; do sleep 1; done; WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /opt/amnezia/awg/wg0.conf && sleep infinity"
  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ \"$STATUS\" != \"running\" ]; then
    docker start \"$CONTAINER_NAME\" >/dev/null 2>&1 || true
  fi
fi

if [ -f /opt/amnezia/awg2/wg0.conf ]; then
  PORT=$(grep -E "^ListenPort" /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  PSK=$(cat /opt/amnezia/awg2/wireguard_psk.key 2>/dev/null || true)
  if [ -z "$PSK" ]; then
    PSK=$(grep -E "^PresharedKey" /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
  fi
  PUBKEY=$(cat /opt/amnezia/awg2/wireguard_server_public_key.key 2>/dev/null || true)
  if [ -z "$PUBKEY" ]; then
    PRIVKEY=$(cat /opt/amnezia/awg2/wireguard_server_private_key.key 2>/dev/null || true)
    if [ -n "$PRIVKEY" ]; then
      PUBKEY=$(echo "$PRIVKEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
    fi
  fi

  echo "Using existing AmneziaWG 2.0 configuration"
  echo "Port: ${PORT:-$VPN_PORT}"
  if [ -n "${PUBKEY:-}" ]; then echo "Server Public Key: $PUBKEY"; fi
  if [ -n "${PSK:-}" ]; then echo "PresharedKey = $PSK"; fi

  EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
  echo "Server Host: $EXTERNAL_IP"

  for P in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
    VAL=$(grep -E "^$P " /opt/amnezia/awg2/wg0.conf | cut -d= -f2 | tr -d "[:space:]")
    if [ -n "$VAL" ]; then echo "Variable: $P=$VAL"; fi
  done
  echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"
  exit 0
fi

PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

JC=5
JMIN=50
JMAX=1000
S1_VAL=50
S2_VAL=100
S3_VAL=20
S4_VAL=10
H1_VAL=123456789
H2_VAL=223456789
H3_VAL=323456789
H4_VAL=423456789

cat > /opt/amnezia/awg2/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1_VAL
S2 = $S2_VAL
S3 = $S3_VAL
S4 = $S4_VAL
H1 = $H1_VAL
H2 = $H2_VAL
H3 = $H3_VAL
H4 = $H4_VAL
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.1.2/32
EOF

echo "$PRIVATE_KEY" > /opt/amnezia/awg2/wireguard_server_private_key.key
echo "$PUBLIC_KEY" > /opt/amnezia/awg2/wireguard_server_public_key.key
echo "$PRESHARED_KEY" > /opt/amnezia/awg2/wireguard_psk.key
echo "[]" > /opt/amnezia/awg2/clientsTable

EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo "AmneziaWG 2.0 installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
echo "Server Host: $EXTERNAL_IP"
echo "Variable: Jc=$JC"
echo "Variable: Jmin=$JMIN"
echo "Variable: Jmax=$JMAX"
echo "Variable: S1=$S1_VAL"
echo "Variable: S2=$S2_VAL"
echo "Variable: S3=$S3_VAL"
echo "Variable: S4=$S4_VAL"
echo "Variable: H1=$H1_VAL"
echo "Variable: H2=$H2_VAL"
echo "Variable: H3=$H3_VAL"
echo "Variable: H4=$H4_VAL"
echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"'
WHERE slug = 'awg2';

-- 5. Update output_template for AWG2 (add S3/S4 padding params)
UPDATE protocols SET output_template = '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = {{dns_servers}}
MTU = 1280
Jc = {{Jc}}
Jmin = {{Jmin}}
Jmax = {{Jmax}}
S1 = {{S1}}
S2 = {{S2}}
S3 = {{S3}}
S4 = {{S4}}
H1 = {{H1}}
H2 = {{H2}}
H3 = {{H3}}
H4 = {{H4}}

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25'
WHERE slug = 'awg2';

-- 6. Add S3/S4 protocol variables for awg2
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'S3', 'number', '20', 'Padding of handshake cookie message', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'S3');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'S4', 'number', '10', 'Padding of transport messages', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'S4');
