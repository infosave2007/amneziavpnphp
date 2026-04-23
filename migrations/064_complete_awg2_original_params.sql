-- Complete AWG2 support with original Amnezia parameters, including I1-I5.

UPDATE protocols
SET output_template = '[Interface]
Address = {{client_ip}}/32
DNS = {{dns_servers}}
PrivateKey = {{private_key}}
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
I1 = {{I1}}
I2 = {{I2}}
I3 = {{I3}}
I4 = {{I4}}
I5 = {{I5}}

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25',
    install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"
MTU=${MTU:-1280}

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
  docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v /opt/amnezia/awg2:/opt/amnezia/awg amnezia-awg2 sh -c "while [ ! -f /opt/amnezia/awg/awg0.conf ]; do sleep 1; done; WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /opt/amnezia/awg/awg0.conf && sleep infinity"
  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ "$STATUS" != "running" ]; then
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi
# Check for existing config: first on host, then inside container (native Amnezia app installs)
CONF_FILE="/opt/amnezia/awg2/awg0.conf"
if [ ! -f "$CONF_FILE" ]; then
  # Try to extract config from inside the container (native Amnezia app stores config without volume mount)
  CONTAINER_CONF=$(docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/awg0.conf 2>/dev/null || true)
  if [ -n "$CONTAINER_CONF" ] && echo "$CONTAINER_CONF" | grep -q "\\[Interface\\]"; then
    mkdir -p /opt/amnezia/awg2
    echo "$CONTAINER_CONF" > /opt/amnezia/awg2/awg0.conf
    # Also extract keys if available
    docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_server_private_key.key > /opt/amnezia/awg2/wireguard_server_private_key.key 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_server_public_key.key > /opt/amnezia/awg2/wireguard_server_public_key.key 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_psk.key > /opt/amnezia/awg2/wireguard_psk.key 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/clientsTable > /opt/amnezia/awg2/clientsTable 2>/dev/null || true
    echo "Extracted existing config from container"
  fi
fi

if [ -f /opt/amnezia/awg2/awg0.conf ]; then
  PORT=$(grep -E "^ListenPort" /opt/amnezia/awg2/awg0.conf | cut -d= -f2 | tr -d "[:space:]")
  PSK=$(cat /opt/amnezia/awg2/wireguard_psk.key 2>/dev/null || true)
  if [ -z "$PSK" ]; then
    PSK=$(grep -E "^PresharedKey" /opt/amnezia/awg2/awg0.conf | head -1 | cut -d= -f2 | tr -d "[:space:]")
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

  for P in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5; do
    VAL=$(sed -n -E "s/^[[:space:]]*$P[[:space:]]*=[[:space:]]*//p" /opt/amnezia/awg2/awg0.conf | head -1 | tr -d "\\r")
    if [ -n "$VAL" ] || [[ "$P" =~ ^I[2-5]$ ]]; then echo "Variable: $P=$VAL"; fi
  done
  echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"
  exit 0
fi

PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

JC=5
JMIN=10
JMAX=50
S1_VAL=51
S2_VAL=125
S3_VAL=13
S4_VAL=9
H1_VAL="1443912531-1981073285"
H2_VAL="1984025557-2135018048"
H3_VAL="2145217268-2146643749"
H4_VAL="2146790761-2146860793"
I1_VAL="<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
I2_VAL=""
I3_VAL=""
I4_VAL=""
I5_VAL=""

{
echo "[Interface]"
echo "PrivateKey = $PRIVATE_KEY"
echo "Address = 10.8.1.1/24"
echo "ListenPort = $VPN_PORT"
echo "Jc = $JC"
echo "Jmin = $JMIN"
echo "Jmax = $JMAX"
echo "S1 = $S1_VAL"
echo "S2 = $S2_VAL"
echo "S3 = $S3_VAL"
echo "S4 = $S4_VAL"
echo "H1 = $H1_VAL"
echo "H2 = $H2_VAL"
echo "H3 = $H3_VAL"
echo "H4 = $H4_VAL"
echo "I1 = $I1_VAL"
echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
} > /opt/amnezia/awg2/awg0.conf

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
echo "Variable: I1=$I1_VAL"
echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"'
WHERE slug = 'awg2';

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I1', 'text', '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>', 'Original AmneziaWG packet template I1', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'I1');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I2', 'text', '', 'Original AmneziaWG packet template I2', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'I2');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I3', 'text', '', 'Original AmneziaWG packet template I3', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'I3');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I4', 'text', '', 'Original AmneziaWG packet template I4', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'I4');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'I5', 'text', '', 'Original AmneziaWG packet template I5', false
FROM protocols p WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'I5');

UPDATE protocol_variables pv
JOIN protocols p ON p.id = pv.protocol_id
SET pv.default_value = CASE pv.variable_name
    WHEN 'Jc' THEN '5'
    WHEN 'Jmin' THEN '10'
    WHEN 'Jmax' THEN '50'
    WHEN 'S1' THEN '51'
    WHEN 'S2' THEN '125'
    WHEN 'S3' THEN '13'
    WHEN 'S4' THEN '9'
    WHEN 'H1' THEN '1443912531-1981073285'
    WHEN 'H2' THEN '1984025557-2135018048'
    WHEN 'H3' THEN '2145217268-2146643749'
    WHEN 'H4' THEN '2146790761-2146860793'
    ELSE pv.default_value
END
WHERE p.slug = 'awg2'
  AND pv.variable_name IN ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4');

-- Fix awg_params for all existing servers using awg2 protocol
-- Problem: H1-H4 parameters were stored with single values instead of "value1-value2" format
-- This was causing QR codes to be detected as "legacy" instead of proper AmneziaWG 2.0 format
UPDATE vpn_servers
SET awg_params = '{"JC":5,"JMIN":10,"JMAX":50,"S1":51,"S2":125,"S3":13,"S4":9,"H1":"1443912531-1981073285","H2":"1984025557-2135018048","H3":"2145217268-2146643749","H4":"2146790761-2146860793","I1":"<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>","I2":"","I3":"","I4":"","I5":""}'
WHERE install_protocol = 'awg2';