-- Isolated, source-pinned AmneziaWG 3.1 protocol. Existing AWG rows are untouched.
INSERT INTO protocols (name, slug, description, install_script, uninstall_script, output_template, ubuntu_compatible, is_active, definition, created_at, updated_at)
SELECT
  'AmneziaWG 3.1', 'awg31',
  'AmneziaWG 3.1 userspace engine pinned to audited upstream source commits.',
  '#!/bin/bash
set -euo pipefail
missing=""
command -v git >/dev/null 2>&1 || missing="$missing git"
command -v ss >/dev/null 2>&1 || missing="$missing iproute2"
if [ -n "$missing" ]; then
  command -v apt-get >/dev/null 2>&1 || { echo "AWG31 prerequisites missing:$missing (install git and iproute2)" >&2; exit 41; }
  DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y git iproute2 >/dev/null
fi
command -v git >/dev/null 2>&1 && command -v ss >/dev/null 2>&1 || { echo "AWG31 prerequisites unavailable after install: git iproute2" >&2; exit 41; }
ROOT=/opt/amnezia/awg31
SRC="$ROOT/src"
ENGINE_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
TOOLS_COMMIT=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
CONTAINER_NAME=amnezia-awg31
IMAGE_NAME=amnezia-awg31
VPN_PORT="${SERVER_PORT:?SERVER_PORT is required}"
mkdir -p "$ROOT"
if [ -f "$ROOT/awg0.conf" ]; then
  EXISTING_PORT=$(sed -n "s/^[[:space:]]*ListenPort[[:space:]]*=[[:space:]]*//p" "$ROOT/awg0.conf" | head -1)
  printf "%s" "$EXISTING_PORT" | grep -Eq "^[0-9]+$" || { echo "Invalid existing AWG31 ListenPort" >&2; exit 44; }
  VPN_PORT="$EXISTING_PORT"
fi
if [ -d "$SRC/.git" ]; then
  test "$(git -C "$SRC" rev-parse HEAD)" = "$ENGINE_COMMIT" || { echo "provenance failure: existing AWG31 source is at another commit" >&2; exit 42; }
else
  test ! -e "$SRC" || { echo "provenance failure: source path exists without git metadata" >&2; exit 42; }
  git clone https://github.com/amnezia-vpn/amneziawg-go.git "$SRC"
  git -C "$SRC" checkout --detach "$ENGINE_COMMIT"
fi
test "$(git -C "$SRC" rev-parse HEAD)" = "$ENGINE_COMMIT"
git -C "$SRC" reset --hard "$ENGINE_COMMIT" >/dev/null
git -C "$SRC" clean -fdx >/dev/null
# The upstream engine Dockerfile pins a release tag. Replace that build ARG
# with the adopted immutable tools commit and verify the resulting source.
sed -i "s|^ARG AWGTOOLS_COMMIT=.*|ARG AWGTOOLS_COMMIT=$TOOLS_COMMIT|" "$SRC/Dockerfile"
grep -Fq "ARG AWGTOOLS_COMMIT=$TOOLS_COMMIT" "$SRC/Dockerfile"
test "$(git -C "$SRC" status --porcelain | head -1)" = " M Dockerfile"
test "$(git -C "$SRC" status --porcelain | wc -l)" -eq 1
DOCKERFILE_SHA=$(sha256sum "$SRC/Dockerfile" | cut -c1-64)
if ss -lunH | grep -Eq "[:.]${VPN_PORT}[[:space:]]"; then
  docker inspect "$CONTAINER_NAME" >/dev/null 2>&1 || { echo "UDP port already occupied" >&2; exit 43; }
fi
docker build --pull=false --label "org.opencontainers.image.revision=$ENGINE_COMMIT" --label "io.amnezia.awgtools.revision=$TOOLS_COMMIT" --label "io.amnezia.awg31.dockerfile-sha256=$DOCKERFILE_SHA" -t "$IMAGE_NAME" "$SRC"
if [ -f "$ROOT/awg0.conf" ]; then
  test "$(git -C "$SRC" rev-parse HEAD)" = "$ENGINE_COMMIT"
else
  PRIVATE_KEY=$(docker run --rm "$IMAGE_NAME" wg genkey)
  PUBLIC_KEY=$(printf "%s" "$PRIVATE_KEY" | docker run --rm -i "$IMAGE_NAME" wg pubkey)
  PRESHARED_KEY=$(docker run --rm "$IMAGE_NAME" wg genpsk)
  HEADER_KEY="${AWG31_HEADER_PROTECTION_KEY:-$(docker run --rm "$IMAGE_NAME" wg genkey)}"
  JC="${AWG31_JC:-$((4 + RANDOM % 3))}"
  JMIN="${AWG31_JMIN:-10}"; JMAX="${AWG31_JMAX:-50}"
  S1="${AWG31_S1:-12}"; S2="${AWG31_S2:-12}"; S3="${AWG31_S3:-12}"; S4="${AWG31_S4:-12}"
  H1="${AWG31_H1:-1}"; H2="${AWG31_H2:-2}"; H3="${AWG31_H3:-3}"; H4="${AWG31_H4:-4}"
  I1="${AWG31_I1:-<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>}"
  REKEY_AFTER="${AWG31_REKEY_AFTER_TIME:-100-120}"; REKEY_TIMEOUT="${AWG31_REKEY_TIMEOUT:-3-7}"
  REJECT_AFTER="${AWG31_REJECT_AFTER_TIME:-150-180}"; KEEPALIVE_TIMEOUT="${AWG31_KEEPALIVE_TIMEOUT:-5-15}"
  MAX_ATTEMPTS="${AWG31_MAX_HANDSHAKE_ATTEMPTS:-15-20}"
  RANDOM_TRAILERS="${AWG31_RANDOM_TRAILERS:-on}"; DISABLE_COOKIES="${AWG31_DISABLE_COOKIES:-on}"
  {
    echo "[Interface]"
    echo "PrivateKey = $PRIVATE_KEY"; echo "Address = 10.8.31.1/24"; echo "ListenPort = $VPN_PORT"; echo "MTU = 1280"
    echo "Jc = $JC"; echo "Jmin = $JMIN"; echo "Jmax = $JMAX"
    echo "S1 = $S1"; echo "S2 = $S2"; echo "S3 = $S3"; echo "S4 = $S4"
    echo "H1 = $H1"; echo "H2 = $H2"; echo "H3 = $H3"; echo "H4 = $H4"
    echo "I1 = $I1"
    for n in 2 3 4 5; do v=$(printenv "AWG31_I$n" 2>/dev/null || true); test -z "$v" || echo "I$n = $v"; done
    echo "HeaderProtectionKey = $HEADER_KEY"
    test -z "${AWG31_CONTENT_PADDING_ADDITION:-}" || echo "ContentPaddingAddition = $AWG31_CONTENT_PADDING_ADDITION"
    echo "RekeyAfterTime = $REKEY_AFTER"; echo "RekeyTimeout = $REKEY_TIMEOUT"; echo "RejectAfterTime = $REJECT_AFTER"
    echo "KeepaliveTimeout = $KEEPALIVE_TIMEOUT"; echo "MaxHandshakeAttempts = $MAX_ATTEMPTS"
    echo "RandomTrailers = $RANDOM_TRAILERS"; echo "DisableCookies = $DISABLE_COOKIES"
    echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.8.31.0/24 -o eth0 -j MASQUERADE"
    echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.8.31.0/24 -o eth0 -j MASQUERADE"
  } > "$ROOT/awg0.conf"
  printf "%s\n" "$PRIVATE_KEY" > "$ROOT/wireguard_server_private_key.key"
  printf "%s\n" "$PUBLIC_KEY" > "$ROOT/wireguard_server_public_key.key"
  printf "%s\n" "$PRESHARED_KEY" > "$ROOT/wireguard_psk.key"
  printf "[]\n" > "$ROOT/clientsTable"
  chmod 600 "$ROOT"/*.key "$ROOT/awg0.conf"
fi
cat > "$ROOT/start-userspace.sh" <<"START_AWG31"
#!/bin/sh
set -eu
amneziawg-go -f awg0 &
engine_pid=$!
trap "kill $engine_pid 2>/dev/null || true" EXIT INT TERM
i=0
until ip link show awg0 >/dev/null 2>&1; do i=$((i+1)); test "$i" -lt 50 || exit 1; sleep 0.1; done
awg-quick strip /opt/amnezia/awg/awg0.conf > /tmp/awg0.setconf
awg setconf awg0 /tmp/awg0.setconf
ip address replace 10.8.31.1/24 dev awg0
ip link set mtu 1280 up dev awg0
iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -j ACCEPT
iptables -C FORWARD -o awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o awg0 -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.8.31.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.31.0/24 -o eth0 -j MASQUERADE
wait "$engine_pid"
START_AWG31
chmod 700 "$ROOT/start-userspace.sh"
PUBLIC_KEY=$(cat "$ROOT/wireguard_server_public_key.key")
PRESHARED_KEY=$(cat "$ROOT/wireguard_psk.key")
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" --restart unless-stopped --cap-add NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v "$ROOT:/opt/amnezia/awg:rw" "$IMAGE_NAME" sh /opt/amnezia/awg/start-userspace.sh >/dev/null
sleep 2
docker exec "$CONTAINER_NAME" awg show awg0 >/dev/null
docker exec "$CONTAINER_NAME" pgrep -x amneziawg-go >/dev/null
docker top "$CONTAINER_NAME" -eo pid,comm,args | grep -F "amneziawg-go -f awg0" >/dev/null
IMAGE_ID=$(docker image inspect "$IMAGE_NAME" --format "{{.Id}}")
ENGINE_BINARY_SHA=$(docker exec "$CONTAINER_NAME" sha256sum /usr/bin/amneziawg-go | cut -c1-64)
TOOLS_BINARY_SHA=$(docker exec "$CONTAINER_NAME" sha256sum /usr/bin/awg | cut -c1-64)
printf "Success: true\nPort: %s\nContainer Name: %s\nRuntime Commit: %s\nTools Commit: %s\nImage ID: %s\nDockerfile SHA: %s\nEngine Binary SHA: %s\nTools Binary SHA: %s\n" "$VPN_PORT" "$CONTAINER_NAME" "$ENGINE_COMMIT" "$TOOLS_COMMIT" "$IMAGE_ID" "$DOCKERFILE_SHA" "$ENGINE_BINARY_SHA" "$TOOLS_BINARY_SHA"
printf "Server Public Key: %s\nPresharedKey = %s\n" "$PUBLIC_KEY" "$PRESHARED_KEY"
for field in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies; do
  value=$(sed -n "s/^[[:space:]]*$field[[:space:]]*=[[:space:]]*//p" "$ROOT/awg0.conf" | head -1)
  test -z "$value" || printf "%s: %s\n" "$field" "$value"
done
',
  '#!/bin/bash
set -euo pipefail
docker rm -f amnezia-awg31 >/dev/null 2>&1 || true
docker image rm amnezia-awg31 >/dev/null 2>&1 || true
rm -rf /opt/amnezia/awg31
printf "{\"success\":true,\"message\":\"AWG31 isolated resources removed\"}\n"',
  '[Interface]
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
HeaderProtectionKey = {{HeaderProtectionKey}}
ContentPaddingAddition = {{ContentPaddingAddition}}
RekeyAfterTime = {{RekeyAfterTime}}
RekeyTimeout = {{RekeyTimeout}}
RejectAfterTime = {{RejectAfterTime}}
KeepaliveTimeout = {{KeepaliveTimeout}}
MaxHandshakeAttempts = {{MaxHandshakeAttempts}}
RandomTrailers = {{RandomTrailers}}
DisableCookies = {{DisableCookies}}

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25-35',
  1, 1,
  JSON_OBJECT('engine','builtin_awg','metadata',JSON_OBJECT(
    'container_name','amnezia-awg31','host_config_dir','/opt/amnezia/awg31',
    'container_config_dir','/opt/amnezia/awg','config_file','/opt/amnezia/awg/awg0.conf',
    'host_config_file','/opt/amnezia/awg31/awg0.conf','interface','awg0',
    'vpn_subnet','10.8.31.0/24','port_range',JSON_ARRAY(30000,65000),
    'runtime_commit','b5928efb6ca19f0153958460c3d141f04abc5c2e',
    'tools_commit','ee0f0a9aa34ff0a0da4b3433b9512781cfe02843')),
  NOW(), NOW()
ON DUPLICATE KEY UPDATE name=VALUES(name), description=VALUES(description), install_script=VALUES(install_script), uninstall_script=VALUES(uninstall_script), output_template=VALUES(output_template), ubuntu_compatible=VALUES(ubuntu_compatible), is_active=VALUES(is_active), definition=VALUES(definition), updated_at=NOW();

INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT id, 'Default AmneziaWG 3.1', output_template, 1 FROM protocols p
WHERE slug='awg31' AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id=p.id AND template_name='Default AmneziaWG 3.1');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, v.name, 'text', v.defval, CONCAT('AWG 3.1 setting ', v.name), v.required
FROM protocols p JOIN (
 SELECT 'Jc' name,'5' defval,1 required UNION ALL SELECT 'Jmin','10',1 UNION ALL SELECT 'Jmax','50',1
 UNION ALL SELECT 'S1','12',1 UNION ALL SELECT 'S2','12',1 UNION ALL SELECT 'S3','12',1 UNION ALL SELECT 'S4','12',1
 UNION ALL SELECT 'H1','1',1 UNION ALL SELECT 'H2','2',1 UNION ALL SELECT 'H3','3',1 UNION ALL SELECT 'H4','4',1
 UNION ALL SELECT 'I1','<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>',1
 UNION ALL SELECT 'I2','',0 UNION ALL SELECT 'I3','',0 UNION ALL SELECT 'I4','',0 UNION ALL SELECT 'I5','',0
 UNION ALL SELECT 'HeaderProtectionKey','',1 UNION ALL SELECT 'ContentPaddingAddition','',0
 UNION ALL SELECT 'RekeyAfterTime','100-120',1 UNION ALL SELECT 'RekeyTimeout','3-7',1
 UNION ALL SELECT 'RejectAfterTime','150-180',1 UNION ALL SELECT 'KeepaliveTimeout','5-15',1
 UNION ALL SELECT 'MaxHandshakeAttempts','15-20',1 UNION ALL SELECT 'RandomTrailers','on',1 UNION ALL SELECT 'DisableCookies','on',1
) v ON 1=1
WHERE p.slug='awg31' AND NOT EXISTS (
 SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id=p.id AND pv.variable_name=v.name
);
