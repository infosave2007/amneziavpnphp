-- Update XRay VLESS protocol to Reality/Vision setup
UPDATE protocols SET install_script = '#!/bin/bash\n\nset -euo pipefail\nset -x\n\nCONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"\nPORT_RANGE_START=${PORT_RANGE_START:-30000}\nPORT_RANGE_END=${PORT_RANGE_END:-65000}\nXRAY_PORT=$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))\n\nPRIVATE_KEY=$(docker run --rm teddysun/xray xray x25519 | grep "Private key:" | awk ''{print $3}'')\nPUBLIC_KEY=$(docker run --rm teddysun/xray xray x25519 -i "$PRIVATE_KEY" | grep "Public key:" | awk ''{print $3}'')\nSHORT_ID=$(openssl rand -hex 8)\nCLIENT_ID=$(cat /proc/sys/kernel/random/uuid)\n\nSERVER_NAME="www.googletagmanager.com"\nFINGERPRINT="chrome"\nSPIDER_X="/"\n\ndocker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true\nmkdir -p /opt/amnezia/xray\n\ncat > /opt/amnezia/xray/server.json << EOF\n{\n  "log": { "loglevel": "warning" },\n  "inbounds": [\n    {\n      "listen": "0.0.0.0",\n      "port": ${XRAY_PORT},\n      "protocol": "vless",\n      "settings": {\n        "clients": [ { "id": "${CLIENT_ID}" } ],\n        "decryption": "none",\n        "fallbacks": [ { "dest": 80 } ]\n      },\n      "streamSettings": {\n        "network": "tcp",\n        "security": "reality",\n        "realitySettings": {\n          "show": false,\n          "dest": "${SERVER_NAME}:443",\n          "xver": 0,\n          "serverNames": [ "${SERVER_NAME}" ],\n          "privateKey": "${PRIVATE_KEY}",\n          "shortIds": [ "${SHORT_ID}" ],\n          "fingerprint": "${FINGERPRINT}",\n          "spiderX": "${SPIDER_X}"\n        }\n      }\n    }\n  ],\n  "outbounds": [ { "protocol": "freedom", "tag": "direct" } ]\n}\nEOF\n\n# start container\ndocker run -d \\\n  --name "$CONTAINER_NAME" \\\n  --restart always \\\n  -p "${XRAY_PORT}:${XRAY_PORT}" \\\n  -v /opt/amnezia/xray:/opt/amnezia/xray \\\n  teddysun/xray xray run -c /opt/amnezia/xray/server.json\n\nsleep 2\n\n# panel output\necho "Port: ${XRAY_PORT}"\necho "ClientID: ${CLIENT_ID}"\necho "PublicKey: ${PUBLIC_KEY}"\necho "PrivateKey: ${PRIVATE_KEY}"\necho "ShortID: ${SHORT_ID}"\necho "ServerName: ${SERVER_NAME}"',
output_template = 'vless://{{client_id}}@{{server_host}}:{{server_port}}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={{reality_server_name}}&fp=chrome&pbk={{reality_public_key}}&sid={{reality_short_id}}&type=tcp'
WHERE slug = 'xray-vless';

-- Ensure protocol variables exist
SET @pid = (SELECT id FROM protocols WHERE slug = 'xray-vless');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, description, required)
SELECT @pid, 'reality_public_key', 'string', 'Reality public key (base64url)', true
WHERE NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=@pid AND variable_name='reality_public_key');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, description, required)
SELECT @pid, 'reality_short_id', 'string', 'Reality shortId', true
WHERE NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=@pid AND variable_name='reality_short_id');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, description, required)
SELECT @pid, 'reality_server_name', 'string', 'SNI server name for Reality', true
WHERE NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=@pid AND variable_name='reality_server_name');