-- =====================================================================
-- Migration 059: Add MTProxy (Telegram) protocol
-- https://hub.docker.com/r/telegrammessenger/proxy/
-- Zero-configuration Telegram MTProto proxy server
-- =====================================================================

-- 1. Insert the MTProxy protocol
INSERT INTO protocols (name, slug, description, install_script, uninstall_script, output_template, show_text_content, ubuntu_compatible, is_active, definition, created_at, updated_at)
SELECT
  'MTProxy (Telegram)',
  'mtproxy',
  'Telegram MTProto proxy — zero-configuration proxy server for Telegram messenger.',
  '#!/bin/bash
set -euo pipefail

# Use exported variables from panel (SERVER_PORT, SERVER_CONTAINER) or defaults
CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-mtproxy}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
MTPROXY_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"

mkdir -p /opt/amnezia/mtproxy

# Generate secret if not exists
if [ -f /opt/amnezia/mtproxy/secret ]; then
  SECRET=$(cat /opt/amnezia/mtproxy/secret)
  echo "Using existing MTProxy secret"
else
  SECRET=$(cat /dev/urandom | tr -dc a-f0-9 | head -c 32 || true)
  echo "$SECRET" > /opt/amnezia/mtproxy/secret
fi

# Store port
echo "$MTPROXY_PORT" > /opt/amnezia/mtproxy/port

# Remove existing container
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Run MTProxy container (single line for heredoc compatibility)
docker run -d --name "$CONTAINER_NAME" --restart always -p "${MTPROXY_PORT}:443" -v /opt/amnezia/mtproxy:/data -e SECRET="$SECRET" telegrammessenger/proxy:latest

sleep 3

# Get external IP
EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo "MTProxy installed successfully"
echo "Port: $MTPROXY_PORT"
echo "Secret: $SECRET"
echo "Server Host: $EXTERNAL_IP"',
  '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-mtproxy}"

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm -fv "$CONTAINER_NAME" 2>/dev/null || true
docker image rm telegrammessenger/proxy:latest 2>/dev/null || true
rm -rf /opt/amnezia/mtproxy 2>/dev/null || true

echo "{\"success\":true,\"message\":\"MTProxy uninstalled\"}"',
  'tg://proxy?server={{server_host}}&port={{server_port}}&secret={{secret}}',
  1,
  1,
  1,
  JSON_OBJECT(
    'engine', 'shell',
    'metadata', JSON_OBJECT(
      'container_name', 'amnezia-mtproxy',
      'port_range', JSON_ARRAY(30000, 65000),
      'config_dir', '/opt/amnezia/mtproxy'
    )
  ),
  NOW(),
  NOW()
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug = 'mtproxy');

-- 2. Add protocol variables for MTProxy
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'secret', 'string', '', 'MTProxy secret (32 hex chars)', true
FROM protocols p WHERE p.slug = 'mtproxy'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'secret');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true
FROM protocols p WHERE p.slug = 'mtproxy'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'server_host');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_port', 'number', '443', 'MTProxy external port', true
FROM protocols p WHERE p.slug = 'mtproxy'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'server_port');

-- 3. Add default template for MTProxy
INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default MTProxy', 'tg://proxy?server={{server_host}}&port={{server_port}}&secret={{secret}}', true
FROM protocols p WHERE p.slug = 'mtproxy'
  AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id = p.id AND template_name = 'Default MTProxy');

-- 4. Add QR code template (same as output)
UPDATE protocols SET
  qr_code_template = 'tg://proxy?server={{server_host}}&port={{server_port}}&secret={{secret}}',
  qr_code_format = 'raw'
WHERE slug = 'mtproxy';

-- 5. Add translations for MTProxy
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'protocol_mtproxy', 'MTProxy (Telegram)')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'protocol_mtproxy', 'MTProxy (Telegram)')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
