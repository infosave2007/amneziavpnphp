-- =====================================================================
-- Migration 066: Add Cloudflare WARP proxy protocol
-- Installs Cloudflare WARP on VPS and enables SOCKS5/HTTPS proxy mode
-- Creates chain: AmneziaWG → WARP (127.0.0.1:40000) → Internet
-- Adds DPI/censorship bypass layer via Cloudflare tunnel
-- =====================================================================

-- 1. Insert the Cloudflare WARP protocol
INSERT INTO protocols (name, slug, description, install_script, uninstall_script, output_template, show_text_content, ubuntu_compatible, is_active, definition, created_at, updated_at)
SELECT
  'Cloudflare WARP Proxy',
  'cf-warp',
  'Cloudflare WARP — прокси-слой для обхода DPI/цензуры. Устанавливает WARP на сервер в режиме SOCKS5 прокси (127.0.0.1:40000). Трафик идёт по цепочке: VPN-клиент → AmneziaWG → WARP → Cloudflare → Интернет. Скрывает конечные домены от провайдера VPS.',
  '#!/bin/bash
set -eo pipefail

# ======================================================================
# Cloudflare WARP Proxy Installer
# Installs WARP in proxy mode (SOCKS5 on 127.0.0.1:40000)
# For chain: AmneziaWG → WARP → Internet
# ======================================================================

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
WARP_MODE="${WARP_MODE:-proxy}"

export DEBIAN_FRONTEND=noninteractive

echo "=== Installing Cloudflare WARP ==="

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="$ID"
  OS_VERSION="$VERSION_ID"
else
  OS_ID="unknown"
  OS_VERSION="0"
fi

echo "Detected OS: $OS_ID $OS_VERSION"

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
  echo "ERROR: WARP supports only x86_64 and aarch64, got: $ARCH"
  exit 1
fi

# Install prerequisites
apt-get update -qq
apt-get install -y -qq curl gnupg lsb-release >/dev/null 2>&1

# Add Cloudflare WARP repository
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

# Determine correct repo codename
REPO_CODENAME=""
case "$OS_ID" in
  ubuntu)
    case "$OS_VERSION" in
      24.04) REPO_CODENAME="noble" ;;
      22.04) REPO_CODENAME="jammy" ;;
      20.04) REPO_CODENAME="focal" ;;
      *)     REPO_CODENAME="jammy" ;;
    esac
    ;;
  debian)
    case "$OS_VERSION" in
      12*) REPO_CODENAME="bookworm" ;;
      11*) REPO_CODENAME="bullseye" ;;
      *)   REPO_CODENAME="bookworm" ;;
    esac
    ;;
  *)
    REPO_CODENAME="jammy"
    echo "WARNING: Unsupported OS $OS_ID, trying Ubuntu Jammy repo"
    ;;
esac

echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $REPO_CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list

# Install WARP client
apt-get update -qq
apt-get install -y -qq cloudflare-warp >/dev/null 2>&1

echo "WARP package installed"

# Check if already registered
WARP_STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "unregistered")

if echo "$WARP_STATUS" | grep -qiE "Registration Missing|unregistered"; then
  echo "Registering WARP..."
  warp-cli --accept-tos registration new
  echo "WARP registered"
else
  echo "WARP already registered"
fi

# Set proxy mode
echo "Setting WARP to proxy mode on port $WARP_PROXY_PORT..."
warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port "$WARP_PROXY_PORT"

# Connect WARP
echo "Connecting WARP..."
warp-cli --accept-tos connect

# Wait for connection
for i in $(seq 1 15); do
  CONN_STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "")
  if echo "$CONN_STATUS" | grep -qi "Connected"; then
    echo "WARP connected successfully"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "WARNING: WARP connection timeout, may still be connecting..."
  fi
  sleep 2
done

# Verify proxy is listening
sleep 2
if command -v ss >/dev/null 2>&1; then
  LISTENING=$(ss -tlnp 2>/dev/null | grep ":${WARP_PROXY_PORT}" || true)
elif command -v netstat >/dev/null 2>&1; then
  LISTENING=$(netstat -tlnp 2>/dev/null | grep ":${WARP_PROXY_PORT}" || true)
else
  LISTENING=""
fi

if [ -n "$LISTENING" ]; then
  echo "WARP SOCKS5 proxy listening on 127.0.0.1:${WARP_PROXY_PORT}"
else
  echo "WARNING: Proxy port ${WARP_PROXY_PORT} not yet listening, WARP may need more time"
fi

# Test proxy connectivity
PROXY_TEST=$(curl -x socks5h://127.0.0.1:${WARP_PROXY_PORT} -s -o /dev/null -w "%{http_code}" --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo "000")
if [ "$PROXY_TEST" = "200" ]; then
  echo "WARP proxy test: OK (HTTP 200)"
else
  echo "WARNING: WARP proxy test returned HTTP $PROXY_TEST (may need a moment to initialize)"
fi

# Get WARP IP info
WARP_IP=$(curl -x socks5h://127.0.0.1:${WARP_PROXY_PORT} -s --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip=" | cut -d= -f2 || echo "unknown")
WARP_ACCOUNT=$(warp-cli --accept-tos registration show 2>/dev/null | grep -i "Account ID" | awk "{print \$NF}" || echo "unknown")

# Enable WARP service to start on boot
systemctl enable warp-svc 2>/dev/null || true

# Get server external IP
EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo ""
echo "=== Cloudflare WARP Proxy Installed ==="
echo "Variable: warp_proxy_port=$WARP_PROXY_PORT"
echo "Variable: warp_mode=$WARP_MODE"
echo "Variable: warp_ip=$WARP_IP"
echo "Variable: warp_account=$WARP_ACCOUNT"
echo "Variable: server_host=$EXTERNAL_IP"
echo "Variable: proxy_address=127.0.0.1:${WARP_PROXY_PORT}"',
  '#!/bin/bash
set -eo pipefail

echo "=== Uninstalling Cloudflare WARP ==="

# Disconnect and deregister
warp-cli --accept-tos disconnect 2>/dev/null || true
warp-cli --accept-tos registration delete 2>/dev/null || true

# Stop service
systemctl stop warp-svc 2>/dev/null || true
systemctl disable warp-svc 2>/dev/null || true

# Remove package
apt-get remove -y cloudflare-warp 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# Clean up config
rm -rf /var/lib/cloudflare-warp 2>/dev/null || true
rm -f /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null || true
rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true

echo "{\"success\":true,\"message\":\"Cloudflare WARP uninstalled\"}"',
  'WARP SOCKS5 Proxy: socks5h://127.0.0.1:{{warp_proxy_port}}
WARP IP: {{warp_ip}}
Mode: {{warp_mode}}
Server: {{server_host}}',
  1,
  1,
  1,
  JSON_OBJECT(
    'engine', 'shell',
    'metadata', JSON_OBJECT(
      'container_name', '',
      'port_range', JSON_ARRAY(40000, 40000),
      'config_dir', '/var/lib/cloudflare-warp',
      'is_proxy_layer', true,
      'proxy_port', 40000,
      'proxy_protocol', 'socks5'
    )
  ),
  NOW(),
  NOW()
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug = 'cf-warp');

-- 2. Add protocol variables for WARP
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'warp_proxy_port', 'number', '40000', 'WARP SOCKS5 proxy port (default 40000)', true
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'warp_proxy_port');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'warp_mode', 'string', 'proxy', 'WARP mode (proxy / warp)', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'warp_mode');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'warp_ip', 'string', '', 'WARP exit IP address (via Cloudflare)', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'warp_ip');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'warp_account', 'string', '', 'WARP account ID', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'warp_account');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'server_host');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'proxy_address', 'string', '127.0.0.1:40000', 'Full proxy address', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'proxy_address');

-- 3. Add default template for WARP
INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default WARP', 'WARP SOCKS5 Proxy: socks5h://127.0.0.1:{{warp_proxy_port}}
WARP IP: {{warp_ip}}
Mode: {{warp_mode}}
Server: {{server_host}}', true
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id = p.id AND template_name = 'Default WARP');

-- 4. Add translations for Cloudflare WARP
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'protocol_cf_warp', 'Cloudflare WARP Proxy')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'protocol_cf_warp', 'Cloudflare WARP Прокси')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

-- WARP-specific UI translations
INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'warp_status', 'WARP Status')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'warp_status', 'Статус WARP')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'warp_connected', 'Connected via Cloudflare')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'warp_connected', 'Подключён через Cloudflare')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'warp_disconnected', 'Disconnected')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'warp_disconnected', 'Отключён')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'warp_proxy_info', 'WARP proxy adds a Cloudflare encryption layer to hide destination domains from VPS provider. Traffic chain: Client → AmneziaWG → WARP → Cloudflare → Internet')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'warp_proxy_info', 'WARP прокси добавляет слой шифрования Cloudflare для скрытия конечных доменов от провайдера VPS. Цепочка: Клиент → AmneziaWG → WARP → Cloudflare → Интернет')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'protocols', 'warp_warning_ram', '⚠️ Cloudflare WARP uses ~50-100MB additional RAM')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('ru', 'protocols', 'warp_warning_ram', '⚠️ Cloudflare WARP использует ~50-100 МБ дополнительной RAM')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);
