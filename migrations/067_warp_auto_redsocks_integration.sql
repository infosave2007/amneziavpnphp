-- =====================================================================
-- Migration 067: WARP auto-integration with redsocks + iptables
-- Automatically routes all VPN client TCP traffic through WARP proxy
-- Chain: VPN clients (10.8.x.0/24) → redsocks → WARP SOCKS5 → Cloudflare
-- Also detects X-Ray and patches its outbound config
-- =====================================================================

UPDATE protocols
SET install_script = '#!/bin/bash
set -eo pipefail

# ======================================================================
# Cloudflare WARP Proxy Installer (v2 — with auto-routing)
# Installs WARP + redsocks, auto-routes VPN client traffic through CF
# Chain: VPN clients → redsocks → WARP SOCKS5 → Cloudflare → Internet
# ======================================================================

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
WARP_MODE="${WARP_MODE:-proxy}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

export DEBIAN_FRONTEND=noninteractive

echo "=== Installing Cloudflare WARP (v2 with auto-routing) ==="

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

# Check available RAM (warn if < 512MB)
TOTAL_RAM_MB=$(free -m 2>/dev/null | awk "/^Mem:/{print \\$2}" || echo "0")
if [ "$TOTAL_RAM_MB" -gt 0 ] && [ "$TOTAL_RAM_MB" -lt 512 ]; then
  echo "WARNING: Server has only ${TOTAL_RAM_MB}MB RAM. WARP needs ~100MB. Consider upgrading."
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
WARP_ACCOUNT=$(warp-cli --accept-tos registration show 2>/dev/null | grep -i "Account ID" | awk "{print \\$NF}" || echo "unknown")

# Enable WARP service to start on boot
systemctl enable warp-svc 2>/dev/null || true

# ======================================================================
# AUTO-ROUTING: Install redsocks + iptables rules
# Routes all VPN client TCP traffic through WARP
# ======================================================================
echo ""
echo "=== Setting up auto-routing (redsocks) ==="

ROUTED_SUBNETS=""

# Install redsocks
apt-get install -y -qq redsocks >/dev/null 2>&1 || {
  echo "WARNING: redsocks not available in repos, trying manual install"
  apt-get install -y -qq gcc libevent-dev make git >/dev/null 2>&1 || true
  if [ ! -f /usr/local/bin/redsocks ]; then
    cd /tmp
    git clone --depth=1 https://github.com/darkk/redsocks.git redsocks-build 2>/dev/null || true
    if [ -d redsocks-build ]; then
      cd redsocks-build && make -j$(nproc) 2>/dev/null && cp redsocks /usr/local/bin/redsocks && chmod +x /usr/local/bin/redsocks
      cd / && rm -rf /tmp/redsocks-build
      echo "redsocks built from source"
    fi
  fi
}

REDSOCKS_BIN=$(command -v redsocks 2>/dev/null || echo "")
if [ -z "$REDSOCKS_BIN" ] && [ -f /usr/local/bin/redsocks ]; then
  REDSOCKS_BIN="/usr/local/bin/redsocks"
fi

if [ -n "$REDSOCKS_BIN" ]; then
  echo "redsocks found: $REDSOCKS_BIN"

  # Create redsocks config
  mkdir -p /etc/redsocks
  cat > /etc/redsocks/redsocks.conf << REDSOCKS_EOF
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    redirector = iptables;
}
redsocks {
    local_ip = 127.0.0.1;
    local_port = ${REDSOCKS_PORT};
    ip = 127.0.0.1;
    port = ${WARP_PROXY_PORT};
    type = socks5;
}
REDSOCKS_EOF

  # Create systemd service for redsocks
  cat > /etc/systemd/system/redsocks-warp.service << SYSTEMD_EOF
[Unit]
Description=Redsocks WARP transparent proxy
After=network.target warp-svc.service
Wants=warp-svc.service

[Service]
Type=forking
ExecStart=${REDSOCKS_BIN} -c /etc/redsocks/redsocks.conf
ExecStop=/bin/kill -TERM \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

  # Stop any existing redsocks
  systemctl stop redsocks 2>/dev/null || true
  systemctl stop redsocks-warp 2>/dev/null || true
  killall redsocks 2>/dev/null || true

  # Start redsocks
  systemctl daemon-reload
  systemctl enable redsocks-warp 2>/dev/null || true
  systemctl start redsocks-warp
  echo "redsocks-warp service started on port ${REDSOCKS_PORT}"

  # Detect VPN subnets to route
  # 1. AWG subnets from running containers
  for container in $(docker ps --format "{{.Names}}" 2>/dev/null | grep -iE "amnezia-awg|awg" || true); do
    SUBNET=$(docker exec "$container" cat /opt/amnezia/awg/wg0.conf 2>/dev/null | grep -oP "Address\s*=\s*\K[0-9./]+" | head -1 || true)
    if [ -z "$SUBNET" ]; then
      SUBNET=$(docker exec "$container" cat /opt/amnezia/awg/awg0.conf 2>/dev/null | grep -oP "Address\s*=\s*\K[0-9./]+" | head -1 || true)
    fi
    if [ -n "$SUBNET" ]; then
      # Convert server IP/mask to network: 10.8.1.1/24 -> 10.8.1.0/24
      NET=$(echo "$SUBNET" | sed -E "s/([0-9]+\\.[0-9]+\\.[0-9]+)\\.[0-9]+/\\1.0/")
      ROUTED_SUBNETS="$ROUTED_SUBNETS $NET"
      echo "Detected AWG subnet from $container: $NET"
    fi
  done

  # 2. Check server vpn_subnet from panel config
  if [ -z "$ROUTED_SUBNETS" ]; then
    # Fallback: common Amnezia subnets
    ROUTED_SUBNETS="10.8.1.0/24"
    echo "Using default AWG subnet: 10.8.1.0/24"
  fi

  # Setup iptables REDSOCKS chain
  echo "Setting up iptables rules for subnets:$ROUTED_SUBNETS"

  iptables -t nat -N REDSOCKS_WARP 2>/dev/null || iptables -t nat -F REDSOCKS_WARP

  # Skip local/private destinations
  iptables -t nat -A REDSOCKS_WARP -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 100.64.0.0/10 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 224.0.0.0/4 -j RETURN
  iptables -t nat -A REDSOCKS_WARP -d 240.0.0.0/4 -j RETURN

  # Redirect remaining TCP to redsocks
  iptables -t nat -A REDSOCKS_WARP -p tcp -j REDIRECT --to-ports ${REDSOCKS_PORT}

  # Apply REDSOCKS_WARP chain to VPN subnets
  for SUBNET in $ROUTED_SUBNETS; do
    # Remove old rule if exists
    iptables -t nat -D PREROUTING -s "$SUBNET" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
    # Add new rule
    iptables -t nat -A PREROUTING -s "$SUBNET" -p tcp -j REDSOCKS_WARP
    echo "Routing $SUBNET TCP traffic through WARP"
  done

  # Save iptables rules for persistence
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save 2>/dev/null || true
  elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi

  # Save routed subnets for uninstall cleanup
  echo "$ROUTED_SUBNETS" > /var/lib/cloudflare-warp/routed_subnets

  echo "Auto-routing configured: VPN client TCP traffic now goes through WARP"
else
  echo "WARNING: redsocks not available, skipping auto-routing."
  echo "VPN clients will NOT automatically route through WARP."
  echo "Manual SOCKS5 proxy: socks5h://127.0.0.1:${WARP_PROXY_PORT}"
fi

# ======================================================================
# X-Ray integration: patch outbound config if X-Ray is running
# ======================================================================
XRAY_CONTAINER=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i "xray" | head -1 || true)
if [ -n "$XRAY_CONTAINER" ]; then
  echo ""
  echo "=== Detected X-Ray container: $XRAY_CONTAINER ==="
  XRAY_CONFIG=$(docker exec "$XRAY_CONTAINER" cat /etc/xray/config.json 2>/dev/null || echo "")
  if [ -n "$XRAY_CONFIG" ]; then
    # Check if warp-out already configured
    if echo "$XRAY_CONFIG" | grep -q "warp-out"; then
      echo "X-Ray already has warp-out outbound, skipping"
    else
      echo "NOTE: X-Ray detected but auto-patching disabled for safety."
      echo "To route X-Ray traffic through WARP, add this outbound manually:"
      echo "  {\"tag\":\"warp-out\",\"protocol\":\"socks\",\"settings\":{\"servers\":[{\"address\":\"127.0.0.1\",\"port\":${WARP_PROXY_PORT}}]}}"
    fi
  fi
fi

# Get server external IP
EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo ""
echo "=== Cloudflare WARP Proxy Installed ==="
echo "Variable: warp_proxy_port=$WARP_PROXY_PORT"
echo "Variable: warp_mode=$WARP_MODE"
echo "Variable: warp_ip=$WARP_IP"
echo "Variable: warp_account=$WARP_ACCOUNT"
echo "Variable: server_host=$EXTERNAL_IP"
echo "Variable: proxy_address=127.0.0.1:${WARP_PROXY_PORT}"
echo "Variable: redsocks_port=$REDSOCKS_PORT"
echo "Variable: routed_subnets=$ROUTED_SUBNETS"',
    uninstall_script = '#!/bin/bash
set -eo pipefail

echo "=== Uninstalling Cloudflare WARP ==="

# ── Remove iptables rules ──
ROUTED_SUBNETS=""
if [ -f /var/lib/cloudflare-warp/routed_subnets ]; then
  ROUTED_SUBNETS=$(cat /var/lib/cloudflare-warp/routed_subnets)
fi
if [ -z "$ROUTED_SUBNETS" ]; then
  ROUTED_SUBNETS="10.8.1.0/24"
fi

for SUBNET in $ROUTED_SUBNETS; do
  iptables -t nat -D PREROUTING -s "$SUBNET" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
done
iptables -t nat -F REDSOCKS_WARP 2>/dev/null || true
iptables -t nat -X REDSOCKS_WARP 2>/dev/null || true
echo "iptables REDSOCKS_WARP chain removed"

# Save cleaned iptables
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save 2>/dev/null || true
elif command -v iptables-save >/dev/null 2>&1; then
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ── Stop and remove redsocks ──
systemctl stop redsocks-warp 2>/dev/null || true
systemctl disable redsocks-warp 2>/dev/null || true
rm -f /etc/systemd/system/redsocks-warp.service
rm -rf /etc/redsocks
systemctl daemon-reload 2>/dev/null || true
echo "redsocks-warp service removed"

# ── Disconnect and deregister WARP ──
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

echo "{\"success\":true,\"message\":\"Cloudflare WARP + redsocks uninstalled\"}"',
    updated_at = NOW()
WHERE slug = 'cf-warp';

-- Add new protocol variables for redsocks integration
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'redsocks_port', 'number', '12345', 'Redsocks transparent proxy port', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'redsocks_port');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'routed_subnets', 'string', '10.8.1.0/24', 'VPN subnets routed through WARP', false
FROM protocols p WHERE p.slug = 'cf-warp'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = p.id AND variable_name = 'routed_subnets');
