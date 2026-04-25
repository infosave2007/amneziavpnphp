-- =====================================================================
-- Migration 069: WARP auto-detect AIVPN subnet for routing
-- Adds aivpn0 interface subnet detection alongside AWG containers
-- =====================================================================

UPDATE protocols
SET install_script = '#!/bin/bash

# ======================================================================
# Cloudflare WARP Proxy Installer v4 (AWG + AIVPN + X-Ray)
# Installs WARP + redsocks, auto-routes ALL VPN client traffic through CF
# ======================================================================

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
WARP_MODE="${WARP_MODE:-proxy}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

export DEBIAN_FRONTEND=noninteractive

echo "=== Installing Cloudflare WARP v4 ==="

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="$ID"
  OS_VERSION="$VERSION_ID"
else
  OS_ID="unknown"
  OS_VERSION="0"
fi
echo "OS: $OS_ID $OS_VERSION"

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
  echo "FAIL: WARP supports only x86_64 and aarch64, got: $ARCH"
  exit 1
fi

TOTAL_RAM_MB=$(free -m 2>/dev/null | awk "/^Mem:/{print \$2}" || echo "0")
if [ "$TOTAL_RAM_MB" -gt 0 ] && [ "$TOTAL_RAM_MB" -lt 512 ]; then
  echo "NOTE: Low RAM ${TOTAL_RAM_MB}MB. WARP needs ~100MB."
fi

apt-get update -qq
apt-get install -y -qq curl gnupg lsb-release >/dev/null 2>&1

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

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
    ;;
esac

echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $REPO_CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list

apt-get update -qq
apt-get install -y -qq cloudflare-warp >/dev/null 2>&1
echo "WARP package installed"

WARP_STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "unregistered")
if echo "$WARP_STATUS" | grep -qiE "Registration Missing|unregistered"; then
  warp-cli --accept-tos registration new
  echo "WARP registered"
else
  echo "WARP already registered"
fi

warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port "$WARP_PROXY_PORT"
warp-cli --accept-tos connect
echo "WARP connecting..."

for i in $(seq 1 15); do
  CONN_STATUS=$(warp-cli --accept-tos status 2>/dev/null || echo "")
  if echo "$CONN_STATUS" | grep -qi "Connected"; then
    echo "WARP connected"
    break
  fi
  sleep 2
done

sleep 2
LISTENING=""
if command -v ss >/dev/null 2>&1; then
  LISTENING=$(ss -tlnp 2>/dev/null | grep ":${WARP_PROXY_PORT}" || true)
fi
if [ -n "$LISTENING" ]; then
  echo "WARP SOCKS5 proxy on 127.0.0.1:${WARP_PROXY_PORT} OK"
else
  echo "NOTE: Proxy port ${WARP_PROXY_PORT} not yet listening"
fi

PROXY_TEST=$(curl -x socks5h://127.0.0.1:${WARP_PROXY_PORT} -s -o /dev/null -w "%{http_code}" --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo "000")
if [ "$PROXY_TEST" = "200" ]; then
  echo "WARP proxy test OK"
fi

WARP_IP=$(curl -x socks5h://127.0.0.1:${WARP_PROXY_PORT} -s --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip=" | cut -d= -f2 || echo "unknown")
WARP_ACCOUNT=$(warp-cli --accept-tos registration show 2>/dev/null | grep -i "Account ID" | awk "{print \$NF}" || echo "unknown")

systemctl enable warp-svc 2>/dev/null || true

# ── AUTO-ROUTING: redsocks + iptables ──
echo "=== Setting up redsocks auto-routing ==="

apt-get install -y -qq redsocks >/dev/null 2>&1 || true

REDSOCKS_BIN=$(command -v redsocks 2>/dev/null || echo "")
if [ -z "$REDSOCKS_BIN" ]; then
  if [ -f /usr/sbin/redsocks ]; then
    REDSOCKS_BIN="/usr/sbin/redsocks"
  fi
fi

if [ -n "$REDSOCKS_BIN" ]; then
  echo "redsocks binary: $REDSOCKS_BIN"

  mkdir -p /etc/redsocks
  printf "base {\\n  log_debug = off;\\n  log_info = on;\\n  log = \\"syslog:daemon\\";\\n  daemon = on;\\n  redirector = iptables;\\n}\\nredsocks {\\n  local_ip = 0.0.0.0;\\n  local_port = %s;\\n  ip = 127.0.0.1;\\n  port = %s;\\n  type = socks5;\\n}\\n" "$REDSOCKS_PORT" "$WARP_PROXY_PORT" > /etc/redsocks/redsocks.conf
  echo "redsocks config created"

  printf "[Unit]\\nDescription=Redsocks WARP transparent proxy\\nAfter=network.target warp-svc.service\\nWants=warp-svc.service\\n\\n[Service]\\nType=forking\\nExecStart=%s -c /etc/redsocks/redsocks.conf\\nRestart=on-failure\\nRestartSec=5\\n\\n[Install]\\nWantedBy=multi-user.target\\n" "$REDSOCKS_BIN" > /etc/systemd/system/redsocks-warp.service
  echo "systemd service created"

  systemctl stop redsocks 2>/dev/null || true
  systemctl stop redsocks-warp 2>/dev/null || true
  killall redsocks 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable redsocks-warp 2>/dev/null || true
  systemctl start redsocks-warp 2>/dev/null || true
  echo "redsocks-warp started"

  ROUTED_SUBNETS=""
  CONTAINER_IPS=""

  # 1. Detect AWG container IPs (containers MASQUERADE VPN traffic,
  #    so on the host we see src=container_IP, not VPN subnet)
  for container in $(docker ps --format "{{`{{.Names}}`}}" 2>/dev/null | grep -iE "amnezia-awg|awg" || true); do
    CIP=$(docker inspect -f "{{`{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`}}" "$container" 2>/dev/null || true)
    if [ -n "$CIP" ]; then
      CONTAINER_IPS="$CONTAINER_IPS $CIP"
      echo "AWG container $container IP: $CIP"
    fi
  done

  # 2. Detect host-level VPN subnets (aivpn0, wg0, etc.)
  for iface in aivpn0 wg0 wg1; do
    ADDR=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP "inet \\K[0-9./]+" | head -1 || true)
    if [ -n "$ADDR" ]; then
      NET=$(echo "$ADDR" | sed -E "s/([0-9]+\\.[0-9]+\\.[0-9]+)\\.[0-9]+(.*)/\\1.0\\2/")
      if ! echo "$ROUTED_SUBNETS" | grep -q "$NET"; then
        ROUTED_SUBNETS="$ROUTED_SUBNETS $NET"
        echo "VPN subnet from $iface: $NET"
      fi
    fi
  done

  # 3. Fallback if nothing detected
  if [ -z "$ROUTED_SUBNETS" ] && [ -z "$CONTAINER_IPS" ]; then
    ROUTED_SUBNETS="10.8.1.0/24 10.0.0.0/24"
    echo "Default subnets: 10.8.1.0/24 10.0.0.0/24"
  fi

  # Enable route_localnet so DNAT to 127.0.0.1 works for Docker traffic
  sysctl -w net.ipv4.conf.docker0.route_localnet=1 2>/dev/null || true
  sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || true
  grep -q route_localnet /etc/sysctl.d/99-warp.conf 2>/dev/null || {
    mkdir -p /etc/sysctl.d
    echo "net.ipv4.conf.docker0.route_localnet=1" >> /etc/sysctl.d/99-warp.conf
    echo "net.ipv4.conf.all.route_localnet=1" >> /etc/sysctl.d/99-warp.conf
  }

  iptables -t nat -N REDSOCKS_WARP 2>/dev/null || iptables -t nat -F REDSOCKS_WARP
  iptables -t nat -A REDSOCKS_WARP -d 0.0.0.0/8 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 10.0.0.0/8 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 100.64.0.0/10 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 127.0.0.0/8 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 169.254.0.0/16 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 172.16.0.0/12 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 192.168.0.0/16 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 224.0.0.0/4 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -d 240.0.0.0/4 -j RETURN 2>/dev/null || true
  iptables -t nat -A REDSOCKS_WARP -p tcp -j REDIRECT --to-ports ${REDSOCKS_PORT} 2>/dev/null || true

  # Add rules for host-level VPN subnets
  for SUBNET in $ROUTED_SUBNETS; do
    iptables -t nat -D PREROUTING -s "$SUBNET" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
    iptables -t nat -A PREROUTING -s "$SUBNET" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
    echo "Routing subnet $SUBNET through WARP"
  done

  # Add rules for AWG container IPs (traffic exits container MASQUERADEd)
  for CIP in $CONTAINER_IPS; do
    iptables -t nat -D PREROUTING -s "$CIP" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
    iptables -t nat -A PREROUTING -s "$CIP" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
    echo "Routing container $CIP through WARP"
  done

  mkdir -p /var/lib/cloudflare-warp
  echo "$ROUTED_SUBNETS $CONTAINER_IPS" > /var/lib/cloudflare-warp/routed_subnets
  echo "Auto-routing active"
else
  echo "NOTE: redsocks not available, auto-routing skipped"
  echo "Manual proxy: socks5h://127.0.0.1:${WARP_PROXY_PORT}"
fi

EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

echo ""
echo "=== Cloudflare WARP Installed ==="
echo "Variable: warp_proxy_port=$WARP_PROXY_PORT"
echo "Variable: warp_mode=$WARP_MODE"
echo "Variable: warp_ip=$WARP_IP"
echo "Variable: warp_account=$WARP_ACCOUNT"
echo "Variable: server_host=$EXTERNAL_IP"
echo "Variable: proxy_address=127.0.0.1:${WARP_PROXY_PORT}"
echo "Variable: redsocks_port=$REDSOCKS_PORT"
echo "Variable: routed_subnets=$ROUTED_SUBNETS"',
    updated_at = NOW()
WHERE slug = 'cf-warp';
