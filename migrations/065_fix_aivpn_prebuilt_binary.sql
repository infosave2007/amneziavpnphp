-- =====================================================================
-- Migration 069: Fix AIVPN installation - use prebuilt binary via Dockerfile.prebuilt
-- Instead of pulling from registry, build locally from prebuilt binary
-- Based on: https://github.com/infosave2007/aivpn/blob/master/README_RU.md
-- =====================================================================

UPDATE protocols
SET install_script = '#!/bin/bash
set -eo pipefail

# Use exported variables from panel (SERVER_PORT, SERVER_CONTAINER) or defaults
CONTAINER_NAME="${SERVER_CONTAINER:-aivpn-server}"
VPN_PORT="${SERVER_PORT:-443}"
CONFIG_DIR="/etc/aivpn"

# Install Docker if not available
if ! command -v docker &> /dev/null; then
  apt-get update -qq
  apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release >/dev/null 2>&1
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq && apt-get install -y -qq docker-ce docker-ce-cli containerd.io >/dev/null 2>&1
fi

# Install git, iptables, curl if not available
if ! command -v git &> /dev/null || ! command -v iptables &> /dev/null || ! command -v curl &> /dev/null; then
  apt-get update -qq
  if ! command -v git &> /dev/null; then
    apt-get install -y -qq git >/dev/null 2>&1
  fi
  if ! command -v iptables &> /dev/null; then
    apt-get install -y -qq iptables >/dev/null 2>&1
  fi
  if ! command -v curl &> /dev/null; then
    apt-get install -y -qq curl >/dev/null 2>&1
  fi
fi

mkdir -p "$CONFIG_DIR"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# Generate server key if not exists
if [ ! -f "$CONFIG_DIR/server.key" ]; then
  openssl rand 32 > "$CONFIG_DIR/server.key"
  chmod 600 "$CONFIG_DIR/server.key"
  echo "Generated new AIVPN server key"
else
  echo "Using existing AIVPN server key"
fi

# Setup NAT - find default interface
DEFAULT_IFACE=""
if command -v ip >/dev/null 2>&1; then
  DEFAULT_IFACE=$(ip route show default 2>/dev/null | grep default | head -1 | tr -s " " | cut -d" " -f5)
elif command -v route >/dev/null 2>&1; then
  DEFAULT_IFACE=$(route -n 2>/dev/null | grep "^0\.0\.0\.0" | head -1 | tr -s " " | cut -d" " -f8)
elif [ -d /sys/class/net ]; then
  # Fallback: try common interface names
  for iface in eth0 ens3 enp0s3 wlan0; do
    if [ -d "/sys/class/net/$iface" ]; then
      DEFAULT_IFACE=$iface
      break
    fi
  done
fi

if [ -n "$DEFAULT_IFACE" ]; then
  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE
else
  echo "WARNING: Could not determine default network interface, skipping NAT setup"
fi

# Get external IP
EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")

# Clone AIVPN repository
AIVPN_DIR="/opt/amnezia/aivpn"
if [ ! -d "$AIVPN_DIR" ]; then
  echo "Cloning AIVPN repository..."
  git clone --depth=1 https://github.com/infosave2007/aivpn.git "$AIVPN_DIR"
else
  echo "AIVPN repository already exists"
fi

cd "$AIVPN_DIR"

# Download prebuilt binary directly from repository
echo "Downloading prebuilt AIVPN server binary..."
DOWNLOAD_URL="https://github.com/infosave2007/aivpn/blob/master/releases/aivpn-server-linux-x86_64?raw=true"

if [ -z "$DOWNLOAD_URL" ]; then
  echo "ERROR: Could not find download URL for aivpn-server-linux-x86_64"
  exit 1
fi

echo "Downloading from: $DOWNLOAD_URL"
curl -L -o aivpn-server-linux-x86_64 "$DOWNLOAD_URL"

if [ ! -f "./aivpn-server-linux-x86_64" ]; then
  echo "ERROR: Binary download failed"
  exit 1
fi

chmod +x ./aivpn-server-linux-x86_64
echo "Binary downloaded successfully: $(ls -lh aivpn-server-linux-x86_64)"

# Check /dev/net/tun exists
if [ ! -c /dev/net/tun ]; then
  echo "Creating /dev/net/tun..."
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
  chmod 666 /dev/net/tun
fi

# Remove existing container
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Go back to AIVPN root directory
cd /opt/amnezia/aivpn

# Create docker-entrypoint.sh as a separate file (to avoid Docker build variable expansion issues)
cat > docker-entrypoint.sh << ''ENTRYPOINT_EOF''
#!/bin/sh
set -eu

mkdir -p /etc/aivpn /var/lib/aivpn/masks

# Seed preset masks on first run
PRESET_DIR="/usr/share/aivpn/preset-masks"
if [ -d "$PRESET_DIR" ]; then
    for f in "$PRESET_DIR"/*.json; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        if [ ! -f "/var/lib/aivpn/masks/$base" ]; then
            cp "$f" "/var/lib/aivpn/masks/$base"
        fi
    done
fi

exec /usr/local/bin/aivpn-server "$@"
ENTRYPOINT_EOF
chmod +x docker-entrypoint.sh

# Always create/update Dockerfile.prebuilt
cat > Dockerfile.prebuilt << ''DOCKERFILE''
FROM ubuntu:24.04

# Install runtime dependencies (single line to avoid backslash issues)
RUN apt-get update && apt-get install -y ca-certificates iptables iproute2 netcat-openbsd python3 bc libstdc++6 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy prebuilt Linux server binary from releases/
COPY aivpn-server-linux-x86_64 /usr/local/bin/aivpn-server
RUN chmod +x /usr/local/bin/aivpn-server

# Create config directory, masks directory, and TUN device node (single line to avoid backslash issues)
RUN mkdir -p /etc/aivpn /var/lib/aivpn/masks /var/lib/aivpn/bootstrap /usr/share/aivpn/preset-masks /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null || true && chmod 666 /dev/net/tun

# Copy mask assets to preset directory
COPY mask-assets/*.json /usr/share/aivpn/preset-masks/

# Copy prebuilt entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--listen", "0.0.0.0:443", "--key-file", "/etc/aivpn/server.key", "--clients-db", "/etc/aivpn/clients.json"]
DOCKERFILE

# Build Docker image using Dockerfile.prebuilt
echo "Building AIVPN Docker image from prebuilt binary..."
docker build -t aivpn-server:local -f Dockerfile.prebuilt .

# Run AIVPN container
echo "Running AIVPN container..."
RUN_OUTPUT=$(docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun --network host -v "$CONFIG_DIR:/etc/aivpn" -v /var/lib/aivpn/masks:/var/lib/aivpn/masks aivpn-server:local --listen "0.0.0.0:${VPN_PORT}" --key-file /etc/aivpn/server.key --clients-db /etc/aivpn/clients.json 2>&1)
RUN_EXIT=$?
echo "docker run exit code: $RUN_EXIT"
echo "docker run output: $RUN_OUTPUT"

sleep 3

# Check container exists
echo "Checking container..."
CONTAINER_EXISTS=$(docker ps -a --filter "name=$CONTAINER_NAME" --format {{.Names}} 2>/dev/null)
echo "Container exists: $CONTAINER_EXISTS"

if [ -z "$CONTAINER_EXISTS" ]; then
  echo "ERROR: Container was not created"
  exit 1
fi

# Check container status
STATUS=$(docker inspect --format={{.State.Status}} "$CONTAINER_NAME" 2>/dev/null || echo "")
if [ -z "$STATUS" ]; then
  STATUS="unknown"
fi
echo "Container status: $STATUS"

if [ "$STATUS" != "running" ]; then
  echo "ERROR: AIVPN container is not running (status: $STATUS)"
  echo "=== Container logs ==="
  docker logs "$CONTAINER_NAME" 2>&1 || echo "No logs available"
  echo "=== Container inspect ==="
  docker inspect "$CONTAINER_NAME" 2>&1 || echo "Container not found"
  exit 1
fi

echo "AIVPN installed successfully"
# Output variables for the web panel parser
KEY_B64=$(base64 -w 0 "$CONFIG_DIR/server.key" 2>/dev/null || base64 "$CONFIG_DIR/server.key")
echo "Variable: connection_key=$KEY_B64"
echo "Variable: server_host=$EXTERNAL_IP"
echo "Variable: server_port=$VPN_PORT"
echo "Variable: config_dir=$CONFIG_DIR"',
    definition = JSON_OBJECT(
      'engine', 'shell',
      'metadata', JSON_OBJECT(
        'container_name', 'aivpn-server',
        'port_range', JSON_ARRAY(443, 443),
        'config_dir', '/etc/aivpn',
        'vpn_subnet', '10.0.0.0/24',
        'requires_docker_build', true,
        'git_repo', 'https://github.com/infosave2007/aivpn.git',
        'build_method', 'dockerfile_prebuilt'
      )
    ),
    updated_at = NOW()
WHERE slug = 'aivpn';
