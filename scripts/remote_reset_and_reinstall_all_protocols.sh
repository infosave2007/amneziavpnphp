#!/usr/bin/env bash
set -euo pipefail

# Configuration via environment variables. Required (no defaults, script aborts if unset):
#   PANEL_PASSWORD  panel admin password
#   REMOTE_HOST     target server host/IP
#   REMOTE_PASS     target server SSH password
# Example:
#   REMOTE_HOST=1.2.3.4 REMOTE_PASS=... PANEL_PASSWORD=... ./remote_reset_and_reinstall_all_protocols.sh
PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${PANEL_EMAIL:-admin@amnez.ia}"
PASSWORD="${PANEL_PASSWORD:?set PANEL_PASSWORD}"
SERVER_ID="${SERVER_ID:-1}"
REMOTE_HOST="${REMOTE_HOST:?set REMOTE_HOST}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PASS="${REMOTE_PASS:?set REMOTE_PASS}"

# protocol IDs in this workspace
AWG2_ID="11"
AIVPN_ID="13"
MTPROXY_ID="12"

echo "== auth =="
TOKEN=$(curl -sS -X POST "$PANEL_URL/api/auth/token" \
  -d "email=$EMAIL&password=$PASSWORD" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

echo "== remote full docker cleanup =="
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" 'bash -s' <<'EOSSH'
set -euo pipefail

# Stop and remove all containers if any
if [ -n "$(docker ps -aq 2>/dev/null || true)" ]; then
  docker rm -f $(docker ps -aq) >/dev/null 2>&1 || true
fi

# Full cleanup of images/volumes/networks/build cache
if command -v docker >/dev/null 2>&1; then
  docker system prune -af --volumes >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
fi

# Remove protocol dirs to force fresh bootstrap
rm -rf /opt/amnezia /etc/aivpn /etc/amnezia /etc/mtproxy 2>/dev/null || true
mkdir -p /opt/amnezia /etc/aivpn /etc/amnezia /etc/mtproxy

echo "remote cleanup done"
EOSSH

echo "== install awg2 =="
curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/install" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"protocol_id\":$AWG2_ID}" | tee /tmp/install_awg2_after_remote_reset.json

echo
echo "== install aivpn =="
curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/install" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"protocol_id\":$AIVPN_ID}" | tee /tmp/install_aivpn_after_remote_reset.json

echo
echo "== install mtproxy =="
curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/install" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"protocol_id\":$MTPROXY_ID}" | tee /tmp/install_mtproxy_after_remote_reset.json

echo
echo "== verify containers on remote =="
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" \
  "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"

echo
echo "done"
