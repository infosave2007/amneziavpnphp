#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-admin@amnez.ia}"
PASSWORD="${PASSWORD:-admin123}"
SERVER_HOST="${SERVER_HOST:?set SERVER_HOST (panel server host/IP)}"
PROTOCOL_SLUG="${PROTOCOL_SLUG:-amnezia-wg-advanced}"
CLIENT_NAME="${CLIENT_NAME:-api-selfcheck}"
CLIENT_LOGIN="${CLIENT_LOGIN:-api-selfcheck}"
OUT_DIR="${OUT_DIR:-scripts/_cycle_out}"

mkdir -p "$OUT_DIR"

AUTH_RESP=$(curl -sS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD" || true)
TOKEN=$(printf '%s' "$AUTH_RESP" | python3 -c 'import sys,json; raw=sys.stdin.read().strip();
import sys
if not raw: sys.exit(2)
j=json.loads(raw)
print(j.get("token",""))
') || {
  echo "ERROR: failed to parse /api/auth/token response" >&2
  echo "PANEL_URL=$PANEL_URL" >&2
  echo "Response (first 500 chars):" >&2
  printf '%s' "$AUTH_RESP" | head -c 500 >&2
  echo >&2
  exit 1
}
if [[ -z "${TOKEN:-}" ]]; then
  echo "ERROR: token is empty" >&2
  printf '%s' "$AUTH_RESP" | head -c 500 >&2
  echo >&2
  exit 1
fi
echo "TOKEN_OK"

SERVER_JSON=$(curl -fsS "$PANEL_URL/api/servers" -H "Authorization: Bearer $TOKEN")
SERVER_ID=$(printf '%s' "$SERVER_JSON" | python3 -c 'import sys,json; j=json.load(sys.stdin); host=sys.argv[1];
out="";
for s in j.get("servers",[]):
  if str(s.get("host","" )).strip()==host:
    out=str(s.get("id",""))
    break
print(out)
' "$SERVER_HOST")

if [[ -z "${SERVER_ID:-}" ]]; then
  echo "ERROR: server with host $SERVER_HOST not found" >&2
  printf '%s' "$SERVER_JSON" | python3 -m json.tool | head -200
  exit 1
fi

echo "SERVER_ID=$SERVER_ID"

PROTO_JSON=$(curl -fsS "$PANEL_URL/api/protocols/active" -H "Authorization: Bearer $TOKEN")
PROTOCOL_ID=$(printf '%s' "$PROTO_JSON" | python3 -c 'import sys,json; j=json.load(sys.stdin); slug=sys.argv[1];
out="";
for p in j.get("protocols",[]):
  if p.get("slug")==slug:
    out=str(p.get("id",""))
    break
print(out)
' "$PROTOCOL_SLUG")

if [[ -z "${PROTOCOL_ID:-}" ]]; then
  echo "ERROR: protocol $PROTOCOL_SLUG not found" >&2
  printf '%s' "$PROTO_JSON" | python3 -m json.tool | head -200
  exit 1
fi

echo "PROTOCOL_ID=$PROTOCOL_ID"

pretty_print() {
  # Reads JSON from stdin and pretty-prints it. If it's not JSON, prints raw.
  local data
  data=$(cat)
  if python3 -m json.tool >/dev/null 2>&1 <<<"$data"; then
    python3 -m json.tool <<<"$data"
  else
    printf '%s' "$data"
  fi
}

echo "--- UNINSTALL $PROTOCOL_SLUG (ignore errors)"
set +e
UNINSTALL_RESP=$(curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/$PROTOCOL_SLUG/uninstall" \
  -H "Authorization: Bearer $TOKEN" || true)
printf '%s' "$UNINSTALL_RESP" >"$OUT_DIR/uninstall_${PROTOCOL_SLUG}.txt"
printf '%s' "$UNINSTALL_RESP" | pretty_print | head -200
set -e

echo "--- INSTALL protocol_id=$PROTOCOL_ID"
INSTALL_RESP=$(curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/install" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"protocol_id\":$PROTOCOL_ID}" || true)
printf '%s' "$INSTALL_RESP" >"$OUT_DIR/install_${PROTOCOL_ID}.txt"
printf '%s' "$INSTALL_RESP" | pretty_print | head -200

echo "--- CREATE client"
CLIENT_RESP=$(curl -fsS -X POST "$PANEL_URL/api/clients/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"server_id\":$SERVER_ID,\"protocol_id\":$PROTOCOL_ID,\"name\":\"$CLIENT_NAME\",\"login\":\"$CLIENT_LOGIN\"}")

printf '%s' "$CLIENT_RESP" >"$OUT_DIR/client_create_${PROTOCOL_ID}.txt"

printf '%s' "$CLIENT_RESP" | pretty_print | head -200
CLIENT_ID=$(printf '%s' "$CLIENT_RESP" | python3 -c 'import sys,json; j=json.load(sys.stdin); print(j.get("client",{}).get("id",""))')

if [[ -z "${CLIENT_ID:-}" ]]; then
  echo "ERROR: client_id missing" >&2
  exit 1
fi

echo "CLIENT_ID=$CLIENT_ID"

echo "--- SELFTEST"
SELFTEST_RESP=$(curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/selftest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":$CLIENT_ID,\"create_client\":false,\"install\":false,\"protocol_id\":$PROTOCOL_ID}")

printf '%s' "$SELFTEST_RESP" >"$OUT_DIR/selftest_${CLIENT_ID}.txt"

printf '%s' "$SELFTEST_RESP" | pretty_print | head -260

NEED_DIAG=$(printf '%s' "$SELFTEST_RESP" | python3 -c 'import sys,json; j=json.load(sys.stdin); peer=(j.get("wg") or {}).get("peer") or {}; hs=int(peer.get("latest_handshake") or 0); ep=str(peer.get("endpoint") or ""); print("1" if (ep=="(none)" or hs==0) else "0")')

if [[ "$NEED_DIAG" == "1" ]]; then
  echo "--- DIAGNOSE HANDSHAKE"
  DIAG_RESP=$(curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/diagnose-handshake" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"client_id\":$CLIENT_ID,\"duration_seconds\":5}" || true)
  printf '%s' "$DIAG_RESP" >"$OUT_DIR/diagnose_${CLIENT_ID}.txt"
  printf '%s' "$DIAG_RESP" | pretty_print | head -260
fi

echo "DONE (responses saved in $OUT_DIR)"
