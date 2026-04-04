#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-admin@amnez.ia}"
PASSWORD="${PASSWORD:-admin123}"
CLIENT_NAME="${CLIENT_NAME:-}"
CLIENT_ID="${CLIENT_ID:-}"
OUT_DIR="${OUT_DIR:-scripts/_cycle_out}"

mkdir -p "$OUT_DIR"

if [[ -z "$CLIENT_ID" && -z "$CLIENT_NAME" ]]; then
  echo "ERROR: set CLIENT_ID or CLIENT_NAME" >&2
  exit 2
fi

TOKEN_JSON=$(curl -sS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD")
TOKEN=$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

if [[ -z "${TOKEN:-}" ]]; then
  echo "ERROR: token empty" >&2
  printf '%s' "$TOKEN_JSON" | head -c 200 >&2
  echo >&2
  exit 3
fi

if [[ -z "$CLIENT_ID" ]]; then
  CLIENTS_JSON=$(curl -fsS "$PANEL_URL/api/clients" -H "Authorization: Bearer $TOKEN")
  CLIENT_ID=$(printf '%s' "$CLIENTS_JSON" | python3 -c 'import sys,json; j=json.load(sys.stdin); needle=sys.argv[1];
for c in j.get("clients",[]):
  if str(c.get("name",""))==needle:
    print(c.get("id",""));
    raise SystemExit
print("")' "$CLIENT_NAME")
fi

if [[ -z "${CLIENT_ID:-}" ]]; then
  echo "ERROR: client not found" >&2
  exit 4
fi

RESP=$(curl -fsS -X POST "$PANEL_URL/api/clients/$CLIENT_ID/regenerate-config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' )

JSON_OUT="$OUT_DIR/regenerate_${CLIENT_ID}.json"
CONF_OUT="$OUT_DIR/${CLIENT_NAME:-client_${CLIENT_ID}}_regenerated.conf"

printf '%s' "$RESP" >"$JSON_OUT"

# Extract config field
printf '%s' "$RESP" | python3 -c 'import sys,json; j=json.load(sys.stdin); c=(j.get("client") or {}).get("config") or ""; sys.stdout.write(c)' >"$CONF_OUT"

echo "saved_json:$JSON_OUT"
echo "saved_conf:$CONF_OUT"
