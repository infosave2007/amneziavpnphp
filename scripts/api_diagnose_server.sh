#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-admin@amnez.ia}"
PASSWORD="${PASSWORD:-admin123}"
SERVER_ID="${SERVER_ID:-5}"
OUT_FILE="${OUT_FILE:-scripts/_cycle_out/diagnose_no_client.json}"
DURATION="${DURATION:-2}"

mkdir -p "$(dirname "$OUT_FILE")"

TOKEN_JSON=$(curl -sS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD")
TOKEN=$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

TMP_FILE="${OUT_FILE}.tmp"
RESP=$(curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/diagnose-handshake" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"duration_seconds\":$DURATION}" || true)

if [[ -z "${RESP:-}" ]]; then
  echo "ERROR: empty response from diagnose-handshake" >&2
  echo "PANEL_URL=$PANEL_URL SERVER_ID=$SERVER_ID" >&2
  echo "Token JSON (first 200):" >&2
  printf '%s' "$TOKEN_JSON" | head -c 200 >&2
  echo >&2
  exit 2
fi

printf '%s' "$RESP" > "$TMP_FILE"
mv "$TMP_FILE" "$OUT_FILE"

echo "saved:$OUT_FILE"
