#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-admin@amnez.ia}"
PASSWORD="${PASSWORD:-admin123}"
SERVER_ID="${SERVER_ID:-5}"
CLIENT_ID="${CLIENT_ID:-}"
DURATION="${DURATION:-10}"
OUT_FILE="${OUT_FILE:-}"

if [[ -z "${CLIENT_ID}" ]]; then
  echo "ERROR: CLIENT_ID is required" >&2
  exit 2
fi

if [[ -z "${OUT_FILE}" ]]; then
  OUT_FILE="scripts/_cycle_out/diagnose_client_${CLIENT_ID}.json"
fi

mkdir -p "$(dirname "$OUT_FILE")"

TOKEN_JSON=$(curl -sS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD")
TOKEN=$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: token empty" >&2
  printf '%s' "$TOKEN_JSON" | head -c 300 >&2
  echo >&2
  exit 3
fi

RESP_WITH_STATUS=$(curl -sS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/diagnose-handshake" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":$CLIENT_ID,\"duration_seconds\":$DURATION}" \
  -w "\n__HTTP_STATUS__%{http_code}")

HTTP_STATUS=$(printf '%s' "$RESP_WITH_STATUS" | awk -F'__HTTP_STATUS__' 'END{print $2}')
RESP=$(printf '%s' "$RESP_WITH_STATUS" | awk -F'__HTTP_STATUS__' '{print $1}')

if [[ -z "${RESP:-}" ]]; then
  echo "ERROR: empty response (http_status=${HTTP_STATUS:-unknown})" >&2
  exit 4
fi

TMP_FILE="${OUT_FILE}.tmp"
printf '%s' "$RESP" >"$TMP_FILE"
mv "$TMP_FILE" "$OUT_FILE"

echo "saved:$OUT_FILE (http_status=${HTTP_STATUS:-unknown})"

if [[ "${HTTP_STATUS:-}" =~ ^[0-9]+$ ]] && [[ "${HTTP_STATUS}" -ge 400 ]]; then
  exit 5
fi
