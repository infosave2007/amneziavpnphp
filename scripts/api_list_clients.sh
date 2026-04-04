#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-admin@amnez.ia}"
PASSWORD="${PASSWORD:-admin123}"

TOKEN_JSON=$(curl -sS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD")
TOKEN=$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

if [[ -z "${TOKEN:-}" ]]; then
  echo "ERROR: token empty" >&2
  printf '%s' "$TOKEN_JSON" | head -c 200 >&2
  echo >&2
  exit 3
fi

curl -fsS "$PANEL_URL/api/clients" -H "Authorization: Bearer $TOKEN" | \
  python3 -c 'import sys,json; j=json.load(sys.stdin); cs=j.get("clients",[]);
print("id\tname\tprotocol\tserver_id")
for c in cs:
  print(f"{c.get("id")}\t{c.get("name")}\t{c.get("protocol")}\t{c.get("server_id")}")'
