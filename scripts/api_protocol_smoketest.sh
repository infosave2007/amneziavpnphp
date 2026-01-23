#!/usr/bin/env bash
set -euo pipefail

PANEL_URL="${PANEL_URL:-http://localhost:8082}"
EMAIL="${EMAIL:-}"
PASSWORD="${PASSWORD:-}"
TOKEN="${TOKEN:-}"
SERVER_ID="${SERVER_ID:-1}"
PROTOCOL_ID="${PROTOCOL_ID:-}"
UNINSTALL_SLUG="${UNINSTALL_SLUG:-}"
CLIENT_NAME="${CLIENT_NAME:-smoke-client}"
CLIENT_LOGIN="${CLIENT_LOGIN:-smoke-client}"
SELFTEST="${SELFTEST:-1}"
DIAGNOSE="${DIAGNOSE:-1}"

if [[ -z "$TOKEN" ]]; then
  if [[ -z "$EMAIL" || -z "$PASSWORD" ]]; then
    echo "ERROR: set TOKEN or (EMAIL and PASSWORD)" >&2
    exit 1
  fi
  echo "[1/6] Getting JWT token..." >&2
  TOKEN="$(curl -fsS -X POST "$PANEL_URL/api/auth/token" -d "email=$EMAIL&password=$PASSWORD" | php -r '$j=json_decode(stream_get_contents(STDIN),true); echo $j["token"] ?? "";')"
fi

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: failed to obtain token" >&2
  exit 1
fi

auth=(-H "Authorization: Bearer $TOKEN")

echo "[2/6] Listing active protocols..." >&2
curl -fsS "$PANEL_URL/api/protocols/active" "${auth[@]}" | cat

if [[ -n "$UNINSTALL_SLUG" ]]; then
  echo "[3/6] Uninstalling protocol slug=$UNINSTALL_SLUG on server=$SERVER_ID ..." >&2
  curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/$UNINSTALL_SLUG/uninstall" "${auth[@]}" | cat
else
  echo "[3/6] Skipping uninstall (set UNINSTALL_SLUG to run)." >&2
fi

if [[ -n "$PROTOCOL_ID" ]]; then
  echo "[4/6] Installing protocol_id=$PROTOCOL_ID on server=$SERVER_ID ..." >&2
  curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/install" \
    "${auth[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"protocol_id\": $PROTOCOL_ID}" | cat
else
  echo "[4/6] Skipping install (set PROTOCOL_ID to run)." >&2
fi

echo "[5/6] Creating client on server=$SERVER_ID (protocol_id=${PROTOCOL_ID:-auto})..." >&2
CREATE_PAYLOAD=$(php -r '$d=["server_id"=>(int)getenv("SERVER_ID"),"name"=>getenv("CLIENT_NAME"),"login"=>getenv("CLIENT_LOGIN")]; $pid=getenv("PROTOCOL_ID"); if($pid!==false && $pid!==""){$d["protocol_id"]= (int)$pid;} echo json_encode($d, JSON_UNESCAPED_SLASHES);')
RESP="$(curl -fsS -X POST "$PANEL_URL/api/clients/create" "${auth[@]}" -H "Content-Type: application/json" -d "$CREATE_PAYLOAD")"
echo "$RESP" | cat

CLIENT_ID=$(echo "$RESP" | php -r '$j=json_decode(stream_get_contents(STDIN),true); echo $j["client"]["id"] ?? "";')

if [[ -n "$CLIENT_ID" ]]; then
  echo "[6/6] Fetching client details (includes stats sync)..." >&2
  curl -fsS "$PANEL_URL/api/clients/$CLIENT_ID/details" "${auth[@]}" | cat

  if [[ "$SELFTEST" == "1" ]]; then
    echo >&2
    echo "[selftest] Verifying generated config vs server wg0..." >&2
    SELFTEST_PAYLOAD=$(php -r '$d=["protocol_id"=>getenv("PROTOCOL_ID")!==false && getenv("PROTOCOL_ID")!=="" ? (int)getenv("PROTOCOL_ID") : 0, "install"=>false, "create_client"=>false, "client_id"=>(int)getenv("CLIENT_ID")]; echo json_encode($d, JSON_UNESCAPED_SLASHES);')
    SELFTEST_RESP=$(curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/selftest" \
      "${auth[@]}" \
      -H "Content-Type: application/json" \
      -d "$SELFTEST_PAYLOAD")
    echo "$SELFTEST_RESP" | cat

    if [[ "$DIAGNOSE" == "1" ]]; then
      # If peer endpoint is none OR latest_handshake=0, run server-side diagnostics
      NEED_DIAG=$(echo "$SELFTEST_RESP" | php -r '$j=json_decode(stream_get_contents(STDIN),true); $hs=$j["wg"]["peer"]["latest_handshake"] ?? null; $ep=$j["wg"]["peer"]["endpoint"] ?? null; echo ((string)$ep==="(none)" || (int)$hs===0) ? "1" : "0";')
      if [[ "$NEED_DIAG" == "1" ]]; then
        echo >&2
        echo "[diagnose] Collecting server-side evidence (wg/ports/firewall/tcpdump)..." >&2
        DIAG_PAYLOAD=$(php -r '$d=["client_id"=>(int)getenv("CLIENT_ID"),"duration_seconds"=>5]; echo json_encode($d, JSON_UNESCAPED_SLASHES);')
        curl -fsS -X POST "$PANEL_URL/api/servers/$SERVER_ID/protocols/diagnose-handshake" \
          "${auth[@]}" \
          -H "Content-Type: application/json" \
          -d "$DIAG_PAYLOAD" | cat
      fi
    fi
  fi
else
  echo "[6/6] No client id returned; skipping details." >&2
fi

echo >&2
echo "Done." >&2
