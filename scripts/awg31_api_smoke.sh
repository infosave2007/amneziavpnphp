#!/bin/sh
set -eu
umask 077
: "${AWG31_API_BASE:?set AWG31_API_BASE}"
: "${AWG31_TOKEN_FILE:?set AWG31_TOKEN_FILE}"
: "${AWG31_SERVER_ID:?set AWG31_SERVER_ID}"
: "${AWG31_OUTPUT_DIR:?set AWG31_OUTPUT_DIR to a private directory}"
command -v jq >/dev/null
mkdir -p "$AWG31_OUTPUT_DIR"
chmod 700 "$AWG31_OUTPUT_DIR"
OWNER_CURL="$AWG31_OUTPUT_DIR/owner.curl"; ADMIN_CURL="$AWG31_OUTPUT_DIR/admin.curl"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$AWG31_TOKEN_FILE")" > "$OWNER_CURL"
cp "$OWNER_CURL" "$ADMIN_CURL"
if [ -n "${AWG31_ADMIN_TOKEN_FILE:-}" ]; then printf 'header = "Authorization: Bearer %s"\n' "$(cat "$AWG31_ADMIN_TOKEN_FILE")" > "$ADMIN_CURL"; fi
chmod 600 "$OWNER_CURL" "$ADMIN_CURL"
api() { method=$1; path=$2; body=${3-}; out=$4; limit=30; [ "$path" = "/api/servers/$AWG31_SERVER_ID/protocols/install" ] && limit=900; if [ -n "$body" ]; then curl -K "$OWNER_CURL" --connect-timeout 5 --max-time "$limit" -fsS -X "$method" -H 'Content-Type: application/json' --data "$body" "$AWG31_API_BASE$path" > "$out"; else curl -K "$OWNER_CURL" --connect-timeout 5 --max-time "$limit" -fsS -X "$method" "$AWG31_API_BASE$path" > "$out"; fi; }
api GET /api/protocols/active '' "$AWG31_OUTPUT_DIR/protocols.json"
AWG31_PROTOCOL_ID=${AWG31_PROTOCOL_ID:-$(jq -er '.protocols[]|select(.slug=="awg31")|.id' "$AWG31_OUTPUT_DIR/protocols.json" | head -1)}
jq -e --argjson id "$AWG31_PROTOCOL_ID" '.protocols[] | select(.id==$id and .slug=="awg31")' "$AWG31_OUTPUT_DIR/protocols.json" >/dev/null
api POST "/api/servers/$AWG31_SERVER_ID/protocols/install" "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"settings\":{}}" "$AWG31_OUTPUT_DIR/install.json"
jq -e '(.success==true or .success=="true" or .success==1)' "$AWG31_OUTPUT_DIR/install.json" >/dev/null
ids=''
RUN_NAME=${AWG31_RUN_NAME:-awg31-smoke-$$}
i=1
while [ "$i" -le 3 ]; do
  api POST /api/clients/create "{\"server_id\":$AWG31_SERVER_ID,\"protocol_id\":$AWG31_PROTOCOL_ID,\"name\":\"$RUN_NAME-$i\"}" "$AWG31_OUTPUT_DIR/create-$i.json"
  id=$(jq -er '.client.id' "$AWG31_OUTPUT_DIR/create-$i.json")
  ids="$ids $id"
  i=$((i+1))
done
set -- $ids
first=$1; second=$2; third=$3
jq -s -e 'map(.client.client_ip) | length==3 and (unique|length)==3' "$AWG31_OUTPUT_DIR/create-1.json" "$AWG31_OUTPUT_DIR/create-2.json" "$AWG31_OUTPUT_DIR/create-3.json" >/dev/null
api GET "/api/clients/$second/details" '' "$AWG31_OUTPUT_DIR/details.json"
api GET "/api/clients/$second/qr" '' "$AWG31_OUTPUT_DIR/qr.json"
jq -e '.client.config|contains("HeaderProtectionKey = ")' "$AWG31_OUTPUT_DIR/details.json" >/dev/null
jq -e '(.vpn_url|startswith("vpn://")) and (.qr_code|startswith("data:image/png;base64,"))' "$AWG31_OUTPUT_DIR/qr.json" >/dev/null
PROBE_RESULT=SKIP
probe_phase() {
  phase=$1
  [ -n "${AWG31_PROBE_BIN:-}" ] || return 0
  : "${AWG31_EXPECTED_EGRESS:?set AWG31_EXPECTED_EGRESS with AWG31_PROBE_BIN}"
  api POST "/api/servers/$AWG31_SERVER_ID/protocols/selftest" "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"client_id\":$second,\"create_client\":false}" "$AWG31_OUTPUT_DIR/selftest-$phase-before.json"
  jq -er '.client.config' "$AWG31_OUTPUT_DIR/details.json" > "$AWG31_OUTPUT_DIR/probe.conf"; chmod 600 "$AWG31_OUTPUT_DIR/probe.conf"
  "$AWG31_PROBE_BIN" -config "$AWG31_OUTPUT_DIR/probe.conf" -expected-egress "$AWG31_EXPECTED_EGRESS" > "$AWG31_OUTPUT_DIR/probe-$phase.json"
  jq -e '.success==true and .egress_matches_expected==true and .dns_answers>0 and .https_status>=200 and .https_status<400' "$AWG31_OUTPUT_DIR/probe-$phase.json" >/dev/null
  api POST "/api/servers/$AWG31_SERVER_ID/protocols/selftest" "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"client_id\":$second,\"create_client\":false}" "$AWG31_OUTPUT_DIR/selftest-$phase-after.json"
  jq -e --slurpfile before "$AWG31_OUTPUT_DIR/selftest-$phase-before.json" '.success==true and ((.wg.peer.transfer_rx > $before[0].wg.peer.transfer_rx) or (.wg.peer.transfer_tx > $before[0].wg.peer.transfer_tx))' "$AWG31_OUTPUT_DIR/selftest-$phase-after.json" >/dev/null
  PROBE_RESULT=PASS
}
api POST "/api/clients/$second/regenerate-config" '{}' "$AWG31_OUTPUT_DIR/regenerate.json"
api POST "/api/clients/$first/revoke" '{}' "$AWG31_OUTPUT_DIR/revoke.json"
probe_phase revoked
api POST /api/clients/create "{\"server_id\":$AWG31_SERVER_ID,\"protocol_id\":$AWG31_PROTOCOL_ID,\"name\":\"$RUN_NAME-4\"}" "$AWG31_OUTPUT_DIR/create-4.json"
fourth=$(jq -er '.client.id' "$AWG31_OUTPUT_DIR/create-4.json")
fourth_ip=$(jq -er '.client.client_ip' "$AWG31_OUTPUT_DIR/create-4.json")
api POST "/api/clients/$first/restore" '{}' "$AWG31_OUTPUT_DIR/restore-client.json"
api POST "/api/servers/$AWG31_SERVER_ID/backup" '{}' "$AWG31_OUTPUT_DIR/backup.json"
backup=$(jq -er '.backup.id' "$AWG31_OUTPUT_DIR/backup.json")
api DELETE "/api/clients/$fourth/delete" '' "$AWG31_OUTPUT_DIR/delete-before-restore.json"
probe_phase deleted
api POST "/api/servers/$AWG31_SERVER_ID/restore" "{\"backup_id\":$backup}" "$AWG31_OUTPUT_DIR/restore-backup.json"
jq -e '.success==true and .restored>=1' "$AWG31_OUTPUT_DIR/restore-backup.json" >/dev/null
api POST "/api/servers/$AWG31_SERVER_ID/protocols/selftest" "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"client_id\":$second,\"create_client\":false}" "$AWG31_OUTPUT_DIR/selftest.json"
jq -e '.success==true and (.mismatches|length)==0 and .checks.effective_settings.ok==true' "$AWG31_OUTPUT_DIR/selftest.json" >/dev/null
curl -K "$ADMIN_CURL" --connect-timeout 5 --max-time 30 -fsS -X POST -H 'Content-Type: application/json' --data "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"client_id\":$second,\"duration_seconds\":1}" "$AWG31_API_BASE/api/servers/$AWG31_SERVER_ID/protocols/diagnose-handshake" > "$AWG31_OUTPUT_DIR/diagnose.json"
jq -e '.success==true and .evidence.pinned_provenance_match==true and (.evidence.docker_published_port==.vpn_port_db)' "$AWG31_OUTPUT_DIR/diagnose.json" >/dev/null
if [ -n "${AWG31_STRANGER_TOKEN_FILE:-}" ]; then
  STRANGER_CURL="$AWG31_OUTPUT_DIR/stranger.curl"; printf 'header = "Authorization: Bearer %s"\n' "$(cat "$AWG31_STRANGER_TOKEN_FILE")" > "$STRANGER_CURL"; chmod 600 "$STRANGER_CURL"
  code=$(curl -K "$STRANGER_CURL" -sS -o "$AWG31_OUTPUT_DIR/stranger-details.json" -w '%{http_code}' --connect-timeout 5 --max-time 30 "$AWG31_API_BASE/api/clients/$second/details"); [ "$code" = 403 ]
  code=$(curl -K "$STRANGER_CURL" -sS -o "$AWG31_OUTPUT_DIR/stranger-install.json" -w '%{http_code}' --connect-timeout 5 --max-time 30 -X POST -H 'Content-Type: application/json' --data "{\"protocol_id\":$AWG31_PROTOCOL_ID,\"settings\":{}}" "$AWG31_API_BASE/api/servers/$AWG31_SERVER_ID/protocols/install"); [ "$code" = 403 ]
  STRANGER_RESULT=PASS
fi
CLEANUP_RESULT=SKIP
if [ "${AWG31_CLEANUP:-0}" = 1 ]; then
  api GET "/api/servers/$AWG31_SERVER_ID/clients" '' "$AWG31_OUTPUT_DIR/clients-after-restore.json"
  restored_fourth=$(jq -er --arg n "$RUN_NAME-4" --arg ip "$fourth_ip" --argjson old "$fourth" '[.clients[]|select(.name==$n and .client_ip==$ip and .id!=$old)|.id] | if length==1 then .[0] else error("expected one restored fourth client") end' "$AWG31_OUTPUT_DIR/clients-after-restore.json")
  for id in $first $second $third $restored_fourth; do api DELETE "/api/clients/$id/delete" '' "$AWG31_OUTPUT_DIR/delete-$id.json"; done
  CLEANUP_RESULT=PASS
fi
printf 'install=PASS clients=%s,%s,%s,%s backup=%s backup_restore=PASS details=PASS qr=PASS regenerate=PASS revoke_restore=PASS selftest=PASS diagnose=PASS probe=%s stranger=%s cleanup=%s\n' "$first" "$second" "$third" "$fourth" "$backup" "$PROBE_RESULT" "${STRANGER_RESULT:-SKIP}" "$CLEANUP_RESULT"
