# AmneziaWG 3.1

AWG 3.1 is a separate protocol named `awg31`. It does not upgrade or reuse an
existing AWG/AWG2 installation. The panel installs the pinned userspace engine
in `amnezia-awg31`, stores host state in `/opt/amnezia/awg31`, and mounts it at
`/opt/amnezia/awg` inside the container.

Install it through the existing API: list `/api/protocols/active`, pass the
`awg31` protocol id to `/api/servers/{id}/protocols/install`, and pass that same
`protocol_id` when creating clients or running self-test/diagnostics. The
optional `settings` object accepts only the documented AWG 3.1 fields; omitted
values use the pinned upstream defaults. Exports include native `.conf`, QR,
and `vpn://` with `container=amnezia-awg`, protocol key `awg`, and
`protocol_version=3.1`.

The target remains an Ubuntu server reachable over the panel's SSH transport.
The installer requires Docker, Git and `ss` from `iproute2`; the existing Docker
bootstrap runs first, and the AWG 3.1 script installs Git/iproute2 with `apt-get`
when they are absent or returns an actionable prerequisite error.

Run `php scripts/awg31_contract_test.php` for the dependency-light contract
suite. `scripts/awg31_api_smoke.sh` documents the protected-token API smoke
entry point. Native Amnezia application import is a separate interoperability
check and is not implied by envelope-schema or userspace traffic tests.

For an existing native Amnezia backup, `container=amnezia-awg` describes the
observed runtime and remains separate from the `awg31` protocol identity. The
importer validates AWG 3.1 fields and stores the protocol binding by slug so a
destination catalog may use different numeric IDs. Fresh panel installs retain
the isolated `amnezia-awg31` namespace. Panel uninstall intentionally refuses
an imported native runtime because the panel does not own it; remove that
runtime through the native installation workflow. Fresh panel-owned AWG31
uninstall removes only `amnezia-awg31`, its image and `/opt/amnezia/awg31`.

## Migrating an existing AWG or AWG2 installation

Migration is an explicit parallel cutover. Keep the old container and a
protected copy of its configuration while installing `awg31` into its separate
container and directory. If an HTTP install request was interrupted, first
check that no original request, remote build, or install process is still
running. Reuse the existing server row and call its protocol-install API again;
do not create a duplicate server or select the generic **Restore** action for a
panel-owned AWG 3.1 userspace installation. The pinned installer is idempotent
for a complete `/opt/amnezia/awg31` state and reports incomplete source, config,
or key sets as errors that must be reconciled before retrying.

Preserve client identities only when their complete configurations, including
client private keys, are available. Native server metadata commonly contains
only peer public keys and PSKs. In that case create new clients through the
maintained API, record a stable old-to-new name mapping, assign unique target
addresses, and deliver the newly exported configurations. Disambiguate
duplicate names without merging or dropping peers. Verify every exported
public key, PSK, and address against the live AWG 3.1 peer, test tunnel DNS,
HTTPS, and egress, and restart-test the new container before stopping the old
container. Retain the stopped old container and protected backup until the
operator accepts the new configurations; rollback means stopping AWG 3.1 and
starting the preserved old container and restoring its recorded original
restart policy. This procedure does not claim automatic in-place client
migration.

The lifecycle runner takes its endpoint, token file, server ID, protocol ID and
private output directory from environment variables. It installs AWG 3.1,
creates four clients, exercises details, QR, regeneration, revoke, restore,
backup, self-test and diagnosis, and can delete its clients with
`AWG31_CLEANUP=1`. It writes secret-bearing API bodies only into the private
output directory and prints a compact receipt.

## Reproducible checks

```sh
AWG31_API_BASE=http://127.0.0.1:18082 \
AWG31_TOKEN_FILE=/private/owner-token AWG31_ADMIN_TOKEN_FILE=/private/admin-token \
AWG31_STRANGER_TOKEN_FILE=/private/stranger-token AWG31_SERVER_ID=1 \
AWG31_OUTPUT_DIR=/private/run AWG31_PROBE_BIN=/path/to/awg31-netstack-probe \
AWG31_EXPECTED_EGRESS=203.0.113.10 \
  sh scripts/awg31_api_smoke.sh

/path/to/awg31-netstack-probe -config /private/exported.conf \
  -expected-egress 203.0.113.10
```

The probe runs the exact exported config in an unprivileged userspace netstack and requires nonce ICMP, DNS, HTTPS, and the expected public egress to succeed. Build it from the pinned `amneziawg-go` module checkout so its imports resolve to that source tree.

```sh
git clone https://github.com/amnezia-vpn/amneziawg-go.git /tmp/amneziawg-go-31
git -C /tmp/amneziawg-go-31 checkout --detach b5928efb6ca19f0153958460c3d141f04abc5c2e
cp scripts/awg31_netstack_probe.go /tmp/amneziawg-go-31/
(cd /tmp/amneziawg-go-31 && go build -o /tmp/awg31-netstack-probe ./awg31_netstack_probe.go)
```
The runner resolves the `awg31` catalog id automatically. Probe and stranger-token stages run when their inputs are supplied; otherwise their absence is not reported as a pass. `AWG31_CLEANUP=1` removes every exact per-run client, including the disabled replacement created by backup restore. Uninstall is intentionally a separate destructive API check because it removes the isolated AWG31 keys and client reachability.
Run `scripts/awg31_regression/run.sh` for the SQLite/mocked-transport maintained-caller suite covering allocation, regeneration, portable/native imports, secondary protocol IDs, peer PSKs, restore/delete state, and failure paths.

## AWG 3.1 fields

| Field | Fresh-install default | Accepted value / omission |
|---|---:|---|
| `HeaderProtectionKey` | generated 32-byte key | 44-character base64; may remain absent on legacy/native import |
| `ContentPaddingAddition` | absent | uint16 or `low-high`; omitted line stays absent |
| `RekeyAfterTime` | `100-120` | uint16 or ordered uint16 range |
| `RekeyTimeout` | `3-7` | uint16 or ordered uint16 range |
| `RejectAfterTime` | `150-180` | uint16 or ordered uint16 range |
| `KeepaliveTimeout` | `5-15` | uint16 or ordered uint16 range |
| `MaxHandshakeAttempts` | `15-20` | uint16 or ordered uint16 range |
| `RandomTrailers` | `on` | `on`/`off` (boolean spellings normalize) |
| `DisableCookies` | `on` | `on`/`off` (boolean spellings normalize) |

When `HeaderProtectionKey` is present, `S1` through `S4` must each be at least 12. Scalar settings reject CR/LF. Fresh installation validates defaults plus overrides before SSH effects. Import and regeneration preserve absence because older clients and native backups may not carry the nine fields. Native Amnezia app import remains unverified unless that application is actually run; the schema, QR decode, and userspace traffic tests are separate evidence.

## QR imports

The client page exposes two camera formats for AWG 2 and AWG 3.1. **Native AWG configuration** is a plain WireGuard-style config QR, matching Amnezia's native AWG export. **Full Amnezia connection** is the compressed native connection envelope split into numbered QR parts at the upstream 850-byte boundary. Scan every numbered part in order. The separately displayed `vpn://` value is for copy and paste; its scheme is intentionally not encoded into the camera QR parts.

QR images are generated from the current stored config when the page or API export is read. This corrects QR output for clients created by older panel versions without rotating keys, changing the peer, or regenerating the VPN config. The `/api/clients/{id}/qr` and details responses include `vpn_qr_codes` as an ordered array and retain `vpn_url` as text.

Run the self-contained QR framing test and the broader AWG 3.1 contract checks after changing exports:

```bash
php scripts/qr_import_contract_test.php
php scripts/awg31_contract_test.php
```

Translation migration source checks run without a database. The integration test creates and removes a uniquely named disposable schema and requires a protected MySQL client option file with create/drop privileges:

```bash
scripts/encoding_migration_contract_test.sh
MYSQL_DEFAULTS_FILE=/path/to/mode-600-client.cnf scripts/encoding_mysql_integration_test.sh
```
