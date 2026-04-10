# Amnezia VPN Web Panel

Web-based management panel for Amnezia AWG (WireGuard) VPN servers.

## Features

- VPN server deployment via SSH (Password or **SSH Key**)
- **Import from existing VPN panels** (wg-easy, 3x-ui)
- **Advanced Protocol Management** (WireGuard, AmneziaWG, OpenVPN, Shadowsocks, etc.)
- **AI-powered Protocol Configuration** using OpenRouter (optional)
- Client configuration management with **expiration dates**
- **Traffic limits** for clients with automatic enforcement
- **Server backup and restore** functionality
- **Scenario Testing**: Define and test different VPN connection scenarios across protocols
- **Advanced Log Management**: View, search, and manage system and container logs
- Traffic statistics monitoring
- QR code generation for mobile apps
- Multi-language interface (English, Russian, Spanish, German, French, Chinese)
- REST API with JWT authentication
- User authentication and access control
- **Automatic client expiration and traffic limit checks** via cron

## Available Protocols

- AmneziaWG Advanced (`amnezia-wg-advanced`)
- AmneziaWG 2.0 (`awg2`)
- WireGuard Standard (`wireguard-standard`)
- OpenVPN (`openvpn`)
- Shadowsocks (`shadowsocks`)
- XRay VLESS (`xray-vless`)
- MTProxy (Telegram) (`mtproxy`)
- SMB Server (`smb`)
- AIVPN (`aivpn`) - https://github.com/infosave2007/aivpn


## Requirements

- Docker
- Docker Compose

## Installation

```bash
git clone https://github.com/infosave2007/amneziavpnphp.git
cd amneziavpnphp
cp .env.example .env

# For Docker Compose V2 (recommended)
docker compose up -d
docker compose exec web composer install

# Wait until DB is healthy (initial SQL migration files are applied automatically by MySQL entrypoint)
until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# Or for older Docker Compose V1
docker-compose up -d
docker-compose exec web composer install

until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# Manual migration mode (existing installations / updates only)
set -a; source .env; set +a
for f in migrations/*.sql; do
  docker compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
done

# For Docker Compose V1 manual migration mode:
# for f in migrations/*.sql; do
#   docker-compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
# done
```

Access: http://localhost:8082

Default login: admin@amnez.ia / admin123

### Remote Server Prerequisite

For protocol deployment on a clean remote host, Docker Engine must be available on that host.
If Docker is missing, install it first (Ubuntu example):

```bash
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
```

## Configuration

Edit `.env`:

```
DB_HOST=db
DB_PORT=3306
DB_DATABASE=amnezia_panel
DB_USERNAME=amnezia
DB_PASSWORD=amnezia

ADMIN_EMAIL=admin@amnez.ia
ADMIN_PASSWORD=admin123

JWT_SECRET=your-secret-key-change-this
```

## Usage

### Add VPN Server

1. Servers → Add Server
2. Enter: name, host IP, SSH port, username
3. Choose authentication method: **Password** or **SSH Key**
   - For SSH Key: Paste your private key (PEM/OpenSSH format)
3. **(Optional) Enable import from existing panel:**
   - Check "Import from existing panel"
   - Select panel type (wg-easy or 3x-ui)
   - Upload backup file (JSON)
4. Click "Create Server"
5. Wait for deployment
6. Clients will be imported automatically if import was enabled

### Create Client

1. Open server details
2. Enter client name
3. **Select expiration period** (optional, default: never expires)
4. **Select traffic limit** (optional, default: unlimited)
5. Click Create Client
6. Download config or scan QR code

### Manage Client Expiration

Set expiration via UI or API:
```bash
# Set specific date
curl -X POST http://localhost:8082/api/clients/123/set-expiration \
  -H "Authorization: Bearer <token>" \
  -d '{"expires_at": "2025-12-31 23:59:59"}'

# Extend by 30 days
curl -X POST http://localhost:8082/api/clients/123/extend \
  -H "Authorization: Bearer <token>" \
  -d '{"days": 30}'

# Get expiring clients (within 7 days)
curl http://localhost:8082/api/clients/expiring?days=7 \
  -H "Authorization: Bearer <token>"
```

### Manage Traffic Limits

Set and monitor traffic limits via UI or API:
```bash
# Set traffic limit (10 GB = 10737418240 bytes)
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": 10737418240}'

# Remove traffic limit (set to unlimited)
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": null}'

# Check traffic limit status
curl http://localhost:8082/api/clients/123/traffic-limit-status \
  -H "Authorization: Bearer <token>"

# Get clients over traffic limit
curl http://localhost:8082/api/clients/overlimit \
  -H "Authorization: Bearer <token>"
```

### Server Backups

Create and restore backups via UI or API:
```bash
# Create backup
curl -X POST http://localhost:8082/api/servers/1/backup \
  -H "Authorization: Bearer <token>"

# List backups
curl http://localhost:8082/api/servers/1/backups \
  -H "Authorization: Bearer <token>"

# Restore from backup
curl -X POST http://localhost:8082/api/servers/1/restore \
  -H "Authorization: Bearer <token>" \
  -d '{"backup_id": 123}'
```

### Protocol Management

Manage VPN protocols via **Settings → Protocols**:
- Install/Uninstall protocols (WireGuard, AmneziaWG, OpenVPN, etc.)
- Configure protocol settings (ports, transport, obfuscation)
- **AI Assistant**: Use "Ask AI" to generate complex protocol configurations tailored to your needs (requires OpenRouter API key).

### Scenario Testing & Logs

**Scenario Testing**:
- Create test scenarios to verify connectivity across different protocols and network conditions.
- Run automated tests to ensure your VPN infrastructure is reliable.

**Log Management**:
- Centralized view of all system, container, and application logs.
- Search and filter capabilities to quickly diagnose issues.

### AI Assistant

Configure OpenRouter API key in **Settings** to enable:
- Auto-translation of the interface
- AI-assisted protocol configuration
- Intelligent troubleshooting suggestions

### Automatic Monitoring and Metrics Collection

**Metrics collector runs automatically** on container startup and is monitored by cron every 3 minutes. If the process crashes, it will be automatically restarted.

Check metrics collector logs:
```bash
docker compose exec web tail -f /var/log/metrics_collector.log
```

Check monitoring script logs:
```bash
docker compose exec web tail -f /var/log/metrics_monitor.log
```

Restart metrics collector manually:
```bash
docker compose exec web pkill -f collect_metrics.php
# It will be auto-restarted within 3 minutes by the monitoring script
```

### Automatic Client Expiration Check

**Runs automatically in Docker container** every hour to disable expired clients.

Check cron logs:
```bash
docker compose exec web tail -f /var/log/cron.log
```

Run manually:
```bash
docker compose exec web php /var/www/html/bin/check_expired_clients.php
```

### Automatic Traffic Limit Check

**Runs automatically in Docker container** every hour to disable clients that exceeded their traffic limit.

Check cron logs:
```bash
docker compose exec web tail -f /var/log/cron.log
```

Run manually:
```bash
docker compose exec web php /var/www/html/bin/check_traffic_limits.php
```

### API Authentication

Get JWT token:
```bash
curl -X POST http://localhost:8082/api/auth/token \
  -d "email=admin@amnez.ia&password=admin123"
```

Use token:
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8082/api/servers
```

## API Endpoints

### Authentication
```
POST   /api/auth/token              - Get JWT token
POST   /api/tokens                  - Create persistent API token
GET    /api/tokens                  - List API tokens
DELETE /api/tokens/{id}             - Revoke token
```

### Servers
```
GET    /api/servers                 - List all servers
POST   /api/servers/create          - Create new server
       Parameters: name, host, port, username, password
DELETE /api/servers/{id}/delete     - Delete server by ID
GET    /api/servers/{id}/clients    - List clients on server
```

### Protocols
```
GET    /api/protocols/active        - List all available protocols (JWT-friendly, includes protocol IDs)
GET    /api/protocols               - Protocol management endpoint (requires session admin auth, not JWT)
GET    /api/servers/{id}/protocols  - List installed protocols on server
POST   /api/servers/{id}/protocols/install - Install protocol
```

### Clients
```
GET    /api/clients                 - List all clients
GET    /api/clients/{id}/details    - Get client details with stats, config and QR code
GET    /api/clients/{id}/qr         - Get client QR code
POST   /api/clients/create          - Create new client (returns config and QR code)
       Parameters: server_id, name, protocol_id (optional, default: installed), expires_in_days (optional)
POST   /api/clients/{id}/revoke     - Revoke client access
POST   /api/clients/{id}/restore    - Restore client access
DELETE /api/clients/{id}/delete     - Delete client by ID (removes from DB and server)
POST   /api/clients/{id}/set-expiration  - Set client expiration date
POST   /api/clients/{id}/set-expiration  - Set client expiration date
       Parameters: expires_at (Y-m-d H:i:s or null)
POST   /api/clients/{id}/extend     - Extend client expiration
       Parameters: days (int)
GET    /api/clients/expiring        - Get clients expiring soon
       Parameters: days (default: 7)
POST   /api/clients/{id}/set-traffic-limit  - Set client traffic limit
       Parameters: limit_bytes (int or null for unlimited)
GET    /api/clients/{id}/traffic-limit-status - Get traffic limit status
GET    /api/clients/overlimit       - Get clients over traffic limit
```

### Backups
```
POST   /api/servers/{id}/backup     - Create server backup
GET    /api/servers/{id}/backups    - List server backups
POST   /api/servers/{id}/restore    - Restore from backup
       Parameters: backup_id
DELETE /api/backups/{id}             - Delete backup
```

### Panel Import
```
POST   /api/servers/{id}/import     - Import clients from existing panel
       Parameters: panel_type (wg-easy|3x-ui), backup_file (multipart/form-data)
GET    /api/servers/{id}/imports    - Get import history for server
```

## Translation

Add OpenRouter API key in Settings, then run:
```bash
docker compose exec web php bin/translate_all.php
```

Or translate via web interface: Settings → Auto-translate

## Structure

```
public/index.php      - Routes
inc/                  - Core classes
  Auth.php           - Authentication
  DB.php             - Database connection
  Router.php         - URL routing
  View.php           - Twig templates
  VpnServer.php      - Server management
  VpnClient.php      - Client management
  Translator.php     - Multi-language
  JWT.php            - Token auth
  QrUtil.php         - QR code generation
  PanelImporter.php  - Import from wg-easy/3x-ui
  InstallProtocolManager.php - Protocol management core
  OpenRouterService.php - AI integration
templates/           - Twig templates
migrations/          - SQL migrations (executed in alphabetical order)
```

## Tech Stack

- PHP 8.2
- MySQL 8.0
- Twig 3
- Tailwind CSS
- Docker

## License

MIT

## Support the Project

If you find this project helpful, you can support its development through a donation via Tribute: https://t.me/tribute/app?startapp=dzX1

# amneziavpnphp
