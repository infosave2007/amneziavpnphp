# Amnezia VPN Web Panel

用于管理 Amnezia AWG (WireGuard) VPN 服务器的 Web 面板。

## 功能特性

- 通过 SSH 部署 VPN 服务器（密码或 **SSH 密钥**）
- **从现有 VPN 面板导入**（wg-easy、3x-ui）
- **高级协议管理**（WireGuard、AmneziaWG、OpenVPN、Shadowsocks 等）
- **AI 驱动的协议配置** 使用 OpenRouter（可选）
- 客户端配置管理，支持**过期日期**
- 客户端**流量限制**，自动执行
- **服务器备份和恢复**功能
- **场景测试**：定义和测试不同协议的网络连接场景
- **高级日志管理**：查看、搜索和管理系统和容器日志
- 流量统计监控
- 为移动应用生成二维码
- 多语言界面（英语、俄语、西班牙语、德语、法语、中文）
- 带 JWT 认证的 REST API
- 用户认证和访问控制
- **自动客户端过期和流量限制检查** 通过 cron

## 可用协议

- AmneziaWG Advanced (`amnezia-wg-advanced`)
- AmneziaWG 2.0 (`awg2`)
- WireGuard 标准 (`wireguard-standard`)
- OpenVPN (`openvpn`)
- Shadowsocks (`shadowsocks`)
- XRay VLESS (`xray-vless`)
- MTProxy (Telegram) (`mtproxy`)
- SMB 服务器 (`smb`)
- AIVPN (`aivpn`) - https://github.com/infosave2007/aivpn
- Cloudflare WARP 代理 (`cf-warp`) — 通过 Cloudflare 透明代理流量

## 系统要求

- Docker
- Docker Compose

## 安装

```bash
git clone https://github.com/infosave2007/amneziavpnphp.git
cd amneziavpnphp
cp .env.example .env

# 对于 Docker Compose V2（推荐）
docker compose up -d
docker compose exec web composer install

# 等待数据库准备就绪（初始 SQL 迁移文件由 MySQL 入口点自动应用）
until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# 或者对于旧版 Docker Compose V1
docker-compose up -d
docker-compose exec web composer install

until [ "$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null)" = "healthy" ]; do
  sleep 2
done

# 手动迁移模式（仅用于现有安装/更新）
set -a; source .env; set +a
for f in migrations/*.sql; do
  docker compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
done

# 对于 Docker Compose V1 手动迁移模式：
# for f in migrations/*.sql; do
#   docker-compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < "$f" || true
# done
```

访问地址：http://localhost:8082

默认登录凭据：admin@amnez.ia / admin123

### 远程服务器前提条件

要在干净的远程主机上部署协议，该主机必须可用 Docker Engine。
如果缺少 Docker，请先安装（Ubuntu 示例）：

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

## 配置

编辑 `.env` 文件：

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

## 使用方法

### 添加 VPN 服务器

1. 服务器 → 添加服务器
2. 输入：名称、主机 IP、SSH 端口、用户名
3. 选择认证方法：**密码** 或 **SSH 密钥**
   - 对于 SSH 密钥：粘贴您的私钥（PEM/OpenSSH 格式）
3. **（可选）启用从现有面板导入：**
   - 勾选"从现有面板导入"
   - 选择面板类型（wg-easy 或 3x-ui）
   - 上传备份文件（JSON）
4. 点击"创建服务器"
5. 等待部署完成
6. 如果启用了导入，客户端将自动导入

### 创建客户端

1. 打开服务器详情
2. 输入客户端名称
3. **选择过期时间**（可选，默认：永不过期）
4. **选择流量限制**（可选，默认：无限制）
5. 点击创建客户端
6. 下载配置或扫描二维码

### 管理客户端过期时间

通过 UI 或 API 设置过期时间：
```bash
# 设置特定日期
curl -X POST http://localhost:8082/api/clients/123/set-expiration \
  -H "Authorization: Bearer <token>" \
  -d '{"expires_at": "2025-12-31 23:59:59"}'

# 延长 30 天
curl -X POST http://localhost:8082/api/clients/123/extend \
  -H "Authorization: Bearer <token>" \
  -d '{"days": 30}'

# 获取即将过期的客户端（7 天内）
curl http://localhost:8082/api/clients/expiring?days=7 \
  -H "Authorization: Bearer <token>"
```

### 管理流量限制

通过 UI 或 API 设置和监控流量限制：
```bash
# 设置流量限制（10 GB = 10737418240 字节）
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": 10737418240}'

# 移除流量限制（设置为无限制）
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": null}'

# 检查流量限制状态
curl http://localhost:8082/api/clients/123/traffic-limit-status \
  -H "Authorization: Bearer <token>"

# 获取超过流量限制的客户端
curl http://localhost:8082/api/clients/overlimit \
  -H "Authorization: Bearer <token>"
```

### 服务器备份

通过 UI 或 API 创建和恢复备份：
```bash
# 创建备份
curl -X POST http://localhost:8082/api/servers/1/backup \
  -H "Authorization: Bearer <token>"

# 列出备份
curl http://localhost:8082/api/servers/1/backups \
  -H "Authorization: Bearer <token>"

# 从备份恢复
curl -X POST http://localhost:8082/api/servers/1/restore \
  -H "Authorization: Bearer <token>" \
  -d '{"backup_id": 123}'
```

### 协议管理

通过 **设置 → 协议** 管理 VPN 协议：
- 安装/卸载协议（WireGuard、AmneziaWG、OpenVPN 等）
- 配置协议设置（端口、传输、混淆）
- **AI 助手**：使用"询问 AI"生成符合您需求的复杂协议配置（需要 OpenRouter API 密钥）。

### Cloudflare WARP 代理

WARP 透明地代理 **所有 TCP 流量** 从 VPN 客户端通过 Cloudflare 网络，隐藏服务器的真实 IP 地址。

> **⚠️ 最后安装 WARP** — 在所有其他协议之后（AWG、X-Ray、AIVPN 等）。安装过程中，WARP 会自动检测活跃的 VPN 容器和接口，并为每个配置路由。

**支持的协议：**
- **AWG / AWG2** — 通过容器 IP + 主机 redsocks 路由
- **X-Ray VLESS** — 通过 X-Ray 配置中的 SOCKS5 `warp-out` 出站
- **AIVPN / WireGuard** — 通过主机级 iptables + redsocks 路由

**验证：** 连接到 VPN 并打开 `https://1.1.1.1/cdn-cgi/trace` — 字段 `warp=on` 确认工作正常。

### 场景测试和日志

**场景测试**：
- 创建测试场景以验证跨不同协议和网络条件的连接。
- 运行自动化测试以确保您的 VPN 基础设施可靠。

**日志管理**：
- 所有系统、容器和应用程序日志的集中视图。
- 搜索和过滤功能，快速诊断问题。

### AI 助手

在 **设置** 中配置 OpenRouter API 密钥以启用：
- 界面自动翻译
- AI 辅助协议配置
- 智能故障排除建议

### 自动监控和指标收集

**指标收集器在容器启动时自动运行**，并由 cron 每 3 分钟监控一次。如果进程崩溃，将自动重启。

检查指标收集器日志：
```bash
docker compose exec web tail -f /var/log/metrics_collector.log
```

检查监控脚本日志：
```bash
docker compose exec web tail -f /var/log/metrics_monitor.log
```

手动重启指标收集器：
```bash
docker compose exec web pkill -f collect_metrics.php
# 它将在 3 分钟内由监控脚本自动重启
```

### 自动客户端过期检查

**在 Docker 容器中自动运行**，每小时禁用过期客户端。

检查 cron 日志：
```bash
docker compose exec web tail -f /var/log/cron.log
```

手动运行：
```bash
docker compose exec web php /var/www/html/bin/check_expired_clients.php
```

### 自动流量限制检查

**在 Docker 容器中自动运行**，每小时禁用超过流量限制的客户端。

检查 cron 日志：
```bash
docker compose exec web tail -f /var/log/cron.log
```

手动运行：
```bash
docker compose exec web php /var/www/html/bin/check_traffic_limits.php
```

### API 认证

获取 JWT 令牌：
```bash
curl -X POST http://localhost:8082/api/auth/token \
  -d "email=admin@amnez.ia&password=admin123"
```

使用令牌：
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8082/api/servers
```

## API 端点

### 认证
```
POST   /api/auth/token              - 获取 JWT 令牌
POST   /api/tokens                  - 创建持久 API 令牌
GET    /api/tokens                  - 列出 API 令牌
DELETE /api/tokens/{id}             - 撤销令牌
```

### 服务器
```
GET    /api/servers                 - 列出所有服务器
POST   /api/servers/create          - 创建新服务器
       参数：name, host, port, username, password
DELETE /api/servers/{id}/delete     - 按 ID 删除服务器
GET    /api/servers/{id}/clients    - 列出服务器上的客户端
```

### 协议
```
GET    /api/protocols/active        - 列出所有可用协议（JWT 友好，包含协议 ID）
GET    /api/protocols               - 协议管理端点（需要会话管理员认证，非 JWT）
GET    /api/servers/{id}/protocols  - 列出服务器上已安装的协议
POST   /api/servers/{id}/protocols/install - 安装协议
```

### 客户端
```
GET    /api/clients                 - 列出所有客户端
GET    /api/clients/{id}/details    - 获取客户端详情，包括统计信息、配置和二维码
GET    /api/clients/{id}/qr         - 获取客户端二维码
POST   /api/clients/create          - 创建新客户端（返回配置和二维码）
       参数：server_id, name, protocol_id（可选，默认：已安装）, expires_in_days（可选）
POST   /api/clients/{id}/revoke     - 撤销客户端访问
POST   /api/clients/{id}/restore    - 恢复客户端访问
DELETE /api/clients/{id}/delete     - 按 ID 删除客户端（从数据库和服务器删除）
POST   /api/clients/{id}/set-expiration  - 设置客户端过期日期
       参数：expires_at（Y-m-d H:i:s 或 null）
POST   /api/clients/{id}/extend     - 延长客户端过期时间
       参数：days（int）
GET    /api/clients/expiring        - 获取即将过期的客户端
       参数：days（默认：7）
POST   /api/clients/{id}/set-traffic-limit  - 设置客户端流量限制
       参数：limit_bytes（int 或 null 表示无限制）
GET    /api/clients/{id}/traffic-limit-status - 获取流量限制状态
GET    /api/clients/overlimit       - 获取超过流量限制的客户端
```

### 备份
```
POST   /api/servers/{id}/backup     - 创建服务器备份
GET    /api/servers/{id}/backups    - 列出服务器备份
POST   /api/servers/{id}/restore    - 从备份恢复
       参数：backup_id
DELETE /api/backups/{id}             - 删除备份
```

### 面板导入
```
POST   /api/servers/{id}/import     - 从现有面板导入客户端
       参数：panel_type（wg-easy|3x-ui）, backup_file（multipart/form-data）
GET    /api/servers/{id}/imports    - 获取服务器导入历史记录
```

## 翻译

在设置中添加 OpenRouter API 密钥，然后运行：
```bash
docker compose exec web php bin/translate_all.php
```

或通过 Web 界面翻译：设置 → 自动翻译

## 项目结构

```
public/index.php      - 路由
inc/                  - 核心类
  Auth.php           - 认证
  DB.php             - 数据库连接
  Router.php         - URL 路由
  View.php           - Twig 模板
  VpnServer.php      - 服务器管理
  VpnClient.php      - 客户端管理
  Translator.php     - 多语言
  JWT.php            - 令牌认证
  QrUtil.php         - 二维码生成
  PanelImporter.php  - 从 wg-easy/3x-ui 导入
  InstallProtocolManager.php - 协议管理核心
  OpenRouterService.php - AI 集成
templates/           - Twig 模板
migrations/          - SQL 迁移（按字母顺序执行）
```

## 技术栈

- PHP 8.2
- MySQL 8.0
- Twig 3
- Tailwind CSS
- Docker

## 许可证

MIT

## 支持项目

如果您觉得这个项目有用，可以通过 Tribute 捐款支持其开发：https://t.me/tribute/app?startapp=dzX1