# Release Notes - Amnezia VPN Web Panel v2.0.1

**Release Date:** 2026-04-25

**Previous Release:** v2.0.0 (3 weeks ago)

## 🆕 What's New in v2.0.1

This patch release focuses on improving international accessibility with comprehensive documentation in Russian and Chinese, making the panel more accessible to users worldwide.

### 📄 New Documentation
- **Russian Documentation** ([`README_RU.md`](README_RU.md)) - Complete translation with all features, API examples, and troubleshooting guides
- **Chinese Documentation** ([`README_ZH.md`](README_ZH.md)) - Full Chinese translation for better accessibility

## 🎉 Major Features (from v2.0.0)

### 🌍 Multi-Language Documentation
- Added comprehensive Russian documentation ([`README_RU.md`](README_RU.md))
- Added comprehensive Chinese documentation ([`README_ZH.md`](README_ZH.md))
- Improves accessibility for Russian and Chinese speaking users

### ☁️ Cloudflare WARP Integration
- New protocol: **Cloudflare WARP Proxy** (`cf-warp`)
- Transparent TCP traffic proxying through Cloudflare network
- Hides server's real IP address from VPN clients
- Automatic detection and routing for multiple VPN protocols:
  - AWG / AWG2 (container IP + host redsocks)
  - X-Ray VLESS (SOCKS5 `warp-out` outbound)
  - AIVPN / WireGuard (host-level iptables + redsocks)
- Verification via `https://1.1.1.1/cdn-cgi/trace`

### 🤖 AI-Powered Features
- **AI Assistant** for protocol configuration using OpenRouter
- Auto-translation of interface via AI
- Intelligent troubleshooting suggestions
- Context-aware protocol configuration generation

### 📊 Enhanced Monitoring & Automation
- Automatic metrics collection with self-healing (3-minute monitoring)
- Automated client expiration checks (hourly)
- Automated traffic limit enforcement (hourly)
- Centralized log management with search and filtering
- Real-time server monitoring and health checks

### 🔧 Advanced Protocol Management
- **AmneziaWG 2.0** (`awg2`) protocol support
- **AIVPN** protocol integration
- **MTProxy** (Telegram) protocol support
- Dynamic protocol installation/uninstallation
- Per-protocol configuration management
- Protocol-specific port and transport settings

### 📥 Panel Import Feature
- Import from **wg-easy** backup files
- Import from **3x-ui** backup files
- Automatic client migration
- Import history tracking

### 🔐 Enhanced Security & Access Control
- JWT-based API authentication
- Persistent API tokens
- User roles and permissions
- LDAP integration for enterprise environments
- SSH key authentication for server deployment

### 📱 Client Management Enhancements
- Client expiration dates with automatic enforcement
- Traffic limits with automatic blocking
- QR code generation for mobile apps
- Client connection statistics and monitoring
- Current speed monitoring per client

### 🧪 Scenario Testing
- Define custom VPN connection scenarios
- Automated testing across different protocols
- Network condition simulation
- Reliability verification

## 🐛 Bug Fixes

- Fixed AWG2 empty peer parameters (migration 063)
- Fixed AIVPN prebuilt binary handling (migration 065)
- Fixed AWG2 original parameters completion (migration 064)
- Fixed XRay port mapping and IP enforcement
- Fixed traffic limit counter offsets for AIVPN
- Fixed client connection instructions translation
- Fixed WARP heredoc compatibility issues
- Fixed WARP subnet detection for AIVPN compatibility

## 🔧 Technical Improvements

### Database Migrations
- Added 22 new migration files (048-069) covering:
  - Protocol management tables
  - Monitoring and metrics
  - LDAP configurations
  - QR code templates
  - Protocol editor translations
  - AWG2 and AIVPN support
  - Cloudflare WARP integration

### Performance Optimizations
- Optimized metrics collection queries
- Improved database indexing for client lookups
- Enhanced Docker container health checks
- Reduced API response times

### Code Quality
- Improved error handling and logging
- Better input validation
- Enhanced security checks
- Cleaner separation of concerns

## 📚 Documentation Updates

- Complete Russian translation of all features
- Complete Chinese translation of all features
- Updated API examples with new endpoints
- Added troubleshooting guides
- Enhanced installation instructions
- Added Cloudflare WARP configuration examples

## 🔗 API Changes

### New Endpoints
- `POST /api/clients/{id}/set-traffic-limit` - Set client traffic limit
- `GET /api/clients/{id}/traffic-limit-status` - Get traffic limit status
- `GET /api/clients/overlimit` - Get clients over traffic limit
- `POST /api/clients/{id}/set-expiration` - Set client expiration date
- `POST /api/clients/{id}/extend` - Extend client expiration
- `GET /api/clients/expiring` - Get clients expiring soon
- `POST /api/servers/{id}/import` - Import from existing panel
- `GET /api/servers/{id}/imports` - Get import history
- `POST /api/servers/{id}/backup` - Create server backup
- `GET /api/servers/{id}/backups` - List server backups
- `POST /api/servers/{id}/restore` - Restore from backup
- `GET /api/protocols/active` - List available protocols (JWT-friendly)

### Enhanced Endpoints
- Improved client creation with expiration and traffic limits
- Enhanced server management with import capabilities
- Better protocol management with AI assistance

## 🚀 Upgrade Guide

### From Previous Versions

1. **Backup your database** before upgrading
2. Pull the latest code:
   ```bash
   git pull origin main
   ```
3. Run new migrations:
   ```bash
   docker compose exec -T db mysql -u"$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" < migrations/048_enable_xray_stats.sql
   # ... run all new migration files in order
   ```
4. Restart containers:
   ```bash
   docker compose restart
   ```
5. Clear application cache if needed

### Fresh Installation

See the installation instructions in [`README.md`](README.md), [`README_RU.md`](README_RU.md), or [`README_ZH.md`](README_ZH.md)

## 📋 Migration Files (Since v2.0.0)

This release includes all migrations from v2.0.0 plus the following new files:

### New in v2.0.1:
- No new database migrations - this is a documentation-focused release

### From v2.0.0:
- `048_enable_xray_stats.sql` - Enable XRay statistics collection
- `049_add_dns_servers.sql` - Add DNS server configuration
- `050_fix_awg_random_params.sql` - Fix AWG random parameters
- `051_fix_awg_fresh_install.sql` - Fix AWG fresh installation
- `052_add_current_speed_to_clients.sql` - Add current speed monitoring
- `053_split_speed.sql` - Split upload/download speed
- `054_xray_single_ip_enforcement.sql` - XRay IP enforcement
- `055_dashboard_online_now_translation.sql` - Dashboard translation
- `056_enable_show_text_content_for_xray.sql` - XRay text content
- `057_add_protocol_management_translations.sql` - Protocol management
- `058_add_awg2_protocol.sql` - AWG2 protocol support
- `059_add_mtproxy_protocol.sql` - MTProxy protocol support
- `060_add_aivpn_protocol.sql` - AIVPN protocol support
- `061_fix_client_connection_instructions_translation.sql` - Translation fix
- `062_add_aivpn_counter_offsets.sql` - AIVPN counter fixes
- `063_fix_awg2_empty_peer_in_install_script.sql` - AWG2 peer fix
- `064_complete_awg2_original_params.sql` - AWG2 parameters
- `065_fix_aivpn_prebuilt_binary.sql` - AIVPN binary fix
- `066_add_cloudflare_warp_protocol.sql` - WARP protocol
- `067_warp_auto_redsocks_integration.sql` - WARP redsocks
- `068_fix_warp_heredoc_compat.sql` - WARP heredoc fix
- `069_warp_aivpn_subnet_detect.sql` - WARP subnet detection

## 🙏 Acknowledgments

Special thanks to:
- All contributors who helped with translations
- The Amnezia VPN community for feedback and testing
- OpenRouter for AI integration support
- Cloudflare for WARP technology

## 📞 Support

- **GitHub Issues:** https://github.com/infosave2007/amneziavpnphp/issues
- **Documentation:** See README files in English, Russian, and Chinese
- **Donations:** https://t.me/tribute/app?startapp=dzX1

## 📄 License

This release is licensed under the MIT License - see the [`LICENSE`](LICENSE) file for details.

---

**Full Changelog:** https://github.com/infosave2007/amneziavpnphp/compare/v2.0.0...v2.0.1

**Changes since v2.0.0:**
- Added comprehensive Russian documentation ([`README_RU.md`](README_RU.md))
- Added comprehensive Chinese documentation ([`README_ZH.md`](README_ZH.md))
- Updated release notes with multi-language support information