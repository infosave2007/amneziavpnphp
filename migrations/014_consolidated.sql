INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','servers','backup_upload_type','Backup type'),
('en','servers','backup_type_auto','Auto detect'),
('en','servers','backup_type_amnezia','Amnezia app (.backup)'),
('en','servers','backup_type_panel','Panel export (.json)'),
('en','servers','backup_upload_hint','Upload a .backup or .json file. After upload, pick a server entry above.'),
('ru','servers','backup_upload_type','Тип бэкапа'),
('ru','servers','backup_type_auto','Определить автоматически'),
('ru','servers','backup_type_amnezia','Приложение Amnezia (.backup)'),
('ru','servers','backup_type_panel','Экспорт панели (.json)'),
('ru','servers','backup_upload_hint','Загрузите файл .backup или .json. После загрузки выберите сервер выше.'),
('es','servers','backup_upload_type','Tipo de copia de seguridad'),
('es','servers','backup_type_auto','Detectar automáticamente'),
('es','servers','backup_type_amnezia','Aplicación Amnezia (.backup)'),
('es','servers','backup_type_panel','Exportación del panel (.json)'),
('es','servers','backup_upload_hint','Suba un archivo .backup o .json. Después seleccione el servidor arriba.'),
('de','servers','backup_upload_type','Backup-Typ'),
('de','servers','backup_type_auto','Automatisch erkennen'),
('de','servers','backup_type_amnezia','Amnezia-App (.backup)'),
('de','servers','backup_type_panel','Panel-Export (.json)'),
('de','servers','backup_upload_hint','Laden Sie eine .backup- oder .json-Datei hoch. Wählen Sie anschließend oben einen Server aus.'),
('fr','servers','backup_upload_type','Type de sauvegarde'),
('fr','servers','backup_type_auto','Détection automatique'),
('fr','servers','backup_type_amnezia','Application Amnezia (.backup)'),
('fr','servers','backup_type_panel','Export du panneau (.json)'),
('fr','servers','backup_upload_hint','Téléversez un fichier .backup ou .json, puis sélectionnez un serveur ci-dessus.'),
('zh','servers','backup_upload_type','备份类型'),
('zh','servers','backup_type_auto','自动检测'),
('zh','servers','backup_type_amnezia','Amnezia 应用 (.backup)'),
('zh','servers','backup_type_panel','面板导出 (.json)'),
('zh','servers','backup_upload_hint','上传 .backup 或 .json 文件，随后在上方选择服务器。')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en', 'servers', 'config_import_title', 'Import configuration'),
('en', 'servers', 'config_import_hint', 'Upload a configuration backup to update this server and its clients.'),
('en', 'servers', 'config_import_type_label', 'Backup type'),
('en', 'servers', 'config_import_type_panel', 'Panel backup (.json)'),
('en', 'servers', 'config_import_type_amnezia', 'Amnezia app backup (.backup)'),
('en', 'servers', 'config_import_file_label', 'Configuration file'),
('en', 'servers', 'config_import_file_hint', 'Our panel uses .json files. The Amnezia app uses .backup files.'),
('en', 'servers', 'config_import_submit', 'Import configuration'),
('ru', 'servers', 'config_import_title', 'Импорт конфигурации'),
('ru', 'servers', 'config_import_hint', 'Загрузите файл бэкапа, чтобы обновить настройки сервера и список клиентов.'),
('ru', 'servers', 'config_import_type_label', 'Источник бэкапа'),
('ru', 'servers', 'config_import_type_panel', 'Бэкап панели (.json)'),
('ru', 'servers', 'config_import_type_amnezia', 'Бэкап приложения Amnezia (.backup)'),
('ru', 'servers', 'config_import_file_label', 'Файл конфигурации'),
('ru', 'servers', 'config_import_file_hint', 'Панель использует файлы .json. Приложение Amnezia — файлы .backup.'),
('ru', 'servers', 'config_import_submit', 'Импортировать конфигурацию'),
('es', 'servers', 'config_import_title', 'Importar configuración'),
('es', 'servers', 'config_import_hint', 'Cargue un respaldo para actualizar este servidor y sus clientes.'),
('es', 'servers', 'config_import_type_label', 'Tipo de backup'),
('es', 'servers', 'config_import_type_panel', 'Backup del panel (.json)'),
('es', 'servers', 'config_import_type_amnezia', 'Backup de la app Amnezia (.backup)'),
('es', 'servers', 'config_import_file_label', 'Archivo de configuración'),
('es', 'servers', 'config_import_file_hint', 'El panel usa archivos .json. La app Amnezia usa archivos .backup.'),
('es', 'servers', 'config_import_submit', 'Importar configuración'),
('de', 'servers', 'config_import_title', 'Konfiguration importieren'),
('de', 'servers', 'config_import_hint', 'Laden Sie eine Sicherung hoch, um diesen Server und seine Clients zu aktualisieren.'),
('de', 'servers', 'config_import_type_label', 'Backup-Typ'),
('de', 'servers', 'config_import_type_panel', 'Panel-Backup (.json)'),
('de', 'servers', 'config_import_type_amnezia', 'Amnezia-App-Backup (.backup)'),
('de', 'servers', 'config_import_file_label', 'Konfigurationsfile'),
('de', 'servers', 'config_import_file_hint', 'Die Panel-Backups sind .json. Die Amnezia-App nutzt .backup-Dateien.'),
('de', 'servers', 'config_import_submit', 'Konfiguration importieren'),
('fr', 'servers', 'config_import_title', 'Importer la configuration'),
('fr', 'servers', 'config_import_hint', 'Téléversez un fichier de sauvegarde pour mettre à jour ce serveur et ses clients.'),
('fr', 'servers', 'config_import_type_label', 'Type de sauvegarde'),
('fr', 'servers', 'config_import_type_panel', 'Sauvegarde du panneau (.json)'),
('fr', 'servers', 'config_import_type_amnezia', 'Sauvegarde de l’application Amnezia (.backup)'),
('fr', 'servers', 'config_import_file_label', 'Fichier de configuration'),
('fr', 'servers', 'config_import_file_hint', 'Notre panneau utilise des fichiers .json. L’application Amnezia utilise des fichiers .backup.'),
('fr', 'servers', 'config_import_submit', 'Importer la configuration'),
('zh', 'servers', 'config_import_title', '导入配置'),
('zh', 'servers', 'config_import_hint', '上传备份文件以更新此服务器及其客户端。'),
('zh', 'servers', 'config_import_type_label', '备份类型'),
('zh', 'servers', 'config_import_type_panel', '面板备份 (.json)'),
('zh', 'servers', 'config_import_type_amnezia', 'Amnezia 应用备份 (.backup)'),
('zh', 'servers', 'config_import_file_label', '配置文件'),
('zh', 'servers', 'config_import_file_hint', '面板使用 .json 文件，Amnezia 应用使用 .backup 文件。'),
('zh', 'servers', 'config_import_submit', '导入配置')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','servers','creation_mode','Creation mode'),
('en','servers','creation_mode_manual','Manual setup'),
('en','servers','creation_mode_backup','Import from backup'),
('en','servers','upload_backup_file','Upload backup file'),
('en','servers','backup_upload_hint','Supported formats: panel JSON export or Amnezia application .backup'),
('en','servers','backup_server_entry','Select server entry'),
('en','servers','backup_summary_host','Host'),
('en','servers','backup_summary_clients','Clients'),
('en','servers','config_import_title','Restore configuration from backup'),
('en','servers','config_import_hint','Import server configuration (and optional clients) from a panel export or Amnezia application backup.'),
('en','servers','config_import_type_label','Backup type'),
('en','servers','config_import_type_panel','Panel export (.json)'),
('en','servers','config_import_type_amnezia','Amnezia app backup (.backup)'),
('en','servers','config_import_file_label','Configuration file'),
('en','servers','config_import_file_hint','The file remains on the server only during import and is deleted afterwards.'),
('en','servers','config_import_submit','Import configuration'),
('ru','servers','creation_mode','Режим создания'),
('ru','servers','creation_mode_manual','Ручная настройка'),
('ru','servers','creation_mode_backup','Импорт из бэкапа'),
('ru','servers','upload_backup_file','Загрузите файл бэкапа'),
('ru','servers','backup_upload_hint','Поддерживаются форматы: экспорт панели JSON или бэкап приложения Amnezia (.backup)'),
('ru','servers','backup_server_entry','Выберите запись сервера'),
('ru','servers','backup_summary_host','Хост'),
('ru','servers','backup_summary_clients','Клиенты'),
('ru','servers','config_import_title','Восстановление конфигурации из бэкапа'),
('ru','servers','config_import_hint','Импортируйте конфигурацию сервера (и при необходимости клиентов) из экспорта панели или бэкапа приложения Amnezia.'),
('ru','servers','config_import_type_label','Тип бэкапа'),
('ru','servers','config_import_type_panel','Экспорт панели (.json)'),
('ru','servers','config_import_type_amnezia','Бэкап приложения Amnezia (.backup)'),
('ru','servers','config_import_file_label','Файл конфигурации'),
('ru','servers','config_import_file_hint','Файл хранится на сервере только во время импорта и удаляется сразу после завершения.'),
('ru','servers','config_import_submit','Импортировать конфигурацию')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

CREATE TABLE IF NOT EXISTS protocols (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    install_script TEXT,
    output_template TEXT,
    ubuntu_compatible BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_protocols_slug (slug),
    INDEX idx_protocols_active (is_active),
    INDEX idx_protocols_ubuntu_compatible (ubuntu_compatible)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS protocol_templates (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    protocol_id INT UNSIGNED NOT NULL,
    template_name VARCHAR(255) NOT NULL,
    template_content TEXT NOT NULL,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_protocol_templates_protocol (protocol_id),
    INDEX idx_protocol_templates_default (is_default),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS protocol_variables (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    protocol_id INT UNSIGNED NOT NULL,
    variable_name VARCHAR(100) NOT NULL,
    variable_type VARCHAR(50) NOT NULL DEFAULT 'string',
    default_value TEXT,
    description TEXT,
    required BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_protocol_variables_protocol (protocol_id),
    INDEX idx_protocol_variables_name (variable_name),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS server_protocols (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    server_id INT UNSIGNED NOT NULL,
    protocol_id INT UNSIGNED NOT NULL,
    config_data JSON,
    applied_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_server_protocols_server (server_id),
    INDEX idx_server_protocols_protocol (protocol_id),
    INDEX idx_server_protocols_applied (applied_at),
    UNIQUE KEY unique_server_protocol (server_id, protocol_id),
    FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ai_generations (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    protocol_id INT UNSIGNED NULL,
    model_used VARCHAR(100) NOT NULL,
    prompt TEXT NOT NULL,
    generated_script TEXT,
    suggestions JSON,
    ubuntu_compatible BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ai_generations_protocol (protocol_id),
    INDEX idx_ai_generations_model (model_used),
    INDEX idx_ai_generations_created (created_at DESC),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active) 
SELECT 'AmneziaWG Advanced', 'amnezia-wg-advanced', 'AmneziaWG protocol with advanced junk packet obfuscation parameters', '#!/bin/bash
echo "AmneziaWG Advanced installed"
', '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
Endpoint = {{server_host}}:{{server_port}}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

Jc = {{jc}}
Jmin = {{jmin}}
Jmax = {{jmax}}
S1 = {{s1}}
S2 = {{s2}}
H1 = {{h1}}
H2 = {{h2}}
H3 = {{h3}}
H4 = {{h4}}', true, true
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='amnezia-wg-advanced');

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active) 
SELECT 'WireGuard Standard', 'wireguard-standard', 'Standard WireGuard VPN protocol', '#!/bin/bash
CONTAINER_NAME="wireguard"
VPN_SUBNET="10.8.2.0/24"
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo $PRIVATE_KEY | wg pubkey)
PRESHARED_KEY=$(wg genpsk)
docker run -d \
  --name $CONTAINER_NAME \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  -v /opt/wireguard:/etc/wireguard \
  linuxserver/wireguard
cat > /opt/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.2.1/24
ListenPort = 51820

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.2.2/32
EOF
echo "WireGuard Standard installed successfully"
echo "Server Public Key: $PUBLIC_KEY"', '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
Endpoint = {{server_host}}:{{server_port}}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25', true, true
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='wireguard-standard');

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active) 
SELECT 'OpenVPN', 'openvpn', 'OpenVPN protocol with TCP/UDP support', '#!/bin/bash
CONTAINER_NAME="openvpn"
VPN_SUBNET="10.8.3.0/24"
docker run -d \
  --name $CONTAINER_NAME \
  --cap-add=NET_ADMIN \
  -p 1194:1194/udp \
  -p 1194:1194/tcp \
  -v /opt/openvpn:/etc/openvpn \
  kylemanna/openvpn
docker exec -it $CONTAINER_NAME ovpn_genconfig -u udp://{{server_host}}:1194
docker exec -it $CONTAINER_NAME ovpn_initpki
echo "OpenVPN installed successfully"
echo "Available on ports: 1194/udp, 1194/tcp"', 'client
dev tun
proto {{protocol}}
remote {{server_host}} {{server_port}}
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3', true, true
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='openvpn');

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active) 
SELECT 'Shadowsocks', 'shadowsocks', 'Shadowsocks proxy protocol', '#!/bin/bash
CONTAINER_NAME="shadowsocks"
PASSWORD=$(openssl rand -base64 12)
docker run -d \
  --name $CONTAINER_NAME \
  -p 8388:8388 \
  -e METHOD=aes-256-gcm \
  -e PASSWORD=$PASSWORD \
  shadowsocks/shadowsocks-libev
echo "Shadowsocks installed successfully"
echo "Port: 8388"
echo "Method: aes-256-gcm"
echo "Password: $PASSWORD"', '{
  "server": "{{server_host}}",
  "server_port": {{server_port}},
  "password": "{{password}}",
  "method": "{{method}}"
}', true, true
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='shadowsocks');

INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default AmneziaWG', '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
Endpoint = {{server_host}}:{{server_port}}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

Jc = {{jc}}
Jmin = {{jmin}}
Jmax = {{jmax}}
S1 = {{s1}}
S2 = {{s2}}
H1 = {{h1}}
H2 = {{h2}}
H3 = {{h3}}
H4 = {{h4}}', true
FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id=p.id AND template_name='Default AmneziaWG');

INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default WireGuard', '[Interface]
PrivateKey = {{private_key}}
Address = {{client_ip}}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
Endpoint = {{server_host}}:{{server_port}}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25', true
FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id=p.id AND template_name='Default WireGuard');

INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default OpenVPN', 'client
dev tun
proto {{protocol}}
remote {{server_host}} {{server_port}}
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3', true
FROM protocols p WHERE p.slug='openvpn' AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id=p.id AND template_name='Default OpenVPN');

INSERT INTO protocol_templates (protocol_id, template_name, template_content, is_default)
SELECT p.id, 'Default Shadowsocks', '{
  "server": "{{server_host}}",
  "server_port": {{server_port}},
  "password": "{{password}}",
  "method": "{{method}}"
}', true
FROM protocols p WHERE p.slug='shadowsocks' AND NOT EXISTS (SELECT 1 FROM protocol_templates WHERE protocol_id=p.id AND template_name='Default Shadowsocks');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'private_key', 'string', '', 'Client private key', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='private_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'client_ip', 'string', '10.8.1.2', 'Client IP address', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='client_ip');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_public_key', 'string', '', 'Server public key', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_public_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'preshared_key', 'string', '', 'Pre-shared key for additional security', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='preshared_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_port', 'number', '51820', 'Server port', true FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_port');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'jc', 'number', '4', 'Junk packet count', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='jc');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'jmin', 'number', '50', 'Minimum junk packet size', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='jmin');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'jmax', 'number', '1000', 'Maximum junk packet size', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='jmax');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 's1', 'number', '148', 'Junk packet size 1', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='s1');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 's2', 'number', '450', 'Junk packet size 2', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='s2');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'h1', 'number', '320121696', 'Junk packet header 1', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='h1');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'h2', 'number', '51525354', 'Junk packet header 2', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='h2');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'h3', 'number', '13141516', 'Junk packet header 3', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='h3');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'h4', 'number', '92435495', 'Junk packet header 4', false FROM protocols p WHERE p.slug='amnezia-wg-advanced' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='h4');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'private_key', 'string', '', 'Client private key', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='private_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'client_ip', 'string', '10.8.2.2', 'Client IP address', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='client_ip');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_public_key', 'string', '', 'Server public key', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_public_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'preshared_key', 'string', '', 'Pre-shared key for additional security', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='preshared_key');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_port', 'number', '51820', 'Server port', true FROM protocols p WHERE p.slug='wireguard-standard' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_port');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'protocol', 'string', 'udp', 'Connection protocol (udp/tcp)', true FROM protocols p WHERE p.slug='openvpn' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='protocol');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true FROM protocols p WHERE p.slug='openvpn' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_port', 'number', '1194', 'Server port', true FROM protocols p WHERE p.slug='openvpn' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_port');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_host', 'string', '', 'Server hostname or IP', true FROM protocols p WHERE p.slug='shadowsocks' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'server_port', 'number', '8388', 'Server port', true FROM protocols p WHERE p.slug='shadowsocks' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='server_port');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, 'password', 'string', '', 'Connection password', true FROM protocols p WHERE p.slug='shadowsocks' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id=p.id AND variable_name='password');

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','common','cancel','Cancel'),
('ru','common','cancel','Отмена'),
('es','common','cancel','Cancelar'),
('de','common','cancel','Abbrechen'),
('fr','common','cancel','Annuler'),
('zh','common','cancel','取消'),
('en','common','format','Format'),
('ru','common','format','Форматировать'),
('es','common','format','Formatear'),
('de','common','format','Formatieren'),
('fr','common','format','Formater'),
('zh','common','format','格式化'),
('en','common','clear','Clear'),
('ru','common','clear','Очистить'),
('es','common','clear','Borrar'),
('de','common','clear','Leeren'),
('fr','common','clear','Effacer'),
('zh','common','clear','清空'),
('en','protocols','template_editor_help','Use placeholders like {{variable}} and preview client output'),
('ru','protocols','template_editor_help','Используйте плейсхолдеры вида {{variable}} и просматривайте вывод клиента'),
('es','protocols','template_editor_help','Usa marcadores como {{variable}} y previsualiza la salida del cliente'),
('de','protocols','template_editor_help','Verwenden Sie Platzhalter wie {{variable}} und sehen Sie die Client‑Ausgabe in der Vorschau'),
('fr','protocols','template_editor_help','Utilisez des placeholders comme {{variable}} et prévisualisez la sortie client'),
('zh','protocols','template_editor_help','使用如 {{variable}} 的占位符并预览客户端输出'),
('en','protocols','variable_private_key_help','Client private key'),
('ru','protocols','variable_private_key_help','Приватный ключ клиента'),
('es','protocols','variable_private_key_help','Clave privada del cliente'),
('de','protocols','variable_private_key_help','Privater Schlüssel des Clients'),
('fr','protocols','variable_private_key_help','Clé privée du client'),
('zh','protocols','variable_private_key_help','客户端私钥'),
('en','protocols','variable_public_key_help','Server public key'),
('ru','protocols','variable_public_key_help','Публичный ключ сервера'),
('es','protocols','variable_public_key_help','Clave pública del servidor'),
('de','protocols','variable_public_key_help','Öffentlicher Schlüssel des Servers'),
('fr','protocols','variable_public_key_help','Clé publique du serveur'),
('zh','protocols','variable_public_key_help','服务器公钥'),
('en','protocols','variable_client_ip_help','Client IP address'),
('ru','protocols','variable_client_ip_help','IP‑адрес клиента'),
('es','protocols','variable_client_ip_help','Dirección IP del cliente'),
('de','protocols','variable_client_ip_help','IP‑Adresse des Clients'),
('fr','protocols','variable_client_ip_help','Adresse IP du client'),
('zh','protocols','variable_client_ip_help','客户端 IP 地址'),
('en','protocols','variable_server_host_help','VPN server host'),
('ru','protocols','variable_server_host_help','Хост VPN‑сервера'),
('es','protocols','variable_server_host_help','Host del servidor VPN'),
('de','protocols','variable_server_host_help','VPN‑Server‑Host'),
('fr','protocols','variable_server_host_help','Hôte du serveur VPN'),
('zh','protocols','variable_server_host_help','VPN 服务器主机'),
('en','protocols','variable_server_port_help','VPN server port'),
('ru','protocols','variable_server_port_help','Порт VPN‑сервера'),
('es','protocols','variable_server_port_help','Puerto del servidor VPN'),
('de','protocols','variable_server_port_help','VPN‑Server‑Port'),
('fr','protocols','variable_server_port_help','Port du serveur VPN'),
('zh','protocols','variable_server_port_help','VPN 服务器端口'),
('en','protocols','variable_preshared_key_help','WireGuard preshared key'),
('ru','protocols','variable_preshared_key_help','Предварительно общий ключ WireGuard'),
('es','protocols','variable_preshared_key_help','Clave precompartida de WireGuard'),
('de','protocols','variable_preshared_key_help','WireGuard‑vorausgeteilter Schlüssel'),
('fr','protocols','variable_preshared_key_help','Clé prépartagée WireGuard'),
('zh','protocols','variable_preshared_key_help','WireGuard 预共享密钥')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);


INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','ai','enter_protocol_id_to_apply','Enter protocol ID to apply'),
('ru','ai','enter_protocol_id_to_apply','Введите ID протокола для применения'),
('es','ai','enter_protocol_id_to_apply','Introduce el ID de protocolo para aplicar'),
('de','ai','enter_protocol_id_to_apply','Protokoll‑ID zum Anwenden eingeben'),
('fr','ai','enter_protocol_id_to_apply','Saisissez l’ID du protocole à appliquer'),
('zh','ai','enter_protocol_id_to_apply','输入要应用的协议 ID'),
('en','ai','improve_protocol','Improve protocol script for'),
('ru','ai','improve_protocol','Улучшить скрипт протокола для'),
('es','ai','improve_protocol','Mejorar script del protocolo для'),
('de','ai','improve_protocol','Protokollskript verbessern für'),
('fr','ai','improve_protocol','Améliorer le script du protocole pour'),
('zh','ai','improve_protocol','改进协议脚本：'),
('en','protocols','enter_protocol_name','Enter protocol name'),
('ru','protocols','enter_protocol_name','Введите имя протокола'),
('es','protocols','enter_protocol_name','Introduce el nombre del protocolo'),
('de','protocols','enter_protocol_name','Protokollnamen eingeben'),
('fr','protocols','enter_protocol_name','Saisissez le nom du protocole'),
('zh','protocols','enter_protocol_name','输入协议名称'),
('en','protocols','enter_protocol_slug','Enter protocol slug'),
('ru','protocols','enter_protocol_slug','Введите slug протокола'),
('es','protocols','enter_protocol_slug','Introduce el slug del protocolo'),
('de','protocols','enter_protocol_slug','Protokoll‑Slug eingeben'),
('fr','protocols','enter_protocol_slug','Saisissez le slug du protocole'),
('zh','protocols','enter_protocol_slug','输入协议 slug'),
('en','protocols','protocol_created_successfully','Protocol created successfully'),
('ru','protocols','protocol_created_successfully','Протокол успешно создан'),
('es','protocols','protocol_created_successfully','Protocolo creado correctamente'),
('de','protocols','protocol_created_successfully','Protokoll erfolgreich erstellt'),
('fr','protocols','protocol_created_successfully','Protocole créé avec succès'),
('zh','protocols','protocol_created_successfully','协议创建成功'),
('en','protocols','error_creating_protocol','Error creating protocol'),
('ru','protocols','error_creating_protocol','Ошибка создания протокола'),
('es','protocols','error_creating_protocol','Error al crear el protocolo'),
('de','protocols','error_creating_protocol','Fehler beim Erstellen des Protokolls'),
('fr','protocols','error_creating_protocol','Erreur lors de la création du protocole'),
('zh','protocols','error_creating_protocol','创建协议时出错')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','settings','protocols','Protocols'),
('ru','settings','protocols','Протоколы'),
('es','settings','protocols','Protocolos'),
('de','settings','protocols','Protokolle'),
('fr','settings','protocols','Protocoles'),
('zh','settings','protocols','协议'),
('en','settings','protocol_management','Protocol Management'),
('ru','settings','protocol_management','Управление протоколами'),
('es','settings','protocol_management','Gestión de protocolos'),
('de','settings','protocol_management','Protokollverwaltung'),
('fr','settings','protocol_management','Gestion des protocoles'),
('zh','settings','protocol_management','协议管理')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO translations (locale, category, key_name, translation) VALUES
('en','protocols','test_install','Test install'),
('ru','protocols','test_install','Протестировать установку'),
('es','protocols','test_install','Probar instalación'),
('de','protocols','test_install','Installation testen'),
('fr','protocols','test_install','Tester l’installation'),
('zh','protocols','test_install','测试安装'),
('en','protocols','testing_on_ubuntu22','Testing on Ubuntu 22.04 in isolated Docker'),
('ru','protocols','testing_on_ubuntu22','Тест на Ubuntu 22.04 в изолированном Docker'),
('es','protocols','testing_on_ubuntu22','Prueba en Ubuntu 22.04 en Docker aislado'),
('de','protocols','testing_on_ubuntu22','Test auf Ubuntu 22.04 in isoliertem Docker'),
('fr','protocols','testing_on_ubuntu22','Test sur Ubuntu 22.04 dans Docker isolé'),
('zh','protocols','testing_on_ubuntu22','在隔离的 Docker 中于 Ubuntu 22.04 测试'),
('en','protocols','test_result','Test result'),
('ru','protocols','test_result','Результат теста'),
('es','protocols','test_result','Resultado de la prueba'),
('de','protocols','test_result','Testergebnis'),
('fr','protocols','test_result','Résultat du test'),
('zh','protocols','test_result','测试结果'),
('en','protocols','client_output_preview','Client output preview'),
('ru','protocols','client_output_preview','Предпросмотр ответа клиенту'),
('es','protocols','client_output_preview','Vista previa de salida del cliente'),
('de','protocols','client_output_preview','Client‑Ausgabevorschau'),
('fr','protocols','client_output_preview','Aperçu de la sortie client'),
('zh','protocols','client_output_preview','客户端输出预览'),
('en','protocols','test_failed','Test failed'),
('ru','protocols','test_failed','Ошибка теста'),
('es','protocols','test_failed','La prueba falló'),
('de','protocols','test_failed','Test fehlgeschlagen'),
('fr','protocols','test_failed','Échec du test'),
('zh','protocols','test_failed','测试失败')
ON DUPLICATE KEY UPDATE translation = VALUES(translation);

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active, created_at, updated_at)
SELECT 'SMB Server', 'smb', 'Samba SMB file share inside Docker with random host port', '#!/bin/bash\n\nset -euo pipefail\nset -x\n\nCONTAINER_NAME="${CONTAINER_NAME:-amnezia-smb}"\nPORT_RANGE_START=${PORT_RANGE_START:-30000}\nPORT_RANGE_END=${PORT_RANGE_END:-65000}\nSMB_PORT=$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))\n\n docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true\nmkdir -p /opt/amnezia/smb/share\n docker run -d \\\n  --name "$CONTAINER_NAME" \\\n  -p "${SMB_PORT}:445" \\\n  -v /opt/amnezia/smb/share:/share \\\n  dperson/samba -p -u "amnezia;amnezia" -s "share;/share;yes;no;no;amnezia"\n echo "Port: ${SMB_PORT}"\n echo "Password: amnezia"\n', 'smb://{{server_host}}:{{server_port}}/share\nUsername: amnezia\nPassword: {{password}}', true, true, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='smb');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'server_host', 'string', '127.0.0.1', 'Server hostname or IP', true FROM protocols WHERE slug = 'smb' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='smb') AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'server_port', 'number', '445', 'Server port', true FROM protocols WHERE slug = 'smb' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='smb') AND variable_name='server_port');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'password', 'string', '', 'Connection password', true FROM protocols WHERE slug = 'smb' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='smb') AND variable_name='password');

INSERT INTO protocols (name, slug, description, install_script, output_template, ubuntu_compatible, is_active, created_at, updated_at)
SELECT 'XRay VLESS', 'xray-vless', 'XRay VLESS server inside Docker with generated client UUID', '#!/bin/bash\n\nset -euo pipefail\nset -x\n\nCONTAINER_NAME="${CONTAINER_NAME:-amnezia-xray}"\nPORT_RANGE_START=${PORT_RANGE_START:-30000}\nPORT_RANGE_END=${PORT_RANGE_END:-65000}\nXRAY_PORT=$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))\nCLIENT_ID=$(cat /proc/sys/kernel/random/uuid)\n docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true\nmkdir -p /opt/amnezia/xray\n cat > /opt/amnezia/xray/config.json << EOF\n{\n  "inbounds": [\n    {\n      "listen": "0.0.0.0",\n      "port": 443,\n      "protocol": "vless",\n      "settings": {\n        "clients": [\n          { "id": "${CLIENT_ID}" }\n        ],\n        "decryption": "none"\n      },\n      "streamSettings": {\n        "network": "tcp",\n        "security": "none"\n      }\n    }\n  ],\n  "outbounds": [\n    { "protocol": "freedom" }\n  ]\n}\nEOF\n docker run -d \\\n  --name "$CONTAINER_NAME" \\\n  --restart always \\\n  -p "${XRAY_PORT}:443" \\\n  -v /opt/amnezia/xray:/etc/xray \\\n  teddysun/xray\n echo "Port: ${XRAY_PORT}"\n echo "ClientID: ${CLIENT_ID}"\n', 'vless://{{client_id}}@{{server_host}}:{{server_port}}?security=none&type=tcp', true, true, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM protocols WHERE slug='xray-vless');

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'server_host', 'string', '127.0.0.1', 'Server hostname or IP', true FROM protocols WHERE slug = 'xray-vless' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='xray-vless') AND variable_name='server_host');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'server_port', 'number', '443', 'Server port', true FROM protocols WHERE slug = 'xray-vless' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='xray-vless') AND variable_name='server_port');
INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT id, 'client_id', 'string', '', 'VLESS client ID (UUID)', true FROM protocols WHERE slug = 'xray-vless' AND NOT EXISTS (SELECT 1 FROM protocol_variables WHERE protocol_id = (SELECT id FROM protocols WHERE slug='xray-vless') AND variable_name='client_id');

DELIMITER $$
CREATE PROCEDURE add_protocol_column_and_constraints()
BEGIN
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='vpn_clients' AND COLUMN_NAME='protocol_id') = 0 THEN
    ALTER TABLE vpn_clients ADD COLUMN protocol_id INT UNSIGNED NULL AFTER user_id;
  END IF;

  IF (SELECT COUNT(*) FROM information_schema.STATISTICS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='vpn_clients' AND INDEX_NAME='idx_protocol_id') = 0 THEN
    ALTER TABLE vpn_clients ADD INDEX idx_protocol_id (protocol_id);
  END IF;

  IF (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='vpn_clients' AND CONSTRAINT_NAME='fk_vpn_clients_protocol') = 0 THEN
    ALTER TABLE vpn_clients ADD CONSTRAINT fk_vpn_clients_protocol FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE SET NULL;
  END IF;
END$$
DELIMITER ;
CALL add_protocol_column_and_constraints();
DROP PROCEDURE add_protocol_column_and_constraints;

DELIMITER $$
CREATE PROCEDURE ensure_users_role_column_and_index()
BEGIN
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='role') = 0 THEN
    ALTER TABLE users ADD COLUMN role ENUM('admin','user') DEFAULT 'user' AFTER name;
  END IF;
  IF (SELECT COUNT(*) FROM information_schema.STATISTICS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND INDEX_NAME='idx_role') = 0 THEN
    ALTER TABLE users ADD INDEX idx_role (role);
  END IF;
END$$
DELIMITER ;
CALL ensure_users_role_column_and_index();
DROP PROCEDURE ensure_users_role_column_and_index;

DELIMITER $$
CREATE PROCEDURE add_protocols_optional_columns()
BEGIN
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='protocols' AND COLUMN_NAME='uninstall_script') = 0 THEN
    ALTER TABLE protocols ADD COLUMN uninstall_script MEDIUMTEXT NULL AFTER install_script;
  END IF;
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='protocols' AND COLUMN_NAME='password_command') = 0 THEN
    ALTER TABLE protocols ADD COLUMN password_command TEXT NULL AFTER uninstall_script;
  END IF;
END$$
DELIMITER ;
CALL add_protocols_optional_columns();
DROP PROCEDURE add_protocols_optional_columns;

DELIMITER $$
CREATE PROCEDURE ensure_users_display_name_column()
BEGIN
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='display_name') = 0 THEN
    ALTER TABLE users ADD COLUMN display_name VARCHAR(255) NULL AFTER name;
  END IF;
END$$
DELIMITER ;
CALL ensure_users_display_name_column();
DROP PROCEDURE ensure_users_display_name_column;
UPDATE users SET display_name = name WHERE (display_name IS NULL OR display_name = '') AND name IS NOT NULL;

UPDATE protocols SET 
  install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT=${VPN_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}
MTU=${MTU:-1420}

EXISTING=$(docker ps -aq -f "name=$CONTAINER_NAME" 2>/dev/null | head -1)
if [ -z "$EXISTING" ]; then
  docker run -d --name "$CONTAINER_NAME" --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p "${VPN_PORT}:${VPN_PORT}/udp" -v /lib/modules:/lib/modules amneziavpn/amnezia-wg:latest
  sleep 2
else
  STATUS=$(docker inspect --format="{{.State.Status}}" "$CONTAINER_NAME" 2>/dev/null || echo "")
  if [ "$STATUS" != "running" ]; then
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
fi

docker exec -i "$CONTAINER_NAME" sh -lc "mkdir -p /opt/amnezia/awg"

HAS_CONF=$(docker exec "$CONTAINER_NAME" sh -lc "[ -f /opt/amnezia/awg/wg0.conf ] && echo yes || echo no")
if [ "$HAS_CONF" = "yes" ]; then
  PORT=$(docker exec "$CONTAINER_NAME" sh -lc "grep -E \"^ListenPort\" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d \"[:space:]\"")
  PSK=$(docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true)
  if [ -z "$PSK" ]; then
    PSK=$(docker exec "$CONTAINER_NAME" sh -lc "grep -E \"^PresharedKey\" /opt/amnezia/awg/wg0.conf | cut -d= -f2 | tr -d \"[:space:]\"")
  fi
  PUBKEY=$(docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || true)
  if [ -z "$PUBKEY" ]; then
    PRIVKEY=$(docker exec "$CONTAINER_NAME" cat /opt/amnezia/awg/wireguard_server_private_key.key 2>/dev/null || true)
    if [ -n "$PRIVKEY" ]; then
      PUBKEY=$(echo "$PRIVKEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
    fi
  fi
  echo "Using existing AmneziaWG configuration"
  echo "Port: ${PORT:-$VPN_PORT}"
  if [ -n "${PUBKEY:-}" ]; then echo "Server Public Key: $PUBKEY"; fi
  if [ -n "${PSK:-}" ]; then echo "PresharedKey = $PSK"; fi
  exit 0
fi

PRIVATE_KEY=$(docker exec "$CONTAINER_NAME" wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | docker exec -i "$CONTAINER_NAME" wg pubkey)
PRESHARED_KEY=$(docker exec "$CONTAINER_NAME" wg genpsk)

cat > /opt/amnezia/awg/wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
MTU = $MTU
Jc = 5
Jmin = 100
Jmax = 200
S1 = 50
S2 = 100
S3 = 20
S4 = 10
H1 = 0xDEADBEEF
H2 = 0xCAFEBABE
H3 = 0x12345678
H4 = 0x9ABCDEF0
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
PresharedKey = $PRESHARED_KEY
AllowedIPs = 10.8.1.2/32
EOF

docker exec "$CONTAINER_NAME" sh -lc "echo $PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key"
docker exec "$CONTAINER_NAME" sh -lc "echo $PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key"
docker exec "$CONTAINER_NAME" sh -lc "echo $PRESHARED_KEY > /opt/amnezia/awg/wireguard_psk.key"
docker exec "$CONTAINER_NAME" sh -lc "echo [] > /opt/amnezia/awg/clientsTable"

docker exec "$CONTAINER_NAME" wg-quick up /opt/amnezia/awg/wg0.conf || true

echo "AmneziaWG Advanced installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY' 
WHERE slug = 'amnezia-wg-advanced';

UPDATE protocols SET 
  uninstall_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm -fv "$CONTAINER_NAME" 2>/dev/null || true
docker image rm amneziavpn/amnezia-wg:latest 2>/dev/null || true
docker network rm amnezia-dns-net 2>/dev/null || true
rm -rf /opt/amnezia/amnezia-awg 2>/dev/null || true
rm -rf /opt/amnezia/awg 2>/dev/null || true

echo "{\"success\":true,\"message\":\"AmneziaWG uninstalled\"}"' 
WHERE slug = 'amnezia-wg-advanced';

DELIMITER $$
CREATE PROCEDURE ensure_vpn_servers_install_columns()
BEGIN
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='vpn_servers' AND COLUMN_NAME='install_protocol') = 0 THEN
    ALTER TABLE vpn_servers ADD COLUMN install_protocol VARCHAR(100) NULL AFTER container_name;
  END IF;
  IF (SELECT COUNT(*) FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='vpn_servers' AND COLUMN_NAME='install_options') = 0 THEN
    ALTER TABLE vpn_servers ADD COLUMN install_options JSON NULL AFTER install_protocol;
  END IF;
END$$
DELIMITER ;
CALL ensure_vpn_servers_install_columns();
DROP PROCEDURE ensure_vpn_servers_install_columns;