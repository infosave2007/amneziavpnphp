CREATE TABLE IF NOT EXISTS protocols (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(50) NOT NULL UNIQUE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  definition JSON,
  show_text_content TINYINT(1) DEFAULT 0,
  is_active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_slug (slug),
  INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default protocols (X-Ray, AWG)
-- We populate initial data so the panel is usable immediately
INSERT IGNORE INTO protocols (slug, name, description, definition, show_text_content, is_active) VALUES
('amnezia-wg', 'AmneziaWG', 'Amnezia WireGuard implementation', '{}', 0, 1),
('amnezia-xray', 'Amnezia XRay', 'XRay (VLESS/Reality)', '{"scripts":{}}', 0, 1),
('wireguard', 'WireGuard', 'Standard WireGuard', '{}', 0, 1),
('openvpn', 'OpenVPN', 'Standard OpenVPN', '{}', 0, 1),
('shadowsocks', 'Shadowsocks', 'Shadowsocks proxy', '{}', 0, 1),
('cloak', 'Cloak', 'Cloak obfuscation', '{}', 0, 1);

-- Add protocol_id to vpn_clients if it does not exist
SET @exist := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vpn_clients' AND COLUMN_NAME='protocol_id');
SET @sql := IF(@exist=0, 'ALTER TABLE vpn_clients ADD COLUMN protocol_id INT UNSIGNED NULL AFTER server_id, ADD INDEX idx_protocol_id (protocol_id), ADD CONSTRAINT fk_clients_protocol FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE SET NULL', 'SELECT "Column protocol_id exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Also check server_protocols table existence (referenced in InstallProtocolManager)
CREATE TABLE IF NOT EXISTS server_protocols (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  server_id INT UNSIGNED NOT NULL,
  protocol_id INT UNSIGNED NOT NULL,
  config_data JSON,
  container_id VARCHAR(255) NULL,
  applied_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_server_proto (server_id, protocol_id),
  FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE,
  FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
