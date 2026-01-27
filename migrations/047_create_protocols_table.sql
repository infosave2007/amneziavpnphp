-- Safely update protocols table schema and data

-- 1. Ensure columns exist
SET @dbname = DATABASE();
SET @tablename = "protocols";
SET @columnname = "definition";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  "ALTER TABLE protocols ADD COLUMN definition JSON NULL AFTER description"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

SET @columnname = "show_text_content";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  "ALTER TABLE protocols ADD COLUMN show_text_content TINYINT(1) DEFAULT 0 AFTER definition"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 2. Insert Data
INSERT IGNORE INTO protocols (slug, name, description, definition, show_text_content, is_active) VALUES
('amnezia-wg', 'AmneziaWG', 'Amnezia WireGuard implementation', '{}', 0, 1),
('wireguard', 'WireGuard', 'Standard WireGuard', '{}', 0, 1),
('openvpn', 'OpenVPN', 'Standard OpenVPN', '{}', 0, 1),
('shadowsocks', 'Shadowsocks', 'Shadowsocks proxy', '{}', 0, 1),
('cloak', 'Cloak', 'Cloak obfuscation', '{}', 0, 1);

-- 3. Update vpn_clients structure (original logic from migration)
SET @exist := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vpn_clients' AND COLUMN_NAME='protocol_id');
SET @sql := IF(@exist=0, 'ALTER TABLE vpn_clients ADD COLUMN protocol_id INT UNSIGNED NULL AFTER server_id, ADD INDEX idx_protocol_id (protocol_id), ADD CONSTRAINT fk_clients_protocol FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE SET NULL', 'SELECT "Column protocol_id exists"');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4. Create server_protocols if not exists
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
