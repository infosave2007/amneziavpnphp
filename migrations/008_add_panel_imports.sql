-- Add panel imports tracking table
-- This migration adds functionality to track imports from other VPN panels

CREATE TABLE IF NOT EXISTS panel_imports (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  server_id INT UNSIGNED NOT NULL,
  panel_type ENUM('wg-easy', '3x-ui') NOT NULL,
  import_file_name VARCHAR(255) NOT NULL,
  clients_imported INT UNSIGNED DEFAULT 0,
  import_data JSON NULL COMMENT 'Original import data for reference',
  status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
  error_message TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by INT UNSIGNED NULL,
  INDEX idx_server_id (server_id),
  INDEX idx_panel_type (panel_type),
  INDEX idx_status (status),
  FOREIGN KEY (server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
