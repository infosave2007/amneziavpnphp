-- Migration: Add user roles and permissions
-- Date: 2025-11-10

-- User roles table
CREATE TABLE IF NOT EXISTS user_roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add role to users table
SET @role_col_exists := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'users'
      AND COLUMN_NAME = 'role'
);

SET @add_role_col_sql := IF(
    @role_col_exists = 0,
    'ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT ''viewer'' AFTER ldap_dn',
    'SELECT 1'
);
PREPARE add_role_col_stmt FROM @add_role_col_sql;
EXECUTE add_role_col_stmt;
DEALLOCATE PREPARE add_role_col_stmt;

SET @role_idx_exists := (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'users'
      AND INDEX_NAME = 'idx_role'
);

SET @add_role_idx_sql := IF(
    @role_idx_exists = 0,
    'ALTER TABLE users ADD INDEX idx_role (role)',
    'SELECT 1'
);
PREPARE add_role_idx_stmt FROM @add_role_idx_sql;
EXECUTE add_role_idx_stmt;
DEALLOCATE PREPARE add_role_idx_stmt;

-- Insert default roles
INSERT IGNORE INTO user_roles (name, display_name, description, permissions) VALUES
('admin', 'Administrator', 'Full access to all features', JSON_ARRAY('*')),
('manager', 'Manager', 'Can manage servers and clients', JSON_ARRAY('servers.view', 'servers.create', 'servers.edit', 'clients.view', 'clients.create', 'clients.edit', 'clients.delete')),
('viewer', 'Viewer', 'Can only view own clients', JSON_ARRAY('clients.view_own', 'clients.download_own'));

-- Insert default LDAP group mappings (examples)
INSERT IGNORE INTO ldap_group_mappings (ldap_group, role_name, description) VALUES
('vpn-admins', 'admin', 'VPN administrators with full access'),
('vpn-managers', 'manager', 'VPN managers who can create and manage clients'),
('vpn-users', 'viewer', 'Regular VPN users with view-only access');

-- Update existing users to admin role (backward compatibility)
UPDATE users SET role = 'admin' WHERE role IS NULL OR role = '';
