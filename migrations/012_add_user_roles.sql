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
ALTER TABLE users 
ADD COLUMN role VARCHAR(50) DEFAULT 'viewer' AFTER ldap_dn,
ADD INDEX idx_role (role);

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
