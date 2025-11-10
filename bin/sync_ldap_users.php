#!/usr/bin/env php
<?php
/**
 * LDAP User Synchronization Script
 * Runs periodically to sync users from LDAP/AD
 */

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/LdapSync.php';

try {
    $ldap = new LdapSync();
    
    if (!$ldap->isEnabled()) {
        exit(0); // LDAP not enabled, nothing to do
    }
    
    echo "[" . date('Y-m-d H:i:s') . "] Starting LDAP user synchronization...\n";
    
    $result = $ldap->syncUsers();
    
    if ($result['success']) {
        echo "✓ Synchronization completed successfully:\n";
        echo "  - Total users in LDAP: {$result['total']}\n";
        echo "  - Synced (updated): {$result['synced']}\n";
        echo "  - Created: {$result['created']}\n";
        echo "  - Disabled: {$result['disabled']}\n";
    } else {
        echo "✗ Synchronization failed: {$result['error']}\n";
        exit(1);
    }
    
} catch (Exception $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
    exit(1);
}
