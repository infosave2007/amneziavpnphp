<?php

/**
 * LdapSync - LDAP integration and user synchronization
 * 
 * Provides:
 * - Connection to LDAP/Active Directory
 * - User authentication via LDAP
 * - Group-based access control
 * - Automatic user synchronization
 */
class LdapSync
{
    private $connection;
    private array $config;
    
    public function __construct()
    {
        $this->loadConfig();
    }
    
    /**
     * Load LDAP configuration from database
     */
    private function loadConfig(): void
    {
        $db = DB::conn();
        $stmt = $db->query("SELECT * FROM ldap_configs WHERE id = 1");
        $this->config = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }
    
    /**
     * Check if LDAP is enabled
     */
    public function isEnabled(): bool
    {
        return !empty($this->config) && $this->config['enabled'];
    }
    
    /**
     * Connect to LDAP server
     */
    public function connect(): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }
        
        $ldapUri = ($this->config['use_tls'] ? 'ldaps://' : 'ldap://') . 
                   $this->config['host'] . ':' . $this->config['port'];
        
        $this->connection = @ldap_connect($ldapUri);
        
        if (!$this->connection) {
            error_log("LDAP: Failed to connect to {$ldapUri}");
            return false;
        }
        
        ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
        
        // Bind with admin credentials
        $bindResult = @ldap_bind(
            $this->connection, 
            $this->config['bind_dn'], 
            $this->config['bind_password']
        );
        
        if (!$bindResult) {
            error_log("LDAP: Failed to bind as " . $this->config['bind_dn']);
            return false;
        }
        
        return true;
    }
    
    /**
     * Authenticate user via LDAP
     */
    public function authenticate(string $username, string $password): ?array
    {
        if (!$this->connect()) {
            return null;
        }
        
        try {
            // Search for user
            $filter = str_replace('%s', ldap_escape($username, '', LDAP_ESCAPE_FILTER), 
                                   $this->config['user_search_filter']);
            
            $search = @ldap_search(
                $this->connection, 
                $this->config['base_dn'], 
                $filter,
                ['dn', 'cn', 'mail', 'memberOf', 'displayName']
            );
            
            if (!$search) {
                return null;
            }
            
            $entries = ldap_get_entries($this->connection, $search);
            
            if ($entries['count'] === 0) {
                return null;
            }
            
            $userDn = $entries[0]['dn'];
            
            // Try to bind as user (authenticate)
            if (!@ldap_bind($this->connection, $userDn, $password)) {
                return null;
            }
            
            // Get user groups
            $groups = $this->getUserGroups($userDn);
            $role = $this->mapGroupsToRole($groups);
            
            return [
                'username' => $username,
                'email' => $entries[0]['mail'][0] ?? '',
                'display_name' => $entries[0]['displayname'][0] ?? $entries[0]['cn'][0] ?? $username,
                'ldap_dn' => $userDn,
                'groups' => $groups,
                'role' => $role
            ];
            
        } catch (Exception $e) {
            error_log("LDAP auth error: " . $e->getMessage());
            return null;
        } finally {
            $this->disconnect();
        }
    }
    
    /**
     * Get user's LDAP groups
     */
    private function getUserGroups(string $userDn): array
    {
        $groups = [];
        
        try {
            $filter = str_replace('%s', ldap_escape(explode(',', $userDn)[0], '', LDAP_ESCAPE_FILTER), 
                                   $this->config['group_search_filter']);
            
            $search = @ldap_search(
                $this->connection, 
                $this->config['base_dn'], 
                $filter,
                ['cn']
            );
            
            if ($search) {
                $entries = ldap_get_entries($this->connection, $search);
                for ($i = 0; $i < $entries['count']; $i++) {
                    $groups[] = $entries[$i]['cn'][0];
                }
            }
        } catch (Exception $e) {
            error_log("LDAP get groups error: " . $e->getMessage());
        }
        
        return $groups;
    }
    
    /**
     * Map LDAP groups to application role
     */
    private function mapGroupsToRole(array $groups): string
    {
        $db = DB::conn();
        
        foreach ($groups as $group) {
            $stmt = $db->prepare("SELECT role_name FROM ldap_group_mappings WHERE ldap_group = ?");
            $stmt->execute([$group]);
            $mapping = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($mapping) {
                return $mapping['role_name'];
            }
        }
        
        return 'viewer'; // Default role
    }
    
    /**
     * Synchronize all LDAP users
     */
    public function syncUsers(): array
    {
        if (!$this->connect()) {
            return ['success' => false, 'error' => 'Failed to connect to LDAP'];
        }
        
        try {
            $search = @ldap_search(
                $this->connection, 
                $this->config['base_dn'], 
                '(objectClass=person)',
                ['dn', 'cn', 'mail', 'uid']
            );
            
            if (!$search) {
                return ['success' => false, 'error' => 'LDAP search failed'];
            }
            
            $entries = ldap_get_entries($this->connection, $search);
            $db = DB::conn();
            $synced = 0;
            $created = 0;
            $disabled = 0;
            
            // Get existing LDAP users
            $existingUsers = $db->query("SELECT ldap_dn FROM users WHERE ldap_synced = 1")
                                ->fetchAll(PDO::FETCH_COLUMN);
            
            $currentDns = [];
            
            for ($i = 0; $i < $entries['count']; $i++) {
                $entry = $entries[$i];
                $dn = $entry['dn'];
                $username = $entry['uid'][0] ?? $entry['cn'][0];
                $email = $entry['mail'][0] ?? '';
                
                $currentDns[] = $dn;
                
                // Get user groups and map to role
                $groups = $this->getUserGroups($dn);
                $role = $this->mapGroupsToRole($groups);
                
                // Check if user exists
                $stmt = $db->prepare("SELECT id FROM users WHERE ldap_dn = ?");
                $stmt->execute([$dn]);
                $existing = $stmt->fetch();
                
                if ($existing) {
                    // Update existing user
                    $stmt = $db->prepare("
                        UPDATE users 
                        SET email = ?, role = ?, status = 'active', ldap_synced = 1 
                        WHERE ldap_dn = ?
                    ");
                    $stmt->execute([$email, $role, $dn]);
                    $synced++;
                } else {
                    // Create new user
                    $stmt = $db->prepare("
                        INSERT INTO users (username, email, password, role, status, ldap_synced, ldap_dn) 
                        VALUES (?, ?, '', ?, 'active', 1, ?)
                    ");
                    $stmt->execute([$username, $email, $role, $dn]);
                    $created++;
                }
            }
            
            // Disable users no longer in LDAP
            $missingDns = array_diff($existingUsers, $currentDns);
            if (!empty($missingDns)) {
                $placeholders = str_repeat('?,', count($missingDns) - 1) . '?';
                $stmt = $db->prepare("UPDATE users SET status = 'disabled' WHERE ldap_dn IN ($placeholders)");
                $stmt->execute($missingDns);
                $disabled = count($missingDns);
            }
            
            return [
                'success' => true,
                'synced' => $synced,
                'created' => $created,
                'disabled' => $disabled,
                'total' => $entries['count']
            ];
            
        } catch (Exception $e) {
            error_log("LDAP sync error: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            $this->disconnect();
        }
    }
    
    /**
     * Test LDAP connection
     */
    public function testConnection(): array
    {
        if (!$this->connect()) {
            return [
                'success' => false,
                'message' => 'Failed to connect or bind to LDAP server'
            ];
        }
        
        $this->disconnect();
        
        return [
            'success' => true,
            'message' => 'Successfully connected to LDAP server'
        ];
    }
    
    /**
     * Disconnect from LDAP
     */
    private function disconnect(): void
    {
        if ($this->connection) {
            @ldap_unbind($this->connection);
            $this->connection = null;
        }
    }
}
