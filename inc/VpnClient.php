<?php
/**
 * VPN Client Management Class
 * Handles creation and management of VPN client configurations
 * Based on amnezia_client_config_v2.php
 */
class VpnClient {
    private $clientId;
    private $data;
    
    public function __construct(?int $clientId = null) {
        $this->clientId = $clientId;
        if ($clientId) {
            $this->load();
        }
    }
    
    /**
     * Load client data from database
     */
    private function load(): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE id = ?');
        $stmt->execute([$this->clientId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Client not found');
        }
    }
    
    /**
     * Create new VPN client
     * 
     * @param int $serverId Server ID
     * @param int $userId User ID
     * @param string $name Client name
     * @param int|null $expiresInDays Days until expiration (null = never expires)
     * @return int Client ID
     */
    public static function create(int $serverId, int $userId, string $name, ?int $expiresInDays = null): int {
        $pdo = DB::conn();
        
        // Sanitize client name (replace spaces and special characters)
        $name = trim($name);
        $name = preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
        
        // Get server data
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            throw new Exception('Server is not active');
        }
        
        // Generate client keys
        $containerName = $serverData['container_name'];
        $keys = self::generateClientKeys($serverData, $name);
        
        // Get next available IP
        $clientIP = self::getNextClientIP($serverData);
        
        // Get AWG parameters from server
        $awgParams = json_decode($serverData['awg_params'], true);
        
        // Build client configuration
        $config = self::buildClientConfig(
            $keys['private'],
            $clientIP,
            $serverData['server_public_key'],
            $serverData['preshared_key'],
            $serverData['host'],
            $serverData['vpn_port'],
            $awgParams
        );
        
        // Add client to server
        self::addClientToServer($serverData, $keys['public'], $clientIP);
        
        // Generate QR code
        $qrCode = self::generateQRCode($config);
        
        // Calculate expiration date
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;
        
        // Insert into database
        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients 
            (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        
        $stmt->execute([
            $serverId,
            $userId,
            $name,
            $clientIP,
            $keys['public'],
            $keys['private'],
            $serverData['preshared_key'],
            $config,
            $qrCode,
            'active',
            $expiresAt
        ]);
        
        return (int)$pdo->lastInsertId();
    }
    
    /**
     * Generate client keys on remote server
     */
    private static function generateClientKeys(array $serverData, string $clientName): array {
        $containerName = $serverData['container_name'];
        
        $cmd = sprintf(
            "docker exec -i %s sh -c \"umask 077; wg genkey | tee /tmp/%s_priv.key | wg pubkey > /tmp/%s_pub.key; cat /tmp/%s_priv.key; echo '---'; cat /tmp/%s_pub.key; rm -f /tmp/%s_priv.key /tmp/%s_pub.key\"",
            $containerName,
            $clientName, $clientName, $clientName, $clientName, $clientName, $clientName
        );
        
        $escaped = escapeshellarg($cmd);
        $sshCmd = sprintf(
            "sshpass -p '%s' ssh -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $serverData['password'],
            $serverData['username'],
            $serverData['host'],
            $escaped
        );
        
        $out = shell_exec($sshCmd);
        $parts = explode("---", trim($out));
        
        if (count($parts) < 2) {
            throw new Exception("Failed to generate client keys");
        }
        
        return [
            'private' => trim($parts[0]),
            'public' => trim($parts[1])
        ];
    }
    
    /**
     * Get next available client IP
     */
    private static function getNextClientIP(array $serverData): string {
        $pdo = DB::conn();
        
        // Get used IPs from database
        $stmt = $pdo->prepare('SELECT client_ip FROM vpn_clients WHERE server_id = ? AND status = ?');
        $stmt->execute([$serverData['id'], 'active']);
        $usedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Parse subnet
        $parts = explode('/', $serverData['vpn_subnet']);
        $networkLong = ip2long($parts[0]);
        
        // Reserve network address
        $used = ['10.8.1.0' => true];
        foreach ($usedIPs as $ip) {
            $used[$ip] = true;
        }
        
        // Find next free IP starting from .1
        for ($i = 1; $i <= 253; $i++) {
            $candidate = long2ip($networkLong + $i);
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }
        
        throw new Exception('No free IP addresses in subnet');
    }
    
    /**
     * Build client configuration file
     */
    private static function buildClientConfig(
        string $privateKey,
        string $clientIP,
        string $serverPublicKey,
        string $presharedKey,
        string $serverHost,
        int $serverPort,
        array $awgParams
    ): string {
        $config = "[Interface]\n";
        $config .= "PrivateKey = {$privateKey}\n";
        $config .= "Address = {$clientIP}/32\n";
        $config .= "DNS = 1.1.1.1, 1.0.0.1\n";
        
        // Add AWG parameters
        foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $key) {
            if (isset($awgParams[$key])) {
                $config .= "{$key} = {$awgParams[$key]}\n";
            }
        }
        
        $config .= "\n[Peer]\n";
        $config .= "PublicKey = {$serverPublicKey}\n";
        $config .= "PresharedKey = {$presharedKey}\n";
        $config .= "Endpoint = {$serverHost}:{$serverPort}\n";
        $config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        $config .= "PersistentKeepalive = 25\n";
        
        return $config;
    }
    
    /**
     * Add client to server using official method (append + wg syncconf)
     */
    private static function addClientToServer(array $serverData, string $publicKey, string $clientIP): void {
        $containerName = $serverData['container_name'];
        
        // Build peer block
        $peerBlock = "\n[Peer]\n";
        $peerBlock .= "PublicKey = {$publicKey}\n";
        $peerBlock .= "PresharedKey = {$serverData['preshared_key']}\n";
        $peerBlock .= "AllowedIPs = {$clientIP}/32\n";
        
        $escaped = addslashes($peerBlock);
        $tempFile = '/tmp/' . bin2hex(random_bytes(8)) . '.tmp';
        
        // Create temp file
        $cmd1 = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $containerName, $escaped, $tempFile);
        self::executeServerCommand($serverData, $cmd1, true);
        
        // Append to wg0.conf
        $cmd2 = sprintf("docker exec -i %s sh -c 'cat %s >> /opt/amnezia/awg/wg0.conf'", $containerName, $tempFile);
        self::executeServerCommand($serverData, $cmd2, true);
        
        // Apply via wg syncconf
        $cmd3 = sprintf("docker exec -i %s bash -c 'wg syncconf wg0 <(wg-quick strip /opt/amnezia/awg/wg0.conf)'", $containerName);
        self::executeServerCommand($serverData, $cmd3, true);
        
        // Remove temp file
        $cmd4 = sprintf("docker exec -i %s rm -f %s", $containerName, $tempFile);
        self::executeServerCommand($serverData, $cmd4, true);
        
        // Update clientsTable
        self::updateClientsTable($serverData, $publicKey, $clientIP);
    }
    
    /**
     * Update clientsTable on server
     */
    private static function updateClientsTable(array $serverData, string $publicKey, string $name): void {
        $containerName = $serverData['container_name'];
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/clientsTable 2>/dev/null", $containerName);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            $table = [];
        }
        
        // Add new client
        $table[] = [
            'clientId' => $publicKey,
            'userData' => [
                'clientName' => $name,
                'creationDate' => date('D M j H:i:s Y')
            ]
        ];
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > /opt/amnezia/awg/clientsTable'", $containerName, $escaped);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Execute command on server
     */
    private static function executeServerCommand(array $serverData, string $command, bool $sudo = false): string {
        if ($sudo && strtolower($serverData['username']) !== 'root') {
            $command = "echo '{$serverData['password']}' | sudo -S " . $command;
        }
        
        $escapedCommand = escapeshellarg($command);
        $sshCommand = sprintf(
            "sshpass -p '%s' ssh -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $serverData['password'],
            $serverData['username'],
            $serverData['host'],
            $escapedCommand
        );
        
        return shell_exec($sshCommand) ?? '';
    }
    
    /**
     * Generate QR code for configuration using Amnezia format
     * Uses working QrUtil from /Users/oleg/Documents/amnezia
     */
    private static function generateQRCode(string $config): string {
        require_once __DIR__ . '/QrUtil.php';
        
        try {
            // Use old Amnezia format with Qt/QDataStream encoding
            $payloadOld = QrUtil::encodeOldPayloadFromConf($config);
            $dataUri = QrUtil::pngBase64($payloadOld);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate QR code: ' . $e->getMessage());
            return ''; // QR code generation failed, but continue
        }
    }
    
    /**
     * Get all clients for a server
     */
    public static function listByServer(int $serverId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE server_id = ? ORDER BY created_at DESC');
        $stmt->execute([$serverId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get all clients for a user
     */
    public static function listByUser(int $userId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host as server_host
            FROM vpn_clients c
            LEFT JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Revoke client access (disable without deleting)
     */
    public function revoke(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Remove from server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                self::removeClientFromServer($serverData, $this->data['public_key']);
            } catch (Exception $e) {
                error_log('Failed to remove client from server: ' . $e->getMessage());
            }
        }
        
        // Mark as disabled in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['disabled', $this->clientId]);
    }
    
    /**
     * Restore client access
     */
    public function restore(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Re-add to server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                self::addClientToServer($serverData, $this->data['public_key'], $this->data['client_ip']);
            } catch (Exception $e) {
                throw new Exception('Failed to restore client on server: ' . $e->getMessage());
            }
        }
        
        // Mark as active in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['active', $this->clientId]);
    }
    
    /**
     * Delete client permanently
     */
    public function delete(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // First revoke to remove from server
        if ($this->data['status'] === 'active') {
            $this->revoke();
        }
        
        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_clients WHERE id = ?');
        return $stmt->execute([$this->clientId]);
    }
    
    /**
     * Remove client from server WireGuard configuration
     */
    private static function removeClientFromServer(array $serverData, string $publicKey): void {
        $containerName = $serverData['container_name'];
        
        // First, remove using wg command (live removal)
        $removeCmd = sprintf(
            "docker exec -i %s wg set wg0 peer %s remove",
            $containerName,
            escapeshellarg($publicKey)
        );
        
        self::executeServerCommand($serverData, $removeCmd, true);
        
        // Then remove from wg0.conf file to make it persistent
        // Use a more reliable method: read, filter, write
        $readCmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/wg0.conf", $containerName);
        $config = self::executeServerCommand($serverData, $readCmd, true);
        
        // Parse and remove the peer section
        $newConfig = self::removePeerFromConfig($config, $publicKey);
        
        // Write back to file
        $escapedConfig = str_replace("'", "'\\''", $newConfig);
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'echo '\''%s'\'' > /opt/amnezia/awg/wg0.conf'",
            $containerName,
            $escapedConfig
        );
        
        self::executeServerCommand($serverData, $writeCmd, true);
        
        // Save config
        $saveCmd = sprintf("docker exec -i %s wg-quick save wg0", $containerName);
        self::executeServerCommand($serverData, $saveCmd, true);
        
        // Remove from clientsTable
        self::removeFromClientsTable($serverData, $publicKey);
    }
    
    /**
     * Remove peer section from WireGuard config
     */
    private static function removePeerFromConfig(string $config, string $publicKey): string {
        $lines = explode("\n", $config);
        $newLines = [];
        $inPeerBlock = false;
        $skipBlock = false;
        
        foreach ($lines as $line) {
            $trimmed = trim($line);
            
            // Start of new section
            if (strpos($trimmed, '[') === 0) {
                $inPeerBlock = ($trimmed === '[Peer]');
                $skipBlock = false;
            }
            
            // Check if this peer block should be skipped
            if ($inPeerBlock && strpos($trimmed, 'PublicKey') === 0) {
                $parts = explode('=', $line, 2);
                if (count($parts) === 2 && trim($parts[1]) === $publicKey) {
                    $skipBlock = true;
                    // Remove the [Peer] line that was already added
                    array_pop($newLines);
                    continue;
                }
            }
            
            // Skip lines in the block to be removed
            if ($skipBlock && $inPeerBlock) {
                // Empty line ends the peer block
                if (empty($trimmed)) {
                    $skipBlock = false;
                    $inPeerBlock = false;
                }
                continue;
            }
            
            $newLines[] = $line;
        }
        
        return implode("\n", $newLines);
    }
    
    /**
     * Remove client from clientsTable
     */
    private static function removeFromClientsTable(array $serverData, string $publicKey): void {
        $containerName = $serverData['container_name'];
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/clientsTable 2>/dev/null", $containerName);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            return;
        }
        
        // Filter out the client
        $table = array_filter($table, function($client) use ($publicKey) {
            return ($client['clientId'] ?? '') !== $publicKey;
        });
        
        // Re-index array
        $table = array_values($table);
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > /opt/amnezia/awg/clientsTable'", $containerName, $escaped);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Get client data
     */
    public function getData(): ?array {
        return $this->data;
    }
    
    /**
     * Get configuration file content
     */
    public function getConfig(): string {
        return $this->data['config'] ?? '';
    }
    
    /**
     * Get QR code
     */
    public function getQRCode(): string {
        return $this->data['qr_code'] ?? '';
    }
    
    /**
     * Sync traffic statistics from server
     */
    public function syncStats(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            return false;
        }
        
        try {
            $stats = self::getClientStatsFromServer($serverData, $this->data['public_key']);
            
            $pdo = DB::conn();
            $stmt = $pdo->prepare('
                UPDATE vpn_clients 
                SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, last_sync_at = NOW()
                WHERE id = ?
            ');
            
            $lastHandshake = $stats['last_handshake'] > 0 
                ? date('Y-m-d H:i:s', $stats['last_handshake']) 
                : null;
            
            return $stmt->execute([
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $lastHandshake,
                $this->clientId
            ]);
        } catch (Exception $e) {
            error_log('Failed to sync client stats: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get client statistics from server
     */
    private static function getClientStatsFromServer(array $serverData, string $publicKey): array {
        $containerName = $serverData['container_name'];
        
        // Get WireGuard interface stats
        $cmd = sprintf("docker exec -i %s wg show wg0 dump", $containerName);
        $output = self::executeServerCommand($serverData, $cmd, true);
        
        $stats = [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'last_handshake' => 0
        ];
        
        // Parse wg dump output
        // Format: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
        // First line is server (private key), skip it
        // For clients: transfer_rx = bytes received by server (sent by client)
        //              transfer_tx = bytes sent by server (received by client)
        $lines = explode("\n", trim($output));
        foreach ($lines as $line) {
            if (empty($line)) continue;
            
            $parts = preg_split('/\s+/', trim($line));
            
            // Skip first line (server) - it has different format
            if (count($parts) < 7) continue;
            
            // Match by public key
            if ($parts[0] === $publicKey) {
                $stats['last_handshake'] = (int)$parts[4];
                $stats['bytes_sent'] = (int)$parts[5];      // transfer_rx - client sent
                $stats['bytes_received'] = (int)$parts[6];  // transfer_tx - client received
                break;
            }
        }
        
        return $stats;
    }
    
    /**
     * Sync stats for all active clients on a server
     */
    public static function syncAllStatsForServer(int $serverId): int {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND status = ?');
        $stmt->execute([$serverId, 'active']);
        $clientIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $synced = 0;
        foreach ($clientIds as $clientId) {
            try {
                $client = new VpnClient($clientId);
                if ($client->syncStats()) {
                    $synced++;
                }
            } catch (Exception $e) {
                error_log('Failed to sync stats for client ' . $clientId . ': ' . $e->getMessage());
            }
        }
        
        return $synced;
    }
    
    /**
     * Get human-readable traffic statistics
     */
    public function getFormattedStats(): array {
        if (!$this->data) {
            return ['sent' => 'N/A', 'received' => 'N/A', 'total' => 'N/A', 'last_seen' => 'Never'];
        }
        
        $sent = $this->formatBytes($this->data['bytes_sent'] ?? 0);
        $received = $this->formatBytes($this->data['bytes_received'] ?? 0);
        $total = $this->formatBytes(($this->data['bytes_sent'] ?? 0) + ($this->data['bytes_received'] ?? 0));
        
        $lastSeen = 'Never';
        if (!empty($this->data['last_handshake'])) {
            $lastHandshake = strtotime($this->data['last_handshake']);
            $diff = time() - $lastHandshake;
            
            if ($diff < 300) {
                $lastSeen = 'Online';
            } elseif ($diff < 3600) {
                $lastSeen = floor($diff / 60) . ' minutes ago';
            } elseif ($diff < 86400) {
                $lastSeen = floor($diff / 3600) . ' hours ago';
            } else {
                $lastSeen = floor($diff / 86400) . ' days ago';
            }
        }
        
        return [
            'sent' => $sent,
            'received' => $received,
            'total' => $total,
            'last_seen' => $lastSeen,
            'is_online' => !empty($this->data['last_handshake']) && (time() - strtotime($this->data['last_handshake'])) < 300
        ];
    }
    
    /**
     * Format bytes to human-readable string
     */
    private function formatBytes(int $bytes): string {
        if ($bytes === 0) return '0 B';
        
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = floor(log($bytes) / log(1024));
        
        return round($bytes / pow(1024, $i), 2) . ' ' . $units[$i];
    }
    
    /**
     * Set client expiration date
     * 
     * @param int $clientId Client ID
     * @param string|null $expiresAt Expiration date (Y-m-d H:i:s) or null for never expires
     * @return bool Success
     */
    public static function setExpiration(int $clientId, ?string $expiresAt): bool {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET expires_at = ? WHERE id = ?');
        return $stmt->execute([$expiresAt, $clientId]);
    }
    
    /**
     * Extend client expiration by days
     * 
     * @param int $clientId Client ID
     * @param int $days Days to extend
     * @return bool Success
     */
    public static function extendExpiration(int $clientId, int $days): bool {
        $pdo = DB::conn();
        
        // Get current expiration
        $stmt = $pdo->prepare('SELECT expires_at FROM vpn_clients WHERE id = ?');
        $stmt->execute([$clientId]);
        $client = $stmt->fetch();
        
        if (!$client) {
            return false;
        }
        
        // Calculate new expiration from current or now
        $baseDate = $client['expires_at'] ? strtotime($client['expires_at']) : time();
        $newExpiration = date('Y-m-d H:i:s', strtotime("+{$days} days", $baseDate));
        
        return self::setExpiration($clientId, $newExpiration);
    }
    
    /**
     * Get clients expiring soon
     * 
     * @param int $days Check for clients expiring within N days
     * @return array List of expiring clients
     */
    public static function getExpiringClients(int $days = 7): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host, u.name as user_name, u.email
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            JOIN users u ON c.user_id = u.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= DATE_ADD(NOW(), INTERVAL ? DAY)
            AND c.expires_at > NOW()
            AND c.status = "active"
            ORDER BY c.expires_at ASC
        ');
        $stmt->execute([$days]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get expired clients
     * 
     * @return array List of expired clients
     */
    public static function getExpiredClients(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT c.*, s.name as server_name, s.host
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= NOW()
            AND c.status = "active"
            ORDER BY c.expires_at DESC
        ');
        return $stmt->fetchAll();
    }
    
    /**
     * Disable expired clients automatically
     * 
     * @return int Number of clients disabled
     */
    public static function disableExpiredClients(): int {
        $expiredClients = self::getExpiredClients();
        $count = 0;
        
        foreach ($expiredClients as $clientData) {
            try {
                $client = new self($clientData['id']);
                $client->revoke();
                $count++;
            } catch (Exception $e) {
                error_log("Failed to disable expired client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $count;
    }
    
    /**
     * Check if client is expired
     * 
     * @return bool True if expired
     */
    public function isExpired(): bool {
        if (!$this->data) {
            return false;
        }
        
        return $this->data['expires_at'] !== null && strtotime($this->data['expires_at']) <= time();
    }
    
    /**
     * Get days until expiration
     * 
     * @return int|null Days until expiration (negative if expired, null if never expires)
     */
    public function getDaysUntilExpiration(): ?int {
        if (!$this->data || $this->data['expires_at'] === null) {
            return null;
        }
        
        $diff = strtotime($this->data['expires_at']) - time();
        return (int)floor($diff / 86400);
    }
    
    /**
     * Set traffic limit for client
     * 
     * @param int|null $limitBytes Traffic limit in bytes (NULL = unlimited)
     * @return bool Success
     */
    public function setTrafficLimit(?int $limitBytes): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET traffic_limit = ? WHERE id = ?');
        $result = $stmt->execute([$limitBytes, $this->clientId]);
        
        if ($result) {
            $this->data['traffic_limit'] = $limitBytes;
        }
        
        return $result;
    }
    
    /**
     * Get total traffic used (sent + received)
     * 
     * @return int Total traffic in bytes
     */
    public function getTotalTraffic(): int {
        if (!$this->data) {
            return 0;
        }
        
        return (int)($this->data['traffic_sent'] ?? 0) + (int)($this->data['traffic_received'] ?? 0);
    }
    
    /**
     * Check if client has exceeded traffic limit
     * 
     * @return bool True if over limit
     */
    public function isOverLimit(): bool {
        if (!$this->data || $this->data['traffic_limit'] === null) {
            return false; // No limit set
        }
        
        $totalTraffic = $this->getTotalTraffic();
        return $totalTraffic >= (int)$this->data['traffic_limit'];
    }
    
    /**
     * Get traffic limit status
     * 
     * @return array Status info
     */
    public function getTrafficLimitStatus(): array {
        $totalTraffic = $this->getTotalTraffic();
        $limit = $this->data['traffic_limit'] ?? null;
        
        return [
            'total_traffic' => $totalTraffic,
            'traffic_limit' => $limit,
            'is_unlimited' => $limit === null,
            'is_over_limit' => $this->isOverLimit(),
            'percentage_used' => $limit ? min(100, round(($totalTraffic / $limit) * 100, 2)) : 0,
            'remaining' => $limit ? max(0, $limit - $totalTraffic) : null
        ];
    }
    
    /**
     * Get all clients that exceeded their traffic limit
     * 
     * @return array List of client IDs over limit
     */
    public static function getClientsOverLimit(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT id, name, traffic_sent, traffic_received, traffic_limit 
            FROM vpn_clients 
            WHERE traffic_limit IS NOT NULL 
            AND (traffic_sent + traffic_received) >= traffic_limit 
            AND status = "active"
            ORDER BY id
        ');
        
        return $stmt->fetchAll();
    }
    
    /**
     * Disable all clients that exceeded their traffic limit
     * 
     * @return int Number of clients disabled
     */
    public static function disableClientsOverLimit(): int {
        $clients = self::getClientsOverLimit();
        $disabled = 0;
        
        foreach ($clients as $clientData) {
            try {
                $client = new VpnClient($clientData['id']);
                if ($client->revoke()) {
                    $disabled++;
                    error_log("Client {$clientData['name']} (ID: {$clientData['id']}) disabled: traffic limit exceeded");
                }
            } catch (Exception $e) {
                error_log("Failed to disable client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $disabled;
    }
}


