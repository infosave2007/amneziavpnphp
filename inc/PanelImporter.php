<?php

/**
 * PanelImporter - Import clients from other VPN panels
 * 
 * Supports:
 * - wg-easy: Import from db.json backup
 * - 3x-ui: Import from panel export
 */
class PanelImporter
{
    private int $serverId;
    private int $userId;
    private string $panelType;
    private array $importData;
    
    public function __construct(int $serverId, int $userId, string $panelType)
    {
        $this->serverId = $serverId;
        $this->userId = $userId;
        $this->panelType = $panelType;
    }
    
    /**
     * Parse and validate backup file
     */
    public function parseBackupFile(string $jsonContent): bool
    {
        $data = json_decode($jsonContent, true);
        
        if (!$data) {
            throw new Exception('Invalid JSON format');
        }
        
        $this->importData = $data;
        
        // Validate based on panel type
        switch ($this->panelType) {
            case 'wg-easy':
                return $this->validateWgEasy($data);
            case '3x-ui':
                return $this->validate3xUi($data);
            default:
                throw new Exception('Unsupported panel type');
        }
    }
    
    /**
     * Validate wg-easy backup format
     */
    private function validateWgEasy(array $data): bool
    {
        if (!isset($data['clients']) || !is_array($data['clients'])) {
            throw new Exception('Invalid wg-easy format: missing clients array');
        }
        
        return true;
    }
    
    /**
     * Validate 3x-ui export format
     */
    private function validate3xUi(array $data): bool
    {
        if (!isset($data['clients']) || !is_array($data['clients'])) {
            throw new Exception('Invalid 3x-ui format: missing clients array');
        }
        
        return true;
    }
    
    /**
     * Import clients from parsed data
     */
    public function import(): array
    {
        $importId = $this->createImportRecord();
        
        try {
            $this->updateImportStatus($importId, 'processing');
            
            $clients = $this->extractClients();
            $imported = [];
            $errors = [];
            
            foreach ($clients as $clientData) {
                try {
                    $clientId = $this->createClient($clientData);
                    $imported[] = [
                        'id' => $clientId,
                        'name' => $clientData['name']
                    ];
                } catch (Exception $e) {
                    $errors[] = [
                        'name' => $clientData['name'],
                        'error' => $e->getMessage()
                    ];
                }
            }
            
            $this->updateImportRecord($importId, count($imported));
            $this->updateImportStatus($importId, 'completed');
            
            return [
                'success' => true,
                'import_id' => $importId,
                'imported' => $imported,
                'errors' => $errors,
                'total' => count($clients),
                'imported_count' => count($imported),
                'error_count' => count($errors)
            ];
            
        } catch (Exception $e) {
            $this->updateImportStatus($importId, 'failed', $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Extract client data based on panel type
     */
    private function extractClients(): array
    {
        switch ($this->panelType) {
            case 'wg-easy':
                return $this->extractWgEasyClients();
            case '3x-ui':
                return $this->extract3xUiClients();
            default:
                return [];
        }
    }
    
    /**
     * Extract clients from wg-easy backup
     */
    private function extractWgEasyClients(): array
    {
        $clients = [];
        
        foreach ($this->importData['clients'] as $client) {
            $clients[] = [
                'name' => $client['name'] ?? 'imported_client_' . uniqid(),
                'public_key' => $client['publicKey'] ?? null,
                'private_key' => $client['privateKey'] ?? null,
                'preshared_key' => $client['preSharedKey'] ?? null,
                'address' => $client['address'] ?? null,
                'enabled' => $client['enabled'] ?? true,
                'created_at' => $client['createdAt'] ?? null
            ];
        }
        
        return $clients;
    }
    
    /**
     * Extract clients from 3x-ui export
     */
    private function extract3xUiClients(): array
    {
        $clients = [];
        
        foreach ($this->importData['clients'] as $client) {
            // 3x-ui uses email as client name
            $name = $client['email'] ?? 'imported_client_' . uniqid();
            
            $clients[] = [
                'name' => $name,
                'public_key' => null, // Will be generated
                'private_key' => null, // Will be generated
                'preshared_key' => null,
                'address' => null, // Will be assigned from pool
                'enabled' => $client['enable'] ?? true,
                'expiry_time' => $client['expiryTime'] ?? 0,
                'total_gb' => $client['totalGB'] ?? 0
            ];
        }
        
        return $clients;
    }
    
    /**
     * Create client from imported data
     */
    private function createClient(array $clientData): int
    {
        // If we have keys and address from wg-easy, use them
        if (!empty($clientData['public_key']) && !empty($clientData['address'])) {
            return $this->createClientWithKeys($clientData);
        }
        
        // Otherwise, create new client with generated keys
        return $this->createNewClient($clientData);
    }
    
    /**
     * Create client with existing keys (wg-easy import)
     */
    private function createClientWithKeys(array $clientData): int
    {
        $db = DB::conn();
        
        $stmt = $db->prepare("
            INSERT INTO vpn_clients (
                server_id, user_id, name, client_ip,
                public_key, private_key, preshared_key,
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $status = ($clientData['enabled'] ?? true) ? 'active' : 'disabled';
        $privateKey = $clientData['private_key'] ?? '';
        $presharedKey = $clientData['preshared_key'] ?? '';
        
        $stmt->execute([
            $this->serverId,
            $this->userId,
            $clientData['name'],
            $clientData['address'],
            $clientData['public_key'],
            $privateKey,
            $presharedKey,
            $status
        ]);
        
        $clientId = (int)$db->lastInsertId();
        
        // Generate config and QR code
        $client = new VpnClient($clientId);
        $client->generateConfig();
        
        return $clientId;
    }
    
    /**
     * Create new client with generated keys (3x-ui import)
     */
    private function createNewClient(array $clientData): int
    {
        // Calculate expiration if provided
        $expiresInDays = null;
        if (!empty($clientData['expiry_time']) && $clientData['expiry_time'] > 0) {
            $expiryTimestamp = $clientData['expiry_time'] / 1000; // Convert from ms
            $daysUntilExpiry = ceil(($expiryTimestamp - time()) / 86400);
            if ($daysUntilExpiry > 0) {
                $expiresInDays = (int)$daysUntilExpiry;
            }
        }
        
        // Create client using standard method
        $clientId = VpnClient::create(
            $this->serverId,
            $this->userId,
            $clientData['name'],
            $expiresInDays
        );
        
        // Set traffic limit if provided
        if (!empty($clientData['total_gb']) && $clientData['total_gb'] > 0) {
            $client = new VpnClient($clientId);
            $limitBytes = $clientData['total_gb'] * 1073741824; // GB to bytes
            $client->setTrafficLimit($limitBytes);
        }
        
        // Set status
        if (isset($clientData['enabled']) && !$clientData['enabled']) {
            $db = DB::conn();
            $stmt = $db->prepare("UPDATE vpn_clients SET status = 'disabled' WHERE id = ?");
            $stmt->execute([$clientId]);
        }
        
        return $clientId;
    }
    
    /**
     * Create import record in database
     */
    private function createImportRecord(): int
    {
        $db = DB::conn();
        
        $stmt = $db->prepare("
            INSERT INTO panel_imports (
                server_id, panel_type, import_file_name,
                import_data, status, created_by
            ) VALUES (?, ?, ?, ?, 'pending', ?)
        ");
        
        $stmt->execute([
            $this->serverId,
            $this->panelType,
            'backup_' . date('Y-m-d_H-i-s') . '.json',
            json_encode($this->importData),
            $this->userId
        ]);
        
        return (int)$db->lastInsertId();
    }
    
    /**
     * Update import record with results
     */
    private function updateImportRecord(int $importId, int $clientsImported): void
    {
        $db = DB::conn();
        
        $stmt = $db->prepare("
            UPDATE panel_imports 
            SET clients_imported = ?
            WHERE id = ?
        ");
        
        $stmt->execute([$clientsImported, $importId]);
    }
    
    /**
     * Update import status
     */
    private function updateImportStatus(int $importId, string $status, ?string $error = null): void
    {
        $db = DB::conn();
        
        $stmt = $db->prepare("
            UPDATE panel_imports 
            SET status = ?, error_message = ?
            WHERE id = ?
        ");
        
        $stmt->execute([$status, $error, $importId]);
    }
    
    /**
     * Get import history for server
     */
    public static function getImportHistory(int $serverId): array
    {
        $db = DB::conn();
        
        $stmt = $db->prepare("
            SELECT 
                pi.*,
                u.name as created_by_name
            FROM panel_imports pi
            LEFT JOIN users u ON pi.created_by = u.id
            WHERE pi.server_id = ?
            ORDER BY pi.created_at DESC
        ");
        
        $stmt->execute([$serverId]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
