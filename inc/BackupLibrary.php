<?php
/**
 * Backup library utilities for importing servers from backup files.
 */
class BackupLibrary {
    /**
     * Discover available backup files.
     *
     * @param bool $registerTokens Whether to register tokens in the session
     * @return array<int, array<string, mixed>>
     */
    public static function listAvailable(bool $registerTokens = false): array {
        if (!isset($_SESSION['backup_library']) || !is_array($_SESSION['backup_library'])) {
            $_SESSION['backup_library'] = [];
        }

        if (!isset($_SESSION['backup_uploads']) || !is_array($_SESSION['backup_uploads'])) {
            $_SESSION['backup_uploads'] = [];
        }

        $results = [];
        foreach (self::getDirectories() as $directory) {
            $files = glob($directory . DIRECTORY_SEPARATOR . '*.{backup,json}', GLOB_BRACE) ?: [];
            foreach ($files as $filePath) {
                if (!is_file($filePath) || !is_readable($filePath)) {
                    continue;
                }

                try {
                    $parsed = BackupParser::parseMetadata($filePath);
                } catch (Throwable $e) {
                    // Skip invalid backup file but log for debugging
                    error_log('Backup parse failed for ' . $filePath . ': ' . $e->getMessage());
                    continue;
                }

                if (empty($parsed['servers'])) {
                    continue;
                }

                $token = hash('sha256', $filePath);
                if ($registerTokens || !isset($_SESSION['backup_library'][$token])) {
                    $_SESSION['backup_library'][$token] = $filePath;
                }

                $results[] = [
                    'token' => $token,
                    'file_name' => basename($filePath),
                    'type' => $parsed['type'],
                    'origin' => 'filesystem',
                    'servers' => self::mapServerMetadata($parsed['servers'] ?? []),
                ];
            }
        }

        foreach ($_SESSION['backup_uploads'] as $token => $upload) {
            $results[] = [
                'token' => $token,
                'file_name' => $upload['file_name'],
                'type' => $upload['type'],
                'origin' => 'upload',
                'servers' => self::mapServerMetadata($upload['data']['servers'] ?? []),
            ];
        }

        usort($results, function ($a, $b) {
            return strcmp($a['file_name'], $b['file_name']);
        });

        return $results;
    }

    /**
     * Load full server data from backup using the session token and server index.
     *
     * @param string $token Backup token
     * @param int $serverIndex Index of the server inside backup file
     * @return array<string, mixed>
     * @throws Exception When token or server not found
     */
    public static function loadServer(string $token, int $serverIndex): array {
        $path = $_SESSION['backup_library'][$token] ?? null;
        if ($path) {
            if (!is_file($path) || !is_readable($path)) {
                throw new Exception('Selected backup is not available');
            }

            $parsed = BackupParser::parse($path);
            if (!isset($parsed['servers'][$serverIndex])) {
                throw new Exception('Requested server not found in backup');
            }

            $server = $parsed['servers'][$serverIndex];
            $server['source_file'] = $path;
            $server['type'] = $parsed['type'];

            return $server;
        }

        $upload = $_SESSION['backup_uploads'][$token] ?? null;
        if ($upload) {
            $parsed = $upload['data'];
            if (!isset($parsed['servers'][$serverIndex])) {
                throw new Exception('Requested server not found in uploaded backup');
            }

            $server = $parsed['servers'][$serverIndex];
            $server['source_file'] = $upload['path'];
            $server['type'] = $parsed['type'];

            return $server;
        }

        throw new Exception('Selected backup is not available');
    }

    /**
     * Get list of directories that may contain backup files.
     *
     * @return array<int, string>
     */
    private static function getDirectories(): array {
        $directories = [];

        $default = realpath(__DIR__ . '/../backups');
        if ($default) {
            $directories[] = $default;
        }

        $envDirs = Config::get('BACKUP_LIBRARY_DIRS');
        if (!empty($envDirs)) {
            foreach (preg_split('/[;,]+/', $envDirs) as $rawDir) {
                $normalized = trim($rawDir);
                if ($normalized === '') {
                    continue;
                }
                if (is_dir($normalized)) {
                    $real = realpath($normalized);
                    if ($real) {
                        $directories[] = $real;
                    }
                }
            }
        }

        $home = getenv('HOME');
        if ($home) {
            $candidate = realpath($home . DIRECTORY_SEPARATOR . 'Downloads' . DIRECTORY_SEPARATOR . 'infosave');
            if ($candidate) {
                $directories[] = $candidate;
            }
        }

        // Remove duplicates
        $directories = array_values(array_unique($directories));

        return $directories;
    }

    /**
     * Register uploaded backup file and return metadata for UI.
     */
    public static function registerUploaded(string $fileName, string $storedPath, array $parsed): array {
        if (!isset($_SESSION['backup_uploads']) || !is_array($_SESSION['backup_uploads'])) {
            $_SESSION['backup_uploads'] = [];
        }

        $token = 'upload_' . bin2hex(random_bytes(16));

        $_SESSION['backup_uploads'][$token] = [
            'file_name' => $fileName,
            'path' => $storedPath,
            'type' => $parsed['type'],
            'data' => $parsed,
        ];

        return [
            'token' => $token,
            'file_name' => $fileName,
            'type' => $parsed['type'],
            'origin' => 'upload',
            'servers' => self::mapServerMetadata($parsed['servers'] ?? []),
        ];
    }

    /**
     * Check whether provided token belongs to uploaded backup.
     */
    public static function isUploadToken(string $token): bool {
        return isset($_SESSION['backup_uploads'][$token]);
    }

    /**
     * Retrieve stored upload metadata for a token.
     */
    public static function getUploadRecord(string $token): ?array {
        if (!isset($_SESSION['backup_uploads'][$token])) {
            return null;
        }

        return $_SESSION['backup_uploads'][$token];
    }

    /**
     * Get lightweight server metadata for an uploaded backup token.
     */
    public static function getUploadServers(string $token): array {
        $upload = self::getUploadRecord($token);
        if (!$upload) {
            return [];
        }

        return self::mapServerMetadata($upload['data']['servers'] ?? []);
    }

    /**
     * Forget uploaded backup token and remove temporary file.
     */
    public static function forgetUpload(string $token): void {
        $upload = $_SESSION['backup_uploads'][$token] ?? null;
        if (!$upload) {
            return;
        }

        unset($_SESSION['backup_uploads'][$token]);

        $path = $upload['path'] ?? null;
        if ($path && is_file($path)) {
            @unlink($path);
        }
    }

    /**
     * Map server metadata for front-end lists.
     */
    public static function mapServerMetadata($servers): array {
        if (!is_array($servers)) {
            return [];
        }

        return array_map(function ($server, $index) {
            return [
                'index' => $index,
                'label' => $server['label'] ?? ('Server #' . ($index + 1)),
                'host' => $server['host'] ?? null,
                'vpn_port' => $server['vpn_port'] ?? null,
                'client_count' => isset($server['clients']) && is_array($server['clients'])
                    ? count($server['clients'])
                    : 0
            ];
        }, $servers, array_keys($servers));
    }
}

/**
 * Parse backup files and normalize into a single representation.
 */
class BackupParser {
    /**
     * Parse backup file metadata without storing heavy payloads.
     *
     * @param string $path
     * @return array<string, mixed>
     */
    public static function parseMetadata(string $path): array {
        $parsed = self::parse($path);

        // Strip client details to keep metadata light
        $parsed['servers'] = array_map(function ($server) {
            $server['clients'] = $server['clients'] ?? [];
            return $server;
        }, $parsed['servers']);

        return $parsed;
    }

    /**
     * Parse backup file fully.
     *
     * @param string $path
     * @return array<string, mixed>
     * @throws Exception On parse errors
     */
    public static function parse(string $path): array {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new Exception('Unable to read backup file');
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            throw new Exception('Backup file is not valid JSON');
        }

        if (isset($decoded['server']) && isset($decoded['clients'])) {
            return self::parsePanelBackup($decoded);
        }

        if (isset($decoded['Servers/serversList'])) {
            return self::parseAmneziaBackup($decoded);
        }

        throw new Exception('Unsupported backup format');
    }

    /**
     * Parse backup produced by the Amnezia mobile/desktop application (.backup files).
     */
    private static function parseAmneziaBackup(array $decoded): array {
        $serversRaw = json_decode($decoded['Servers/serversList'] ?? '[]', true);
        if (!is_array($serversRaw)) {
            throw new Exception('Invalid Amnezia backup payload');
        }

        $servers = [];
        foreach ($serversRaw as $serverIndex => $serverEntry) {
            $containers = $serverEntry['containers'] ?? [];
            foreach ($containers as $container) {
                if (($container['container'] ?? '') !== 'amnezia-awg') {
                    continue;
                }

                $awg = $container['awg'] ?? [];
                if (empty($awg)) {
                    continue;
                }

                $host = $serverEntry['hostName'] ?? ($awg['hostName'] ?? null);
                if (!$host) {
                    continue;
                }

                $awgParams = [];
                foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $key) {
                    if (isset($awg[$key])) {
                        $awgParams[$key] = is_numeric($awg[$key]) ? (int)$awg[$key] : $awg[$key];
                    }
                }

                $vpnPort = isset($awg['port']) ? (int)$awg['port'] : null;
                $sshPort = isset($serverEntry['port']) ? (int)$serverEntry['port'] : 22;
                $sshUser = $serverEntry['userName'] ?? 'root';
                $sshPass = $serverEntry['password'] ?? '';
                if ($sshPass === '') {
                    // Skip records without SSH credentials; these are likely client snapshots.
                    continue;
                }
                $name = trim($serverEntry['description'] ?? '') ?: $host;

                $subnet = $container['awg']['subnet_address'] ?? null;
                $clients = [];

                if (!empty($awg['last_config'])) {
                    $lastConfig = json_decode($awg['last_config'], true);
                    if (is_array($lastConfig)) {
                        $clientIp = $lastConfig['client_ip'] ?? null;
                        if (!$subnet && $clientIp) {
                            $subnet = self::inferSubnet($clientIp);
                        }

                        $clients[] = [
                            'name' => $lastConfig['client_ip'] ?? ($lastConfig['clientId'] ?? $host . '_client'),
                            'client_ip' => $clientIp,
                            'public_key' => $lastConfig['client_pub_key'] ?? '',
                            'private_key' => $lastConfig['client_priv_key'] ?? '',
                            'preshared_key' => $lastConfig['psk_key'] ?? ($awg['psk_key'] ?? ''),
                            'config' => $lastConfig['config'] ?? '',
                            'status' => 'active',
                            'expires_at' => null,
                        ];
                    }
                }

                if (!$subnet) {
                    $subnet = '10.8.1.0/24';
                } elseif (!str_contains($subnet, '/')) {
                    $subnet .= '/24';
                }

                $servers[] = [
                    'label' => $name . ' (' . $host . ')',
                    'name' => $name,
                    'host' => $host,
                    'ssh_port' => $sshPort,
                    'ssh_username' => $sshUser ?: 'root',
                    'ssh_password' => $sshPass,
                    'vpn_port' => $vpnPort,
                    'container_name' => $container['container'] ?? 'amnezia-awg',
                    'vpn_subnet' => $subnet,
                    'server_public_key' => $awg['server_pub_key'] ?? null,
                    'preshared_key' => $awg['psk_key'] ?? null,
                    'awg_params' => $awgParams,
                    'clients' => $clients,
                ];
            }
        }

        return [
            'type' => 'amnezia_app',
            'servers' => $servers,
        ];
    }

    /**
     * Parse backup generated by this panel (backups/backup_*.json).
     */
    private static function parsePanelBackup(array $decoded): array {
        $server = $decoded['server'];
        $awgParams = $server['awg_params'] ?? [];
        if (is_string($awgParams)) {
            $decodedParams = json_decode($awgParams, true);
            if (is_array($decodedParams)) {
                $awgParams = $decodedParams;
            }
        }

        $vpnPort = isset($server['vpn_port']) ? (int)$server['vpn_port'] : null;
        $sshPort = isset($server['port']) ? (int)$server['port'] : 22;
        $sshUser = $server['username'] ?? 'root';
        $sshPass = $server['password'] ?? '';
        $host = $server['host']
            ?? $server['host_name']
            ?? $server['host_ip']
            ?? null;

        if (!$host) {
            throw new Exception('Panel backup is missing server host/SSH details. Create the server manually and import its clients via the panel importer.');
        }

        $clients = [];
        foreach ($decoded['clients'] as $client) {
            $clients[] = [
                'name' => $client['name'] ?? ($client['client_ip'] ?? 'client'),
                'client_ip' => $client['client_ip'] ?? null,
                'public_key' => $client['public_key'] ?? '',
                'private_key' => $client['private_key'] ?? '',
                'preshared_key' => $client['preshared_key'] ?? ($server['preshared_key'] ?? ''),
                'config' => $client['config'] ?? '',
                'status' => $client['status'] ?? 'active',
                'expires_at' => $client['expires_at'] ?? null,
                'created_at' => $client['created_at'] ?? null,
            ];
        }

        return [
            'type' => 'panel_backup',
            'servers' => [
                [
                    'label' => ($server['name'] ?? 'Server') . ' (' . $host . ')',
                    'name' => $server['name'] ?? 'Server',
                    'host' => $host,
                    'ssh_port' => $sshPort,
                    'ssh_username' => $sshUser,
                    'ssh_password' => $sshPass,
                    'vpn_port' => $vpnPort,
                    'container_name' => $server['container_name'] ?? 'amnezia-awg',
                    'vpn_subnet' => $server['vpn_subnet'] ?? '10.8.1.0/24',
                    'server_public_key' => $server['server_public_key'] ?? null,
                    'preshared_key' => $server['preshared_key'] ?? null,
                    'awg_params' => $awgParams,
                    'clients' => $clients,
                ]
            ],
        ];
    }

    /**
     * Infer /24 subnet from client IP.
     */
    private static function inferSubnet(string $ip): string {
        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }
        return '10.8.1.0/24';
    }
}
