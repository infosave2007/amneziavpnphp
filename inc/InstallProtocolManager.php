<?php
require_once __DIR__ . '/Logger.php';

class InstallProtocolManager
{
    private const DEFAULT_SLUG = 'amnezia-wg';
    private const SESSION_KEY = 'pending_deploy_decisions';

    private static function resolveAivpnContainerName(VpnServer $server, array $options = []): string
    {
        $serverData = $server->getData();
        $candidates = array_values(array_unique(array_filter([
            trim((string) ($options['container_name'] ?? '')),
            trim((string) ($serverData['container_name'] ?? '')),
            'aivpn-server',
        ], static function ($value) {
            return is_string($value) && $value !== '';
        })));

        $namesRaw = (string) $server->executeCommand("docker ps -a --format '{{.Names}}' 2>/dev/null", true);
        $names = array_values(array_filter(array_map('trim', preg_split('/\r?\n/', $namesRaw) ?: []), static function ($value) {
            return $value !== '';
        }));

        foreach ($candidates as $candidate) {
            if (in_array($candidate, $names, true)) {
                return $candidate;
            }
        }

        foreach ($candidates as $candidate) {
            foreach ($names as $name) {
                if (stripos($name, $candidate) !== false) {
                    self::persistServerContainerName($server->getId(), $name);
                    return $name;
                }
            }
        }

        foreach ($names as $name) {
            if (stripos($name, 'aivpn-server') !== false || stripos($name, 'aivpn') !== false) {
                self::persistServerContainerName($server->getId(), $name);
                return $name;
            }
        }

        return $candidates[0] ?? 'aivpn-server';
    }

    private static function persistServerContainerName(int $serverId, string $containerName): void
    {
        $containerName = trim($containerName);
        if ($serverId <= 0 || $containerName === '') {
            return;
        }

        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('UPDATE vpn_servers SET container_name = ? WHERE id = ?');
            $stmt->execute([$containerName, $serverId]);
        } catch (Throwable $e) {
        }
    }

    public static function getDefaultSlug(): string
    {
        return self::DEFAULT_SLUG;
    }

    public static function ensureDefaults(): void
    {
        return;
    }

    public static function listActive(): array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->query('SELECT * FROM protocols WHERE is_active = 1 ORDER BY name');
            $rows = $stmt->fetchAll();
            return array_map([self::class, 'hydrateProtocol'], $rows);
        } catch (Throwable $e) {
            return [];
        }
    }

    public static function getAll(): array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->query('SELECT * FROM protocols ORDER BY name');
            $rows = $stmt->fetchAll();
            return array_map([self::class, 'hydrateProtocol'], $rows);
        } catch (Throwable $e) {
            return [];
        }
    }

    public static function getBySlug(string $slug): ?array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE slug = ? LIMIT 1');
            $stmt->execute([$slug]);
            $row = $stmt->fetch();
            if ($row) {
                return self::hydrateProtocol($row);
            }
        } catch (Throwable $e) {
        }
        return null;
    }

    public static function getById(int $id): ?array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            return $row ? self::hydrateProtocol($row) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    public static function save(array $data): int
    {
        $pdo = DB::conn();
        $definition = $data['definition'] ?? [];
        if (is_string($definition)) {
            $definition = json_decode($definition, true) ?: [];
        }

        $definitionJson = json_encode($definition, JSON_UNESCAPED_SLASHES);
        $isActive = isset($data['is_active']) ? (int) $data['is_active'] : 1;

        if (!empty($data['id'])) {
            $stmt = $pdo->prepare('
                UPDATE install_protocols
                SET slug = ?, name = ?, description = ?, definition = ?, is_active = ?, updated_at = NOW()
                WHERE id = ?
            ');
            $stmt->execute([
                $data['slug'],
                $data['name'],
                $data['description'] ?? null,
                $definitionJson,
                $isActive,
                $data['id']
            ]);
            return (int) $data['id'];
        }

        $stmt = $pdo->prepare('
            INSERT INTO install_protocols (slug, name, description, definition, is_active)
            VALUES (?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $data['slug'],
            $data['name'],
            $data['description'] ?? null,
            $definitionJson,
            $isActive
        ]);

        return (int) $pdo->lastInsertId();
    }

    public static function delete(int $id): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM install_protocols WHERE id = ?');
        $stmt->execute([$id]);
    }

    public static function deploy(VpnServer $server, array $options = []): array
    {
        $serverData = $server->getData();
        $protocolSlug = $serverData['install_protocol'] ?? null;
        if (!$protocolSlug || trim((string) $protocolSlug) === '') {
            throw new Exception('Install protocol not selected');
        }
        $protocol = self::getBySlug($protocolSlug);

        Logger::appendInstall($server->getId(), 'Deploy start for protocol ' . $protocolSlug);

        try {
            if (!$protocol) {
                throw new Exception('Install protocol not found: ' . $protocolSlug);
            }

            $installMode = $options['install_mode'] ?? null;
            $decisionToken = $options['decision_token'] ?? null;
            $serverId = $server->getId();
            $detectionPayload = null;

            if (empty($options['skip_connection_test'])) {
                if (!$server->testConnection()) {
                    Logger::appendInstall($serverId, 'SSH connection test failed');
                    throw new Exception('SSH connection failed');
                }
                Logger::appendInstall($serverId, 'SSH connection test OK');
            }

            if ($installMode !== null && $decisionToken) {
                $entry = self::consumeDecision($serverId, $decisionToken);
                if ($entry && ($entry['protocol'] ?? '') === $protocol['slug']) {
                    $detectionPayload = $entry['detection'] ?? null;
                    Logger::appendInstall($serverId, 'Consumed decision token for restore/reinstall');
                }
            }

            if ($installMode === null) {
                Logger::appendInstall($serverId, 'Running detection...');
                $detection = self::detect($server, $protocol, $options);
                Logger::appendInstall($serverId, 'Detection result: ' . json_encode($detection));

                if (in_array($detection['status'] ?? 'absent', ['existing', 'partial'], true)) {
                    $token = self::storeDecision($serverId, [
                        'protocol' => $protocol['slug'],
                        'detection' => $detection,
                        'stored_at' => time(),
                    ]);

                    Logger::appendInstall($serverId, 'Existing/partial config found, awaiting decision. token=' . $token);

                    return [
                        'success' => false,
                        'requires_action' => true,
                        'action' => 'existing_configuration',
                        'details' => $detection,
                        'decision_token' => $token,
                        'options' => [
                            'restore' => [
                                'mode' => 'restore',
                                'label' => 'Восстановить существующую конфигурацию'
                            ],
                            'reinstall' => [
                                'mode' => 'reinstall',
                                'label' => 'Переустановить заново'
                            ]
                        ]
                    ];
                }

                $installMode = 'install';
                Logger::appendInstall($serverId, 'Proceeding with clean install');
            }

            if ($installMode === 'restore') {
                Logger::appendInstall($serverId, 'Restoring existing configuration...');
                if ($detectionPayload === null) {
                    $detectionPayload = self::detect($server, $protocol, array_merge($options, ['force' => true]));
                    Logger::appendInstall($serverId, 'Forced detection for restore: ' . json_encode($detectionPayload));
                }

                if (!in_array($detectionPayload['status'] ?? '', ['existing', 'partial'], true)) {
                    throw new Exception('Существующая конфигурация на сервере не найдена');
                }

                $res = self::restore($server, $protocol, $detectionPayload, $options);
                Logger::appendInstall($serverId, 'Restore finished: ' . json_encode($res));
                return $res;
            }

            if ($installMode === 'reinstall') {
                $serverData = $server->getData();
                Logger::appendInstall($serverId, 'Reinstall mode selected');
                if (($serverData['status'] ?? '') === 'active' && empty($options['skip_backup'])) {
                    try {
                        $server->createBackup((int) $serverData['user_id'], 'automatic');
                        Logger::appendInstall($serverId, 'Automatic backup created before reinstall');
                    } catch (Throwable $e) {
                        Logger::appendInstall($serverId, 'Backup before reinstall failed: ' . $e->getMessage());
                        // backup errors do not abort reinstall
                    }
                }
            }

            return self::install($server, $protocol, $options);
        } catch (Throwable $e) {
            // Mark server error and log
            self::markServerError($server->getId(), $e->getMessage());
            Logger::appendInstall($server->getId(), 'Deploy failed: ' . $e->getMessage());
            throw $e;
        }
    }

    private static function detect(VpnServer $server, array $protocol, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            case 'awg':
                return self::detectBuiltinAwg($server, $protocol);
            case 'xray':
                return self::detectBuiltinXray($server, $protocol);
            case 'warp':
                return self::detectBuiltinWarp($server, $protocol);
            default:
                return self::runScript($server, $protocol, 'detect', $options);
        }
    }

    public static function install(VpnServer $server, array $protocol, array $options = []): array
    {
        $engine = self::getEngine($protocol);
        $serverId = $server->getId();
        if ($engine === 'builtin_awg') {
            try {
                Logger::appendInstall($serverId, 'Installing builtin AWG...');
                $result = $server->runAwgInstall($options);
                Logger::appendInstall($serverId, 'Builtin AWG install finished: ' . json_encode($result));
                self::markServerActive($serverId, null, [
                    'vpn_port' => $result['vpn_port'] ?? null,
                    'server_public_key' => $result['public_key'] ?? ($result['server_public_key'] ?? null),
                    'preshared_key' => $result['preshared_key'] ?? null,
                    'awg_params' => $result['awg_params'] ?? null,
                ]);
                return $result;
            } catch (Throwable $e) {
                Logger::appendInstall($serverId, 'AWG install failed: ' . $e->getMessage());
                self::markServerError($serverId, $e->getMessage());
                throw $e;
            }
        }

        try {
            Logger::appendInstall($serverId, 'Running scripted install...');
            $metadata = $protocol['definition']['metadata'] ?? [];
            // Choose/ensure VPN UDP port for script-driven installs
            if (($protocol['slug'] ?? '') === 'xray-vless' && (!isset($options['server_port']) || !is_int($options['server_port']) || $options['server_port'] <= 0)) {
                $options['server_port'] = 443;
            }
            if (!isset($options['server_port']) || !is_int($options['server_port'])) {
                $options['server_port'] = self::chooseServerPort($server, $metadata);
            }
            $result = self::runScript($server, $protocol, 'install', $options);
            if (!isset($result['success'])) {
                $result['success'] = true;
            }
            Logger::appendInstall($serverId, 'Scripted install finished: ' . json_encode($result));

            $rawPort = $result['vpn_port'] ?? null;
            $resolvedPort = (is_numeric($rawPort) && (int) $rawPort > 0)
                ? (int) $rawPort
                : ($options['server_port'] ?? null);

            $awgParams = $result['awg_params'] ?? null;
            if (!is_array($awgParams)) {
                $flat = [];
                foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                    if (array_key_exists($k, $result) && $result[$k] !== '' && $result[$k] !== null) {
                        $flat[$k] = $result[$k];
                    }
                }
                if (!empty($flat)) {
                    $awgParams = $flat;
                }
            }

            $extras = [
                'vpn_port' => $resolvedPort,
                'server_public_key' => $result['server_public_key'] ?? null,
                'preshared_key' => $result['preshared_key'] ?? null,
                'awg_params' => $awgParams,
                'secret' => $result['secret'] ?? null,
                'server_host' => $result['server_host'] ?? null,
                'container_name' => $result['container_name'] ?? ($metadata['container_name'] ?? null),
            ];
            if (($protocol['slug'] ?? '') === 'aivpn' && array_key_exists('connection_key', $result)) {
                $extras['connection_key'] = $result['connection_key'];
            }
            if (($protocol['slug'] ?? '') === 'xray-vless') {
                foreach (['client_id', 'container_name', 'server_port', 'xray_port', 'reality_public_key', 'reality_private_key', 'reality_short_id', 'reality_server_name'] as $k) {
                    if (array_key_exists($k, $result)) {
                        $extras[$k] = $result[$k];
                    }
                }
                $extras['result'] = $result;
            }
            self::markServerActive($serverId, null, $extras);
            return $result;
        } catch (Throwable $e) {
            Logger::appendInstall($serverId, 'Scripted install failed: ' . $e->getMessage());
            self::markServerError($serverId, $e->getMessage());
            throw $e;
        }
    }

    private static function restore(VpnServer $server, array $protocol, array $detection, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            case 'awg':
                return self::restoreBuiltinAwg($server, $protocol, $detection, $options);
            case 'xray':
                return self::restoreBuiltinXray($server, $protocol, $detection, $options);
            default:
                $result = self::runScript($server, $protocol, 'restore', array_merge($options, [
                    'detection' => $detection
                ]));
                if (!isset($result['success'])) {
                    $result['success'] = true;
                }
                return $result;
        }
    }

    private static function detectBuiltinAwg(VpnServer $server, array $protocol): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $serverData = $server->getData();
        // For multi-protocol servers, use container_name from protocol metadata first
        // (vpn_servers.container_name stores the primary protocol's container, e.g. 'aivpn-server')
        $containerName = $metadata['container_name'] ?? ($serverData['container_name'] ?? 'amnezia-awg');
        $containerFilter = escapeshellarg('^' . $containerName . '$');
        $containerArg = escapeshellarg($containerName);

        // AWG2 uses awg0.conf (standard, same as native Amnezia app)
        // Old AWG uses wg0.conf
        $isAwg2 = (stripos($containerName, 'awg2') !== false || ($protocol['slug'] ?? '') === 'awg2');
        $configDir = '/opt/amnezia/awg';
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';

        $containerListRaw = trim($server->executeCommand("docker ps -a --filter name={$containerFilter} --format '{{.Names}}'", true));
        if ($containerListRaw === '') {
            return [
                'status' => 'absent',
                'message' => 'Контейнер AmneziaWG не найден на сервере'
            ];
        }

        if (preg_match('/docker: command not found|command not found|cannot connect to the docker daemon|permission denied/i', $containerListRaw)) {
            return [
                'status' => 'absent',
                'message' => 'Docker CLI недоступен на сервере',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerListRaw,
                ]
            ];
        }

        $containerNames = array_values(array_filter(array_map('trim', preg_split('/\R+/', $containerListRaw))));
        if (!in_array($containerName, $containerNames, true)) {
            return [
                'status' => 'absent',
                'message' => 'Контейнер AmneziaWG не найден на сервере'
            ];
        }

        $containerState = trim($server->executeCommand("docker inspect --format '{{.State.Status}}' {$containerArg}", true));

        // AWG2: try awg0.conf first (standard), fall back to wg0.conf (legacy panel installs)
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true);
        if ($isAwg2 && (trim($wgConfig) === '' || strpos($wgConfig, '[Interface]') === false)) {
            // Fallback to wg0.conf for legacy panel installs
            $configFile = 'wg0.conf';
            $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true);
        }
        if (trim($wgConfig) === '' || strpos($wgConfig, '[Interface]') === false) {
            return [
                'status' => 'partial',
                'message' => "Контейнер найден, но конфигурация wg0.conf/awg0.conf отсутствует",
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerState,
                ]
            ];
        }

        $parsedConfig = self::parseWireGuardConfig($wgConfig);
        if (empty($parsedConfig['listen_port']) || empty($parsedConfig['awg_params'])) {
            return [
                'status' => 'partial',
                'message' => 'Не удалось разобрать конфигурацию wg0.conf',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerState,
                ]
            ];
        }

        $publicKey = trim($server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/wireguard_server_public_key.key 2>/dev/null", true));
        $presharedKey = trim($server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/wireguard_psk.key 2>/dev/null", true));

        if ($publicKey === '' || $presharedKey === '') {
            return [
                'status' => 'partial',
                'message' => 'Не удалось прочитать ключи сервера',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerState,
                ]
            ];
        }

        $clientsRaw = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/clientsTable 2>/dev/null", true);
        $clients = json_decode(trim($clientsRaw), true);
        $clientsCount = is_array($clients) ? count($clients) : 0;

        return [
            'status' => 'existing',
            'message' => 'Найдена установленная конфигурация AmneziaWG',
            'details' => [
                'container_name' => $containerName,
                'container_status' => $containerState,
                'vpn_port' => (int) $parsedConfig['listen_port'],
                'server_public_key' => $publicKey,
                'preshared_key' => $presharedKey,
                'awg_params' => $parsedConfig['awg_params'],
                'clients_count' => $clientsCount,
                'summary' => sprintf('Container %s (%s), port %s, clients %d', $containerName, $containerState ?: 'unknown', $parsedConfig['listen_port'], $clientsCount)
            ]
        ];
    }

    private static function restoreBuiltinAwg(VpnServer $server, array $protocol, array $detection, array $options): array
    {
        $details = $detection['details'] ?? [];
        $containerName = $details['container_name'] ?? ($protocol['definition']['metadata']['container_name'] ?? 'amnezia-awg');
        $containerArg = escapeshellarg($containerName);

        // Config is always wg0.conf — container CMD runs: awg-quick up /opt/amnezia/awg/wg0.conf
        $isAwg2 = (stripos($containerName, 'awg2') !== false || ($protocol['slug'] ?? '') === 'awg2');
        $configDir = '/opt/amnezia/awg';
        // AWG2: try awg0.conf first (standard), fall back to wg0.conf (legacy)
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $testConf = trim($server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true));
        if ($isAwg2 && ($testConf === '' || strpos($testConf, '[Interface]') === false)) {
            $configFile = 'wg0.conf';
        }

        // Determine interface name from config filename (wg0.conf -> wg0, awg0.conf -> awg0)
        $ifaceName = str_replace('.conf', '', $configFile);

        // Try to ensure container is running and wg is up
        $server->executeCommand("docker start {$containerArg} 2>/dev/null || true", true);
        $server->executeCommand("docker exec -i {$containerArg} wg-quick down {$configDir}/{$configFile} 2>/dev/null || true", true);
        $server->executeCommand("docker exec -i {$containerArg} wg-quick up {$configDir}/{$configFile} 2>/dev/null || true", true);

        $pdo = DB::conn();
        $serverData = $server->getData();
        $serverId = $server->getId();
        $protocolId = self::resolveProtocolId($protocol);
        $protocolSlug = $protocol['slug'] ?? ($isAwg2 ? 'awg2' : 'amnezia-wg');

        // Check if server already has another primary protocol installed
        $existingProtocol = $serverData['install_protocol'] ?? '';
        $isSecondaryProtocol = ($existingProtocol !== '' && $existingProtocol !== $protocolSlug);

        if (!$isSecondaryProtocol) {
            // Primary protocol — update vpn_servers
            $stmt = $pdo->prepare('
                UPDATE vpn_servers
                SET vpn_port = ?,
                    server_public_key = ?,
                    preshared_key = ?,
                    awg_params = ?,
                    status = ?,
                    error_message = NULL,
                    deployed_at = COALESCE(deployed_at, NOW()),
                    install_protocol = ?
                WHERE id = ?
            ');
            $stmt->execute([
                $details['vpn_port'] ?? null,
                $details['server_public_key'] ?? null,
                $details['preshared_key'] ?? null,
                isset($details['awg_params']) ? json_encode($details['awg_params']) : null,
                'active',
                $protocolSlug,
                $serverId
            ]);
        } else {
            // Secondary protocol — only ensure server is active, don't overwrite primary protocol data
            $stmt = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
            $stmt->execute(['active', $serverId]);
        }
        
        // Store protocol-specific config in server_protocols (works for both primary and secondary)
        if ($protocolId) {
            $configData = json_encode([
                'server_host' => $serverData['ip_address'] ?? $serverData['hostname'] ?? null,
                'server_port' => $details['vpn_port'] ?? null,
                'extras' => [
                    'vpn_port' => $details['vpn_port'] ?? null,
                    'vpn_subnet' => $details['vpn_subnet'] ?? '10.8.1.0/24',
                    'server_public_key' => $details['server_public_key'] ?? null,
                    'preshared_key' => $details['preshared_key'] ?? null,
                    'awg_params' => $details['awg_params'] ?? null,
                    'container_name' => $containerName,
                ],
            ]);
            $stmt = $pdo->prepare('
                INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at)
                VALUES (?, ?, ?, NOW(), NOW())
                ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()
            ');
            $stmt->execute([$serverId, $protocolId, $configData]);
        }

        $server->refresh();
        $serverData = $server->getData();

        // Import existing peers from config into database as disabled clients
        $serverId = $server->getId();
        Logger::appendInstall($serverId, "Restore: configDir={$configDir}, configFile={$configFile}, containerArg={$containerArg}");
        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true);
        $tableRaw = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/clientsTable 2>/dev/null", true);
        Logger::appendInstall($serverId, "Restore: wgConfig length=" . strlen($wgConfig) . ", tableRaw length=" . strlen($tableRaw));
        $clientsTable = json_decode(trim($tableRaw), true);
        $nameByPub = [];
        if (is_array($clientsTable)) {
            foreach ($clientsTable as $entry) {
                $cid = $entry['clientId'] ?? '';
                $uname = $entry['userData']['clientName'] ?? null;
                if ($cid !== '' && $uname) {
                    $nameByPub[$cid] = $uname;
                }
            }
        }
        $restored = 0;
        $pid = self::resolveProtocolId($protocol);
        $needsServerConfigUpdate = false;
        $keyUpdates = []; // Array of ['old' => $oldPub, 'new' => $newPub]
        Logger::appendInstall($serverId, "Restore: protocol_id={$pid}, wgConfig empty=" . (trim($wgConfig) === '' ? 'yes' : 'no'));
        if (trim($wgConfig) !== '') {
            $pattern = '/\[Peer\][^\[]*?PublicKey\s*=\s*(.+?)\s*[\r\n]+[\s\S]*?AllowedIPs\s*=\s*(.+?)(?:\r?\n|$)/';
            if (preg_match_all($pattern, $wgConfig, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $pub = trim($m[1]);
                    $allowed = trim($m[2]);
                    $clientIp = null;
                    foreach (explode(',', $allowed) as $ipSpec) {
                        $ipSpec = trim($ipSpec);
                        if (preg_match('/^([0-9\.]+)\/32$/', $ipSpec, $mm)) {
                            $clientIp = $mm[1];
                            break;
                        }
                    }
                    if (!$clientIp) {
                        continue;
                    }
                    $pdo = DB::conn();
                    $chk = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ?');
                    $chk->execute([$server->getId(), $clientIp]);
                    if ($chk->fetch()) {
                        continue;
                    }
                    $name = $nameByPub[$pub] ?? ('import-' . str_replace('.', '_', $clientIp));
                    
                    // Try to find existing client in database with this public key
                    $stmt = $pdo->prepare('SELECT id, private_key, config, qr_code FROM vpn_clients WHERE server_id = ? AND public_key = ? LIMIT 1');
                    $stmt->execute([$server->getId(), $pub]);
                    $existingClient = $stmt->fetch();
                    
                    $privateKey = $existingClient['private_key'] ?? '';
                    $config = $existingClient['config'] ?? '';
                    $qrCode = $existingClient['qr_code'] ?? '';
                    $newPublicKey = $pub; // By default use existing public key
                    
                    // If client exists in DB with private key, use existing config
                    // Otherwise generate new key pair and update server config
                    if (!empty($privateKey) && $existingClient) {
                        // Use existing keys and config
                    } else {
                        // Generate new key pair for this client
                        // Use awg for AWG2, wg for standard
                        $keyTool = $isAwg2 ? 'awg' : 'wg';
                        $newPrivateKey = trim($server->executeCommand("docker exec {$containerArg} {$keyTool} genkey", true));
                        if (!empty($newPrivateKey)) {
                            $escapedKey = escapeshellarg($newPrivateKey);
                            $newPublicKey = trim($server->executeCommand("docker exec {$containerArg} sh -c 'echo {$escapedKey} | {$keyTool} pubkey'", true));
                        } else {
                            $newPublicKey = '';
                        }
                        
                        Logger::appendInstall($serverId, "Restore: keygen for {$clientIp}: privkey_len=" . strlen($newPrivateKey) . " pubkey_len=" . strlen($newPublicKey));
                        
                        if (!empty($newPrivateKey) && !empty($newPublicKey) && strlen($newPublicKey) >= 40) {
                            $privateKey = $newPrivateKey;
                            $protocolSlug = $protocol['slug'] ?? '';
                            $serverHost = $serverData['host'] ?? $serverData['ip_address'] ?? $serverData['hostname'] ?? '';
                            $config = VpnClient::buildClientConfig(
                                $privateKey,
                                $clientIp,
                                $details['server_public_key'] ?? '',
                                $details['preshared_key'] ?? '',
                                $serverHost,
                                $details['vpn_port'] ?? 51820,
                                $details['awg_params'] ?? [],
                                $protocolSlug
                            );
                            $qrCode = VpnClient::generateQRCode($config, $protocolSlug);
                            
                            // Mark that we need to update server config with new public key
                            $needsServerConfigUpdate = true;
                            $keyUpdates[] = ['old' => $pub, 'new' => $newPublicKey];
                        } else {
                            Logger::appendInstall($serverId, "Restore: WARNING keygen failed for {$clientIp}, keeping original public key");
                        }
                    }
                    
                    $ins = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, protocol_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
                    $ins->execute([
                        $server->getId(),
                        $serverData['user_id'] ?? null,
                        $name,
                        $clientIp,
                        $newPublicKey,
                        $privateKey,
                        $details['preshared_key'] ?? null,
                        $config,
                        $qrCode,
                        $pid ?: null,
                        'active'
                    ]);
                    $restored++;
                }
            }
        }

        // Update server config if any keys were regenerated
        if ($needsServerConfigUpdate && !empty($keyUpdates)) {
            Logger::appendInstall($serverId, "Restore: updating server config with " . count($keyUpdates) . " new public keys");
            
            // Update wg0.conf - replace old public keys with new ones
            $updatedConfig = $wgConfig;
            foreach ($keyUpdates as $update) {
                // Escape special characters for regex
                $oldEscaped = preg_quote($update['old'], '/');
                $updatedConfig = preg_replace(
                    '/(PublicKey\s*=\s*)' . $oldEscaped . '/',
                    '${1}' . $update['new'],
                    $updatedConfig
                );
            }
            
            // Write updated config back to container
            $escapedConfig = addslashes($updatedConfig);
            $server->executeCommand("docker exec -i {$containerArg} sh -c 'echo \"$escapedConfig\" > {$configDir}/{$configFile}'", true);
            
            // Update clientsTable with new public keys
            $updatedTable = $clientsTable;
            if (is_array($updatedTable)) {
                foreach ($keyUpdates as $update) {
                    foreach ($updatedTable as &$entry) {
                        if (($entry['clientId'] ?? '') === $update['old']) {
                            $entry['clientId'] = $update['new'];
                            break;
                        }
                    }
                }
            }
            $tableJson = addslashes(json_encode($updatedTable, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
            $server->executeCommand("docker exec -i {$containerArg} sh -c 'echo \"$tableJson\" > {$configDir}/clientsTable'", true);
            
            // Restart WireGuard interface to apply changes
            $server->executeCommand("docker exec -i {$containerArg} wg-quick down {$configDir}/{$configFile} 2>/dev/null || true", true);
            $server->executeCommand("docker exec -i {$containerArg} wg-quick up {$configDir}/{$configFile} 2>/dev/null || true", true);
            
            Logger::appendInstall($serverId, "Restore: server config updated, WireGuard restarted");
        }
        
        Logger::appendInstall($serverId, "Restore: finished, restored={$restored}");
        return [
            'success' => true,
            'mode' => 'restore',
            'message' => 'Существующая конфигурация восстановлена' . ($needsServerConfigUpdate ? ' (ключи клиентов обновлены)' : ''),
            'vpn_port' => $details['vpn_port'] ?? null,
            'clients_count' => $details['clients_count'] ?? null,
            'restored_clients' => $restored
        ];
    }

    public static function addClient(VpnServer $server, array $protocol, array $options = []): array
    {
        return self::runScript($server, $protocol, 'add_client', $options);
    }

    private static function runScript(VpnServer $server, array $protocol, string $phase, array $options = []): array
    {
        $definition = $protocol['definition'] ?? [];
        $scripts = $definition['scripts'][$phase] ?? null;
        if (!$scripts) {
            if ($phase === 'install') {
                $scripts = $protocol['install_script'] ?? null;
            } elseif ($phase === 'uninstall') {
                $scripts = $protocol['uninstall_script'] ?? null;
            } elseif ($phase === 'add_client' && ($protocol['slug'] ?? '') === 'xray-vless') {
                return self::runBuiltinXrayAddClient($server, $options);
            }
        }
        if (!$scripts) {
            if ($phase === 'detect') {
                return [
                    'status' => 'absent',
                    'message' => 'Скрипт обнаружения не настроен для протокола'
                ];
            }
            if ($phase === 'uninstall') {
                return [
                    'success' => true,
                    'message' => 'Скрипт удаления не настроен для протокола'
                ];
            }
            if ($phase === 'add_client') {
                if (($protocol['slug'] ?? '') === 'aivpn') {
                    return self::runBuiltinAivpnAddClient($server, $options);
                }
                // If no script and no builtin handler, we just skip it (assume not needed or manual)
                // Or throw generic error? Better return success to not break flow if not implemented for other protocols
                return ['success' => true, 'message' => 'No add_client script defined'];
            }
            throw new Exception('Скрипт ' . $phase . ' не настроен для протокола');
        }

        $context = self::buildContext($server, $protocol, $options);
        $script = self::renderTemplate($scripts, $context);
        $script = preg_replace('/\n\+\s*/', "\n", $script);
        $exportLines = self::buildExports($context);

        if ($phase === 'install') {
            Logger::appendInstall($server->getId(), 'INSTALL phase: docker preflight start');
            $bootstrapCmd = "bash -lc 'set -e; "
                . "if command -v docker >/dev/null 2>&1; then command -v docker; docker --version || true; exit 0; fi; "
                . "if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; "
                . "elif command -v wget >/dev/null 2>&1; then wget -qO- https://get.docker.com | sh; "
                . "else echo \"curl/wget not found\"; exit 127; fi; "
                . "(systemctl enable --now docker || service docker start || true); "
                . "command -v docker >/dev/null 2>&1 || { echo \"docker bootstrap failed\"; exit 127; }; "
                . "command -v docker; docker --version || true'";
            $bootstrapOut = trim((string) $server->executeCommand($bootstrapCmd, true));
            if ($bootstrapOut !== '') {
                $bootstrapHead = substr(str_replace(["\r", "\n"], ' ', $bootstrapOut), 0, 280);
                Logger::appendInstall($server->getId(), 'INSTALL phase: docker preflight output ' . $bootstrapHead);
            }

            $dockerCheckAfter = trim((string) $server->executeCommand('command -v docker || true', true));
            if ($dockerCheckAfter === '') {
                throw new Exception('Docker не установлен на сервере и авто-установка не удалась');
            }
        }

        $wrapper = "bash <<'EOS'\nset -eo pipefail\n" . $exportLines . $script . "\nEOS";
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: executing remote script');
        $output = $server->executeCommand($wrapper, true);
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output size ' . strlen((string) $output) . ' bytes');
        $head = substr(str_replace(["\r", "\n"], ' ', (string) $output), 0, 280);
        if ($head !== '') {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output head ' . $head);
        }
        $trimmed = trim($output);
        $installProbeSummary = '';

        if ($phase === 'install' && $trimmed === '') {
            $probeCmd = "echo whoami:\$(whoami) 2>/dev/null || true; echo shell:\$SHELL; command -v docker || echo docker:not-found; docker --version 2>&1 || true; id 2>&1 || true";
            $probeOut = trim((string) $server->executeCommand($probeCmd, true));
            if ($probeOut !== '') {
                $normalizedProbe = substr(str_replace(["\r", "\n"], ' | ', $probeOut), 0, 320);
                Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: probe ' . $normalizedProbe);
                $installProbeSummary = '; probe: ' . $normalizedProbe;
            }
        }

        // Try JSON first
        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: parsed JSON result');
            return $decoded;
        }

        if ($phase === 'install') {
            $lower = strtolower($trimmed);
            $hardErrors = [
                'connection refused',
                'permission denied',
                'command not found',
                'no route to host',
                'could not resolve hostname',
                'host key verification failed',
                'timed out',
                'operation timed out',
            ];
            foreach ($hardErrors as $needle) {
                if ($needle !== '' && strpos($lower, $needle) !== false) {
                    throw new Exception('Ошибка установки (script): ' . $trimmed);
                }
            }
        }

        // Try key-value format (e.g., "Port: 123" or "Server Public Key: abc")
        $result = self::parseKeyValueOutput($trimmed);
        if (!empty($result)) {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: parsed key-value result with ' . count($result) . ' keys');
            return array_merge(['success' => true], $result);
        }

        // Heuristic: treat obvious errors on install as failure to avoid false "active" status
        if ($phase === 'install') {
            $lower = strtolower($trimmed);
            if ($lower === '' || strpos($lower, 'command not found') !== false || strpos($lower, 'error') !== false) {
                throw new Exception('Ошибка установки (script): ' . ($trimmed !== '' ? $trimmed : 'empty output') . $installProbeSummary);
            }
        }

        return [
            'success' => true,
            'output' => $output
        ];
    }

    /**
     * Parse key-value output from installation scripts
     * Supports formats like:
     * - "Port: 123"
     * - "Server Public Key: abc123"
     * - "PresharedKey = xyz789"
     */
    private static function parseKeyValueOutput(string $output): array
    {
        $result = [];
        $lines = preg_split('/\r?\n/', $output);

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '')
                continue;
            $line = preg_replace('/^\+\s*/', '', $line);

            // Match "Variable: name=value" format (for protocol variables)
            if (preg_match('/^Variable:\s*(\w+)=(.*)$/', $line, $matches)) {
                $varName = trim($matches[1]);
                $varValue = trim($matches[2]);
                $result[$varName] = $varValue;
                continue;
            }

            // Match "Key: Value" or "Key = Value" format
            if (preg_match('/^([^:=]+?)[:=]\s*(.+)$/', $line, $matches)) {
                $key = trim($matches[1]);
                $value = trim($matches[2]);

                // Normalize key names to snake_case
                $normalizedKey = strtolower(preg_replace('/\s+/', '_', $key));

                // Map common key names
                $keyMap = [
                    'port' => 'vpn_port',
                    'server_public_key' => 'server_public_key',
                    'presharedkey' => 'preshared_key',
                    'preshared_key' => 'preshared_key',
                    'awg_params' => 'awg_params',
                    'clientid' => 'client_id',
                    'client_id' => 'client_id',
                    'server_port' => 'server_port',
                    'xray_port' => 'server_port',
                    'container_name' => 'container_name',
                    'containername' => 'container_name',
                    'publickey' => 'reality_public_key',
                    'privatekey' => 'reality_private_key',
                    'shortid' => 'reality_short_id',
                    'servername' => 'reality_server_name',
                    'secret' => 'secret',
                    'serverhost' => 'server_host',
                    'server_host' => 'server_host',
                ];

                $finalKey = $keyMap[$normalizedKey] ?? $normalizedKey;
                $result[$finalKey] = $value;
            }
        }

        return $result;
    }

    private static function markServerActive(int $serverId, ?string $message = null, array $extras = []): void
    {
        $pdo = DB::conn();
        $setParts = ['status = ?', 'error_message = NULL', 'deployed_at = COALESCE(deployed_at, NOW())'];
        $params = ['active'];
        if (isset($extras['vpn_port']) && $extras['vpn_port'] !== null) {
            $setParts[] = 'vpn_port = ?';
            $params[] = (int) $extras['vpn_port'];
        }
        if (isset($extras['server_public_key']) && $extras['server_public_key'] !== null) {
            $setParts[] = 'server_public_key = ?';
            $params[] = (string) $extras['server_public_key'];
        }
        if (isset($extras['preshared_key']) && $extras['preshared_key'] !== null) {
            $setParts[] = 'preshared_key = ?';
            $params[] = (string) $extras['preshared_key'];
        }
        if (isset($extras['container_name']) && $extras['container_name'] !== null && $extras['container_name'] !== '') {
            $setParts[] = 'container_name = ?';
            $params[] = (string) $extras['container_name'];
        }
        if (array_key_exists('awg_params', $extras)) {
            $awgParams = $extras['awg_params'];
            if (is_array($awgParams)) {
                $awgParams = json_encode($awgParams);
            }
            if (is_string($awgParams)) {
                $setParts[] = 'awg_params = ?';
                $params[] = $awgParams;
            }
        }
        $params[] = $serverId;
        $sql = 'UPDATE vpn_servers SET ' . implode(', ', $setParts) . ' WHERE id = ?';
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        try {
            $stmt2 = $pdo->prepare('SELECT install_protocol, host, vpn_port FROM vpn_servers WHERE id = ?');
            $stmt2->execute([$serverId]);
            $row = $stmt2->fetch();
            $slug = $row['install_protocol'] ?? null;
            if ($slug) {
                $stmt3 = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
                $stmt3->execute([$slug]);
                $protocolId = $stmt3->fetchColumn();
                if ($protocolId) {
                    $config = [
                        'server_host' => $row['host'] ?? null,
                        'server_port' => $row['vpn_port'] ?? null,
                        'extras' => $extras
                    ];
                    $stmt4 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                    $stmt4->execute([$serverId, (int) $protocolId, json_encode($config)]);

                    // Keep existing MTProxy client links in sync with current runtime port/secret after reinstall.
                    if ($slug === 'mtproxy') {
                        $mtHost = (string) ($config['server_host'] ?? '');
                        $mtPort = (string) ($config['server_port'] ?? '');
                        $mtSecret = '';

                        if (!empty($extras['secret']) && is_scalar($extras['secret'])) {
                            $mtSecret = trim((string) $extras['secret']);
                        }
                        if ($mtSecret === '' && isset($extras['result']) && is_array($extras['result'])) {
                            if (!empty($extras['result']['secret']) && is_scalar($extras['result']['secret'])) {
                                $mtSecret = trim((string) $extras['result']['secret']);
                            }
                        }

                        if ($mtHost !== '' && $mtPort !== '' && $mtSecret !== '') {
                            $mtLink = 'tg://proxy?server=' . $mtHost . '&port=' . $mtPort . '&secret=' . $mtSecret;
                            $stmtSync = $pdo->prepare('UPDATE vpn_clients SET config = ? WHERE server_id = ? AND protocol_id = ? AND (config IS NULL OR config = "" OR config LIKE "tg://proxy?%")');
                            $stmtSync->execute([$mtLink, $serverId, (int) $protocolId]);
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            // ignore linkage errors
        }
    }

    private static function markServerError(int $serverId, string $message): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?');
        $stmt->execute(['error', $message, $serverId]);
    }

    private static function buildContext(VpnServer $server, array $protocol, array $options): array
    {
        return [
            'server' => $server->getData(),
            'protocol' => $protocol,
            'metadata' => $protocol['definition']['metadata'] ?? [],
            'options' => $options
        ];
    }

    private static function buildExports(array $context): string
    {
        $exports = [];
        $serverData = $context['server'] ?? [];
        $metadata = $context['metadata'] ?? [];
        $options = $context['options'] ?? [];

        $pairs = [
            'SERVER_HOST' => $serverData['host'] ?? '',
            'SERVER_USER' => $serverData['username'] ?? '',
            // Prefer protocol-specific settings for scripted installs to avoid
            // reusing a container name/port from another protocol on same server.
            'SERVER_CONTAINER' => $options['container_name']
                ?? ($metadata['container_name'] ?? ($serverData['container_name'] ?? '')),
            'SERVER_PORT' => isset($options['server_port']) && (int) $options['server_port'] > 0
                ? (int) $options['server_port']
                : (isset($serverData['vpn_port']) && (int) $serverData['vpn_port'] > 0
                    ? (int) $serverData['vpn_port']
                    : ''),
        ];

        // Check for saved Reality keys in server_protocols table
        $serverId = $serverData['id'] ?? null;
        if ($serverId) {
            try {
                $pdo = DB::conn();
                $stmt = $pdo->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? ORDER BY applied_at DESC LIMIT 1');
                $stmt->execute([$serverId]);
                $configJson = $stmt->fetchColumn();
                if ($configJson) {
                    $config = json_decode($configJson, true);
                    $extras = $config['extras'] ?? [];
                    // Export saved Reality keys if reinstalling (allow script to reuse them)
                    if (!empty($extras['reality_private_key'])) {
                        $pairs['PRIVATE_KEY'] = $extras['reality_private_key'];
                    }
                    if (!empty($extras['reality_short_id'])) {
                        $pairs['SHORT_ID'] = $extras['reality_short_id'];
                    }
                    // Note: CLIENT_ID is per-client, not per-server, so we don't restore it here
                }
            } catch (Throwable $e) {
                // Ignore errors, will generate new keys
            }
        }

        foreach ($pairs as $key => $value) {
            if ($value !== '' && $value !== null) {
                $exports[] = sprintf('export %s=%s', $key, escapeshellarg((string) $value));
            }
        }

        foreach ($metadata as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalized = strtoupper(preg_replace('/[^A-Z0-9]+/i', '_', (string) $key));
            if ($normalized === '') {
                continue;
            }
            $exports[] = sprintf('export PROTOCOL_%s=%s', $normalized, escapeshellarg((string) $value));
        }

        return $exports ? implode("\n", $exports) . "\n" : '';
    }

    /**
     * Choose a free UDP port on the remote server within metadata-defined range or defaults
     */
    private static function chooseServerPort(VpnServer $server, array $metadata): int
    {
        $range = $metadata['port_range'] ?? [30000, 65000];
        $min = 30000;
        $max = 65000;
        if (is_string($range)) {
            // Accept formats like "[30000, 65000]" or "30000-65000"
            if (preg_match('/(\d{2,})\D+(\d{2,})/', $range, $m)) {
                $min = (int) $m[1];
                $max = (int) $m[2];
            }
        } elseif (is_array($range) && count($range) >= 2) {
            $min = (int) $range[0];
            $max = (int) $range[1];
        }

        for ($attempt = 0; $attempt < 30; $attempt++) {
            $candidate = random_int($min, $max);
            $cmd = "ss -lun | awk '{print $4}' | grep -E ':(" . $candidate . ")($| )' || true";
            $out = $server->executeCommand($cmd, false);
            if (trim($out) === '') {
                return $candidate;
            }
        }

        return 40001; // fallback
    }

    private static function renderTemplate(string $template, array $context): string
    {
        return preg_replace_callback('/{{\s*([a-zA-Z0-9_.]+)\s*}}/', function ($matches) use ($context) {
            $path = explode('.', $matches[1]);
            $value = $context;
            foreach ($path as $segment) {
                if (is_array($value) && array_key_exists($segment, $value)) {
                    $value = $value[$segment];
                } else {
                    return '';
                }
            }
            return is_scalar($value) ? (string) $value : json_encode($value);
        }, $template);
    }

    private static function parseWireGuardConfig(string $config): array
    {
        $lines = preg_split('/\r?\n/', $config);
        $awgKeys = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'];
        $awgParams = [];
        $listenPort = null;

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $line, 2));
            if ($key === 'ListenPort') {
                $listenPort = (int) $value;
            }
            if (in_array($key, $awgKeys, true)) {
                $awgParams[$key] = is_numeric($value) ? (int) $value : $value;
            }
        }

        return [
            'listen_port' => $listenPort,
            'awg_params' => $awgParams
        ];
    }

    private static function hydrateProtocol(array $row): array
    {
        if (isset($row['definition']) && is_string($row['definition'])) {
            $decoded = json_decode($row['definition'], true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $row['definition'] = $decoded;
            } else {
                $row['definition'] = [];
            }
        }
        return $row;
    }

    /**
     * ──────────────────────────────────────────────────────────────────
     * PROTOCOL HANDLER REGISTRY
     * ──────────────────────────────────────────────────────────────────
     * Central dispatcher that determines which builtin handler manages
     * a given protocol. Every dispatch point (detect, install, uninstall)
     * MUST use this method instead of ad-hoc slug/regex checks.
     *
     * Returns one of:
     *   'awg'    – AmneziaWG / AWG variants (Docker container based)
     *   'warp'   – Cloudflare WARP (systemd service, host-level)
     *   'xray'   – X-Ray VLESS (Docker container based)
     *   'script' – Generic script-driven protocol (install/uninstall via shell)
     *
     * Priority order:
     *   1. Explicit slug match (highest priority, cannot be overridden)
     *   2. Engine field from protocol definition
     *   3. Heuristic: install_script content analysis (lowest priority)
     */
    private static function resolveHandler(array $protocol): string
    {
        $slug = $protocol['slug'] ?? '';

        // ── 1. Explicit slug → handler mapping (always wins) ──
        static $slugMap = [
            // WARP
            'cf-warp'               => 'warp',
            'cloudflare-warp'       => 'warp',
            // X-Ray
            'xray-vless'            => 'xray',
            // AWG variants
            'amnezia-wg'            => 'awg',
            'amnezia-wg-advanced'   => 'awg',
            'awg2'                  => 'awg',
        ];

        if (isset($slugMap[$slug])) {
            return $slugMap[$slug];
        }

        // ── 2. Engine from definition ──
        $definition = $protocol['definition'] ?? [];
        $engine = $definition['engine'] ?? '';
        if ($engine === 'builtin_awg') {
            return 'awg';
        }

        // ── 3. Heuristic: AWG Docker image in install_script ──
        // Only check if no explicit slug/engine match above
        if (empty($protocol['install_script'])) {
            // No install_script and no engine → default to AWG (legacy behavior)
            return 'awg';
        }

        $installScript = (string) $protocol['install_script'];
        if (preg_match('/amneziavpn\/amnezia-wg|docker\s.*amnezia-awg/i', $installScript)) {
            return 'awg';
        }

        // ── 4. Fallback: generic script protocol ──
        return 'script';
    }

    /**
     * Legacy compatibility: get engine string
     */
    private static function getEngine(array $protocol): string
    {
        $handler = self::resolveHandler($protocol);
        if ($handler === 'awg') return 'builtin_awg';
        return 'shell';
    }

    private static function fallbackProtocols(): array
    {
        return [
            [
                'id' => null,
                'slug' => self::DEFAULT_SLUG,
                'name' => 'AmneziaWG',
                'description' => 'Default Amnezia WireGuard deployment scenario',
                'definition' => [
                    'engine' => 'builtin_awg',
                    'metadata' => [
                        'container_name' => 'amnezia-awg',
                        'vpn_subnet' => '10.8.1.0/24',
                        'port_range' => [30000, 65000],
                    ],
                ],
                'is_active' => 1,
            ]
        ];
    }

    private static function storeDecision(int $serverId, array $payload): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return '';
        }
        $token = bin2hex(random_bytes(16));
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = [];
        }
        $_SESSION[self::SESSION_KEY][$serverId] = [
            'token' => $token,
            'payload' => $payload,
            'expires_at' => time() + 600
        ];
        return $token;
    }

    private static function consumeDecision(int $serverId, string $token): ?array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return null;
        }

        if (!isset($_SESSION[self::SESSION_KEY][$serverId])) {
            return null;
        }

        $entry = $_SESSION[self::SESSION_KEY][$serverId];
        if (($entry['token'] ?? '') !== $token) {
            return null;
        }

        unset($_SESSION[self::SESSION_KEY][$serverId]);

        if (($entry['expires_at'] ?? 0) < time()) {
            return null;
        }

        return $entry['payload'] ?? null;
    }

    /**
     * Run detection script for a scenario on a server
     * Used for testing scenarios before deployment
     */
    public static function runDetection(VpnServer $server, array $protocol, array $options = []): array
    {
        $handler = self::resolveHandler($protocol);

        switch ($handler) {
            case 'awg':
                return self::detectBuiltinAwg($server, $protocol);
            case 'xray':
                return self::detectBuiltinXray($server, $protocol);
            case 'warp':
                return self::detectBuiltinWarp($server, $protocol);
            default:
                return self::runScript($server, $protocol, 'detect', $options);
        }
    }

    /**
     * Uninstall a protocol from the given server. Supports builtin AWG and scripted protocols
     * Returns array with success and message keys on completion or throws on fatal error
     */
    public static function uninstall(VpnServer $server, array $protocol, array $options = []): array
    {
        $slug = $protocol['slug'] ?? 'unknown';
        $handler = self::resolveHandler($protocol);
        Logger::appendInstall($server->getId(), 'UNINSTALL: slug=' . $slug . ' handler=' . $handler);

        switch ($handler) {
            case 'warp':
                return self::uninstallBuiltinWarp($server, $protocol, $options);

            case 'awg':
                // Prefer builtin AWG uninstall; script variant only on explicit request
                if (!empty($options['use_script_uninstall'])) {
                    $hasScript = isset($protocol['uninstall_script']) && trim((string) $protocol['uninstall_script']) !== '';
                    if ($hasScript) {
                        return self::runScript($server, $protocol, 'uninstall', $options);
                    }
                }
                return self::uninstallBuiltinAwg($server, $protocol, $options);

            case 'xray':
            case 'script':
            default:
                return self::runScript($server, $protocol, 'uninstall', $options);
        }
    }

    private static function uninstallBuiltinAwg(VpnServer $server, array $protocol, array $options = []): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $serverData = $server->getData();
        // IMPORTANT: Use protocol metadata container_name first (e.g. 'amnezia-awg2'),
        // NOT vpn_servers.container_name which belongs to the PRIMARY protocol (e.g. 'aivpn-server')
        $containerName = $metadata['container_name'] ?? $serverData['container_name'] ?? 'amnezia-awg';
        $configDir = trim((string) ($metadata['config_dir'] ?? ''));
        if ($configDir === '') {
            $configDir = (($protocol['slug'] ?? '') === 'awg2') ? '/opt/amnezia/awg2' : '/opt/amnezia/awg';
        }
        $candidateNames = array_values(array_unique(array_filter([
            is_string($containerName) ? trim($containerName) : '',
            is_string($metadata['container_name'] ?? null) ? trim((string) $metadata['container_name']) : '',
            'amnezia-awg',
        ], function ($v) {
            return is_string($v) && trim($v) !== '';
        })));

        // Attempt to stop and remove container, image and cleanup files
        try {
            foreach ($candidateNames as $name) {
                $arg = escapeshellarg($name);
                // Stop container if running
                $server->executeCommand("docker stop {$arg} 2>/dev/null || true", true);
                // Remove container
                $server->executeCommand("docker rm -fv {$arg} 2>/dev/null || true", true);
            }
            // Remove known images (best-effort)
            $server->executeCommand("docker rmi amneziavpn/amnezia-wg amneziavpn/amnezia-awg amnezia-awg2 2>/dev/null || true", true);
            // Attempt to remove amnezia-dns-net network if present (best-effort)
            $server->executeCommand("docker network rm amnezia-dns-net 2>/dev/null || true", true);
            // Remove on-disk data for AWG protocol config to avoid stale restore paths.
            $server->executeCommand("rm -rf " . escapeshellarg($configDir) . " 2>/dev/null || true", true);
            $server->executeCommand("rm -rf /opt/amnezia/amnezia-awg 2>/dev/null || true", true);

            // Clear server deployment metadata in database for this server
            $pdo = DB::conn();
            $stmt = $pdo->prepare('UPDATE vpn_servers SET vpn_port = NULL, server_public_key = NULL, preshared_key = NULL, awg_params = NULL, status = ?, error_message = NULL WHERE id = ?');
            $stmt->execute(['stopped', $server->getId()]);

            // Refresh server object data
            $server->refresh();

            return [
                'success' => true,
                'message' => 'Протокол успешно удалён',
                'mode' => 'uninstall'
            ];
        } catch (Throwable $e) {
            throw new Exception('Uninstall failed: ' . $e->getMessage());
        }
    }

    public static function activate(VpnServer $server, array $protocol, array $options = []): array
    {
        $engine = self::getEngine($protocol);
        $serverId = $server->getId();
        try {
            Logger::appendInstall($serverId, 'Activate start for ' . ($protocol['slug'] ?? 'unknown') . ' engine ' . $engine);

            // ── Check for existing installation before doing anything destructive ──
            $slug = $protocol['slug'] ?? '';
            $handler = self::resolveHandler($protocol);
            $isAwg = $handler === 'awg';
            $isXray = $handler === 'xray';

            if ($isAwg) {
                $detection = self::detectBuiltinAwg($server, $protocol);
                Logger::appendInstall($serverId, 'AWG detect result: status=' . ($detection['status'] ?? 'null') . ' message=' . ($detection['message'] ?? 'none'));
                if (($detection['status'] ?? '') === 'existing') {
                    Logger::appendInstall($serverId, 'Existing AWG installation detected, restoring instead of reinstalling');
                    $restoreResult = self::restoreBuiltinAwg($server, $protocol, $detection, $options);
                    // Import existing clients into DB
                    self::importExistingAwgClients($server, $protocol, $detection);
                    $pdo = DB::conn();
                    $pid = self::resolveProtocolId($protocol);
                    if ($pid) {
                        $details = $detection['details'] ?? [];
                        $config = [
                            'server_host' => $server->getData()['host'] ?? null,
                            'server_port' => $details['vpn_port'] ?? null,
                            'extras' => [
                                'vpn_port' => $details['vpn_port'] ?? null,
                                'server_public_key' => $details['server_public_key'] ?? null,
                                'preshared_key' => $details['preshared_key'] ?? null,
                                'awg_params' => $details['awg_params'] ?? null,
                            ]
                        ];
                        $stmt2 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                        $stmt2->execute([$serverId, $pid, json_encode($config)]);
                    }
                    return array_merge($restoreResult, ['mode' => 'restore_existing']);
                }
            }

            if ($isXray) {
                $xrayDetection = self::detectBuiltinXray($server, $protocol);
                if (($xrayDetection['status'] ?? '') === 'existing') {
                    Logger::appendInstall($serverId, 'Existing X-Ray installation detected, restoring instead of reinstalling');
                    $restoreResult = self::restoreBuiltinXray($server, $protocol, $xrayDetection, $options);
                    return array_merge($restoreResult, ['mode' => 'restore_existing']);
                }
            }

            // For Cloudflare WARP — always run install script even if WARP binary exists
            // because the script is idempotent and handles redsocks/iptables setup
            if (self::resolveHandler($protocol) === 'warp') {
                $warpDetection = self::detectBuiltinWarp($server, $protocol);
                Logger::appendInstall($serverId, 'WARP detect result: status=' . ($warpDetection['status'] ?? 'null'));
                if (($warpDetection['status'] ?? '') === 'existing') {
                    Logger::appendInstall($serverId, 'Existing WARP found, running install script anyway for redsocks/iptables setup');
                    // Don't return — fall through to run the install script
                }
            }

            // ── No existing installation found — proceed with fresh install ──

            if ($engine === 'builtin_awg') {
                $res = $server->runAwgInstall($options);
                Logger::appendInstall($serverId, 'Builtin AWG install finished');

                $resolvedPort = null;
                if (isset($res['vpn_port']) && (int) $res['vpn_port'] > 0) {
                    $resolvedPort = (int) $res['vpn_port'];
                } elseif (isset($res['server_port']) && (int) $res['server_port'] > 0) {
                    $resolvedPort = (int) $res['server_port'];
                }

                $resolvedAwgParams = $res['awg_params'] ?? null;
                if (!is_array($resolvedAwgParams)) {
                    $candidate = [];
                    foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $k) {
                        if (array_key_exists($k, $res)) {
                            $candidate[$k] = $res[$k];
                        }
                    }
                    if ($candidate) {
                        $resolvedAwgParams = $candidate;
                    }
                }

                $existingProtocol = $server->getData()['install_protocol'] ?? '';
                $currentSlug = $protocol['slug'] ?? '';
                $isFirstProtocol = ($existingProtocol === '' || $existingProtocol === $currentSlug);
                if ($isFirstProtocol) {
                    self::markServerActive($serverId, null, [
                        'vpn_port' => $resolvedPort,
                        'server_public_key' => $res['server_public_key'] ?? null,
                        'preshared_key' => $res['preshared_key'] ?? null,
                        'container_name' => $res['container_name'] ?? null,
                        'awg_params' => $resolvedAwgParams,
                    ]);
                } else {
                    // Secondary protocol — just mark active, don't overwrite primary data
                    self::markServerActive($serverId, null, []);
                }

                $pdo = DB::conn();
                $pid = self::resolveProtocolId($protocol);
                if ($pid) {
                    $config = [
                        'server_host' => $server->getData()['host'] ?? null,
                        'server_port' => $resolvedPort,
                        'extras' => $res
                    ];
                    $stmt2 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                    $stmt2->execute([$serverId, $pid, json_encode($config)]);
                }
                // Sync existing clients from DB to Container (Restore active clients)
                self::syncClientsToContainer($server, $protocol);
                return ['success' => true, 'mode' => 'install', 'details' => $res];
            }
            if (!isset($options['server_port']) || !is_int($options['server_port'])) {
                $options['server_port'] = self::chooseServerPort($server, $protocol['definition']['metadata'] ?? []);
            }
            $res = self::runScript($server, $protocol, 'install', $options);
            if (!isset($res['success'])) {
                $res['success'] = true;
            }
            $port = null;
            $password = null;
            $clientId = null;
            if (isset($res['vpn_port'])) {
                $port = (int) $res['vpn_port'];
            }
            if (isset($res['server_port'])) {
                $port = (int) $res['server_port'];
            }
            if (isset($res['client_id']) && is_string($res['client_id'])) {
                $clientId = $res['client_id'];
            }
            if (is_string($res['output'] ?? '')) {
                $out = $res['output'];
                if (preg_match('/Port:\s*(\d+)/i', $out, $m)) {
                    $port = (int) $m[1];
                }
                if (preg_match('/Password:\s*([\w-]+)/i', $out, $m)) {
                    $password = $m[1];
                }
                if (preg_match('/ClientID:\s*([0-9a-fA-F-]+)/i', $out, $m)) {
                    $clientId = $m[1];
                }
            }
            if (($protocol['slug'] ?? '') === 'xray-vless' && $clientId === null) {
                $containerName = 'amnezia-xray';
                if (isset($res['container_name']) && is_string($res['container_name']) && trim($res['container_name']) !== '') {
                    $containerName = trim($res['container_name']);
                }
                try {
                    $cfg = $server->executeCommand("docker exec -i " . escapeshellarg($containerName) . " cat /opt/amnezia/xray/server.json 2>/dev/null", true);
                    if (trim((string) $cfg) === '') {
                        $cfg = $server->executeCommand("docker exec -i " . escapeshellarg($containerName) . " cat /etc/xray/config.json 2>/dev/null", true);
                    }
                    $decoded = json_decode(trim((string) $cfg), true);
                    if (is_array($decoded)) {
                        $inbounds = $decoded['inbounds'] ?? [];
                        if (is_array($inbounds) && !empty($inbounds)) {
                            $settings = $inbounds[0]['settings'] ?? [];
                            $clients = $settings['clients'] ?? [];
                            if (is_array($clients) && !empty($clients)) {
                                $cid = $clients[0]['id'] ?? null;
                                if (is_string($cid) && $cid !== '') {
                                    $clientId = $cid;
                                }
                            }
                            $stream = $inbounds[0]['streamSettings'] ?? [];
                            if (is_array($stream) && ($stream['security'] ?? '') === 'reality') {
                                $rs = $stream['realitySettings'] ?? [];
                                $serverNames = $rs['serverNames'] ?? ($rs['serverName'] ?? []);
                                $shortIds = $rs['shortIds'] ?? ($rs['shortId'] ?? []);
                                $serverName = is_array($serverNames) ? ($serverNames[0] ?? null) : (is_string($serverNames) ? $serverNames : null);
                                $shortId = is_array($shortIds) ? ($shortIds[0] ?? null) : (is_string($shortIds) ? $shortIds : null);
                                $privateKey = $rs['privateKey'] ?? null;
                                $publicKey = null;
                                if (is_string($privateKey) && $privateKey !== '' && function_exists('sodium_crypto_scalarmult_base')) {
                                    $pk = $privateKey;
                                    $b64 = strtr($pk, '-_', '+/');
                                    $bin = base64_decode($b64, true);
                                    if ($bin === false) {
                                        $bin = base64_decode($pk, true);
                                    }
                                    if (is_string($bin) && strlen($bin) === 32) {
                                        $pub = sodium_crypto_scalarmult_base($bin);
                                        $publicKey = rtrim(strtr(base64_encode($pub), '+/', '-_'), '=');
                                    }
                                }
                                if ($publicKey) {
                                    $res['reality_public_key'] = $publicKey;
                                }
                                // Store private key for future restoration
                                if (is_string($privateKey) && $privateKey !== '') {
                                    $res['reality_private_key'] = $privateKey;
                                }
                                if ($shortId) {
                                    $res['reality_short_id'] = $shortId;
                                }
                                if ($serverName) {
                                    $res['reality_server_name'] = $serverName;
                                }
                            }
                        }
                    }
                } catch (Throwable $e) {
                }
            }
            Logger::appendInstall($serverId, 'Scripted install parsed port ' . ($port ?? 0) . ' password ' . ($password ?? ''));
            $pdo = DB::conn();
            $pid = self::resolveProtocolId($protocol);
            if ($pid) {
                $config = [
                    'server_host' => $server->getData()['host'] ?? null,
                    'server_port' => $port,
                    'extras' => [
                        'password' => $password,
                        'client_id' => $clientId,
                        'result' => $res,
                        'reality_public_key' => $res['reality_public_key'] ?? null,
                        'reality_private_key' => $res['reality_private_key'] ?? null,
                        'reality_short_id' => $res['reality_short_id'] ?? null,
                        'reality_server_name' => $res['reality_server_name'] ?? null,
                    ]
                ];
                $stmt2 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
                $stmt2->execute([$serverId, $pid, json_encode($config)]);
            }
            // Save vpn_port to vpn_servers table ONLY for the primary (first) protocol
            // Secondary protocols store their ports in server_protocols.config_data only
            if ($port !== null && $port > 0) {
                $existingProtocol = $server->getData()['install_protocol'] ?? '';
                $currentSlug = $protocol['slug'] ?? '';
                $isFirstProtocol = ($existingProtocol === '' || $existingProtocol === $currentSlug);
                if ($isFirstProtocol) {
                    self::markServerActive($serverId, null, ['vpn_port' => $port]);
                }
            }

            // ── WARP: Auto-patch X-Ray outbound to route through WARP ──
            if (self::resolveHandler($protocol) === 'warp') {
                self::patchXrayForWarp($server);
            }

            return $res;
        } catch (Throwable $e) {
            $message = (string) $e->getMessage();
            if (
                stripos($message, 'server_protocols_ibfk_1') !== false
                || (stripos($message, 'foreign key constraint fails') !== false && stripos($message, 'server_protocols') !== false)
            ) {
                $message = 'Сервер был удален или пересоздан во время установки. Обновите страницу и запустите установку заново.';
            }

            self::markServerError($serverId, $message);
            Logger::appendInstall($serverId, 'Activate failed: ' . $message);
            throw new Exception($message, 0, $e);
        }
    }

    private static function runBuiltinAivpnAddClient(VpnServer $server, array $options): array
    {
        $serverData = $server->getData();
        $containerName = self::resolveAivpnContainerName($server, $options);

        $clientName = trim((string) ($options['login'] ?? ($options['name'] ?? '')));
        if ($clientName === '') {
            $clientName = 'client-' . date('YmdHis');
        }

        $serverHostRaw = trim((string) ($options['server_host'] ?? ($serverData['host'] ?? '')));
        $serverHostSanitized = preg_replace('#^https?://#i', '', $serverHostRaw);
        $serverHostSanitized = preg_replace('#/.*$#', '', $serverHostSanitized ?? '');
        $serverHost = $serverHostSanitized;
        $embeddedPort = null;
        if ($serverHostSanitized !== '' && preg_match('/^(.+?)(?::\d+)+$/', $serverHostSanitized, $m)) {
            $serverHost = trim((string) $m[1]);
            if (preg_match('/:(\d+)$/', $serverHostSanitized, $pm)) {
                $embeddedPort = (int) $pm[1];
            }
        }

        $defaultPort = 443;
        if (stripos((string) ($serverData['install_protocol'] ?? ''), 'aivpn') !== false && (int) ($serverData['vpn_port'] ?? 0) > 0) {
            $defaultPort = (int) $serverData['vpn_port'];
        }
        $serverPort = isset($options['server_port']) ? (int) $options['server_port'] : 0;
        if ($serverPort <= 0 && $embeddedPort !== null && $embeddedPort > 0) {
            $serverPort = $embeddedPort;
        }
        if ($serverPort <= 0) {
            $serverPort = $defaultPort;
        }
        if (
            stripos((string) ($serverData['install_protocol'] ?? ''), 'aivpn') === false &&
            $embeddedPort === null &&
            (int) ($serverData['vpn_port'] ?? 0) > 0 &&
            $serverPort === (int) $serverData['vpn_port']
        ) {
            $serverPort = 443;
        }
        if ($serverPort <= 0) {
            $serverPort = 443;
        }

        // Use full path to aivpn-server binary as per official Dockerfile
        // The binary is installed to /usr/local/bin/aivpn-server in the container
        $binaryCmd = '/usr/local/bin/aivpn-server';
        
        // Verify the binary exists, fallback to other locations if needed
        // Use auto-detection for sudo requirement (null = auto-detect for docker commands)
        $checkCmd = sprintf('docker exec -i %s test -f %s && echo "found" || echo "not found"',
            escapeshellarg($containerName),
            escapeshellarg($binaryCmd));
        $checkResult = (string) $server->executeCommand($checkCmd, null);
        if (strpos($checkResult, 'found') === false) {
            // Try alternative locations
            $fallbacks = [
                'aivpn-server',  // In PATH
                '/usr/bin/aivpn-server',
                '/opt/aivpn/aivpn-server',
                '/app/aivpn-server',
            ];
            foreach ($fallbacks as $loc) {
                $checkCmd = sprintf('docker exec -i %s test -f %s && echo "found" || echo "not found"',
                    escapeshellarg($containerName),
                    escapeshellarg($loc));
                $checkResult = (string) $server->executeCommand($checkCmd, null);
                if (strpos($checkResult, 'found') !== false) {
                    $binaryCmd = $loc;
                    break;
                }
            }
        }
        
        $cmdParts = [
            'docker',
            'exec',
            '-i',
            escapeshellarg($containerName),
            $binaryCmd,
            '--add-client',
            escapeshellarg($clientName),
            '--key-file',
            '/etc/aivpn/server.key',
            '--clients-db',
            '/etc/aivpn/clients.json',
        ];

        if ($serverHost !== '') {
            $cmdParts[] = '--server-ip';
            $cmdParts[] = escapeshellarg($serverHost . ':' . $serverPort);
        }

        $cmd = implode(' ', $cmdParts);
        Logger::appendInstall($server->getId(), 'Adding AIVPN client via builtin add_client: ' . $clientName . ' in ' . $containerName);
        
        try {
            // Use auto-detection for sudo requirement (null = auto-detect for docker commands)
            $output = (string) $server->executeCommand($cmd, null);
        } catch (Exception $e) {
            Logger::appendInstall($server->getId(), 'AIVPN add_client docker exec failed: ' . $e->getMessage());
            $hostResult = self::runAivpnAddClientViaHostBinary($server, $clientName, $serverHost, $serverPort);
            if ($hostResult !== null) {
                return $hostResult;
            }
            return ['success' => true, 'connection_key' => '', 'connection_uri' => ''];
        }
        
        $trimmedOutput = trim($output);
        if ($trimmedOutput === '' ||
            stripos($trimmedOutput, 'Error response from daemon') !== false ||
            stripos($trimmedOutput, 'is restarting') !== false ||
            stripos($trimmedOutput, 'No such container') !== false ||
            stripos($trimmedOutput, 'executable file not found') !== false) {
            Logger::appendInstall($server->getId(), 'AIVPN add_client container unavailable, trying host binary fallback');
            $hostResult = self::runAivpnAddClientViaHostBinary($server, $clientName, $serverHost, $serverPort);
            if ($hostResult !== null) {
                return $hostResult;
            }
            return ['success' => true, 'connection_key' => '', 'connection_uri' => ''];
        }

        if (stripos($trimmedOutput, 'error') !== false || stripos($trimmedOutput, 'failed') !== false) {
            Logger::appendInstall($server->getId(), 'AIVPN add_client returned error: ' . substr($trimmedOutput, 0, 200));
            $hostResult = self::runAivpnAddClientViaHostBinary($server, $clientName, $serverHost, $serverPort);
            if ($hostResult !== null) {
                return $hostResult;
            }
            return ['success' => false, 'error' => $trimmedOutput];
        }
        
        $parsed = self::parseAivpnAddClientOutput($output);

        if (empty($parsed['connection_uri']) && empty($parsed['connection_key'])) {
            $head = substr(str_replace(["\r", "\n"], ' ', $trimmedOutput), 0, 220);
            Logger::appendInstall($server->getId(), 'AIVPN add_client no connection key in output: ' . $head);
            $hostResult = self::runAivpnAddClientViaHostBinary($server, $clientName, $serverHost, $serverPort);
            if ($hostResult !== null) {
                return $hostResult;
            }
            return ['success' => false, 'error' => 'No connection key found'];
        }

        $result = ['success' => true];
        if (!empty($parsed['connection_uri'])) {
            $result['connection_uri'] = $parsed['connection_uri'];
        }
        if (!empty($parsed['connection_key'])) {
            $result['connection_key'] = $parsed['connection_key'];
        }
        if (!empty($parsed['client_ip'])) {
            $result['client_ip'] = $parsed['client_ip'];
        }
        if (!empty($parsed['client_id'])) {
            $result['client_id'] = $parsed['client_id'];
        }

        return $result;
    }

    private static function parseAivpnAddClientOutput(string $output): array
    {
        $result = [];
        $trimmed = trim($output);
        if ($trimmed === '') {
            return $result;
        }

        if (preg_match('/(aivpn:\/\/[A-Za-z0-9_\-+=\/]+)/', $trimmed, $m)) {
            $uri = trim((string) $m[1]);
            $result['connection_uri'] = $uri;
            if (stripos($uri, 'aivpn://') === 0) {
                $result['connection_key'] = substr($uri, strlen('aivpn://'));
            }
        }

        if (preg_match('/\bID:\s*([a-zA-Z0-9]+)/', $trimmed, $m)) {
            $result['client_id'] = trim((string) $m[1]);
        }

        if (preg_match('/\bVPN\s*IP:\s*([0-9.]+)/i', $trimmed, $m)) {
            $result['client_ip'] = trim((string) $m[1]);
        }

        return $result;
    }

    private static function runAivpnAddClientViaHostBinary(VpnServer $server, string $clientName, string $serverHost, int $serverPort): ?array
    {
        $hostBinaryPaths = [
            '/opt/amnezia/aivpn/aivpn-server-linux-x86_64',
            '/opt/amnezia/aivpn/aivpn-server',
            '/usr/local/bin/aivpn-server',
            '/usr/bin/aivpn-server',
        ];

        $binaryPath = null;
        foreach ($hostBinaryPaths as $path) {
            try {
                $check = (string) $server->executeCommand('test -f ' . escapeshellarg($path) . ' && echo "found" || echo "not_found"', true);
                if (trim($check) === 'found') {
                    $binaryPath = $path;
                    break;
                }
            } catch (Exception $e) {
                continue;
            }
        }

        if ($binaryPath === null) {
            Logger::appendInstall($server->getId(), 'AIVPN host binary not found for fallback');
            return null;
        }

        $cmdParts = [
            escapeshellarg($binaryPath),
            '--add-client',
            escapeshellarg($clientName),
            '--key-file',
            escapeshellarg('/etc/aivpn/server.key'),
            '--clients-db',
            escapeshellarg('/etc/aivpn/clients.json'),
        ];

        if ($serverHost !== '') {
            $cmdParts[] = '--server-ip';
            $cmdParts[] = escapeshellarg($serverHost . ':' . $serverPort);
        }

        $cmd = implode(' ', $cmdParts);
        Logger::appendInstall($server->getId(), 'AIVPN add_client fallback via host binary: ' . $clientName);

        try {
            $output = (string) $server->executeCommand($cmd, true);
        } catch (Exception $e) {
            Logger::appendInstall($server->getId(), 'AIVPN host binary fallback failed: ' . $e->getMessage());
            return null;
        }

        $trimmedOutput = trim($output);
        if ($trimmedOutput === '' ||
            stripos($trimmedOutput, 'Failed to add client') !== false ||
            stripos($trimmedOutput, 'error') !== false) {
            Logger::appendInstall($server->getId(), 'AIVPN host binary fallback returned error: ' . substr($trimmedOutput, 0, 200));
            return null;
        }

        $parsed = self::parseAivpnAddClientOutput($output);
        if (empty($parsed['connection_uri']) && empty($parsed['connection_key'])) {
            Logger::appendInstall($server->getId(), 'AIVPN host binary fallback produced no connection key');
            return null;
        }

        $result = ['success' => true];
        if (!empty($parsed['connection_uri'])) {
            $result['connection_uri'] = $parsed['connection_uri'];
        }
        if (!empty($parsed['connection_key'])) {
            $result['connection_key'] = $parsed['connection_key'];
        }
        if (!empty($parsed['client_ip'])) {
            $result['client_ip'] = $parsed['client_ip'];
        }
        if (!empty($parsed['client_id'])) {
            $result['client_id'] = $parsed['client_id'];
        }

        Logger::appendInstall($server->getId(), 'AIVPN host binary fallback succeeded for ' . $clientName);
        return $result;
    }

    private static function runBuiltinXrayAddClient(VpnServer $server, array $options): array
    {
        $clientId = $options['client_id'] ?? null;
        if (!$clientId) {
            throw new Exception("Client ID is required for X-Ray add_client");
        }

        // Default container name if not provided
        $containerName = 'amnezia-xray';
        if (!empty($options['container_name'])) {
            $containerName = $options['container_name'];
        }

        Logger::appendInstall($server->getId(), "Adding X-Ray client $clientId to container $containerName");

        // 1. Read config
        $catCmd = "docker exec -i " . escapeshellarg($containerName) . " cat /opt/amnezia/xray/server.json 2>/dev/null";
        $configRaw = $server->executeCommand($catCmd, true);

        if (trim($configRaw) === '') {
            $catCmd = "docker exec -i " . escapeshellarg($containerName) . " cat /etc/xray/config.json 2>/dev/null";
            $configRaw = $server->executeCommand($catCmd, true);
        }

        if (trim($configRaw) === '') {
            throw new Exception("Could not read X-Ray config from $containerName");
        }

        $config = json_decode($configRaw, true);
        if (!$config) {
            throw new Exception("Invalid JSON in X-Ray config");
        }

        // 2. Modify config

        // Ensure policy for 1 user 1 connection
        if (!isset($config['policy'])) {
            $config['policy'] = ['levels' => ['0' => []]];
        }
        if (!isset($config['policy']['levels'])) {
            $config['policy']['levels'] = ['0' => []];
        }
        if (!isset($config['policy']['levels']['0'])) {
            $config['policy']['levels']['0'] = [];
        }

        // Enforce stats and online tracking for user level 0
        $config['policy']['levels']['0']['handshake'] = 4;
        $config['policy']['levels']['0']['connIdle'] = 300;
        $config['policy']['levels']['0']['uplinkOnly'] = 2;
        $config['policy']['levels']['0']['downlinkOnly'] = 5;
        $config['policy']['levels']['0']['statsUserUplink'] = true;
        $config['policy']['levels']['0']['statsUserDownlink'] = true;
        $config['policy']['levels']['0']['statsUserOnline'] = true; // Enable online tracking
        $config['policy']['levels']['0']['bufferSize'] = 4;

        // Ensure API services include StatsService and RoutingService
        if (!isset($config['api'])) {
            $config['api'] = ['tag' => 'api', 'services' => []];
        }
        if (!isset($config['api']['services'])) {
            $config['api']['services'] = [];
        }
        if (!in_array('StatsService', $config['api']['services'])) {
            $config['api']['services'][] = 'StatsService';
        }
        if (!in_array('RoutingService', $config['api']['services'])) {
            $config['api']['services'][] = 'RoutingService';
        }

        // Ensure blocked outbound exists for IP blocking
        if (!isset($config['outbounds'])) {
            $config['outbounds'] = [];
        }
        $hasBlocked = false;
        foreach ($config['outbounds'] as $ob) {
            if (($ob['tag'] ?? '') === 'blocked') {
                $hasBlocked = true;
                break;
            }
        }
        if (!$hasBlocked) {
            $config['outbounds'][] = ['protocol' => 'blackhole', 'tag' => 'blocked'];
        }

        // Ensure main inbound has a tag for routing rules
        if (!isset($config['inbounds'][0]['tag'])) {
            $config['inbounds'][0]['tag'] = 'vless-in';
        }

        // Assuming VLESS structure: inbounds[0] -> settings -> clients

        if (!isset($config['inbounds'][0]['settings']['clients'])) {
            // Might be different structure? But we stick to standard Amnezia XRay config
            if (!isset($config['inbounds'][0]['settings'])) {
                $config['inbounds'][0]['settings'] = [];
            }
            if (!isset($config['inbounds'][0]['settings']['clients'])) {
                $config['inbounds'][0]['settings']['clients'] = [];
            }
        }

        // Check if client exists
        $clients = &$config['inbounds'][0]['settings']['clients'];
        $duplicateFound = false;
        foreach ($clients as $k => $c) {
            if (($c['id'] ?? '') === $clientId) {
                // Already exists by ID (exact match)
                Logger::appendInstall($server->getId(), "Client $clientId already exists in X-Ray config");
                return ['success' => true, 'message' => 'Client already exists'];
            }
            if (($c['email'] ?? '') === (!empty($options['login']) ? $options['login'] : $clientId)) {
                // Email conflict! (Different ID but same email)
                // This happens if user re-adds a client with same login but new UUID (after deleting from DB)
                Logger::appendInstall($server->getId(), "Client email already exists in X-Ray config. Updating ID/Level.");

                // Update existing client entry with new UUID
                $clients[$k]['id'] = $clientId;
                $clients[$k]['level'] = 0; // Ensure level 0

                $duplicateFound = true;
                break;
            }
        }

        if (!$duplicateFound) {
            // Add new client (no conflict)
            $email = !empty($options['login']) ? $options['login'] : $clientId;
            $newClient = ['id' => $clientId, 'email' => $email];

            // Detect flow from other clients or default
            $flow = 'xtls-rprx-vision'; // Default for Reality
            if (!empty($clients)) {
                if (isset($clients[0]['flow'])) {
                    $flow = $clients[0]['flow'];
                }
            }
            $newClient['flow'] = $flow;
            $newClient['level'] = 0; // Explicitly set level 0

            $clients[] = $newClient;
        }

        // Fix JSON encoding issues (empty objects becoming arrays)
        if (isset($config['stats']) && empty($config['stats'])) {
            $config['stats'] = new stdClass();
        }
        if (isset($config['policy']['levels']) && is_array($config['policy']['levels'])) {
            // Check if it's an indexed array (0, 1...) which is wrong for X-ray levels map
            if (array_keys($config['policy']['levels']) === range(0, count($config['policy']['levels']) - 1)) {
                $newLevels = new stdClass();
                foreach ($config['policy']['levels'] as $idx => $lvl) {
                    $newLevels->{(string) $idx} = $lvl;
                }
                $config['policy']['levels'] = $newLevels;
            } elseif (empty($config['policy']['levels'])) {
                $config['policy']['levels'] = new stdClass();
            }
        } else {
            if (!isset($config['policy'])) {
                $config['policy'] = new stdClass();
            }
            if (!isset($config['policy']['levels'])) {
                $config['policy']['levels'] = new stdClass();
            }
        }

        // Enforce Level 0 Policy with online tracking
        if (!isset($config['policy']['levels']->{'0'})) {
            $config['policy']['levels']->{'0'} = new stdClass();
        }
        $level0 = $config['policy']['levels']->{'0'};
        // Cast to object if array
        if (is_array($level0)) {
            $level0 = (object) $level0;
            $config['policy']['levels']->{'0'} = $level0;
        }

        // Set restriction parameters (statsUserOnline enables connection counting)
        $level0->handshake = 4;
        $level0->connIdle = 300;
        $level0->uplinkOnly = 2;
        $level0->downlinkOnly = 5;
        $level0->statsUserUplink = true;
        $level0->statsUserDownlink = true;
        $level0->statsUserOnline = true; // Enable online tracking for enforcement
        $level0->bufferSize = 4;
        // It's an assoc array, duplicate it to stdClass to ensure object encoding
        $config['policy']['levels'] = (object) $config['policy']['levels'];


        // 3. Write config back
        $newJson = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $b64 = base64_encode($newJson);
        $writeCmd = "docker exec -i " . escapeshellarg($containerName) . " sh -c 'echo \"$b64\" | base64 -d > /opt/amnezia/xray/server.json'";

        $server->executeCommand($writeCmd, true);

        // 4. Restart container
        $server->executeCommand("docker restart " . escapeshellarg($containerName), true);

        Logger::appendInstall($server->getId(), "Updated X-Ray config and restarted container");

        return ['success' => true];
    }

    /**
     * Sync all active clients from DB to the Container configuration
     */
    private static function syncClientsToContainer(VpnServer $server, array $protocol): void
    {
        $serverId = $server->getId();
        $pdo = DB::conn();

        // Fetch active clients
        $stmt = $pdo->prepare("SELECT * FROM vpn_clients WHERE server_id = ? AND status = 'active'");
        $stmt->execute([$serverId]);
        $clients = $stmt->fetchAll();

        if (empty($clients)) {
            return;
        }

        $serverData = $server->getData();
        $metadata = $protocol['definition']['metadata'] ?? [];
        $containerName = $metadata['container_name'] ?? $serverData['container_name'] ?? 'amnezia-awg';
        // AWG2: try awg0.conf first (standard), fall back to wg0.conf (legacy)
        $isAwg2 = (stripos($containerName, 'awg2') !== false || ($protocol['slug'] ?? '') === 'awg2');
        $configDir = '/opt/amnezia/awg';
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $conf = $server->executeCommand("docker exec -i $containerName cat {$configDir}/{$configFile}", true);
        if ($isAwg2 && (!$conf || strpos($conf, '[Interface]') === false)) {
            $configFile = 'wg0.conf';
            $conf = $server->executeCommand("docker exec -i $containerName cat {$configDir}/{$configFile}", true);
        }
        if (!$conf)
            return;

        $newPeersBlock = "";
        $count = 0;

        foreach ($clients as $client) {
            $ip = $client['client_ip'];
            // Check if peer already exists (simple check by IP)
            if (strpos($conf, $ip) !== false) {
                continue;
            }

            // Append Peer
            $newPeersBlock .= "\n[Peer]\n";
            $newPeersBlock .= "PublicKey = " . $client['public_key'] . "\n";
            if (!empty($client['preshared_key'])) {
                $newPeersBlock .= "PresharedKey = " . $client['preshared_key'] . "\n";
            }
            // Use AllowedIPs from DB or default to /32
            $allowed = $client['allowed_ips'] ?? "$ip/32";
            $newPeersBlock .= "AllowedIPs = $allowed\n";
            $count++;
        }

        if ($count > 0) {
            Logger::appendInstall($serverId, "Syncing $count existing clients to server config");
            $conf .= $newPeersBlock;
            $escaped = addslashes($conf);
            $server->executeCommand("docker exec -i $containerName sh -c 'echo \"$escaped\" > {$configDir}/{$configFile}'", true);

            // Reload interface
            $server->executeCommand("docker exec -i $containerName wg-quick down wg0 || true", true);
            $server->executeCommand("docker exec -i $containerName wg-quick up wg0", true);
        }
    }

    /**
     * Resolve protocol ID from protocol array, looking up by slug if needed
     */
    private static function resolveProtocolId(array $protocol): int
    {
        $pid = (int) ($protocol['id'] ?? 0);
        if (!$pid) {
            $slug = $protocol['slug'] ?? '';
            if ($slug === '') {
                return 0;
            }
            try {
                $pdo = DB::conn();
                $stmt = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
                $stmt->execute([$slug]);
                $pid = (int) $stmt->fetchColumn();
            } catch (Throwable $e) {
                return 0;
            }
        }
        return $pid;
    }

    /**
     * Detect existing X-Ray (VLESS Reality) installation on the server
     */
    private static function detectBuiltinXray(VpnServer $server, array $protocol): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $containerName = $metadata['container_name'] ?? 'amnezia-xray';
        $containerFilter = escapeshellarg('^' . $containerName . '$');
        $containerArg = escapeshellarg($containerName);

        $containerListRaw = trim($server->executeCommand("docker ps -a --filter name={$containerFilter} --format '{{.Names}}'", true));
        if ($containerListRaw === '') {
            return [
                'status' => 'absent',
                'message' => 'Контейнер X-Ray не найден на сервере'
            ];
        }

        if (preg_match('/docker: command not found|command not found|cannot connect to the docker daemon|permission denied/i', $containerListRaw)) {
            return [
                'status' => 'absent',
                'message' => 'Docker CLI недоступен на сервере',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerListRaw,
                ]
            ];
        }

        $containerNames = array_values(array_filter(array_map('trim', preg_split('/\R+/', $containerListRaw))));
        if (!in_array($containerName, $containerNames, true)) {
            return [
                'status' => 'absent',
                'message' => 'Контейнер X-Ray не найден на сервере'
            ];
        }

        $containerState = trim($server->executeCommand("docker inspect --format '{{.State.Status}}' {$containerArg}", true));

        // Read X-Ray config
        $configRaw = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/xray/server.json 2>/dev/null", true);
        if (trim($configRaw) === '') {
            $configRaw = $server->executeCommand("docker exec -i {$containerArg} cat /etc/xray/config.json 2>/dev/null", true);
        }

        if (trim($configRaw) === '') {
            return [
                'status' => 'partial',
                'message' => 'Контейнер X-Ray найден, но конфигурация server.json отсутствует',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerState,
                ]
            ];
        }

        $config = json_decode(trim($configRaw), true);
        if (!is_array($config)) {
            return [
                'status' => 'partial',
                'message' => 'Не удалось разобрать JSON конфигурации X-Ray',
                'details' => [
                    'container_name' => $containerName,
                    'container_status' => $containerState,
                ]
            ];
        }

        // Extract port, clients, Reality keys
        $inbounds = $config['inbounds'] ?? [];
        $port = 443;
        $xrayClients = [];
        $realityPublicKey = null;
        $realityPrivateKey = null;
        $realityShortId = null;
        $realityServerName = null;

        if (is_array($inbounds) && !empty($inbounds)) {
            $port = (int) ($inbounds[0]['port'] ?? 443);
            $settings = $inbounds[0]['settings'] ?? [];
            $xrayClients = $settings['clients'] ?? [];

            $stream = $inbounds[0]['streamSettings'] ?? [];
            if (is_array($stream) && ($stream['security'] ?? '') === 'reality') {
                $rs = $stream['realitySettings'] ?? [];
                $serverNames = $rs['serverNames'] ?? ($rs['serverName'] ?? []);
                $shortIds = $rs['shortIds'] ?? ($rs['shortId'] ?? []);
                $realityServerName = is_array($serverNames) ? ($serverNames[0] ?? null) : (is_string($serverNames) ? $serverNames : null);
                $realityShortId = is_array($shortIds) ? ($shortIds[0] ?? null) : (is_string($shortIds) ? $shortIds : null);
                $realityPrivateKey = $rs['privateKey'] ?? null;

                // Derive public key from private
                if (is_string($realityPrivateKey) && $realityPrivateKey !== '' && function_exists('sodium_crypto_scalarmult_base')) {
                    $b64 = strtr($realityPrivateKey, '-_', '+/');
                    $bin = base64_decode($b64, true);
                    if ($bin === false) {
                        $bin = base64_decode($realityPrivateKey, true);
                    }
                    if (is_string($bin) && strlen($bin) === 32) {
                        $pub = sodium_crypto_scalarmult_base($bin);
                        $realityPublicKey = rtrim(strtr(base64_encode($pub), '+/', '-_'), '=');
                    }
                }
            }
        }

        // Read clientsTable for names
        $clientsTableRaw = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/xray/clientsTable 2>/dev/null", true);
        $clientsTable = json_decode(trim($clientsTableRaw), true);
        $clientsCount = is_array($xrayClients) ? count($xrayClients) : 0;

        return [
            'status' => 'existing',
            'message' => 'Найдена установленная конфигурация X-Ray VLESS Reality',
            'details' => [
                'container_name' => $containerName,
                'container_status' => $containerState,
                'port' => $port,
                'clients' => $xrayClients,
                'clients_table' => is_array($clientsTable) ? $clientsTable : [],
                'clients_count' => $clientsCount,
                'reality_public_key' => $realityPublicKey,
                'reality_private_key' => $realityPrivateKey,
                'reality_short_id' => $realityShortId,
                'reality_server_name' => $realityServerName,
                'config' => $config,
                'summary' => sprintf('Container %s (%s), port %d, clients %d', $containerName, $containerState ?: 'unknown', $port, $clientsCount)
            ]
        ];
    }

    /**
     * Restore existing X-Ray installation: save config to DB, import clients
     */
    private static function restoreBuiltinXray(VpnServer $server, array $protocol, array $detection, array $options): array
    {
        $details = $detection['details'] ?? [];
        $containerName = $details['container_name'] ?? 'amnezia-xray';
        $containerArg = escapeshellarg($containerName);
        $serverId = $server->getId();

        // Ensure container is running
        $server->executeCommand("docker start {$containerArg} 2>/dev/null || true", true);

        // Update vpn_servers with X-Ray data
        $port = $details['port'] ?? 443;
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            UPDATE vpn_servers
            SET vpn_port = ?,
                status = ?,
                error_message = NULL,
                deployed_at = COALESCE(deployed_at, NOW())
            WHERE id = ?
        ');
        $stmt->execute([$port, 'active', $serverId]);
        $server->refresh();

        // Save protocol binding
        $pid = self::resolveProtocolId($protocol);
        if ($pid) {
            $config = [
                'server_host' => $server->getData()['host'] ?? null,
                'server_port' => $port,
                'extras' => [
                    'reality_public_key' => $details['reality_public_key'] ?? null,
                    'reality_private_key' => $details['reality_private_key'] ?? null,
                    'reality_short_id' => $details['reality_short_id'] ?? null,
                    'reality_server_name' => $details['reality_server_name'] ?? null,
                    'container_name' => $containerName,
                ]
            ];
            $stmt2 = $pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data, applied_at, created_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE config_data = VALUES(config_data), applied_at = NOW()');
            $stmt2->execute([$serverId, $pid, json_encode($config)]);
        }

        // Import X-Ray clients into database
        $xrayClients = $details['clients'] ?? [];
        $clientsTable = $details['clients_table'] ?? [];
        $serverData = $server->getData();
        $imported = 0;

        // Build name lookup from clientsTable
        $nameById = [];
        if (is_array($clientsTable)) {
            foreach ($clientsTable as $entry) {
                $cid = $entry['clientId'] ?? '';
                $cname = $entry['userData']['clientName'] ?? null;
                if ($cid !== '' && $cname) {
                    $nameById[$cid] = $cname;
                }
            }
        }

        if (is_array($xrayClients)) {
            foreach ($xrayClients as $xClient) {
                $uuid = $xClient['id'] ?? '';
                if ($uuid === '') continue;

                // Check if client already exists by public_key (UUID used as identifier)
                $chk = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND public_key = ?');
                $chk->execute([$serverId, $uuid]);
                if ($chk->fetch()) {
                    continue;
                }

                // Also check by name/email
                $email = $xClient['email'] ?? '';
                if ($email !== '') {
                    $chk2 = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND name = ?');
                    $chk2->execute([$serverId, $email]);
                    if ($chk2->fetch()) {
                        continue;
                    }
                }

                $name = $nameById[$uuid] ?? ($email !== '' ? $email : 'xray-' . substr($uuid, 0, 8));

                // X-Ray config does not store per-client tunnel IP like WireGuard.
                // Keep client_ip deterministic from config client id (UUID) during restore.
                $clientIp = $uuid;

                // Generate VLESS config URL for the client
                $host = $serverData['host'] ?? '';
                $realityPub = $details['reality_public_key'] ?? '';
                $shortId = $details['reality_short_id'] ?? '';
                $sni = $details['reality_server_name'] ?? '';
                $flow = $xClient['flow'] ?? 'xtls-rprx-vision';

                $vlessUrl = sprintf(
                    'vless://%s@%s:%d?type=tcp&security=reality&pbk=%s&fp=chrome&sni=%s&sid=%s&spx=%%2F&flow=%s#%s',
                    $uuid,
                    $host,
                    $port,
                    urlencode($realityPub),
                    urlencode($sni),
                    urlencode($shortId),
                    urlencode($flow),
                    urlencode($name)
                );

                $ins = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, protocol_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
                $ins->execute([
                    $serverId,
                    $serverData['user_id'] ?? null,
                    $name,
                    $clientIp,
                    $uuid,
                    '',
                    '',
                    $vlessUrl,
                    $pid ?: null,
                    'active'      // Import as active since they work on the server
                ]);
                $imported++;
                Logger::appendInstall($serverId, "Imported X-Ray client: {$name} ({$uuid})");
            }
        }

        Logger::appendInstall($serverId, "X-Ray restore complete: imported {$imported} clients");

        return [
            'success' => true,
            'mode' => 'restore',
            'message' => 'Существующая конфигурация X-Ray восстановлена',
            'port' => $port,
            'clients_count' => count($xrayClients),
            'imported_clients' => $imported,
            'reality_public_key' => $details['reality_public_key'] ?? null,
        ];
    }

    /**
     * Import existing AWG clients from server into database (called during activate with existing config)
     */
    private static function importExistingAwgClients(VpnServer $server, array $protocol, array $detection): void
    {
        $details = $detection['details'] ?? [];
        $containerName = $details['container_name'] ?? 'amnezia-awg';
        $containerArg = escapeshellarg($containerName);
        $serverId = $server->getId();
        $pdo = DB::conn();
        $serverData = $server->getData();
        $pid = self::resolveProtocolId($protocol);

        // AWG2: try awg0.conf first (standard), fall back to wg0.conf (legacy)
        $isAwg2 = (stripos($containerName, 'awg2') !== false || ($protocol['slug'] ?? '') === 'awg2');
        $configDir = '/opt/amnezia/awg';
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true);
        if ($isAwg2 && (trim($wgConfig) === '' || strpos($wgConfig, '[Interface]') === false)) {
            $configFile = 'wg0.conf';
            $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/{$configFile} 2>/dev/null", true);
        }
        $tableRaw = $server->executeCommand("docker exec -i {$containerArg} cat {$configDir}/clientsTable 2>/dev/null", true);
        $clientsTable = json_decode(trim($tableRaw), true);

        // Build name lookup
        $nameByPub = [];
        if (is_array($clientsTable)) {
            foreach ($clientsTable as $entry) {
                $cid = $entry['clientId'] ?? '';
                $uname = $entry['userData']['clientName'] ?? null;
                if ($cid !== '' && $uname) {
                    $nameByPub[$cid] = $uname;
                }
            }
        }

        $imported = 0;
        if (trim($wgConfig) !== '') {
            $pattern = '/\[Peer\][^\[]*?PublicKey\s*=\s*(.+?)\s*[\r\n]+[\s\S]*?AllowedIPs\s*=\s*(.+?)(?:\r?\n|$)/';
            if (preg_match_all($pattern, $wgConfig, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $pub = trim($m[1]);
                    $allowed = trim($m[2]);
                    $clientIp = null;
                    foreach (explode(',', $allowed) as $ipSpec) {
                        $ipSpec = trim($ipSpec);
                        if (preg_match('/^([0-9\.]+)\/32$/', $ipSpec, $mm)) {
                            $clientIp = $mm[1];
                            break;
                        }
                    }
                    if (!$clientIp) continue;

                    // Check if client already exists
                    $chk = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND (client_ip = ? OR public_key = ?)');
                    $chk->execute([$serverId, $clientIp, $pub]);
                    if ($chk->fetch()) continue;

                    $name = $nameByPub[$pub] ?? ('import-' . str_replace('.', '_', $clientIp));
                    $ins = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, protocol_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
                    $ins->execute([
                        $serverId,
                        $serverData['user_id'] ?? null,
                        $name,
                        $clientIp,
                        $pub,
                        '',
                        $details['preshared_key'] ?? null,
                        '',
                        $pid ?: null,
                        'active'  // Import as active since they exist on the server
                    ]);
                    $imported++;
                    Logger::appendInstall($serverId, "Imported AWG client: {$name} ({$clientIp})");
                }
            }
        }

        Logger::appendInstall($serverId, "AWG client import complete: imported {$imported} clients");
    }

    // ─────────────────────────────────────────────────────────────────
    // Cloudflare WARP — builtin detection, uninstall, status
    // WARP runs as a systemd service (warp-svc), NOT as a Docker container
    // ─────────────────────────────────────────────────────────────────

    /**
     * Detect existing Cloudflare WARP installation on the server
     */
    private static function detectBuiltinWarp(VpnServer $server, array $protocol): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $proxyPort = $metadata['proxy_port'] ?? 40000;

        // Check if warp-cli binary exists
        $warpCliCheck = trim($server->executeCommand('command -v warp-cli 2>/dev/null || echo ""', true));
        if ($warpCliCheck === '') {
            return [
                'status' => 'absent',
                'message' => 'Cloudflare WARP не установлен на сервере'
            ];
        }

        // Check warp-svc service status
        $svcStatus = trim($server->executeCommand('systemctl is-active warp-svc 2>/dev/null || echo "inactive"', true));

        // Get WARP connection status
        $warpStatus = trim($server->executeCommand('warp-cli --accept-tos status 2>/dev/null || echo "error"', true));

        $isConnected = (bool) preg_match('/Connected/i', $warpStatus);
        $isRegistered = !preg_match('/Registration Missing|unregistered/i', $warpStatus);

        if (!$isRegistered) {
            return [
                'status' => 'partial',
                'message' => 'WARP установлен, но не зарегистрирован',
                'details' => [
                    'warp_cli' => $warpCliCheck,
                    'service_status' => $svcStatus,
                    'warp_status' => $warpStatus,
                ]
            ];
        }

        // Get WARP mode
        $warpMode = '';
        if (preg_match('/Mode:\s*(\S+)/i', $warpStatus, $m)) {
            $warpMode = $m[1];
        }

        // Get WARP account info
        $accountInfo = trim($server->executeCommand('warp-cli --accept-tos registration show 2>/dev/null || echo ""', true));
        $accountId = '';
        if (preg_match('/Account\s*ID[:\s]+([a-zA-Z0-9-]+)/i', $accountInfo, $m)) {
            $accountId = $m[1];
        }

        // Check if proxy port is listening
        $portListening = trim($server->executeCommand(
            'ss -tlnp 2>/dev/null | grep ":' . (int) $proxyPort . '" | head -1 || echo ""', true
        ));

        // Get WARP IP (best-effort)
        $warpIp = '';
        if ($isConnected && $portListening !== '') {
            $traceOut = trim($server->executeCommand(
                'curl -x socks5h://127.0.0.1:' . (int) $proxyPort . ' -s --max-time 5 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""', true
            ));
            if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                $warpIp = $m[1];
            }
        }

        return [
            'status' => 'existing',
            'message' => 'Cloudflare WARP установлен и ' . ($isConnected ? 'подключён' : 'отключён'),
            'details' => [
                'warp_cli' => $warpCliCheck,
                'service_status' => $svcStatus,
                'warp_status_raw' => $warpStatus,
                'connected' => $isConnected,
                'registered' => $isRegistered,
                'warp_mode' => $warpMode,
                'warp_proxy_port' => (int) $proxyPort,
                'warp_ip' => $warpIp,
                'warp_account' => $accountId,
                'port_listening' => $portListening !== '',
                'summary' => sprintf(
                    'WARP %s, mode=%s, proxy=%s:%d%s',
                    $isConnected ? 'connected' : 'disconnected',
                    $warpMode ?: 'unknown',
                    '127.0.0.1',
                    (int) $proxyPort,
                    $warpIp !== '' ? ', exit_ip=' . $warpIp : ''
                )
            ]
        ];
    }

    /**
     * Uninstall Cloudflare WARP from the server (systemd service, not Docker)
     */
    private static function uninstallBuiltinWarp(VpnServer $server, array $protocol, array $options = []): array
    {
        $serverId = $server->getId();
        Logger::appendInstall($serverId, 'Uninstalling Cloudflare WARP (full cleanup)...');

        try {
            // Run entire uninstall as a single remote script to avoid SSH escaping issues
            $script = <<<'BASH'
#!/bin/bash
echo "WARP_UNINSTALL_START"

# 1. Restore X-Ray config
XRAY_NAME=$(docker ps 2>/dev/null | grep -i xray | awk '{ print $NF }' | head -1)
if [ -n "$XRAY_NAME" ]; then
  # Try server.json first (actual runtime config), then config.json
  XRAY_CFG_PATH=""
  for P in /opt/amnezia/xray/server.json /etc/xray/config.json; do
    CONTENT=$(docker exec "$XRAY_NAME" cat "$P" 2>/dev/null || echo "")
    if [ -n "$CONTENT" ] && echo "$CONTENT" | grep -q "warp-out"; then
      XRAY_CFG_PATH="$P"
      XRAY_CFG="$CONTENT"
      break
    fi
  done
  if [ -n "$XRAY_CFG_PATH" ]; then
    echo "$XRAY_CFG" | python3 -c "
import sys, json
try:
    cfg = json.load(sys.stdin)
    cfg['outbounds'] = [o for o in cfg.get('outbounds',[]) if o.get('tag') != 'warp-out']
    if 'routing' in cfg:
        cfg['routing']['rules'] = [r for r in cfg['routing'].get('rules',[]) if r.get('outboundTag') != 'warp-out']
        if not cfg['routing']['rules']: del cfg['routing']
    print(json.dumps(cfg, indent=2))
except: pass
" 2>/dev/null | docker exec -i "$XRAY_NAME" tee "$XRAY_CFG_PATH" > /dev/null 2>&1
    docker restart "$XRAY_NAME" 2>/dev/null || true
    echo "xray_restored"
  fi
fi

# 2. Remove DNAT rules
DOCKER_GW=$(docker network inspect bridge 2>/dev/null | grep Gateway | head -1 | awk -F'"' '{print $4}')
if [ -z "$DOCKER_GW" ]; then DOCKER_GW="172.17.0.1"; fi
iptables -t nat -D OUTPUT -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
iptables -t nat -D PREROUTING -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
iptables -t nat -D PREROUTING -d "$DOCKER_GW" -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true
echo "dnat_removed"

# 3. Remove REDSOCKS_WARP chain
SUBNETS=$(cat /var/lib/cloudflare-warp/routed_subnets 2>/dev/null || echo "10.8.1.0/24 10.0.0.0/24")
for S in $SUBNETS; do
  iptables -t nat -D PREROUTING -s "$S" -p tcp -j REDSOCKS_WARP 2>/dev/null || true
done
iptables -t nat -F REDSOCKS_WARP 2>/dev/null || true
iptables -t nat -X REDSOCKS_WARP 2>/dev/null || true
echo "iptables_cleaned"

# 4. Remove redsocks
systemctl stop redsocks-warp 2>/dev/null || true
systemctl disable redsocks-warp 2>/dev/null || true
rm -f /etc/systemd/system/redsocks-warp.service
rm -rf /etc/redsocks
systemctl daemon-reload 2>/dev/null || true
echo "redsocks_removed"

# 5. Disconnect and remove WARP
warp-cli --accept-tos disconnect 2>/dev/null || true
warp-cli --accept-tos registration delete 2>/dev/null || true
systemctl stop warp-svc 2>/dev/null || true
systemctl disable warp-svc 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get remove -y cloudflare-warp >/dev/null 2>&1 || true
apt-get autoremove -y >/dev/null 2>&1 || true
echo "warp_removed"

# 6. Cleanup
rm -rf /var/lib/cloudflare-warp 2>/dev/null || true
rm -f /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null || true
rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
rm -f /etc/sysctl.d/99-warp.conf 2>/dev/null || true
sysctl -w net.ipv4.conf.docker0.route_localnet=0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.route_localnet=0 2>/dev/null || true

# 7. Save iptables
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo "WARP_UNINSTALL_DONE"
BASH;

            Logger::appendInstall($serverId, 'WARP uninstall: writing script to server...');
            $b64 = base64_encode($script);
            // Phase 1: write script file
            $server->executeCommand("echo " . $b64 . " | base64 -d > /tmp/_warp_uninstall.sh && chmod +x /tmp/_warp_uninstall.sh", true);
            Logger::appendInstall($serverId, 'WARP uninstall: executing script...');
            // Phase 2: execute script
            $output = $server->executeCommand("bash /tmp/_warp_uninstall.sh 2>&1; rm -f /tmp/_warp_uninstall.sh", true);
            $outputStr = (string) $output;
            Logger::appendInstall($serverId, 'WARP uninstall output: ' . substr(str_replace(["\r", "\n"], ' ', $outputStr), 0, 500));

            $success = strpos($outputStr, 'WARP_UNINSTALL_DONE') !== false;

            if ($success) {
                Logger::appendInstall($serverId, 'WARP uninstalled successfully (full cleanup)');
            } else {
                Logger::appendInstall($serverId, 'WARP uninstall script may have partially failed');
            }

            return [
                'success' => $success,
                'message' => $success ? 'Cloudflare WARP удалён' : 'WARP удалён частично, проверьте логи',
                'mode' => 'uninstall'
            ];
        } catch (Throwable $e) {
            Logger::appendInstall($serverId, 'WARP uninstall exception: ' . $e->getMessage());
            throw new Exception('WARP uninstall failed: ' . $e->getMessage());
        }
    }

    /**
     * Remove WARP outbound and routing rules from X-Ray config
     * Restores X-Ray to direct (freedom) outbound mode
     */
    private static function unpatchXrayFromWarp(VpnServer $server): void
    {
        $serverId = $server->getId();

        try {
            $xrayContainer = trim($server->executeCommand(
                'docker ps 2>/dev/null | grep -i xray | awk \'{ print $NF }\' | head -1 || echo ""', true
            ));
            if ($xrayContainer === '') {
                Logger::appendInstall($serverId, 'WARP uninstall: no X-Ray container, skipping config restore');
                return;
            }

            $containerArg = escapeshellarg($xrayContainer);
            $configRaw = trim($server->executeCommand(
                "docker exec -i {$containerArg} cat /etc/xray/config.json 2>/dev/null", true
            ));
            if ($configRaw === '') {
                return;
            }

            $config = json_decode($configRaw, true);
            if (!is_array($config)) {
                return;
            }

            // Remove warp-out outbound
            $outbounds = $config['outbounds'] ?? [];
            $hadWarp = false;
            $newOutbounds = [];
            foreach ($outbounds as $ob) {
                if (($ob['tag'] ?? '') === 'warp-out') {
                    $hadWarp = true;
                    continue; // skip warp-out
                }
                $newOutbounds[] = $ob;
            }

            if (!$hadWarp) {
                Logger::appendInstall($serverId, 'WARP uninstall: X-Ray has no warp-out outbound, nothing to restore');
                return;
            }

            $config['outbounds'] = $newOutbounds;

            // Remove warp routing rules
            if (isset($config['routing']['rules']) && is_array($config['routing']['rules'])) {
                $newRules = [];
                foreach ($config['routing']['rules'] as $rule) {
                    if (($rule['outboundTag'] ?? '') === 'warp-out') {
                        continue; // skip warp routing rule
                    }
                    $newRules[] = $rule;
                }
                $config['routing']['rules'] = $newRules;

                // If routing is empty, remove it entirely for clean config
                if (empty($config['routing']['rules'])) {
                    unset($config['routing']);
                }
            }

            // Write back config
            $newConfig = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $b64Config = base64_encode($newConfig);
            $server->executeCommand(
                "echo {$b64Config} | base64 -d | docker exec -i {$containerArg} tee /etc/xray/config.json > /dev/null", true
            );

            // Restart X-Ray
            $server->executeCommand("docker restart {$containerArg} 2>/dev/null || true", true);

            Logger::appendInstall($serverId, 'WARP uninstall: X-Ray config restored (warp-out removed), container restarted');

        } catch (\Throwable $e) {
            Logger::appendInstall($serverId, 'WARP uninstall: X-Ray restore failed (non-fatal): ' . $e->getMessage());
        }
    }

    /**
     * Get WARP runtime status from a server (used by API endpoint)
     * Returns connection status, proxy port, exit IP, and account info
     */
    public static function getWarpStatus(VpnServer $server): array
    {
        $warpCliCheck = trim($server->executeCommand('command -v warp-cli 2>/dev/null || echo ""', true));
        if ($warpCliCheck === '') {
            return [
                'installed' => false,
                'connected' => false,
                'message' => 'WARP не установлен'
            ];
        }

        $svcStatus = trim($server->executeCommand('systemctl is-active warp-svc 2>/dev/null || echo "inactive"', true));
        $warpStatus = trim($server->executeCommand('warp-cli --accept-tos status 2>/dev/null || echo "error"', true));
        $isConnected = (bool) preg_match('/Connected/i', $warpStatus);

        $warpMode = '';
        if (preg_match('/Mode:\s*(\S+)/i', $warpStatus, $m)) {
            $warpMode = $m[1];
        }

        // Get proxy port from settings
        $proxyPortRaw = trim($server->executeCommand('warp-cli --accept-tos settings 2>/dev/null | grep -i "proxy port" || echo ""', true));
        $proxyPort = 40000;
        if (preg_match('/(\d+)/', $proxyPortRaw, $m)) {
            $proxyPort = (int) $m[1];
        }

        $warpIp = '';
        $portListening = false;
        if ($isConnected) {
            $portCheck = trim($server->executeCommand(
                'ss -tlnp 2>/dev/null | grep ":' . $proxyPort . '" | head -1 || echo ""', true
            ));
            $portListening = $portCheck !== '';

            if ($portListening) {
                $traceOut = trim($server->executeCommand(
                    'curl -x socks5h://127.0.0.1:' . $proxyPort . ' -s --max-time 5 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo ""', true
                ));
                if (preg_match('/ip=([^\s]+)/', $traceOut, $m)) {
                    $warpIp = $m[1];
                }
            }
        }

        return [
            'installed' => true,
            'connected' => $isConnected,
            'service_status' => $svcStatus,
            'mode' => $warpMode,
            'proxy_port' => $proxyPort,
            'proxy_listening' => $portListening,
            'warp_ip' => $warpIp,
            'warp_status_raw' => $warpStatus,
        ];
    }

    /**
     * Auto-patch X-Ray config to route outbound traffic through WARP SOCKS5 proxy
     * X-Ray runs in Docker bridge mode, so we need:
     * 1. iptables DNAT: docker_gateway:40000 → 127.0.0.1:40000
     * 2. X-Ray outbound: socks5 → docker_gateway:40000
     */
    private static function patchXrayForWarp(VpnServer $server): void
    {
        $serverId = $server->getId();

        try {
            // Find X-Ray container
            $xrayContainer = trim($server->executeCommand(
                'docker ps 2>/dev/null | grep -i xray | awk \'{ print $NF }\' | head -1 || echo ""', true
            ));
            if ($xrayContainer === '') {
                Logger::appendInstall($serverId, 'WARP X-Ray patch: no X-Ray container found, skipping');
                return;
            }

            Logger::appendInstall($serverId, 'WARP X-Ray patch: found container ' . $xrayContainer);

            // Get Docker bridge gateway IP
            $dockerGw = trim($server->executeCommand(
                'docker network inspect bridge 2>/dev/null | grep Gateway | head -1 | sed \'s/.*"Gateway"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/\' || echo "172.17.0.1"', true
            ));
            if ($dockerGw === '') {
                $dockerGw = '172.17.0.1';
            }

            // Setup iptables DNAT so Docker containers can reach WARP via gateway IP
            $server->executeCommand(
                'iptables -t nat -D OUTPUT -d ' . escapeshellarg($dockerGw) . ' -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true', true
            );
            $server->executeCommand(
                'iptables -t nat -A OUTPUT -d ' . escapeshellarg($dockerGw) . ' -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true', true
            );
            // Also allow in PREROUTING for container-originated traffic
            $server->executeCommand(
                'iptables -t nat -D PREROUTING -d ' . escapeshellarg($dockerGw) . ' -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true', true
            );
            $server->executeCommand(
                'iptables -t nat -A PREROUTING -d ' . escapeshellarg($dockerGw) . ' -p tcp --dport 40000 -j DNAT --to-destination 127.0.0.1:40000 2>/dev/null || true', true
            );
            Logger::appendInstall($serverId, 'WARP X-Ray patch: iptables DNAT ' . $dockerGw . ':40000 → 127.0.0.1:40000');

            // Enable route_localnet so DNAT to 127.0.0.1 works for Docker container traffic
            $server->executeCommand('sysctl -w net.ipv4.conf.docker0.route_localnet=1 2>/dev/null || true', true);
            $server->executeCommand('sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || true', true);
            $server->executeCommand('grep -q route_localnet /etc/sysctl.d/99-warp.conf 2>/dev/null || { mkdir -p /etc/sysctl.d; echo "net.ipv4.conf.docker0.route_localnet=1" >> /etc/sysctl.d/99-warp.conf; echo "net.ipv4.conf.all.route_localnet=1" >> /etc/sysctl.d/99-warp.conf; }', true);

            // Read X-Ray config — try /opt/amnezia/xray/server.json first (actual runtime config),
            // fall back to /etc/xray/config.json (Docker volume mount)
            $containerArg = escapeshellarg($xrayContainer);
            $xrayConfigPath = '/opt/amnezia/xray/server.json';
            $configRaw = trim($server->executeCommand(
                "docker exec -i {$containerArg} cat {$xrayConfigPath} 2>/dev/null", true
            ));
            if ($configRaw === '' || $configRaw === 'cat: can\'t open') {
                $xrayConfigPath = '/etc/xray/config.json';
                $configRaw = trim($server->executeCommand(
                    "docker exec -i {$containerArg} cat {$xrayConfigPath} 2>/dev/null", true
                ));
            }
            if ($configRaw === '') {
                Logger::appendInstall($serverId, 'WARP X-Ray patch: could not read X-Ray config');
                return;
            }
            Logger::appendInstall($serverId, 'WARP X-Ray patch: using config ' . $xrayConfigPath);

            $config = json_decode($configRaw, true);
            if (!is_array($config)) {
                Logger::appendInstall($serverId, 'WARP X-Ray patch: config.json is not valid JSON');
                return;
            }

            // Check if warp-out already exists
            $outbounds = $config['outbounds'] ?? [];
            foreach ($outbounds as $ob) {
                if (($ob['tag'] ?? '') === 'warp-out') {
                    Logger::appendInstall($serverId, 'WARP X-Ray patch: warp-out outbound already exists');
                    return;
                }
            }

            // Tag existing freedom outbound as "direct" if not tagged
            foreach ($outbounds as &$ob) {
                if (($ob['protocol'] ?? '') === 'freedom' && empty($ob['tag'])) {
                    $ob['tag'] = 'direct';
                }
            }
            unset($ob);

            // Add warp-out SOCKS5 outbound
            $outbounds[] = [
                'tag' => 'warp-out',
                'protocol' => 'socks',
                'settings' => [
                    'servers' => [
                        [
                            'address' => $dockerGw,
                            'port' => 40000
                        ]
                    ]
                ]
            ];

            $config['outbounds'] = $outbounds;

            // Set default routing: all traffic through warp-out
            if (!isset($config['routing'])) {
                $config['routing'] = [];
            }
            if (!isset($config['routing']['rules'])) {
                $config['routing']['rules'] = [];
            }

            // Add rule: route everything through warp-out (as first rule)
            $hasWarpRule = false;
            foreach ($config['routing']['rules'] as $rule) {
                if (($rule['outboundTag'] ?? '') === 'warp-out') {
                    $hasWarpRule = true;
                    break;
                }
            }
            if (!$hasWarpRule) {
                // Add catch-all rule at end to route through WARP
                $config['routing']['rules'][] = [
                    'type' => 'field',
                    'outboundTag' => 'warp-out',
                    'network' => 'tcp,udp'
                ];
            }

            // Write back config
            $newConfig = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $b64Config = base64_encode($newConfig);
            $server->executeCommand(
                "echo {$b64Config} | base64 -d | docker exec -i {$containerArg} tee {$xrayConfigPath} > /dev/null", true
            );

            // Restart X-Ray container
            $server->executeCommand("docker restart {$containerArg} 2>/dev/null || true", true);

            Logger::appendInstall($serverId, 'WARP X-Ray patch: outbound added to ' . $xrayConfigPath . ', container restarted');

        } catch (\Throwable $e) {
            Logger::appendInstall($serverId, 'WARP X-Ray patch failed (non-fatal): ' . $e->getMessage());
            // Non-fatal — WARP still works for AWG clients
        }
    }
}
