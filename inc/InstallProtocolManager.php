<?php
require_once __DIR__ . '/Logger.php';

class InstallProtocolManager
{
    private const DEFAULT_SLUG = 'amnezia-wg';
    private const SESSION_KEY = 'pending_deploy_decisions';

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
        $engine = self::getEngine($protocol);
        if ($engine === 'builtin_awg') {
            return self::detectBuiltinAwg($server, $protocol);
        }

        $slug = $protocol['slug'] ?? '';

        // For AWG shell-based scenarios (amnezia-wg, amnezia-wg-advanced), use builtin AWG detection
        if (self::isAwgProtocol($slug, $protocol)) {
            return self::detectBuiltinAwg($server, $protocol);
        }

        // For X-Ray VLESS, use builtin detection
        if ($slug === 'xray-vless') {
            return self::detectBuiltinXray($server, $protocol);
        }

        return self::runScript($server, $protocol, 'detect', $options);
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
            // Choose/ensure VPN UDP port for script-driven installs
            if (($protocol['slug'] ?? '') === 'xray-vless' && (!isset($options['server_port']) || !is_int($options['server_port']) || $options['server_port'] <= 0)) {
                $options['server_port'] = 443;
            }
            if (!isset($options['server_port']) || !is_int($options['server_port'])) {
                $options['server_port'] = self::chooseServerPort($server, $protocol['definition']['metadata'] ?? []);
            }
            $result = self::runScript($server, $protocol, 'install', $options);
            if (!isset($result['success'])) {
                $result['success'] = true;
            }
            Logger::appendInstall($serverId, 'Scripted install finished: ' . json_encode($result));
            $extras = [
                'vpn_port' => $result['vpn_port'] ?? ($options['server_port'] ?? null),
                'server_public_key' => $result['server_public_key'] ?? null,
                'preshared_key' => $result['preshared_key'] ?? null,
                'awg_params' => $result['awg_params'] ?? null,
            ];
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
        $engine = self::getEngine($protocol);
        if ($engine === 'builtin_awg') {
            return self::restoreBuiltinAwg($server, $protocol, $detection, $options);
        }

        $slug = $protocol['slug'] ?? '';

        // For AWG shell-based scenarios, use builtin AWG restore
        if (self::isAwgProtocol($slug, $protocol)) {
            return self::restoreBuiltinAwg($server, $protocol, $detection, $options);
        }

        // For X-Ray VLESS, use builtin restore
        if ($slug === 'xray-vless') {
            return self::restoreBuiltinXray($server, $protocol, $detection, $options);
        }

        $result = self::runScript($server, $protocol, 'restore', array_merge($options, [
            'detection' => $detection
        ]));
        if (!isset($result['success'])) {
            $result['success'] = true;
        }
        return $result;
    }

    private static function detectBuiltinAwg(VpnServer $server, array $protocol): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $serverData = $server->getData();
        $containerName = $serverData['container_name'] ?? ($metadata['container_name'] ?? 'amnezia-awg');
        $containerFilter = escapeshellarg('^' . $containerName . '$');
        $containerArg = escapeshellarg($containerName);

        $containerList = trim($server->executeCommand("docker ps -a --filter name={$containerFilter} --format '{{.Names}}'", true));
        if ($containerList === '') {
            return [
                'status' => 'absent',
                'message' => 'Контейнер AmneziaWG не найден на сервере'
            ];
        }

        $containerState = trim($server->executeCommand("docker inspect --format '{{.State.Status}}' {$containerArg}", true));

        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/wg0.conf 2>/dev/null", true);
        if (trim($wgConfig) === '') {
            return [
                'status' => 'partial',
                'message' => 'Контейнер найден, но конфигурация wg0.conf отсутствует',
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

        $publicKey = trim($server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null", true));
        $presharedKey = trim($server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null", true));

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

        $clientsRaw = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/clientsTable 2>/dev/null", true);
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

        // Try to ensure container is running and wg is up
        $server->executeCommand("docker start {$containerArg} 2>/dev/null || true", true);
        $server->executeCommand("docker exec -i {$containerArg} wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null || true", true);
        $server->executeCommand("docker exec -i {$containerArg} wg-quick up /opt/amnezia/awg/wg0.conf 2>/dev/null || true", true);

        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            UPDATE vpn_servers
            SET vpn_port = ?,
                server_public_key = ?,
                preshared_key = ?,
                awg_params = ?,
                status = ?,
                error_message = NULL,
                deployed_at = COALESCE(deployed_at, NOW())
            WHERE id = ?
        ');
        $stmt->execute([
            $details['vpn_port'] ?? null,
            $details['server_public_key'] ?? null,
            $details['preshared_key'] ?? null,
            isset($details['awg_params']) ? json_encode($details['awg_params']) : null,
            'active',
            $server->getId()
        ]);

        $server->refresh();
        $serverData = $server->getData();

        // Import existing peers from wg0.conf into database as disabled clients
        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/wg0.conf 2>/dev/null", true);
        $tableRaw = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/clientsTable 2>/dev/null", true);
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
                    $ins = $pdo->prepare('INSERT INTO vpn_clients (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, protocol_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())');
                    $ins->execute([
                        $server->getId(),
                        $serverData['user_id'] ?? null,
                        $name,
                        $clientIp,
                        $pub,
                        '',
                        $details['preshared_key'] ?? null,
                        '',
                        $pid ?: null,
                        'active'  // Import as active since they already work on the server
                    ]);
                    $restored++;
                }
            }
        }

        return [
            'success' => true,
            'mode' => 'restore',
            'message' => 'Существующая конфигурация восстановлена',
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
                // If no script and no builtin handler, we just skip it (assume not needed or manual)
                // Or throw generic error? Better return success to not break flow if not implemented for other protocols
                return ['success' => true, 'message' => 'No add_client script defined'];
            }
            throw new Exception('Скрипт ' . $phase . ' не настроен для протокола');
        }

        $context = self::buildContext($server, $protocol, $options);
        $script = self::renderTemplate($scripts, $context);
        $script = preg_replace('/<<\s*EOF\b/', "<<'EOF'", $script);
        $script = preg_replace('/\n\+\s*/', "\n", $script);
        $exportLines = self::buildExports($context);
        $wrapper = "bash <<'EOS'\nset -euo pipefail\n" . $exportLines . $script . "\nEOS";
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: executing remote script');
        $output = $server->executeCommand($wrapper, true);
        Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output size ' . strlen((string) $output) . ' bytes');
        $head = substr(str_replace(["\r", "\n"], ' ', (string) $output), 0, 280);
        if ($head !== '') {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: output head ' . $head);
        }
        $trimmed = trim($output);

        // Try JSON first
        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            Logger::appendInstall($server->getId(), strtoupper($phase) . ' phase: parsed JSON result');
            return $decoded;
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
                throw new Exception('Ошибка установки (script): ' . ($trimmed !== '' ? $trimmed : 'empty output'));
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
            'SERVER_CONTAINER' => $serverData['container_name'] ?? ($metadata['container_name'] ?? ''),
            'SERVER_PORT' => isset($serverData['vpn_port']) && (int) $serverData['vpn_port'] > 0
                ? (int) $serverData['vpn_port']
                : (isset($options['server_port']) ? (int) $options['server_port'] : ''),
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
        $awgKeys = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];
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

    private static function getEngine(array $protocol): string
    {
        $definition = $protocol['definition'] ?? [];
        if (!empty($protocol['install_script'])) {
            return 'shell';
        }
        return $definition['engine'] ?? 'builtin_awg';
    }

    /**
     * Check if a protocol is an AWG variant (by slug or install_script content)
     * Used to route shell-based AWG scenarios to builtin AWG detection/restore
     */
    private static function isAwgProtocol(string $slug, array $protocol): bool
    {
        if (in_array($slug, ['amnezia-wg', 'amnezia-wg-advanced'], true)) {
            return true;
        }
        $installScript = (string) ($protocol['install_script'] ?? '');
        if ($installScript !== '' && preg_match('/amneziavpn\/amnezia-wg|amnezia\/awg|amnezia-awg/i', $installScript)) {
            return true;
        }
        return false;
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
        $engine = self::getEngine($protocol);
        if ($engine === 'builtin_awg') {
            return self::detectBuiltinAwg($server, $protocol);
        }

        $slug = $protocol['slug'] ?? '';

        // For AWG shell-based scenarios (amnezia-wg, amnezia-wg-advanced), use builtin AWG detection
        if (self::isAwgProtocol($slug, $protocol)) {
            return self::detectBuiltinAwg($server, $protocol);
        }

        // For X-Ray VLESS, use builtin detection
        if ($slug === 'xray-vless') {
            return self::detectBuiltinXray($server, $protocol);
        }

        return self::runScript($server, $protocol, 'detect', $options);
    }

    /**
     * Uninstall a protocol from the given server. Supports builtin AWG and scripted protocols
     * Returns array with success and message keys on completion or throws on fatal error
     */
    public static function uninstall(VpnServer $server, array $protocol, array $options = []): array
    {
        $engine = self::getEngine($protocol);
        if ($engine === 'builtin_awg') {
            return self::uninstallBuiltinAwg($server, $protocol, $options);
        }

        // For script-driven protocols, try to detect AWG scenario and fallback to builtin uninstall
        $slug = $protocol['slug'] ?? '';
        if (self::isAwgProtocol($slug, $protocol)) {
            // Prefer builtin AWG uninstall by default because script variants may have CRLF issues
            // or leave behind the canonical container name, causing install conflicts.
            if (!empty($options['use_script_uninstall'])) {
                $hasScript = isset($protocol['uninstall_script']) && trim((string) $protocol['uninstall_script']) !== '';
                if ($hasScript) {
                    return self::runScript($server, $protocol, 'uninstall', $options);
                }
            }
            return self::uninstallBuiltinAwg($server, $protocol, $options);
        }

        // For other script-driven protocols, look for an "uninstall" phase in scripts
        return self::runScript($server, $protocol, 'uninstall', $options);
    }

    private static function uninstallBuiltinAwg(VpnServer $server, array $protocol, array $options = []): array
    {
        $metadata = $protocol['definition']['metadata'] ?? [];
        $serverData = $server->getData();
        $containerName = $serverData['container_name'] ?? ($metadata['container_name'] ?? 'amnezia-awg');
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
            $server->executeCommand("docker rmi amneziavpn/amnezia-wg amneziavpn/amnezia-awg 2>/dev/null || true", true);
            // Attempt to remove amnezia-dns-net network if present (best-effort)
            $server->executeCommand("docker network rm amnezia-dns-net 2>/dev/null || true", true);
            // Remove on-disk data for AWG
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
            $isAwg = $engine === 'builtin_awg' || self::isAwgProtocol($slug, $protocol);
            $isXray = $slug === 'xray-vless';

            if ($isAwg) {
                $detection = self::detectBuiltinAwg($server, $protocol);
                if (in_array($detection['status'] ?? '', ['existing', 'partial'], true)) {
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
                if (in_array($xrayDetection['status'] ?? '', ['existing', 'partial'], true)) {
                    Logger::appendInstall($serverId, 'Existing X-Ray installation detected, restoring instead of reinstalling');
                    $restoreResult = self::restoreBuiltinXray($server, $protocol, $xrayDetection, $options);
                    return array_merge($restoreResult, ['mode' => 'restore_existing']);
                }
            }

            // ── No existing installation found — proceed with fresh install ──

            if ($engine === 'builtin_awg') {
                $res = $server->runAwgInstall($options);
                Logger::appendInstall($serverId, 'Builtin AWG install finished');
                $pdo = DB::conn();
                $pid = self::resolveProtocolId($protocol);
                if ($pid) {
                    $config = [
                        'server_host' => $server->getData()['host'] ?? null,
                        'server_port' => $res['vpn_port'] ?? null,
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
            return $res;
        } catch (Throwable $e) {
            self::markServerError($serverId, $e->getMessage());
            Logger::appendInstall($serverId, 'Activate failed: ' . $e->getMessage());
            throw $e;
        }
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

        $containerName = $server->getData()['container_name'] ?? 'amnezia-awg';

        // Read existing config
        $conf = $server->executeCommand("docker exec -i $containerName cat /opt/amnezia/awg/wg0.conf", true);
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
            $server->executeCommand("docker exec -i $containerName sh -c 'echo \"$escaped\" > /opt/amnezia/awg/wg0.conf'", true);

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

        $containerList = trim($server->executeCommand("docker ps -a --filter name={$containerFilter} --format '{{.Names}}'", true));
        if ($containerList === '') {
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
                    $uuid,        // Use UUID as client_ip (unique key requires non-empty value)
                    $uuid,        // Store UUID as public_key for X-Ray clients
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

        // Read wg0.conf and clientsTable
        $wgConfig = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/wg0.conf 2>/dev/null", true);
        $tableRaw = $server->executeCommand("docker exec -i {$containerArg} cat /opt/amnezia/awg/clientsTable 2>/dev/null", true);
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
}
