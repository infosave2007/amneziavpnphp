<?php
/**
 * VPN Client Management Class
 * Handles creation and management of VPN client configurations
 * Based on amnezia_client_config_v2.php
 */
class VpnClient
{
    private $clientId;
    private $data;

    public function __construct(?int $clientId = null)
    {
        $this->clientId = $clientId;
        if ($clientId) {
            $this->load();
        }
    }

    /**
     * Load client data from database
     */
    private function load(): void
    {
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
    public static function create(int $serverId, int $userId, string $name, ?int $expiresInDays = null, ?int $protocolId = null, ?string $username = null, ?string $login = null): int
    {
        $pdo = DB::conn();

        $name = trim($name);

        // Get server data
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (!$serverData || $serverData['status'] !== 'active') {
            throw new Exception('Server is not active');
        }

        // Determine protocol before sync
        $protoRow = null;
        if ($protocolId === null) {
            $stmtProto = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
            $stmtProto->execute([$serverData['install_protocol'] ?? '']);
            $protocolId = (int) $stmtProto->fetchColumn();
        }
        if ($protocolId) {
            $stmtProto2 = $pdo->prepare('SELECT * FROM protocols WHERE id = ?');
            $stmtProto2->execute([$protocolId]);
            $protoRow = $stmtProto2->fetch();
        }
        $slug = $protoRow['slug'] ?? ($serverData['install_protocol'] ?? 'amnezia-wg');
        $protoMetadata = [];
        if ($protoRow && !empty($protoRow['definition']) && is_string($protoRow['definition'])) {
            $decodedDef = json_decode($protoRow['definition'], true);
            if (is_array($decodedDef)) {
                $protoMetadata = $decodedDef['metadata'] ?? [];
            }
        }
        $isWireguard = in_array($slug, ['amnezia-wg-advanced', 'wireguard-standard', 'amnezia-wg', 'awg2'], true);

        // Auto-sync server keys from container EVERY TIME for WireGuard protocols
        // This ensures we always use current container configuration even if it was recreated
        if ($isWireguard) {
            try {
                // For multi-protocol servers use selected protocol metadata instead of default server row.
                if (!empty($protoMetadata['container_name']) && is_string($protoMetadata['container_name'])) {
                    $serverData['container_name'] = trim($protoMetadata['container_name']);
                }
                $serverData['install_protocol'] = $slug;

                self::syncServerKeysFromContainer($server, $serverData);
                // Reload server data after sync (VpnServer caches DB row in-memory)
                $server->refresh();
                $serverData = $server->getData();
                if (!empty($protoMetadata['container_name']) && is_string($protoMetadata['container_name'])) {
                    $serverData['container_name'] = trim($protoMetadata['container_name']);
                }
                $serverData['install_protocol'] = $slug;
            } catch (Exception $e) {
                error_log('Failed to auto-sync server keys: ' . $e->getMessage());
                // Continue anyway - might fail later but let's try
            }
        }

        $clientIP = self::getNextClientIP($serverData);
        $loginBase = $login !== null && $login !== '' ? $login : $name;
        $loginBase = str_replace(' ', '_', trim($loginBase));
        $loginFinal = $loginBase;
        $suffix = 2;
        while (true) {
            $stmtChk = $pdo->prepare('SELECT COUNT(*) FROM vpn_clients WHERE server_id = ? AND name = ?');
            $stmtChk->execute([$serverId, $loginFinal]);
            if ((int) $stmtChk->fetchColumn() === 0)
                break;
            $loginFinal = $loginBase . '-' . $suffix;
            $suffix++;
        }

        if ($isWireguard) {
            $containerName = $serverData['container_name'];
            $keys = self::generateClientKeys($serverData, $name);

            // Re-fetch awg_params after possible auto-sync
            $awgParams = json_decode($serverData['awg_params'] ?? '{}', true) ?? [];

            // Build variables for template
            $vars = [
                'private_key' => $keys['private'],
                'client_ip' => $clientIP,
                'server_public_key' => $serverData['server_public_key'],
                'preshared_key' => $serverData['preshared_key'],
                'server_host' => $serverData['host'],
                'server_port' => $serverData['vpn_port'],
                'dns_servers' => $serverData['dns_servers'] ?? '1.1.1.1, 1.0.0.1',
            ];


            // Add AWG parameters (use UPPERCASE keys as extracted from container)
            // Normalize AWG params keys case-insensitively
            $cleanAwgParams = [];
            if (is_array($awgParams)) {
                foreach ($awgParams as $k => $v) {
                    $cleanAwgParams[strtoupper($k)] = $v;
                }
            }

            $defaultAwgParams = self::getAwgParamDefaults($slug);

            // Add AWG parameters (use UPPERCASE keys internal logic)
            foreach (array_keys($defaultAwgParams) as $key) {
                if (isset($cleanAwgParams[$key])) {
                    $vars[$key] = $cleanAwgParams[$key];
                } else {
                    $vars[$key] = $defaultAwgParams[$key];
                }
            }

            // Backward/Template compatibility: the AWG client template uses Jc/Jmin/Jmax (not all-caps).
            // Ensure those placeholders are always populated.
            if (!isset($vars['Jc']) && isset($vars['JC'])) {
                $vars['Jc'] = (string) $vars['JC'];
            }
            if (!isset($vars['Jmin']) && isset($vars['JMIN'])) {
                $vars['Jmin'] = (string) $vars['JMIN'];
            }
            if (!isset($vars['Jmax']) && isset($vars['JMAX'])) {
                $vars['Jmax'] = (string) $vars['JMAX'];
            }
            foreach (['S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $key) {
                if (!isset($vars[$key]) && isset($vars[strtoupper($key)])) {
                    $vars[$key] = (string) $vars[strtoupper($key)];
                }
            }

            // Generate config from template
            if ($protoRow && !empty($protoRow['output_template'])) {
                require_once __DIR__ . '/ProtocolService.php';
                $config = ProtocolService::generateProtocolOutput($protoRow, $vars);
            } else {
                // Fallback to old method if no template
                $config = self::buildClientConfig(
                    $keys['private'],
                    $clientIP,
                    $serverData['server_public_key'],
                    $serverData['preshared_key'],
                    $serverData['host'],
                    $serverData['vpn_port'],
                    is_array($awgParams) ? $awgParams : [],
                    $slug
                );
            }

            self::addClientToServer($serverData, $keys['public'], $clientIP);
            $qrCode = self::generateQRCode($config, $slug);
            $priv = $keys['private'];
            $pub = $keys['public'];
            $psk = $serverData['preshared_key'];
            $pass = null;
        } else {
            $vars = [];
            $vars['private_key'] = '';
            $vars['client_ip'] = $clientIP;
            $vars['server_host'] = $serverData['host'] ?? '';
            $vars['server_port'] = $serverData['vpn_port'] ?? '';
            $extras = [];
            if ($protocolId) {
                try {
                    $stmtSp = $pdo->prepare('SELECT config_data FROM server_protocols WHERE server_id = ? AND protocol_id = ? LIMIT 1');
                    $stmtSp->execute([$serverId, $protocolId]);
                    $cfg = $stmtSp->fetchColumn();
                    if ($cfg) {
                        $conf = is_string($cfg) ? json_decode($cfg, true) : $cfg;
                        if (is_array($conf)) {
                            $vars['server_host'] = $conf['server_host'] ?? $vars['server_host'];
                            $vars['server_port'] = $conf['server_port'] ?? $vars['server_port'];
                            $extras = $conf['extras'] ?? [];
                        }
                    }
                } catch (Exception $e) {
                }
            }
            if (is_array($extras)) {
                // If extras has 'result' subarray, merge it into extras for processing
                if (isset($extras['result']) && is_array($extras['result'])) {
                    $extras = array_merge($extras, $extras['result']);
                }

                foreach ($extras as $k => $v) {
                    if (is_scalar($v)) {
                        // Preserve uppercase for AWG obfuscation parameters
                        if (in_array($k, ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'], true)) {
                            $vars[$k] = (string) $v;
                        } else {
                            $vars[strtolower($k)] = (string) $v;
                        }
                    }
                }

                // CRITICAL FIX: Do NOT inherit client_id from server installation data (server_protocols).
                // This prevents new clients from duplicating the admin's UUID.
                if (isset($vars['client_id']) && (stripos($slug, 'xray') !== false || stripos($slug, 'vless') !== false)) {
                    unset($vars['client_id']);
                }

                if (isset($vars['publickey']) && empty($vars['reality_public_key'])) {
                    $vars['reality_public_key'] = $vars['publickey'];
                }
                if (isset($vars['shortid']) && empty($vars['reality_short_id'])) {
                    $vars['reality_short_id'] = $vars['shortid'];
                }
                if (isset($vars['servername']) && empty($vars['reality_server_name'])) {
                    $vars['reality_server_name'] = $vars['servername'];
                }
                if (isset($vars['containername']) && empty($vars['container_name'])) {
                    $vars['container_name'] = $vars['containername'];
                }
            }
            if ($slug === 'xray-vless') {
                if (empty($vars['server_port'])) {
                    if (is_array($extras) && isset($extras['result']) && is_array($extras['result'])) {
                        $res = $extras['result'];
                        if (isset($res['xray_port']) && is_scalar($res['xray_port'])) {
                            $vars['server_port'] = (string) $res['xray_port'];
                        }
                        if (empty($vars['server_port'])) {
                            foreach ($res as $rk => $rv) {
                                if (is_string($rk) && stripos($rk, 'xray_port') !== false && is_scalar($rv)) {
                                    $vars['server_port'] = (string) $rv;
                                    break;
                                }
                            }
                        }
                    }
                }
                $needReality = empty($vars['reality_public_key']) || empty($vars['reality_server_name']) || empty($vars['reality_short_id']);
                if (empty($vars['client_id']) || $needReality) {
                    $containerName = 'amnezia-xray';
                    if (is_array($extras) && isset($extras['result']) && is_array($extras['result'])) {
                        $res = $extras['result'];
                        if (isset($res['container_name']) && is_scalar($res['container_name'])) {
                            $containerName = trim((string) $res['container_name']) ?: $containerName;
                        }
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
                                // Block removed: Do not reuse existing client ID for new clients
                                // $settings = $inbounds[0]['settings'] ?? [];
                                // $clients = $settings['clients'] ?? [];
                                // if (is_array($clients) && !empty($clients)) {
                                //    $cid = $clients[0]['id'] ?? null;
                                //    if (is_string($cid) && $cid !== '' && empty($vars['client_id'])) {
                                //        $vars['client_id'] = $cid;
                                //    }
                                // }
                                $stream = $inbounds[0]['streamSettings'] ?? [];
                                if (is_array($stream) && ($stream['security'] ?? '') === 'reality') {
                                    $rs = $stream['realitySettings'] ?? [];
                                    $serverNames = $rs['serverNames'] ?? ($rs['serverName'] ?? []);
                                    $shortIds = $rs['shortIds'] ?? ($rs['shortId'] ?? []);
                                    $serverName = is_array($serverNames) ? ($serverNames[0] ?? null) : (is_string($serverNames) ? $serverNames : null);
                                    $shortId = is_array($shortIds) ? ($shortIds[0] ?? null) : (is_string($shortIds) ? $shortIds : null);
                                    $privateKey = $rs['privateKey'] ?? null;
                                    if (is_string($serverName) && $serverName !== '') {
                                        $vars['reality_server_name'] = $serverName;
                                    }
                                    if (is_string($shortId) && $shortId !== '') {
                                        $vars['reality_short_id'] = $shortId;
                                    }
                                    if (is_string($privateKey) && $privateKey !== '' && function_exists('sodium_crypto_scalarmult_base')) {
                                        $b64 = strtr($privateKey, '-_', '+/');
                                        $padLen = strlen($b64) % 4;
                                        if ($padLen) {
                                            $b64 .= str_repeat('=', 4 - $padLen);
                                        }
                                        $bin = base64_decode($b64, true);
                                        if ($bin === false) {
                                            $pk = $privateKey;
                                            $padLen2 = strlen($pk) % 4;
                                            if ($padLen2) {
                                                $pk .= str_repeat('=', 4 - $padLen2);
                                            }
                                            $bin = base64_decode($pk, true);
                                        }
                                        if (is_string($bin) && strlen($bin) === 32) {
                                            $pub = sodium_crypto_scalarmult_base($bin);
                                            $vars['reality_public_key'] = rtrim(strtr(base64_encode($pub), '+/', '-_'), '=');
                                        }
                                    }
                                    if (is_string($privateKey) && $privateKey !== '' && empty($vars['reality_public_key'])) {
                                        $cmd = "docker exec -i " . escapeshellarg($containerName) . " /usr/bin/xray x25519 -i " . escapeshellarg($privateKey) . " 2>/dev/null";
                                        $out = $server->executeCommand($cmd, true);
                                        $outTrim = trim((string) $out);
                                        if ($outTrim !== '') {
                                            $pub = '';
                                            if (preg_match('/[Pp]ublic\s*[Kk]ey[:\s]+(.+)/', $outTrim, $mm)) {
                                                $pub = trim((string) $mm[1]);
                                            } else {
                                                $pub = $outTrim;
                                            }
                                            if ($pub !== '') {
                                                $vars['reality_public_key'] = $pub;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception $e) {
                    }
                }
            }
            if ($slug === 'openvpn') {
                $containerName = $serverData['container_name'] ?? 'openvpn';
                $config = '';

                // Try to generate config via Docker
                try {
                    // 1. Generate client certificate (ignore output)
                    $server->executeCommand("docker run --rm -v openvpn-data:/etc/openvpn kylemanna/openvpn easyrsa build-client-full " . escapeshellarg($loginFinal) . " nopass", true);

                    // 2. Get full client config
                    $fullConfig = $server->executeCommand("docker run --rm -v openvpn-data:/etc/openvpn kylemanna/openvpn ovpn_getclient " . escapeshellarg($loginFinal), true);

                    if (trim($fullConfig) !== '' && strpos($fullConfig, 'BEGIN CERTIFICATE') !== false) {
                        $config = $fullConfig;
                        $protoRow = null; // Skip template generation
                    }
                } catch (Exception $e) {
                    // Fallback to template
                }

                if (empty($config)) {
                    if (empty($vars['server_port']) || !preg_match('/^\d+$/', (string) $vars['server_port'])) {
                        $vars['server_port'] = '1194';
                    }
                    if (empty($vars['protocol'])) {
                        $vars['protocol'] = 'udp';
                    }
                    if (empty($vars['proto'])) {
                        $vars['proto'] = $vars['protocol'];
                    }
                    if (empty($vars['port'])) {
                        $vars['port'] = $vars['server_port'];
                    }
                    if (empty($vars['host'])) {
                        $vars['host'] = $vars['server_host'];
                    }
                }
            }
            if ($slug === 'aivpn') {
                // Canonical connection key should come from AIVPN --add-client output.
                // We keep fallback generation later only if add_client flow didn't provide a key.
            }
            $pass = null;
            $pwdCmd = isset($protoRow['password_command']) ? trim((string) $protoRow['password_command']) : '';
            if ($pwdCmd !== '') {
                try {
                    $wrapper = "bash <<'EOS'\nLOGIN=" . escapeshellarg($loginFinal) . "\n" . $pwdCmd . "\nEOS";
                    $out = $server->executeCommand($wrapper, true);
                    $passTrim = trim((string) $out);
                    if ($passTrim !== '')
                        $pass = $passTrim;
                } catch (Exception $e) {
                }
            }
            if ($pass === null) {
                if (!empty($vars['password'])) {
                    $pass = (string) $vars['password'];
                } else {
                    $pass = 'amnezia';
                }
            }
            $vars['login'] = $loginFinal;
            $vars['password'] = $pass;
            if (($slug ?? '') === 'smb' && empty($vars['password'])) {
                $vars['password'] = $pass;
            }

            // Ensure client_id (UUID) for X-Ray
            if (empty($vars['client_id']) && (stripos($slug, 'xray') !== false || stripos($slug, 'vless') !== false)) {
                $data = random_bytes(16);
                $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
                $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
                $vars['client_id'] = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
            }

            // Try to add client to server via universal manager (supports scripts and builtins)
            if ($protoRow) {
                // We pass generic options. InstallProtocolManager will handle specific logic for 'add_client' phase.
                // For xray-vless it uses builtin fallback in runScript.
                try {
                    require_once __DIR__ . '/InstallProtocolManager.php';
                    $addClientResult = InstallProtocolManager::addClient($server, $protoRow, $vars);
                    if (is_array($addClientResult)) {
                        foreach ($addClientResult as $rk => $rv) {
                            if (!is_scalar($rv)) {
                                continue;
                            }
                            $key = (string) $rk;
                            $value = trim((string) $rv);
                            if ($value === '') {
                                continue;
                            }
                            $vars[$key] = $value;
                            $vars[strtolower($key)] = $value;
                        }

                        if ($slug === 'aivpn') {
                            if (empty($vars['connection_key']) && !empty($vars['connection_uri']) && stripos((string) $vars['connection_uri'], 'aivpn://') === 0) {
                                $vars['connection_key'] = substr((string) $vars['connection_uri'], strlen('aivpn://'));
                            }
                            if (!empty($vars['client_ip']) && preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/', (string) $vars['client_ip'])) {
                                $clientIP = (string) $vars['client_ip'];
                                $vars['client_ip'] = $clientIP;
                            }
                        }
                    }
                } catch (Exception $e) {
                    error_log("Failed to add client to server: " . $e->getMessage());
                    throw $e;
                }
            }

            if ($slug === 'aivpn' && empty($vars['connection_key'])) {
                try {
                    $rawKey = trim((string) $server->executeCommand('cat /etc/aivpn/server.key 2>/dev/null', true));
                    if ($rawKey !== '' && !empty($vars['client_ip']) && !empty($vars['server_host']) && !empty($vars['server_port'])) {
                        $payload = [
                            'i' => (string) $vars['client_ip'],
                            'k' => $rawKey,
                            'p' => '',
                            's' => (string) $vars['server_host'] . ':' . (string) $vars['server_port'],
                        ];
                        $json = (string) json_encode($payload, JSON_UNESCAPED_SLASHES);
                        $vars['connection_key'] = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
                    }
                } catch (Exception $e) {
                    // Keep empty: final template output will expose a missing key.
                }
            }

            if ($slug === 'aivpn' && !empty($vars['connection_key'])) {
                $vars['connection_key'] = self::normalizeAivpnConnectionKey((string) $vars['connection_key']);
            }

            $config = $protoRow ? ProtocolService::generateProtocolOutput($protoRow, $vars) : '';

            // Prepare last_config_json for QR code generation if config is JSON (XRay)
            if ($config !== '' && ($decoded = json_decode($config)) !== null) {
                $vars['last_config_json'] = json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            }

            $qrCode = self::generateQRCode($config, $slug);

            $priv = '';
            $pub = '';
            $psk = '';
        }

        // Calculate expiration date
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;

        // Insert into database
        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients 
            (server_id, user_id, protocol_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $stmt->execute([
            $serverId,
            $userId,
            $protocolId ?: null,
            $loginFinal,
            $clientIP,
            $pub,
            $priv,
            $psk,
            $config,
            $qrCode,
            'active',
            $expiresAt
        ]);

        return (int) $pdo->lastInsertId();
    }

    private static function normalizeAivpnConnectionKey(string $key): string
    {
        $key = trim($key);
        if ($key === '') {
            return $key;
        }

        $decoded = base64_decode(strtr($key, '-_', '+/'), true);
        if ($decoded === false) {
            $padLen = strlen($key) % 4;
            $normalized = $key;
            if ($padLen > 0) {
                $normalized .= str_repeat('=', 4 - $padLen);
            }
            $decoded = base64_decode(strtr($normalized, '-_', '+/'), true);
        }

        if ($decoded === false) {
            return $key;
        }

        $data = json_decode($decoded, true);
        if (!is_array($data) || empty($data['s']) || !is_string($data['s'])) {
            return $key;
        }

        $endpoint = trim($data['s']);
        $endpoint = preg_replace('#^https?://#i', '', $endpoint);
        $endpoint = preg_replace('#/.*$#', '', $endpoint ?? '');

        if ($endpoint !== '' && preg_match('/^(.+?)(?::\d+){2,}$/', $endpoint, $m) && preg_match('/:(\d+)$/', $endpoint, $pm)) {
            $endpoint = trim((string) $m[1]) . ':' . (string) $pm[1];
            $data['s'] = $endpoint;
            $json = (string) json_encode($data, JSON_UNESCAPED_SLASHES);
            return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        }

        return $key;
    }

    public static function listByServerAndProtocol(int $serverId, int $protocolId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, p.name as protocol_name 
            FROM vpn_clients c
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.server_id = ? AND c.protocol_id = ? 
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$serverId, $protocolId]);
        return $stmt->fetchAll();
    }

    /**
     * Import client data directly from backup without touching remote server.
     */
    public static function importFromBackup(array $serverData, int $userId, array $clientData): ?int
    {
        if (empty($serverData['id'])) {
            throw new Exception('Server must be saved before importing clients');
        }

        $pdo = DB::conn();

        $clientIp = trim($clientData['client_ip'] ?? '');
        $publicKey = trim($clientData['public_key'] ?? '');
        $privateKey = trim($clientData['private_key'] ?? '');

        if ($clientIp === '' || $publicKey === '' || $privateKey === '') {
            throw new Exception('Client backup data is incomplete');
        }

        // Skip if client with same IP already exists
        $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ? LIMIT 1');
        $stmt->execute([$serverData['id'], $clientIp]);
        if ($stmt->fetchColumn()) {
            return null;
        }

        $name = trim($clientData['name'] ?? '');
        if ($name === '') {
            $name = $clientIp;
        }

        $presharedKey = $clientData['preshared_key'] ?? ($serverData['preshared_key'] ?? '');
        $config = $clientData['config'] ?? '';

        if ($config === '' && !empty($serverData['server_public_key']) && !empty($serverData['host']) && !empty($serverData['vpn_port'])) {
            $awgParams = json_decode($serverData['awg_params'] ?? '{}', true);
            if (!is_array($awgParams)) {
                $awgParams = [];
            }
            $config = self::buildClientConfig(
                $privateKey,
                $clientIp,
                $serverData['server_public_key'],
                $presharedKey,
                $serverData['host'],
                (int) $serverData['vpn_port'],
                $awgParams,
                (string) ($serverData['install_protocol'] ?? '')
            );
        }

        // Try to fetch protocol for QR code generation
        $protocol = null;
        if (!empty($serverData['install_protocol'])) {
            $stmtP = $pdo->prepare('SELECT * FROM protocols WHERE slug = ?');
            $stmtP->execute([$serverData['install_protocol']]);
            $protocol = $stmtP->fetch(PDO::FETCH_ASSOC);
        }

        $vars = [];
        // Prepare last_config_json if config is JSON
        if ($config !== '' && ($decoded = json_decode($config)) !== null) {
            $vars['last_config_json'] = json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        }

        $qrCode = $config !== '' ? self::generateQRCode($config, $serverData['install_protocol'] ?? '') : '';
        $status = strtolower($clientData['status'] ?? 'active') === 'disabled' ? 'disabled' : 'active';

        $expiresAt = $clientData['expires_at'] ?? null;
        if ($expiresAt) {
            $timestamp = strtotime($expiresAt);
            $expiresAt = $timestamp ? date('Y-m-d H:i:s', $timestamp) : null;
        }

        $stmt = $pdo->prepare('
            INSERT INTO vpn_clients 
            (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $stmt->execute([
            $serverData['id'],
            $userId,
            $name,
            $clientIp,
            $publicKey,
            $privateKey,
            $presharedKey,
            $config,
            $qrCode,
            $status,
            $expiresAt
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Generate client keys on remote server
     */
    private static function generateClientKeys(array $serverData, string $clientName): array
    {
        $containerName = $serverData['container_name'];
        $cmd = sprintf(
            "docker exec -i %s sh -lc 'set -e; umask 077; priv=\$(wg genkey | tr -d " . '"' . "\\r\\n" . '"' . "); [ -n \"\$priv\" ] || { echo empty_private_key; exit 1; }; pub=\$(printf " . '"' . "%%s\\n" . '"' . " \"\$priv\" | wg pubkey | tr -d " . '"' . "\\r\\n" . '"' . "); [ -n \"\$pub\" ] || { echo empty_public_key; exit 1; }; printf " . '"' . "%%s\\n---\\n%%s\\n" . '"' . " \"\$priv\" \"\$pub\"'",
            escapeshellarg($containerName)
        );

        $escaped = escapeshellarg($cmd);
        $sshCmd = sprintf(
            "sshpass -p '%s' ssh -p %d -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $serverData['password'],
            $serverData['port'],
            $serverData['username'],
            $serverData['host'],
            $escaped
        );

        $out = shell_exec($sshCmd);
        $parts = explode("---", trim($out));

        if (count($parts) < 2) {
            $head = substr(trim((string) $out), 0, 240);
            throw new Exception("Failed to generate client keys" . ($head !== '' ? (": " . $head) : ''));
        }

        $private = trim((string) $parts[0]);
        $public = trim((string) $parts[1]);
        if ($private === '' || $public === '') {
            throw new Exception('Failed to generate client keys: empty key output');
        }

        return [
            'private' => $private,
            'public' => $public
        ];
    }

    /**
     * Get next available client IP
     */
    public static function getNextClientIP(array $serverData): string
    {
        $pdo = DB::conn();

        // Get used IPs from database
        $stmt = $pdo->prepare('SELECT client_ip FROM vpn_clients WHERE server_id = ?');
        $stmt->execute([$serverData['id']]);
        $usedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);

        // Reserve network address and server gateway (.1)
        $used = ['10.8.1.0' => true, '10.8.1.1' => true];
        foreach ($usedIPs as $ip) {
            $used[$ip] = true;
        }

        // ALSO check IPs used in actual server config (catches clients created outside web panel)
        try {
            $containerName = $serverData['container_name'] ?? 'amnezia-awg';
            $server = new VpnServer($serverData['id']);
            $cmd = sprintf(
                "docker exec %s cat /opt/amnezia/awg/wg0.conf 2>/dev/null",
                escapeshellarg($containerName)
            );
            $serverConfig = $server->executeCommand($cmd, true);

            // Extract AllowedIPs from all peers
            if (preg_match_all('/AllowedIPs\s*=\s*([0-9.]+)\/\d+/i', $serverConfig, $matches)) {
                foreach ($matches[1] as $ip) {
                    $used[$ip] = true;
                }
            }
        } catch (Exception $e) {
            error_log('Failed to check server config for used IPs: ' . $e->getMessage());
            // Continue with DB-only check
        }

        // Parse subnet
        $parts = explode('/', $serverData['vpn_subnet']);
        $networkLong = ip2long($parts[0]);

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
     * Auto-sync server keys from running container (for externally installed protocols)
     */
    private static function getAwgParamDefaults(string $protocolSlug = ''): array
    {
        if ($protocolSlug === 'awg2') {
            return [
                'JC' => 5,
                'JMIN' => 10,
                'JMAX' => 50,
                'S1' => 51,
                'S2' => 125,
                'S3' => 13,
                'S4' => 9,
                'H1' => '1443912531-1981073285',
                'H2' => '1984025557-2135018048',
                'H3' => '2145217268-2146643749',
                'H4' => '2146790761-2146860793',
                'I1' => '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>',
                'I2' => '',
                'I3' => '',
                'I4' => '',
                'I5' => '',
            ];
        }

        return [
            'JC' => 5,
            'JMIN' => 100,
            'JMAX' => 200,
            'S1' => 50,
            'S2' => 100,
            'S3' => 20,
            'S4' => 10,
            'H1' => 1,
            'H2' => 2,
            'H3' => 3,
            'H4' => 4,
        ];
    }

    private static function extractAwgParamsFromWg0Conf(VpnServer $server, string $containerName, string $confPath): array
    {
        $awgParams = [];

        $awgLinesCmd = sprintf(
            "docker exec %s sh -c \"grep -E '^[[:space:]]*(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5)[[:space:]]*=' %s 2>/dev/null || true\"",
            escapeshellarg($containerName),
            escapeshellarg($confPath)
        );
        $awgLines = (string) $server->executeCommand($awgLinesCmd, true);

        foreach (preg_split('/\r?\n/', trim($awgLines)) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (preg_match('/^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5)\s*=\s*(.*)$/i', $line, $m)) {
                $k = strtoupper($m[1]);
                $value = trim($m[2]);
                $awgParams[$k] = ctype_digit($value) ? (int) $value : $value;
            }
        }

        return $awgParams;
    }

    private static function extractPeerPskFromWgDump(VpnServer $server, string $containerName, string $clientPublicKey): ?string
    {
        $clientPublicKey = trim($clientPublicKey);
        if ($clientPublicKey === '') {
            return null;
        }

        // wg show wg0 dump peer line format:
        // public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t rx \t tx \t keepalive
        $cmdDump = sprintf('docker exec %s wg show wg0 dump 2>/dev/null || true', escapeshellarg($containerName));
        $dump = (string) $server->executeCommand($cmdDump, true);
        foreach (preg_split('/\r?\n/', trim($dump)) as $line) {
            if ($line === '') {
                continue;
            }
            // Skip interface header line (has many fields but first field is private key)
            if (strpos($line, '\t') === false) {
                continue;
            }
            if (strpos($line, $clientPublicKey . "\t") !== 0) {
                continue;
            }

            $parts = explode("\t", $line);
            if (count($parts) < 2) {
                return null;
            }
            $psk = trim((string) $parts[1]);
            if ($psk === '' || $psk === '(none)') {
                return null;
            }
            return $psk;
        }

        return null;
    }

    private static function syncServerKeysFromContainer(VpnServer $server, array $serverData): void
    {
        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        $primaryConfigDir = $protocolSlug === 'awg2' ? '/opt/amnezia/awg2' : '/opt/amnezia/awg';

        try {
            // Try to get public key from wg show
            $pubKeyCmd = "docker exec $containerName wg show wg0 2>/dev/null | grep 'public key:' | awk '{print \$3}'";
            $pubKey = trim($server->executeCommand($pubKeyCmd, true));

            // Get listening port
            $portCmd = "docker exec $containerName wg show wg0 2>/dev/null | grep 'listening port:' | awk '{print \$3}'";
            $port = trim($server->executeCommand($portCmd, true));

            // PresharedKey is stored per-peer, and in this project we persist it in wireguard_psk.key.
            // Prefer that file (stable) and fall back to parsing the first peer PSK from wg0.conf.
            $psk = '';

            $pskKeyFileCmd = "docker exec $containerName sh -c \"cat $primaryConfigDir/wireguard_psk.key 2>/dev/null || cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true\"";
            $psk = trim($server->executeCommand($pskKeyFileCmd, true));

            if ($psk === '') {
                $pskFromConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' $primaryConfigDir/wg0.conf 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromConfCmd, true));
            }

            if ($psk === '' && $primaryConfigDir !== '/opt/amnezia/awg') {
                $pskFromAwgConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' /opt/amnezia/awg/wg0.conf 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromAwgConfCmd, true));
            }

            if ($psk === '') {
                $pskFromAltConfCmd = "docker exec $containerName sh -c \"grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' /etc/wireguard/wg0.conf 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'\" 2>/dev/null || true";
                $psk = trim($server->executeCommand($pskFromAltConfCmd, true));
            }

            // Extract DNS from config
            $dnsCmd = "docker exec $containerName sh -c \"grep -E '^DNS' $primaryConfigDir/wg0.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
            $dns = trim($server->executeCommand($dnsCmd, true));

            if (empty($dns) && $primaryConfigDir !== '/opt/amnezia/awg') {
                $dnsAwgCmd = "docker exec $containerName sh -c \"grep -E '^DNS' /opt/amnezia/awg/wg0.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
                $dns = trim($server->executeCommand($dnsAwgCmd, true));
            }

            if (empty($dns)) {
                // Try alternative config location
                $dnsCmd2 = "docker exec $containerName sh -c \"grep -E '^DNS' /etc/wireguard/wg0.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]'\" 2>/dev/null || echo ''";
                $dns = trim($server->executeCommand($dnsCmd2, true));
            }

            // Default DNS if not found
            if (empty($dns)) {
                $dns = '1.1.1.1, 1.0.0.1';
            }

            // Extract AWG parameters.
            // NOTE: amnezia-awg does not expose these via `wg show` in many builds,
            // so we primarily read them from /opt/amnezia/awg/wg0.conf.
            $awgParams = [];

            // Legacy attempt: some builds print jc/jmin/... in `wg show` output.
            $wgShowCmd = "docker exec $containerName wg show wg0 2>/dev/null";
            $wgOutput = (string) $server->executeCommand($wgShowCmd, true);
            $paramNames = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'];
            foreach ($paramNames as $param) {
                // For H1-H4 parameters, expect format like "1443912531-1981073285" (two values with dash)
                // For other parameters, expect single integer value
                if (in_array($param, ['h1', 'h2', 'h3', 'h4'], true)) {
                    if (preg_match('/^\s*' . preg_quote($param, '/') . ':\s*(\d+-\d+)/mi', $wgOutput, $matches)) {
                        $awgParams[strtoupper($param)] = $matches[1];
                    }
                } else {
                    if (preg_match('/^\s*' . preg_quote($param, '/') . ':\s*(\d+)/mi', $wgOutput, $matches)) {
                        $awgParams[strtoupper($param)] = (int) $matches[1];
                    }
                }
            }

            // Primary source: wg0.conf
            if (empty($awgParams)) {
                $awgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, $primaryConfigDir . '/wg0.conf');
                if (empty($awgParams) && $primaryConfigDir !== '/opt/amnezia/awg') {
                    $awgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, '/opt/amnezia/awg/wg0.conf');
                }
                if (empty($awgParams)) {
                    $awgParams = self::extractAwgParamsFromWg0Conf($server, $containerName, '/etc/wireguard/wg0.conf');
                }
            }

            // Update database if we found keys
            if (!empty($pubKey) && !empty($port)) {
                $pdo = DB::conn();

                $awgParamsJson = !empty($awgParams) ? json_encode($awgParams) : null;

                // Update vpn_servers with all extracted values including DNS
                if (!empty($psk)) {
                    $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, preshared_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ? WHERE id = ?');
                    $stmt->execute([$pubKey, $psk, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                } else {
                    $stmt = $pdo->prepare('UPDATE vpn_servers SET server_public_key = ?, vpn_port = ?, awg_params = ?, dns_servers = ? WHERE id = ?');
                    $stmt->execute([$pubKey, (int) $port, $awgParamsJson, $dns, $serverData['id']]);
                }

                error_log("Auto-synced server keys from container $containerName: port=$port, dns=$dns, awg_params=" . ($awgParamsJson ?? 'none'));
            }
        } catch (Exception $e) {
            error_log('Error syncing keys from container: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Build client configuration file
     */
    public static function buildClientConfig(
        string $privateKey,
        string $clientIP,
        string $serverPublicKey,
        string $presharedKey,
        string $serverHost,
        int $serverPort,
        array $awgParams,
        string $protocolSlug = ''
    ): string {
        // Get default parameters for the protocol
        $defaultParams = self::getAwgParamDefaults($protocolSlug);
        
        // Normalize $awgParams keys to uppercase for consistency
        $normalizedAwgParams = [];
        foreach ($awgParams as $k => $v) {
            $normalizedAwgParams[strtoupper($k)] = $v;
        }
        
        // Merge: use server params only if they have correct format, otherwise use defaults
        // This is critical for H1-H4 which must have "value1-value2" format
        $finalParams = $defaultParams;
        foreach ($normalizedAwgParams as $key => $value) {
            $upperKey = strtoupper($key);
            
            // For H1-H4 parameters, only use server value if it has the correct "value1-value2" format
            if (in_array($upperKey, ['H1', 'H2', 'H3', 'H4'], true)) {
                if (is_string($value) && preg_match('/^\d+-\d+$/', $value)) {
                    $finalParams[$upperKey] = $value;
                }
                // Otherwise keep the default value
            } else {
                // For other parameters, use server value if present
                $finalParams[$upperKey] = $value;
            }
        }
        
        $config = "[Interface]\n";
        $config .= "Address = {$clientIP}/32\n";
        $config .= "DNS = 1.1.1.1, 1.0.0.1\n";
        $config .= "PrivateKey = {$privateKey}\n";

        // Add AWG parameters (in the order used by Amnezia app)
        // For awg2 include I1-I5, S3, S4; for regular awg only H1-H4, Jc, Jmin, Jmax, S1, S2
        // Order: Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4, I1, I2, I3, I4, I5
        $paramKeys = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'];
        if ($protocolSlug === 'awg2') {
            $paramKeys = array_merge($paramKeys, ['I1', 'I2', 'I3', 'I4', 'I5']);
        }
        
        foreach ($paramKeys as $key) {
            $value = null;
            if (isset($finalParams[$key])) {
                $value = $finalParams[$key];
            } elseif (isset($finalParams[strtoupper($key)])) {
                $value = $finalParams[strtoupper($key)];
            }
            
            // Always add parameter if it's defined (even if empty for I2-I5)
            if ($value !== null) {
                $config .= "{$key} = {$value}\n";
            }
        }

        $config .= "\n[Peer]\n";
        $config .= "PublicKey = {$serverPublicKey}\n";
        $config .= "PresharedKey = {$presharedKey}\n";
        $config .= "Endpoint = {$serverHost}:{$serverPort}\n";
        $config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        $config .= "PersistentKeepalive = 25\n\n";

        return $config;
    }

    /**
     * Add client to server using wg set (more reliable than syncconf)
     */
    public static function addClientToServer(array $serverData, string $publicKey, string $clientIP): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/awg0.conf
        $isAwg2 = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2');
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg
        $configFile = $isAwg2 ? 'awg0.conf' : 'wg0.conf';
        $presharedKey = $serverData['preshared_key'];
        $publicKey = trim($publicKey);

        if ($publicKey === '') {
            throw new Exception('Refusing to add client with empty public key');
        }

        // 1. Create temp file for PSK (to avoid shell escaping issues)
        $pskFile = '/tmp/' . bin2hex(random_bytes(8)) . '.psk';
        $cmd1 = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $containerName, $presharedKey, $pskFile);
        self::executeServerCommand($serverData, $cmd1, true);

        // 2. Add peer using wg set
        // wg set wg0 peer <PUBKEY> preshared-key <FILE> allowed-ips <IPS>
        $cmd2 = sprintf(
            "docker exec -i %s wg set wg0 peer %s preshared-key %s allowed-ips %s/32",
            $containerName,
            escapeshellarg($publicKey),
            $pskFile,
            $clientIP
        );
        self::executeServerCommand($serverData, $cmd2, true);

        // 3. Remove temp PSK file
        $cmd3 = sprintf("docker exec -i %s rm -f %s", $containerName, $pskFile);
        self::executeServerCommand($serverData, $cmd3, true);

        // 4. Persist to wg0.conf (append)
        $peerBlock = "\n[Peer]\n";
        $peerBlock .= "PublicKey = {$publicKey}\n";
        $peerBlock .= "PresharedKey = {$presharedKey}\n";
        $peerBlock .= "AllowedIPs = {$clientIP}/32\n";

        $escapedBlock = addslashes($peerBlock);
        $configFile = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2') ? 'awg0.conf' : 'wg0.conf';
        $cmd4 = sprintf("docker exec -i %s sh -c 'echo \"%s\" >> %s/%s'", $containerName, $escapedBlock, $configDir, $configFile);
        self::executeServerCommand($serverData, $cmd4, true);

        // 5. Update clientsTable
        self::updateClientsTable($serverData, $publicKey, $clientIP);

        // 6. CRITICAL: Reload WG interface to apply AWG obfuscation params
        // Without this, the interface uses standard WireGuard without Jc/S1/S2/H1-H4
        $cmd5 = sprintf("docker exec -i %s sh -c 'ip link del wg0 2>/dev/null || true; wg-quick up %s/%s 2>&1'", $containerName, $configDir, $configFile);
        self::executeServerCommand($serverData, $cmd5, true);
    }

    /**
     * Update clientsTable on server
     */
    private static function updateClientsTable(array $serverData, string $publicKey, string $name): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg

        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s/clientsTable 2>/dev/null", $containerName, $configDir);
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
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s/clientsTable'", $containerName, $escaped, $configDir);
        self::executeServerCommand($serverData, $updateCmd, true);
    }

    /**
     * Execute command on server
     */
    private static function executeServerCommand(array $serverData, string $command, bool $sudo = false): string
    {
        $needsSudo = $sudo && strtolower((string) ($serverData['username'] ?? '')) !== 'root';
        $baseCommand = $command;

        if ($needsSudo) {
            // Suppress sudo prompt noise in stdout to keep parser output stable.
            $command = "echo '{$serverData['password']}' | sudo -S -p '' " . $command;
        }

        $run = static function (string $cmd) use ($serverData): string {
            $escapedCommand = escapeshellarg($cmd);
            $sshCommand = sprintf(
                "sshpass -p '%s' ssh  -p %d -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
                $serverData['password'],
                $serverData['port'],
                $serverData['username'],
                $serverData['host'],
                $escapedCommand
            );

            return shell_exec($sshCommand) ?? '';
        };

        $output = $run($command);

        // If sudo auth fails but docker is available without sudo (docker group), retry without sudo.
        if (
            $needsSudo
            && preg_match('/(^|\\n)docker(\\s|$)/', ltrim($baseCommand))
            && preg_match('/incorrect password attempts|sorry, try again|a password is required/i', $output)
        ) {
            $output = $run($baseCommand);
        }

        return $output;
    }

    /**
     * Generate QR code for configuration using Amnezia format
     * Uses working QrUtil from /Users/oleg/Documents/amnezia
     */
    public static function generateQRCode(string $config, string $protocolSlug = ''): string
    {
        require_once __DIR__ . '/QrUtil.php';

        try {
            // Check for X-Ray VLESS
            if (strpos($config, 'vless://') === 0) {
                // Parse VLESS URI
                $parsed = parse_url($config);
                // Allow missing user (UUID) and port for partial configs
                if ($parsed && isset($parsed['host'])) {
                    $host = $parsed['host'];
                    $port = isset($parsed['port']) ? (int) $parsed['port'] : 443;
                    $clientId = $parsed['user'] ?? '';
                    $fragment = $parsed['fragment'] ?? '';

                    parse_str($parsed['query'] ?? '', $query);
                    $flow = $query['flow'] ?? '';

                    $reality = null;
                    if (($query['security'] ?? '') === 'reality') {
                        $reality = [
                            'publicKey' => $query['pbk'] ?? '',
                            'serverName' => $query['sni'] ?? '',
                            'shortId' => $query['sid'] ?? '',
                            'fingerprint' => $query['fp'] ?? 'chrome'
                        ];
                    }

                    // Use QrUtil to encode correct X-Ray payload (Native Amnezia Client Config)
                    $payloadXray = QrUtil::encodeXrayPayload($host, $port, $clientId, $fragment, $reality, $config, $flow);
                    return QrUtil::pngBase64($payloadXray);
                }
            }

            // Fallback for WireGuard / default
            // Use old Amnezia format with Qt/QDataStream encoding, but pass protocol slug
            $payloadOld = QrUtil::encodeOldPayloadFromConf($config, $protocolSlug);
            $dataUri = QrUtil::pngBase64($payloadOld);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate QR code: ' . $e->getMessage());
            return ''; // QR code generation failed, but continue
        }
    }

    /**
     * Generate second QR code in vpn:// URL format
     * Used for newer Amnezia app versions that support vpn:// scheme
     */
    public static function generateQRCodeVpnUrl(string $config, string $protocolSlug = ''): string
    {
        require_once __DIR__ . '/QrUtil.php';

        try {
            // For X-Ray VLESS, use same format as regular QR
            if (strpos($config, 'vless://') === 0) {
                return self::generateQRCode($config, $protocolSlug);
            }

            // For AWG2 and other WireGuard/AWG, use vpn:// URL format with JSON + zlib
            $payloadVpn = QrUtil::encodeVpnUrlConf($config, $protocolSlug);
            $dataUri = QrUtil::pngBase64($payloadVpn);
            return $dataUri;
        } catch (Throwable $e) {
            error_log('Failed to generate vpn:// QR code: ' . $e->getMessage());
            return '';
        }
    }

    /**
     * Get all clients for a server
     */
    public static function listByServer(int $serverId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, p.name as protocol_name, p.show_text_content
            FROM vpn_clients c
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.server_id = ? 
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$serverId]);
        return $stmt->fetchAll();
    }

    /**
     * Get all clients for a user
     */
    public static function listByUser(int $userId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host as server_host, p.name as protocol_name, p.show_text_content
            FROM vpn_clients c
            LEFT JOIN vpn_servers s ON c.server_id = s.id
            LEFT JOIN protocols p ON c.protocol_id = p.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /**
     * Revoke client access (disable without deleting)
     */
    public function revoke(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $isWireguard = self::isWireguardProtocol((int) ($this->data['protocol_id'] ?? 0));
        if ($isWireguard) {
            $server = new VpnServer($this->data['server_id']);
            $serverData = $server->getData();
            if ($serverData && $serverData['status'] === 'active') {
                try {
                    self::removeClientFromServer($serverData, $this->data['public_key']);
                } catch (Exception $e) {
                    error_log('Failed to remove client from server: ' . $e->getMessage());
                }
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
    public function restore(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $isWireguard = self::isWireguardProtocol((int) ($this->data['protocol_id'] ?? 0));
        if ($isWireguard) {
            $server = new VpnServer($this->data['server_id']);
            $serverData = $server->getData();
            if ($serverData && $serverData['status'] === 'active') {
                try {
                    self::addClientToServer($serverData, $this->data['public_key'], $this->data['client_ip']);
                } catch (Exception $e) {
                    throw new Exception('Failed to restore client on server: ' . $e->getMessage());
                }
            }
        }

        // Mark as active in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['active', $this->clientId]);
    }

    private static function isWireguardProtocol(?int $protocolId): bool
    {
        if (!$protocolId)
            return true;
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT slug FROM protocols WHERE id = ?');
            $stmt->execute([$protocolId]);
            $slug = (string) $stmt->fetchColumn();
            return in_array($slug, ['amnezia-wg-advanced', 'wireguard-standard', 'amnezia-wg', 'awg2'], true);
        } catch (Exception $e) {
            return true;
        }
    }

    /**
     * Delete client permanently
     */
    public function delete(): bool
    {
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
    private static function removeClientFromServer(array $serverData, string $publicKey): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg

        // Determine config filename
        $configFile = (stripos($containerName, 'awg2') !== false || $protocolSlug === 'awg2') ? 'awg0.conf' : 'wg0.conf';

        // First, remove using wg command (live removal)
        $removeCmd = sprintf(
            "docker exec -i %s wg set wg0 peer %s remove",
            $containerName,
            escapeshellarg($publicKey)
        );

        self::executeServerCommand($serverData, $removeCmd, true);

        // Then remove from config file to make it persistent
        // Use a more reliable method: read, filter, write
        $readCmd = sprintf("docker exec -i %s cat %s/%s", $containerName, $configDir, $configFile);
        $config = self::executeServerCommand($serverData, $readCmd, true);

        // Parse and remove the peer section
        $newConfig = self::removePeerFromConfig($config, $publicKey);

        // Write back to file
        $escapedConfig = str_replace("'", "'\\''", $newConfig);
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'echo '\''%s'\'' > %s/%s'",
            $containerName,
            $escapedConfig,
            $configDir,
            $configFile
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
    private static function removePeerFromConfig(string $config, string $publicKey): string
    {
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
    private static function removeFromClientsTable(array $serverData, string $publicKey): void
    {
        $containerName = $serverData['container_name'];
        $protocolSlug = (string) ($serverData['install_protocol'] ?? '');
        // Для AWG2 конфигурация внутри контейнера находится в /opt/amnezia/awg/
        $configDir = '/opt/amnezia/awg'; // Внутри контейнера всегда /opt/amnezia/awg

        // Read current table
        $cmd = sprintf("docker exec -i %s cat %s/clientsTable 2>/dev/null", $containerName, $configDir);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);

        if (!is_array($table)) {
            return;
        }

        // Filter out the client
        $table = array_filter($table, function ($client) use ($publicKey) {
            return ($client['clientId'] ?? '') !== $publicKey;
        });

        // Re-index array
        $table = array_values($table);

        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s/clientsTable'", $containerName, $escaped, $configDir);
        self::executeServerCommand($serverData, $updateCmd, true);
    }

    /**
     * Get client data
     */
    public function getData(): ?array
    {
        return $this->data;
    }

    /**
     * Get configuration file content
     */
    public function getConfig(): string
    {
        $config = $this->data['config'] ?? '';
        // Decode escape sequences like \n that may be stored in database
        return stripcslashes($config);
    }

    /**
     * Regenerate and persist client configuration using current server container data.
     * Useful when server was reinstalled/recreated and AWG params/keys changed.
     */
    public function regenerateConfigFromServer(bool $forceSyncServer = true): array
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $server = new VpnServer((int) $this->data['server_id']);
        $serverData = $server->getData();
        if (!$serverData) {
            throw new Exception('Server not found');
        }

        $protocolId = (int) ($this->data['protocol_id'] ?? 0);
        $protoRow = null;
        if ($protocolId > 0) {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
            $stmt->execute([$protocolId]);
            $protoRow = $stmt->fetch();
        }
        $slug = $protoRow['slug'] ?? '';
        $isWireguard = in_array($slug, ['amnezia-wg-advanced', 'wireguard-standard', 'amnezia-wg', 'awg2'], true);

        if (!$isWireguard) {
            return ['success' => false, 'error' => 'not_wireguard_protocol', 'protocol_slug' => $slug];
        }

        if ($forceSyncServer) {
            self::syncServerKeysFromContainer($server, $serverData);
            $server->refresh();
            $serverData = $server->getData();
        }

        $privateKey = (string) ($this->data['private_key'] ?? '');
        $clientPublicKey = (string) ($this->data['public_key'] ?? '');
        $clientIP = (string) ($this->data['client_ip'] ?? '');
        if ($privateKey === '' || $clientIP === '') {
            throw new Exception('Client keys or IP missing');
        }

        $awgParams = json_decode($serverData['awg_params'] ?? '{}', true) ?? [];
        if (!is_array($awgParams)) {
            $awgParams = [];
        }

        // Accept mixed-case keys from installer outputs (e.g. Jc/Jmin/Jmax)
        // by duplicating them into canonical uppercase AWG keys.
        foreach ($awgParams as $k => $v) {
            $uk = strtoupper((string) $k);
            if (in_array($uk, ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'], true) && !isset($awgParams[$uk])) {
                $awgParams[$uk] = $v;
            }
        }

        // If AWG params are missing (common after reinstall), fetch them directly from wg0.conf
        // to avoid falling back to template defaults that will not match the server.
        if (in_array($slug, ['amnezia-wg-advanced', 'awg2'], true)) {
            $needKeys = ['JC', 'JMIN', 'JMAX', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];
            $missing = false;
            foreach ($needKeys as $k) {
                if (!isset($awgParams[$k])) {
                    $missing = true;
                    break;
                }
            }

            if ($missing) {
                $containerName = $serverData['container_name'] ?? ($slug === 'awg2' ? 'amnezia-awg2' : 'amnezia-awg');
                $configDir = $slug === 'awg2' ? '/opt/amnezia/awg2' : '/opt/amnezia/awg';
                $direct = self::extractAwgParamsFromWg0Conf($server, $containerName, $configDir . '/wg0.conf');
                if (empty($direct)) {
                    $direct = self::extractAwgParamsFromWg0Conf($server, $containerName, '/etc/wireguard/wg0.conf');
                }

                if (!empty($direct)) {
                    $awgParams = $direct;

                    // Persist to server row for future generations/diagnostics
                    try {
                        $pdo = DB::conn();
                        $stmt = $pdo->prepare('UPDATE vpn_servers SET awg_params = ? WHERE id = ?');
                        $stmt->execute([json_encode($awgParams), (int) ($serverData['id'] ?? 0)]);
                    } catch (Exception $e) {
                        // Best-effort only; regeneration can continue.
                        error_log('Failed to persist AWG params during regeneration: ' . $e->getMessage());
                    }
                }
            }

            $awgParams = array_merge(self::getAwgParamDefaults($slug), $awgParams);

            // Still missing? Refuse to overwrite config with template defaults.
            foreach ($needKeys as $k) {
                if (!isset($awgParams[$k])) {
                    return [
                        'success' => false,
                        'error' => 'awg_params_missing',
                        'protocol_slug' => $slug,
                        'server_id' => (int) ($serverData['id'] ?? 0),
                    ];
                }
            }
        }

        // Prefer per-peer PSK from wg dump (server may use different PSKs per peer)
        $presharedKeyForConfig = (string) ($serverData['preshared_key'] ?? '');
        try {
            $containerName = $serverData['container_name'] ?? 'amnezia-awg';
            $peerPsk = self::extractPeerPskFromWgDump($server, $containerName, $clientPublicKey);
            if ($peerPsk !== null && $peerPsk !== '') {
                $presharedKeyForConfig = $peerPsk;
            }
        } catch (Exception $e) {
            // Best-effort; fallback to serverData['preshared_key']
            error_log('Failed to extract peer PSK from wg dump: ' . $e->getMessage());
        }

        $vars = [
            'private_key' => $privateKey,
            'client_ip' => $clientIP,
            'server_public_key' => (string) ($serverData['server_public_key'] ?? ''),
            'preshared_key' => $presharedKeyForConfig,
            'server_host' => (string) ($serverData['host'] ?? ''),
            'server_port' => (string) ((int) ($serverData['vpn_port'] ?? 0)),
            'dns_servers' => (string) ($serverData['dns_servers'] ?? '1.1.1.1, 1.0.0.1'),
        ];

        foreach (array_keys(self::getAwgParamDefaults($slug)) as $key) {
            if (isset($awgParams[$key])) {
                $vars[$key] = $awgParams[$key];
            }
        }

        if (!isset($vars['Jc']) && isset($vars['JC'])) {
            $vars['Jc'] = (string) $vars['JC'];
        }
        if (!isset($vars['Jmin']) && isset($vars['JMIN'])) {
            $vars['Jmin'] = (string) $vars['JMIN'];
        }
        if (!isset($vars['Jmax']) && isset($vars['JMAX'])) {
            $vars['Jmax'] = (string) $vars['JMAX'];
        }
        foreach (['S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5'] as $key) {
            if (!isset($vars[$key]) && isset($vars[strtoupper($key)])) {
                $vars[$key] = (string) $vars[strtoupper($key)];
            }
        }

        if ($protoRow && !empty($protoRow['output_template'])) {
            require_once __DIR__ . '/ProtocolService.php';
            $config = ProtocolService::generateProtocolOutput($protoRow, $vars);
        } else {
            $config = self::buildClientConfig(
                $privateKey,
                $clientIP,
                (string) ($serverData['server_public_key'] ?? ''),
                $presharedKeyForConfig,
                (string) ($serverData['host'] ?? ''),
                (int) ($serverData['vpn_port'] ?? 0),
                $awgParams,
                $slug
            );
        }

        $qrCode = self::generateQRCode($config, $slug);

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET config = ?, qr_code = ?, preshared_key = ? WHERE id = ?');
        $stmt->execute([$config, $qrCode, $presharedKeyForConfig, (int) $this->clientId]);

        // Refresh cached data
        $this->load();

        return [
            'success' => true,
            'client_id' => (int) $this->clientId,
            'protocol_slug' => $slug,
            'server_id' => (int) ($this->data['server_id'] ?? 0),
            'awg_params' => $awgParams,
            'peer_psk_source' => ($presharedKeyForConfig !== '' && $presharedKeyForConfig !== (string) ($serverData['preshared_key'] ?? '')) ? 'wg_dump' : 'server_row',
        ];
    }

    /**
     * Get QR code
     */
    public function getQRCode(): string
    {
        return $this->data['qr_code'] ?? '';
    }

    /**
     * Get XRay client stats
     */
    private static function getXrayStats(array $serverData, string $clientId): array
    {
        $stats = [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'last_handshake' => 0 // XRay stats API does not provide handshake time
        ];

        $containerName = $serverData['container_name'] ?? 'amnezia-xray';

        // Command to query stats
        // We query by email, which should be equal to client ID (UUID)
        $cmd = sprintf(
            "docker exec -i %s xray api statsquery --server=127.0.0.1:10085 --pattern 'user>>>%s>>>traffic>>>' 2>/dev/null",
            escapeshellarg($containerName),
            escapeshellarg($clientId)
        );

        $output = self::executeServerCommand($serverData, $cmd, true);

        if (empty($output)) {
            return $stats;
        }

        // Output format example:
        // user>>>uuid>>>traffic>>>uplink: 1024
        // user>>>uuid>>>traffic>>>downlink: 2048

        // Parse JSON output
        $json = json_decode($output, true);
        if (is_array($json) && isset($json['stat']) && is_array($json['stat'])) {
            foreach ($json['stat'] as $item) {
                if (!isset($item['name']) || !isset($item['value']))
                    continue;
                if (strpos($item['name'], 'uplink') !== false) {
                    $stats['bytes_sent'] += (int) $item['value'];
                } elseif (strpos($item['name'], 'downlink') !== false) {
                    $stats['bytes_received'] += (int) $item['value'];
                }
            }
        } else {
            // Fallback to text parsing (legacy)
            $lines = explode("\n", trim($output));
            foreach ($lines as $line) {
                if (preg_match('/user>>>.+>>>traffic>>>uplink:\s*(\d+)/', $line, $m)) {
                    $stats['bytes_sent'] = (int) $m[1];
                } elseif (preg_match('/user>>>.+>>>traffic>>>downlink:\s*(\d+)/', $line, $m)) {
                    $stats['bytes_received'] = (int) $m[1];
                }
            }
        }


        return $stats;
    }

    /**
     * Sync traffic statistics from server
     */
    public function syncStats(): bool
    {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();

        if (!$serverData || $serverData['status'] !== 'active') {
            return false;
        }

        try {
            // Get previous stats for speed calculation
            $pdo = DB::conn();
            $stmtPrev = $pdo->prepare('SELECT bytes_sent, bytes_received, last_sync_at, last_handshake, aivpn_raw_bytes_in, aivpn_raw_bytes_out, aivpn_offset_bytes_in, aivpn_offset_bytes_out FROM vpn_clients WHERE id = ?');
            $stmtPrev->execute([$this->clientId]);
            $prev = $stmtPrev->fetch();

            $prevSent = (int) ($prev['bytes_sent'] ?? 0);
            $prevReceived = (int) ($prev['bytes_received'] ?? 0);
            $prevSyncAt = $prev['last_sync_at'] ? strtotime($prev['last_sync_at']) : 0;
            $prevHandshake = $prev['last_handshake'] ? strtotime($prev['last_handshake']) : 0;
            $aivpnRawInPrev = (int) ($prev['aivpn_raw_bytes_in'] ?? 0);
            $aivpnRawOutPrev = (int) ($prev['aivpn_raw_bytes_out'] ?? 0);
            $aivpnOffsetIn = (int) ($prev['aivpn_offset_bytes_in'] ?? 0);
            $aivpnOffsetOut = (int) ($prev['aivpn_offset_bytes_out'] ?? 0);

            // XRay stats logic
            $stats = [];

            // Determine protocol by client's protocol_id
            $isXray = false;
            $isAivpn = false;
            $xrayContainerName = 'amnezia-xray'; // Default XRay container name
            
            if (!empty($this->data['protocol_id'])) {
                $stmtProto = $pdo->prepare('SELECT slug FROM protocols WHERE id = ?');
                $stmtProto->execute([$this->data['protocol_id']]);
                $protoData = $stmtProto->fetch();
                if ($protoData) {
                    $slug = (string) ($protoData['slug'] ?? '');
                    if (stripos($slug, 'xray') !== false) {
                        $isXray = true;
                    }
                    if (stripos($slug, 'aivpn') !== false) {
                        $isAivpn = true;
                    }
                }
            }
            
            // Fallback: check container_name or config for xray indicators
            if (!$isXray) {
                $containerName = $serverData['container_name'] ?? '';
                if (strpos($containerName, 'xray') !== false) {
                    $isXray = true;
                    $xrayContainerName = $containerName;
                } elseif (strpos($containerName, 'aivpn') !== false) {
                    $isAivpn = true;
                } elseif (!empty($this->data['config']) && strpos($this->data['config'], 'vless://') !== false) {
                    $isXray = true;
                } elseif (!empty($this->data['config']) && strpos($this->data['config'], 'aivpn://') === 0) {
                    $isAivpn = true;
                }
            }

            if ($isXray) {
                // XRay stats are tracked by email field in xray config
                // Try client name first (typically used as email), then UUID from config as fallback
                $identifier = null;
                $uuid = null;
                
                // Extract UUID from config 
                if (!empty($this->data['config']) && preg_match('/vless:\/\/([0-9a-fA-F-]{36})@/i', $this->data['config'], $m)) {
                    $uuid = $m[1];
                }
                
                // Override container_name for XRay stats
                $xrayServerData = $serverData;
                $xrayServerData['container_name'] = $xrayContainerName;
                
                // Try name first (typically matches email in xray config)
                if (!empty($this->data['name'])) {
                    $identifier = $this->data['name'];
                    $stats = self::getXrayStats($xrayServerData, $identifier);
                }
                
                // If no stats found by name, try UUID
                if ((empty($stats) || ($stats['bytes_sent'] == 0 && $stats['bytes_received'] == 0)) && $uuid) {
                    $identifier = $uuid;
                    $stats = self::getXrayStats($xrayServerData, $identifier);
                }

                if ($identifier && !empty($stats)) {
                    // Infer online status for XRay: if traffic increased, they are online.
                    // Update last_handshake to NOW() if activity detected.
                    if ($stats['bytes_sent'] > $prevSent || $stats['bytes_received'] > $prevReceived) {
                        $stats['last_handshake'] = time();
                    } else {
                        // Keep previous handshake if no new activity
                        $stats['last_handshake'] = $prevHandshake;
                    }
                }

            } elseif ($isAivpn) {
                $stats = self::getAivpnStatsFromServer($serverData, $this->data);
                if (!empty($stats)) {
                    $rawInNow = (int) ($stats['bytes_sent'] ?? 0);
                    $rawOutNow = (int) ($stats['bytes_received'] ?? 0);

                    if ($rawInNow < $aivpnRawInPrev) {
                        $aivpnOffsetIn = max($aivpnOffsetIn + $aivpnRawInPrev, $prevSent);
                    }
                    if ($rawOutNow < $aivpnRawOutPrev) {
                        $aivpnOffsetOut = max($aivpnOffsetOut + $aivpnRawOutPrev, $prevReceived);
                    }

                    $candidateSent = $aivpnOffsetIn + $rawInNow;
                    $candidateReceived = $aivpnOffsetOut + $rawOutNow;
                    $stats['bytes_sent'] = max($prevSent, $candidateSent);
                    $stats['bytes_received'] = max($prevReceived, $candidateReceived);

                    if (empty($stats['last_handshake']) || (int) $stats['last_handshake'] <= 0) {
                        $stats['last_handshake'] = $prevHandshake;
                    }
                }
            }

            if (empty($stats)) {
                $stats = self::getClientStatsFromServer($serverData, $this->data['public_key']);
            }

            // Calculate speeds (bytes per second)
            $now = time();
            $timeDiff = $now - $prevSyncAt;
            $currentSpeed = 0;
            $speedUp = 0;
            $speedDown = 0;

            if ($timeDiff > 0 && $prevSyncAt > 0) {
                // Total speed
                $bytesDiff = ($stats['bytes_sent'] + $stats['bytes_received']) - ($prevSent + $prevReceived);
                if ($bytesDiff > 0) {
                    $currentSpeed = (int) ($bytesDiff / $timeDiff);
                }

                // Upload speed
                $sentDiff = $stats['bytes_sent'] - $prevSent;
                if ($sentDiff > 0) {
                    $speedUp = (int) ($sentDiff / $timeDiff);
                }

                // Download speed
                $receivedDiff = $stats['bytes_received'] - $prevReceived;
                if ($receivedDiff > 0) {
                    $speedDown = (int) ($receivedDiff / $timeDiff);
                }
            }

            $isAivpnPersist = $isAivpn && !empty($stats);
            if ($isAivpnPersist) {
                $stmt = $pdo->prepare('
                    UPDATE vpn_clients 
                    SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, current_speed = ?, speed_up = ?, speed_down = ?,
                        aivpn_raw_bytes_in = ?, aivpn_raw_bytes_out = ?, aivpn_offset_bytes_in = ?, aivpn_offset_bytes_out = ?,
                        last_sync_at = NOW()
                    WHERE id = ?
                ');
            } else {
                $stmt = $pdo->prepare('
                    UPDATE vpn_clients 
                    SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, current_speed = ?, speed_up = ?, speed_down = ?, last_sync_at = NOW()
                    WHERE id = ?
                ');
            }

            $lastHandshake = $stats['last_handshake'] > 0
                ? date('Y-m-d H:i:s', $stats['last_handshake'])
                : null;

            if ($isAivpnPersist) {
                return $stmt->execute([
                    $stats['bytes_sent'],
                    $stats['bytes_received'],
                    $lastHandshake,
                    $currentSpeed,
                    $speedUp,
                    $speedDown,
                    (int) ($stats['bytes_sent_raw'] ?? 0),
                    (int) ($stats['bytes_received_raw'] ?? 0),
                    $aivpnOffsetIn,
                    $aivpnOffsetOut,
                    $this->clientId
                ]);
            }

            return $stmt->execute([
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $lastHandshake,
                $currentSpeed,
                $speedUp,
                $speedDown,
                $this->clientId
            ]);
        } catch (Exception $e) {
            error_log('Failed to sync client stats: ' . $e->getMessage());
            return false;
        }
    }

    private static function getAivpnStatsFromServer(array $serverData, array $clientData): array
    {
        $stats = [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'bytes_sent_raw' => 0,
            'bytes_received_raw' => 0,
            'last_handshake' => 0,
        ];

        $containerName = (string) ($serverData['container_name'] ?? '');
        if ($containerName === '' || stripos($containerName, 'aivpn') === false) {
            $containerName = 'aivpn-server';
        }

        $cmd = sprintf('docker exec -i %s cat /etc/aivpn/clients.json 2>/dev/null', escapeshellarg($containerName));
        $output = self::executeServerCommand($serverData, $cmd, true);
        if (trim((string) $output) === '') {
            return $stats;
        }

        $data = json_decode((string) $output, true);
        if (!is_array($data) || !isset($data['clients']) || !is_array($data['clients'])) {
            return $stats;
        }

        $name = strtolower(trim((string) ($clientData['name'] ?? '')));
        $clientIp = trim((string) ($clientData['client_ip'] ?? ''));
        $cfgIp = self::extractAivpnIpFromConfig((string) ($clientData['config'] ?? ''));

        $match = null;
        foreach ($data['clients'] as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $entryName = strtolower(trim((string) ($entry['name'] ?? '')));
            $entryIp = trim((string) ($entry['vpn_ip'] ?? ''));
            if ($name !== '' && $entryName === $name) {
                $match = $entry;
                break;
            }
            if ($clientIp !== '' && $entryIp === $clientIp) {
                $match = $entry;
                break;
            }
            if ($cfgIp !== '' && $entryIp === $cfgIp) {
                $match = $entry;
                break;
            }
        }

        if (!is_array($match)) {
            return $stats;
        }

        $s = is_array($match['stats'] ?? null) ? $match['stats'] : [];
        $rawIn = (int) ($s['bytes_in'] ?? 0);
        $rawOut = (int) ($s['bytes_out'] ?? 0);
        $stats['bytes_sent_raw'] = $rawIn;
        $stats['bytes_received_raw'] = $rawOut;
        $stats['bytes_sent'] = $rawIn;
        $stats['bytes_received'] = $rawOut;

        if (!empty($s['last_handshake']) && is_string($s['last_handshake'])) {
            $ts = strtotime($s['last_handshake']);
            if ($ts !== false) {
                $stats['last_handshake'] = (int) $ts;
            }
        }

        return $stats;
    }

    private static function extractAivpnIpFromConfig(string $config): string
    {
        if (stripos($config, 'aivpn://') !== 0) {
            return '';
        }

        $payload = substr($config, strlen('aivpn://'));
        if ($payload === '') {
            return '';
        }

        $b64 = strtr($payload, '-_', '+/');
        $padLen = strlen($b64) % 4;
        if ($padLen > 0) {
            $b64 .= str_repeat('=', 4 - $padLen);
        }

        $decoded = base64_decode($b64, true);
        if ($decoded === false) {
            return '';
        }

        $data = json_decode($decoded, true);
        if (!is_array($data)) {
            return '';
        }

        $ip = trim((string) ($data['i'] ?? ''));
        return preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/', $ip) ? $ip : '';
    }

    /**
     * Get client statistics from server
     */
    private static function getClientStatsFromServer(array $serverData, string $publicKey): array
    {
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
            if (empty($line))
                continue;

            $parts = preg_split('/\s+/', trim($line));

            // Skip first line (server) - it has different format
            if (count($parts) < 7)
                continue;

            // Match by public key
            if ($parts[0] === $publicKey) {
                $stats['last_handshake'] = (int) $parts[4];
                $stats['bytes_sent'] = (int) $parts[5];      // transfer_rx - client sent
                $stats['bytes_received'] = (int) $parts[6];  // transfer_tx - client received
                break;
            }
        }

        return $stats;
    }

    /**
     * Sync stats for all active clients on a server
     */
    public static function syncAllStatsForServer(int $serverId): int
    {
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
    public function getFormattedStats(): array
    {
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
     * Format bytes to human-readable string (always in MB)
     */
    private function formatBytes(int $bytes): string
    {
        $mb = $bytes / 1048576; // 1024 * 1024
        return number_format($mb, 2) . ' MB';
    }

    /**
     * Set client expiration date
     * 
     * @param int $clientId Client ID
     * @param string|null $expiresAt Expiration date (Y-m-d H:i:s) or null for never expires
     * @return bool Success
     */
    public static function setExpiration(int $clientId, ?string $expiresAt): bool
    {
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
    public static function extendExpiration(int $clientId, int $days): bool
    {
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
    public static function getExpiringClients(int $days = 7): array
    {
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
    public static function getExpiredClients(): array
    {
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
    public static function disableExpiredClients(): int
    {
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
    public function isExpired(): bool
    {
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
    public function getDaysUntilExpiration(): ?int
    {
        if (!$this->data || $this->data['expires_at'] === null) {
            return null;
        }

        $diff = strtotime($this->data['expires_at']) - time();
        return (int) floor($diff / 86400);
    }

    /**
     * Set traffic limit for client
     * 
     * @param int|null $limitBytes Traffic limit in bytes (NULL = unlimited)
     * @return bool Success
     */
    public function setTrafficLimit(?int $limitBytes): bool
    {
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
    public function getTotalTraffic(): int
    {
        if (!$this->data) {
            return 0;
        }

        return (int) ($this->data['traffic_sent'] ?? 0) + (int) ($this->data['traffic_received'] ?? 0);
    }

    /**
     * Check if client has exceeded traffic limit
     * 
     * @return bool True if over limit
     */
    public function isOverLimit(): bool
    {
        if (!$this->data || $this->data['traffic_limit'] === null) {
            return false; // No limit set
        }

        $totalTraffic = $this->getTotalTraffic();
        return $totalTraffic >= (int) $this->data['traffic_limit'];
    }

    /**
     * Get traffic limit status
     * 
     * @return array Status info
     */
    public function getTrafficLimitStatus(): array
    {
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
    public static function getClientsOverLimit(): array
    {
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
    public static function disableClientsOverLimit(): int
    {
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


