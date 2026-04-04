<?php

/**
 * ServerMonitoring - Collect and store server metrics
 * 
 * Collects:
 * - CPU usage
 * - RAM usage
 * - Disk usage
 * - Network speed
 * - Client traffic speed
 */
class ServerMonitoring
{
    private VpnServer $server;
    private array $serverData;
    private array $xrayStatsCache = [];
    private bool $xrayStatsFetched = false;
    private array $aivpnStatsCache = ['by_name' => [], 'by_id' => [], 'by_ip' => []];
    private bool $aivpnStatsFetched = false;

    /**
     * Fetch all X-ray user stats in one batch
     * Returns true on success, false on failure (SSH / JSON error)
     */
    private function fetchXrayStats(): bool
    {
        if ($this->xrayStatsFetched) {
            return true;
        }

        // Always try to fetch from amnezia-xray container
        // Even if server's container_name is different, there may be xray clients
        $xrayContainer = $this->getXrayContainerName() ?? 'amnezia-xray';
        
        $cmd = "docker exec $xrayContainer xray api statsquery --pattern 'user>>>' --reset=true --server=127.0.0.1:10085 2>/dev/null";
        $json = $this->execSSH($cmd);

        if (!$json || trim($json) === '') {
            // Assuming a log method exists or needs to be added, for now, using error_log
            error_log("Failed to fetch X-ray stats (empty response)");
            return false;
        }

        $data = json_decode($json, true);
        if (!isset($data['stat'])) {
            // If empty stats, but successful connection, it's fine (just no traffic delta)
            $this->xrayStatsCache = [];
            $this->xrayStatsFetched = true;
            return true;
        }

        $stats = [];
        foreach ($data['stat'] as $item) {
            // "user>>>email>>>traffic>>>downlink"
            $parts = explode('>>>', $item['name']);
            if (count($parts) >= 4) {
                $email = $parts[1];
                $type = $parts[3]; // 'downlink' or 'uplink'

                if (!isset($stats[$email])) {
                    $stats[$email] = ['up' => 0, 'down' => 0];
                }

                if ($type === 'uplink') {
                    $stats[$email]['up'] += (int) $item['value'];
                } elseif ($type === 'downlink') {
                    $stats[$email]['down'] += (int) $item['value'];
                }
            }
        }

        $this->xrayStatsCache = $stats;
        $this->xrayStatsFetched = true;
        return true;
    }

    public function __construct(int $serverId)
    {
        $this->server = new VpnServer($serverId);
        $this->serverData = $this->server->getData();
    }

    /**
     * Collect all server metrics
     */
    public function collectMetrics(): array
    {
        $metrics = [
            'cpu_percent' => $this->getCpuUsage(),
            'ram_used_mb' => $this->getRamUsed(),
            'ram_total_mb' => $this->getRamTotal(),
            'disk_used_gb' => $this->getDiskUsed(),
            'disk_total_gb' => $this->getDiskTotal(),
            'network_rx_mbps' => $this->getNetworkRxSpeed(),
            'network_tx_mbps' => $this->getNetworkTxSpeed(),
        ];

        $this->saveServerMetrics($metrics);

        return $metrics;
    }

    /**
     * Collect client traffic metrics
     */
    public function collectClientMetrics(): array
    {
        // Enforce single IP per user for Xray before collecting stats
        if ($this->isXrayServer()) {
            try {
                $this->enforceXraySingleIpPerUser();
            } catch (Throwable $e) {
                error_log("Xray enforcement error: " . $e->getMessage());
            }
        }

        // Pre-fetch X-ray stats only for Xray servers.
        // Otherwise we block AWG/WireGuard stats collection with irrelevant Xray errors.
        if ($this->isXrayServer()) {
            if (!$this->fetchXrayStats()) {
                error_log("Failed to fetch X-ray stats, preventing DB overwrite");
                return []; // Abort only for Xray servers
            }
        }

        // For AIVPN we best-effort fetch client stats once per cycle.
        if ($this->isAivpnServer()) {
            if (!$this->fetchAivpnStats()) {
                error_log("Failed to fetch AIVPN stats, using DB fallback values");
            }
        }

        $clients = VpnClient::listByServer($this->serverData['id']);
        $results = [];

        foreach ($clients as $client) {
            if ($client['status'] !== 'active')
                continue;

            $stats = $this->getClientStats($client);
            if ($stats) {
                // Check if speed values are excessively high (spike detection)
                // Use 10Gbps (1250 MB/s) as sanity limit. 1250 * 1024 * 1024 ~ 1.3e9
                // Actually ServerMonitoring calculates bytes/sec. 
                // If speed is > 2 Gbit/s likely an error (unless on 10G link, but rare)
                // Let's rely on simple positive check for now.

                $this->saveClientMetrics($client['id'], $stats);
                $results[] = [
                    'client_id' => $client['id'],
                    'client_name' => $client['name'],
                    'speed_up_kbps' => $stats['speed_up_kbps'],
                    'speed_down_kbps' => $stats['speed_down_kbps'],
                ];
            }
        }

        return $results;
    }

    /**
     * Get CPU usage percentage
     */
    private function getCpuUsage(): ?float
    {
        $cmd = "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - \$1}'";
        $result = $this->execSSH($cmd);

        return $result ? (float) trim($result) : null;
    }

    /**
     * Get RAM used in MB
     */
    private function getRamUsed(): ?int
    {
        $cmd = "free -m | grep Mem | awk '{print \$3}'";
        $result = $this->execSSH($cmd);

        return $result ? (int) trim($result) : null;
    }

    /**
     * Get total RAM in MB
     */
    private function getRamTotal(): ?int
    {
        $cmd = "free -m | grep Mem | awk '{print \$2}'";
        $result = $this->execSSH($cmd);

        return $result ? (int) trim($result) : null;
    }

    /**
     * Get disk used in GB
     */
    private function getDiskUsed(): ?float
    {
        $cmd = "df -BG / | tail -1 | awk '{print \$3}' | sed 's/G//'";
        $result = $this->execSSH($cmd);

        return $result ? (float) trim($result) : null;
    }

    /**
     * Get total disk in GB
     */
    private function getDiskTotal(): ?float
    {
        $cmd = "df -BG / | tail -1 | awk '{print \$2}' | sed 's/G//'";
        $result = $this->execSSH($cmd);

        return $result ? (float) trim($result) : null;
    }

    /**
     * Get network RX speed in Mbps
     */
    private function getNetworkRxSpeed(): ?float
    {
        // Get bytes received on main interface
        $cmd = "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/rx_bytes";
        $bytes1 = $this->execSSH($cmd);

        if (!$bytes1)
            return null;

        sleep(1); // Wait 1 second

        $bytes2 = $this->execSSH($cmd);

        if (!$bytes2)
            return null;

        // Calculate speed in Mbps
        $bytesPerSec = (int) $bytes2 - (int) $bytes1;
        $mbps = ($bytesPerSec * 8) / 1000000;

        return round($mbps, 2);
    }

    /**
     * Get network TX speed in Mbps
     */
    private function getNetworkTxSpeed(): ?float
    {
        // Get bytes transmitted on main interface
        $cmd = "cat /sys/class/net/\$(ip route | grep default | awk '{print \$5}' | head -1)/statistics/tx_bytes";
        $bytes1 = $this->execSSH($cmd);

        if (!$bytes1)
            return null;

        sleep(1); // Wait 1 second

        $bytes2 = $this->execSSH($cmd);

        if (!$bytes2)
            return null;

        // Calculate speed in Mbps
        $bytesPerSec = (int) $bytes2 - (int) $bytes1;
        $mbps = ($bytesPerSec * 8) / 1000000;

        return round($mbps, 2);
    }

    /**
     * Get client current stats and calculate speed
     */
    private function getClientStats(array $client): ?array
    {
        $db = DB::conn();
        // this->fetchXrayStats() call moved to collectClientMetrics to handle failure gracefully

        // Get current stats from server
        $containerName = (string) ($this->serverData['container_name'] ?? '');
        $bytesReceived = 0;
        $bytesSent = 0;
        $speedUp = 0;
        $speedDown = 0;

        // Determine if this client is XRay based on protocol_id
        $isXrayClient = false;
        $protocolSlug = '';
        if (!empty($client['protocol_id'])) {
            $stmtProto = $db->prepare('SELECT slug FROM protocols WHERE id = ?');
            $stmtProto->execute([$client['protocol_id']]);
            $protoData = $stmtProto->fetch();
            if ($protoData) {
                $protocolSlug = (string) ($protoData['slug'] ?? '');
                if (stripos($protocolSlug, 'xray') !== false) {
                    $isXrayClient = true;
                }
            }
        }
        
        // Fallback: check config for vless URI
        if (!$isXrayClient && !empty($client['config']) && strpos($client['config'], 'vless://') !== false) {
            $isXrayClient = true;
        }

        $isAivpnClient = (
            stripos($protocolSlug, 'aivpn') !== false ||
            (!empty($client['config']) && strpos((string) $client['config'], 'aivpn://') === 0)
        );

        if ($isXrayClient) {
            // Retrieve DELTA from cache
            if ($this->xrayStatsFetched) {
                // Try name first (matches email in xray config), then UUID from config
                $key = $client['name'];
                if (!isset($this->xrayStatsCache[$key])) {
                    // Try UUID from config
                    if (!empty($client['config']) && preg_match('/vless:\/\/([0-9a-fA-F-]{36})@/i', $client['config'], $m)) {
                        $key = $m[1];
                    }
                }
                
                if (!isset($this->xrayStatsCache[$key])) {
                    // Try client['id'] as last resort
                    $key = $client['id'];
                }

                if (isset($this->xrayStatsCache[$key])) {
                    $xStats = $this->xrayStatsCache[$key];

                    // CRITICAL FIX: Add DELTA to existing DB values
                    // We need to get the current total bytes from the DB first
                    $stmt = $db->prepare("SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?");
                    $stmt->execute([$client['id']]);
                    $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);

                    $bytesSent = ($currentDbStats['bytes_sent'] ?? 0) + (int) $xStats['up'];
                    $bytesReceived = ($currentDbStats['bytes_received'] ?? 0) + (int) $xStats['down'];

                    // Calculate speed based on DELTA (since Reset=true, value IS the delta since last check)
                    // Assuming cron runs every minute (60s):
                    $speedUp = round($xStats['up'] / 60);
                    $speedDown = round($xStats['down'] / 60);
                } else {
                    // No stats in cache, use current DB values
                    $stmt = $db->prepare("SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?");
                    $stmt->execute([$client['id']]);
                    $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);
                    $bytesSent = $currentDbStats['bytes_sent'] ?? 0;
                    $bytesReceived = $currentDbStats['bytes_received'] ?? 0;
                }
            }
        } else {
            // WireGuard Logic - get bytes and handshake timestamp
            $publicKey = $client['public_key'];
            $isWireguardClient = (
                stripos($protocolSlug, 'awg') !== false ||
                stripos($protocolSlug, 'wireguard') !== false
            );

            if ($isWireguardClient) {
                $containerName = $this->resolveContainerForProtocol($protocolSlug);
            }

            if ($isAivpnClient) {
                $aivpn = $this->getAivpnClientStats($client);
                if (is_array($aivpn)) {
                    $stmt = $db->prepare("SELECT bytes_sent, bytes_received, aivpn_raw_bytes_in, aivpn_raw_bytes_out, aivpn_offset_bytes_in, aivpn_offset_bytes_out FROM vpn_clients WHERE id = ?");
                    $stmt->execute([$client['id']]);
                    $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);

                    $prevSent = (int) ($currentDbStats['bytes_sent'] ?? 0);
                    $prevReceived = (int) ($currentDbStats['bytes_received'] ?? 0);
                    $rawInPrev = (int) ($currentDbStats['aivpn_raw_bytes_in'] ?? 0);
                    $rawOutPrev = (int) ($currentDbStats['aivpn_raw_bytes_out'] ?? 0);
                    $offsetIn = (int) ($currentDbStats['aivpn_offset_bytes_in'] ?? 0);
                    $offsetOut = (int) ($currentDbStats['aivpn_offset_bytes_out'] ?? 0);

                    $rawInNow = (int) ($aivpn['bytes_in'] ?? 0);
                    $rawOutNow = (int) ($aivpn['bytes_out'] ?? 0);

                    // Detect counter rollover/reset in AIVPN source and preserve cumulative totals.
                    if ($rawInNow < $rawInPrev) {
                        $offsetIn = max($offsetIn + $rawInPrev, $prevSent);
                    }
                    if ($rawOutNow < $rawOutPrev) {
                        $offsetOut = max($offsetOut + $rawOutPrev, $prevReceived);
                    }

                    $candidateSent = $offsetIn + $rawInNow;
                    $candidateReceived = $offsetOut + $rawOutNow;

                    // AIVPN stores per-client counters as bytes_in/bytes_out.
                    // Map to panel semantics: sent=client upload, received=client download.
                    $bytesSent = max($prevSent, $candidateSent);
                    $bytesReceived = max($prevReceived, $candidateReceived);

                    $stmtAivpn = $db->prepare("UPDATE vpn_clients SET aivpn_raw_bytes_in = ?, aivpn_raw_bytes_out = ?, aivpn_offset_bytes_in = ?, aivpn_offset_bytes_out = ? WHERE id = ?");
                    $stmtAivpn->execute([$rawInNow, $rawOutNow, $offsetIn, $offsetOut, $client['id']]);

                    $lastHandshake = $aivpn['last_handshake'] ?? null;
                    if (is_string($lastHandshake) && $lastHandshake !== '') {
                        $ts = strtotime($lastHandshake);
                        if ($ts) {
                            $stmtHs = $db->prepare("UPDATE vpn_clients SET last_handshake = ? WHERE id = ?");
                            $stmtHs->execute([date('Y-m-d H:i:s', $ts), $client['id']]);
                        }
                    }
                } else {
                    $stmt = $db->prepare("SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?");
                    $stmt->execute([$client['id']]);
                    $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);
                    $bytesSent = (int) ($currentDbStats['bytes_sent'] ?? 0);
                    $bytesReceived = (int) ($currentDbStats['bytes_received'] ?? 0);
                }
            } elseif (empty($publicKey) || !$isWireguardClient) {
                // Non-WireGuard protocols without dedicated collectors keep DB values.
                $stmt = $db->prepare("SELECT bytes_sent, bytes_received FROM vpn_clients WHERE id = ?");
                $stmt->execute([$client['id']]);
                $currentDbStats = $stmt->fetch(PDO::FETCH_ASSOC);
                $bytesSent = (int) ($currentDbStats['bytes_sent'] ?? 0);
                $bytesReceived = (int) ($currentDbStats['bytes_received'] ?? 0);
            } else {
            // wg show all dump format (tab-separated):
            // $1=interface $2=pubkey $3=psk $4=endpoint $5=allowed-ips $6=latest-handshake $7=rx-bytes $8=tx-bytes $9=keepalive
            // rx-bytes = bytes received by server = client's upload (bytes_sent)
            // tx-bytes = bytes transmitted by server = client's download (bytes_received)
            $cmd = "docker exec {$containerName} wg show all dump | grep '{$publicKey}' | awk '{print \$6, \$7, \$8}'";
            $result = $this->execSSH($cmd);

            if ($result) {
                $parts = explode(' ', trim($result));
                if (count($parts) >= 3) {
                    $handshakeTs = (int)$parts[0];
                    $bytesSent = (int)$parts[1];     // server's rx = client's upload
                    $bytesReceived = (int)$parts[2]; // server's tx = client's download
                    
                    // Update last_handshake if there was a recent handshake
                    if ($handshakeTs > 0) {
                        $handshakeDate = date('Y-m-d H:i:s', $handshakeTs);
                        $stmtHs = $db->prepare("UPDATE vpn_clients SET last_handshake = ? WHERE id = ?");
                        $stmtHs->execute([$handshakeDate, $client['id']]);
                    }
                }
            }
            }
        }

        // If we couldn't get stats (and they are 0), check if we have previous stats to avoid zeroing out if API fails?
        // But for speed calc we need current values.

        // Get previous metrics (30 seconds ago)
        $stmt = $db->prepare("
            SELECT bytes_sent, bytes_received, collected_at
            FROM client_metrics
            WHERE client_id = ?
            ORDER BY collected_at DESC
            LIMIT 1
        ");
        $stmt->execute([$client['id']]);
        $previous = $stmt->fetch(PDO::FETCH_ASSOC);

        $speedUp = 0;
        $speedDown = 0;

        if ($previous) {
            $timeDiff = time() - strtotime($previous['collected_at']);
            // Check for reasonable time diff to avoid division by zero or huge spikes
            if ($timeDiff > 0 && $timeDiff < 300) {
                // Calculate speed in Kbps
                $bytesDiffSent = (int) $bytesSent - (int) $previous['bytes_sent'];
                $bytesDiffReceived = (int) $bytesReceived - (int) $previous['bytes_received'];

                // Allow for some jitter/counter resets (ignore negative speed which means restart)
                if ($bytesDiffSent >= 0) {
                    $speedUp = round(($bytesDiffSent * 8) / $timeDiff / 1000, 2);
                }
                if ($bytesDiffReceived >= 0) {
                    $speedDown = round(($bytesDiffReceived * 8) / $timeDiff / 1000, 2);
                }
            }
        }

        return [
            'bytes_sent' => (int) $bytesSent,
            'bytes_received' => (int) $bytesReceived,
            'speed_up_kbps' => $speedUp,
            'speed_down_kbps' => $speedDown,
        ];
    }

    /**
     * Save server metrics to database
     */
    private function saveServerMetrics(array $metrics): void
    {
        $db = DB::conn();

        $stmt = $db->prepare("
            INSERT INTO server_metrics 
            (server_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, network_rx_mbps, network_tx_mbps)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $this->serverData['id'],
            $metrics['cpu_percent'],
            $metrics['ram_used_mb'],
            $metrics['ram_total_mb'],
            $metrics['disk_used_gb'],
            $metrics['disk_total_gb'],
            $metrics['network_rx_mbps'],
            $metrics['network_tx_mbps'],
        ]);
    }

    /**
     * Save client metrics to database
     */
    private function saveClientMetrics(int $clientId, array $stats): void
    {
        $db = DB::conn();

        $stmt = $db->prepare("
            INSERT INTO client_metrics 
            (client_id, bytes_sent, bytes_received, speed_up_kbps, speed_down_kbps)
            VALUES (?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $clientId,
            $stats['bytes_sent'],
            $stats['bytes_received'],
            $stats['speed_up_kbps'],
            $stats['speed_down_kbps'],
        ]);

        // Update vpn_clients table with latest stats (don't touch last_handshake - it's set separately for WG/AWG)
        $stmt = $db->prepare("
            UPDATE vpn_clients 
            SET bytes_sent = ?, bytes_received = ?, speed_up = ?, speed_down = ?, current_speed = ?, last_sync_at = NOW()
            WHERE id = ?
        ");

        $currentSpeed = $stats['speed_up_kbps'] + $stats['speed_down_kbps']; // Total speed in Kbps? Or bytes/s?
        // Note: speed_up_kbps is in Kbps (kilobits?). 
        // VpnClient stores speed in Bytes/s (based on my previous edit: bytesDiff/timeDiff).
        // ServerMonitoring calculates: round(($bytesDiffSent * 8) / $timeDiff / 1000, 2) -> Kbps

        // Wait! VpnClient implementation I did:
        // $speedUp = (int) ($sentDiff / $timeDiff); // Bytes per second

        // ServerMonitoring implementation:
        // $speedUp = round(($bytesDiffSent * 8) / $timeDiff / 1000, 2); // Kilobits per second

        // I need to be consistent. 
        // Frontend expects KB/s (KiloBYTES). 
        // VpnClient stores BYTES per second. Twig does `speed / 1024` -> KB/s.

        // So I should convert ServerMonitoring stats to Bytes/s before saving to vpn_clients.
        // ServerMonitoring $stats['speed_up_kbps'] is Kbps.
        // Bytes/s = Kbps * 1000 / 8.

        $speedUpBytes = (int) ($stats['speed_up_kbps'] * 1000 / 8);
        $speedDownBytes = (int) ($stats['speed_down_kbps'] * 1000 / 8);
        $totalSpeedBytes = $speedUpBytes + $speedDownBytes;

        $stmt->execute([
            $stats['bytes_sent'],
            $stats['bytes_received'],
            $speedUpBytes,
            $speedDownBytes,
            $totalSpeedBytes,
            $clientId
        ]);
    }

    /**
     * Get server metrics for last 24 hours
     */
    public static function getServerMetrics(int $serverId, int $hours = 24): array
    {
        $db = DB::conn();

        $stmt = $db->prepare("
            SELECT *
            FROM server_metrics
            WHERE server_id = ?
            AND collected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
            ORDER BY collected_at ASC
        ");

        $stmt->execute([$serverId, $hours]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get client metrics for last 24 hours
     */
    public static function getClientMetrics(int $clientId, int $hours = 24): array
    {
        $db = DB::conn();

        $stmt = $db->prepare("
            SELECT *
            FROM client_metrics
            WHERE client_id = ?
            AND collected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
            ORDER BY collected_at ASC
        ");

        $stmt->execute([$clientId, $hours]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Clean old metrics (older than 24 hours)
     */
    public static function cleanOldMetrics(): void
    {
        $db = DB::conn();

        // Clean server metrics
        $db->exec("DELETE FROM server_metrics WHERE collected_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

        // Clean client metrics
        $db->exec("DELETE FROM client_metrics WHERE collected_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    }

    /**
     * Execute SSH command on server
     */
    private function execSSH(string $cmd): ?string
    {
        $host = $this->serverData['host'];
        $port = (int)$this->serverData['port'];
        $username = $this->serverData['username'];
        $password = $this->serverData['password'];

        $sshOptions = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null';
        $sshCmd = sprintf(
            "sshpass -p '%s' ssh -p %d %s %s@%s %s 2>/dev/null",
            $password,
            $port,
            $sshOptions,
            $username,
            $host,
            escapeshellarg($cmd)
        );

        $output = shell_exec($sshCmd);

        return $output ?: null;
    }

    /**
     * Get Xray container name for this server
     * @return string|null Container name or null if not an Xray server
     */
    private function getXrayContainerName(): ?string
    {
        $containerName = $this->serverData['container_name'] ?? '';
        // Check if this is an Xray server
        if (stripos($containerName, 'xray') !== false) {
            return $containerName;
        }
        // Also check protocol
        $protocol = $this->serverData['install_protocol'] ?? '';
        if (stripos($protocol, 'xray') !== false || stripos($protocol, 'vless') !== false) {
            return $containerName ?: 'amnezia-xray';
        }
        return null;
    }

    /**
     * Check if this server is an Xray server
     */
    private function isXrayServer(): bool
    {
        return $this->getXrayContainerName() !== null;
    }

    /**
     * Check if this server is an AIVPN server.
     */
    private function isAivpnServer(): bool
    {
        $containerName = (string) ($this->serverData['container_name'] ?? '');
        $protocol = (string) ($this->serverData['install_protocol'] ?? '');
        return stripos($containerName, 'aivpn') !== false || stripos($protocol, 'aivpn') !== false;
    }

    /**
     * Fetch AIVPN clients and their stats once per collection cycle.
     */
    private function fetchAivpnStats(): bool
    {
        if ($this->aivpnStatsFetched) {
            return true;
        }

        $this->aivpnStatsFetched = true;
        $this->aivpnStatsCache = ['by_name' => [], 'by_id' => [], 'by_ip' => []];

        $containerName = trim((string) ($this->serverData['container_name'] ?? ''));
        if ($containerName === '' || stripos($containerName, 'aivpn') === false) {
            $containerName = 'aivpn-server';
        }

        $jsonRaw = $this->execSSH(
            'docker exec -i ' . escapeshellarg($containerName) . ' cat /etc/aivpn/clients.json 2>/dev/null'
        );

        if (!$jsonRaw || trim($jsonRaw) === '') {
            return false;
        }

        $data = json_decode($jsonRaw, true);
        if (!is_array($data) || !isset($data['clients']) || !is_array($data['clients'])) {
            return false;
        }

        foreach ($data['clients'] as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $stats = is_array($entry['stats'] ?? null) ? $entry['stats'] : [];
            $record = [
                'id' => (string) ($entry['id'] ?? ''),
                'name' => (string) ($entry['name'] ?? ''),
                'vpn_ip' => (string) ($entry['vpn_ip'] ?? ''),
                'bytes_in' => (int) ($stats['bytes_in'] ?? 0),
                'bytes_out' => (int) ($stats['bytes_out'] ?? 0),
                'last_handshake' => isset($stats['last_handshake']) ? (string) $stats['last_handshake'] : null,
            ];

            if ($record['name'] !== '') {
                $this->aivpnStatsCache['by_name'][strtolower($record['name'])] = $record;
            }
            if ($record['id'] !== '') {
                $this->aivpnStatsCache['by_id'][$record['id']] = $record;
            }
            if ($record['vpn_ip'] !== '') {
                $this->aivpnStatsCache['by_ip'][$record['vpn_ip']] = $record;
            }
        }

        return true;
    }

    private function getAivpnClientStats(array $client): ?array
    {
        if (!$this->aivpnStatsFetched && !$this->fetchAivpnStats()) {
            return null;
        }

        $name = trim((string) ($client['name'] ?? ''));
        if ($name !== '') {
            $nameKey = strtolower($name);
            if (isset($this->aivpnStatsCache['by_name'][$nameKey])) {
                return $this->aivpnStatsCache['by_name'][$nameKey];
            }
        }

        $clientIp = trim((string) ($client['client_ip'] ?? ''));
        if ($clientIp !== '' && isset($this->aivpnStatsCache['by_ip'][$clientIp])) {
            return $this->aivpnStatsCache['by_ip'][$clientIp];
        }

        $cfgIp = $this->extractAivpnIpFromConfig((string) ($client['config'] ?? ''));
        if ($cfgIp !== '' && isset($this->aivpnStatsCache['by_ip'][$cfgIp])) {
            return $this->aivpnStatsCache['by_ip'][$cfgIp];
        }

        return null;
    }

    private function extractAivpnIpFromConfig(string $config): string
    {
        if (stripos($config, 'aivpn://') !== 0) {
            return '';
        }

        $payload = substr($config, strlen('aivpn://'));
        if ($payload === '') {
            return '';
        }

        $decoded = base64_decode(strtr($payload, '-_', '+/'), true);
        if ($decoded === false) {
            $padLen = strlen($payload) % 4;
            $normalized = $payload;
            if ($padLen > 0) {
                $normalized .= str_repeat('=', 4 - $padLen);
            }
            $decoded = base64_decode(strtr($normalized, '-_', '+/'), true);
        }

        if ($decoded === false) {
            return '';
        }

        $data = json_decode($decoded, true);
        if (!is_array($data)) {
            return '';
        }

        $ip = trim((string) ($data['i'] ?? ''));
        if ($ip !== '' && preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/', $ip)) {
            return $ip;
        }

        return '';
    }

    private function resolveContainerForProtocol(string $protocolSlug): string
    {
        $default = trim((string) ($this->serverData['container_name'] ?? ''));
        if ($protocolSlug === '') {
            return $default;
        }

        try {
            $db = DB::conn();
            $stmt = $db->prepare('SELECT definition FROM protocols WHERE slug = ? LIMIT 1');
            $stmt->execute([$protocolSlug]);
            $definitionJson = $stmt->fetchColumn();
            if (is_string($definitionJson) && $definitionJson !== '') {
                $definition = json_decode($definitionJson, true);
                if (is_array($definition)) {
                    $candidate = trim((string) ($definition['metadata']['container_name'] ?? ''));
                    if ($candidate !== '') {
                        return $candidate;
                    }
                }
            }
        } catch (Throwable $e) {
            // Fallback to default container.
        }

        if ($protocolSlug === 'awg2') {
            return 'amnezia-awg2';
        }
        if (stripos($protocolSlug, 'aivpn') !== false) {
            return 'aivpn-server';
        }

        return $default;
    }

    /**
     * Enforce single IP per user for Xray connections
     * If a user is connected from multiple IPs, block all but the first one
     */
    public function enforceXraySingleIpPerUser(): void
    {
        $xrayContainer = $this->getXrayContainerName();
        if (!$xrayContainer) {
            return; // Not an Xray server
        }

        // Get all online users
        $cmd = "docker exec $xrayContainer xray api statsgetallonlineusers --server=127.0.0.1:10085";
        $result = $this->execSSH($cmd);
        if (!$result) {
            return;
        }

        $data = json_decode($result, true);
        if (!isset($data['users']) || !is_array($data['users'])) {
            return;
        }

        $ipsToBlock = [];

        foreach ($data['users'] as $user) {
            // Format: "user>>>email>>>online"
            if (!is_string($user)) {
                continue;
            }
            $parts = explode('>>>', $user);
            if (count($parts) < 2) {
                continue;
            }
            $email = $parts[1];
            if (!$email) {
                continue;
            }

            // Get IP list for this user
            $ipCmd = "docker exec $xrayContainer xray api statsonlineiplist --server=127.0.0.1:10085 --email=" . escapeshellarg($email);
            $ipResult = $this->execSSH($ipCmd);
            if (!$ipResult) {
                continue;
            }

            $ipData = json_decode($ipResult, true);
            if (!isset($ipData['ips']) || !is_array($ipData['ips'])) {
                continue;
            }

            // If more than 1 IP, block all but the first (oldest by timestamp)
            if (count($ipData['ips']) > 1) {
                // Sort by timestamp (value) ascending
                asort($ipData['ips']);
                $first = true;
                foreach ($ipData['ips'] as $ip => $timestamp) {
                    if ($first) {
                        $first = false;
                        continue; // Keep first IP
                    }
                    $ipsToBlock[] = $ip;
                }
            }
        }

        // Update blocking rules
        if (!empty($ipsToBlock)) {
            // Block collected IPs (with -reset to replace existing rule)
            $ipList = implode(' ', array_unique($ipsToBlock));
            $blockCmd = "docker exec $xrayContainer xray api sib --server=127.0.0.1:10085 -outbound=blocked -inbound=vless-in -reset $ipList";
            $this->execSSH($blockCmd);
            error_log("[Xray Enforcement] Blocked IPs: $ipList");
        } else {
            // No IPs to block - remove the blocking rule if it exists
            $rmCmd = "docker exec $xrayContainer xray api rmrules --server=127.0.0.1:10085 sourceIpBlock 2>/dev/null || true";
            $this->execSSH($rmCmd);
        }
    }

    /**
     * Enforce single IP per peer for AWG/WireGuard connections.
     * If a peer's endpoint changes while session is active, block the new IP.
     */
    public function enforceAwgSingleIpPerPeer(): void
    {
        $containerName = $this->serverData['container_name'] ?? '';
        if (strpos($containerName, 'awg') === false && strpos($containerName, 'wireguard') === false) {
            return; // Not an AWG server
        }

        // Get current peer states
        $cmd = "docker exec $containerName wg show wg0 dump";
        $result = $this->execSSH($cmd);
        if (!$result) {
            return;
        }

        $lines = explode("\n", trim($result));
        if (count($lines) < 2) {
            return; // No peers
        }

        // Load locked endpoints from file
        $lockFile = '/tmp/awg_locked_endpoints_' . $this->serverData['id'] . '.json';
        $lockedEndpoints = [];
        $lockFileCmd = "cat $lockFile 2>/dev/null || echo '{}'";
        $lockData = $this->execSSH($lockFileCmd);
        if ($lockData) {
            $lockedEndpoints = json_decode($lockData, true) ?: [];
        }

        $currentPeers = [];
        $ipsToBlock = [];
        $now = time();

        // Skip first line (interface info)
        for ($i = 1; $i < count($lines); $i++) {
            $parts = preg_split('/\s+/', trim($lines[$i]));
            if (count($parts) < 8) {
                continue;
            }

            // Format: interface pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive
            $pubkey = $parts[0];
            $endpoint = $parts[2]; // IP:Port or (none)
            $latestHandshake = (int)$parts[4];

            if ($endpoint === '(none)' || $latestHandshake === 0) {
                // Peer not connected - clear lock
                unset($lockedEndpoints[$pubkey]);
                continue;
            }

            // Extract just IP from endpoint (IP:Port)
            $endpointIp = explode(':', $endpoint)[0];
            $isActive = ($now - $latestHandshake) < 180; // Active if handshake within 3 minutes

            $currentPeers[$pubkey] = $endpointIp;

            if ($isActive) {
                if (!isset($lockedEndpoints[$pubkey])) {
                    // First connection - lock this IP
                    $lockedEndpoints[$pubkey] = $endpointIp;
                } elseif ($lockedEndpoints[$pubkey] !== $endpointIp) {
                    // Endpoint changed during active session - block new IP
                    $ipsToBlock[] = $endpointIp;
                    error_log("[AWG Enforcement] Peer $pubkey changed endpoint from {$lockedEndpoints[$pubkey]} to $endpointIp - blocking");
                }
            } else {
                // Session expired - update locked endpoint for next connection
                $lockedEndpoints[$pubkey] = $endpointIp;
            }
        }

        // Clean up locks for peers that no longer exist
        foreach ($lockedEndpoints as $pubkey => $ip) {
            if (!isset($currentPeers[$pubkey])) {
                unset($lockedEndpoints[$pubkey]);
            }
        }

        // Save locked endpoints
        $lockJson = json_encode($lockedEndpoints);
        $saveLockCmd = "echo " . escapeshellarg($lockJson) . " > $lockFile";
        $this->execSSH($saveLockCmd);

        // Apply iptables rules for blocked IPs
        if (!empty($ipsToBlock)) {
            foreach ($ipsToBlock as $ip) {
                // Block UDP traffic from this IP to WireGuard port
                $wgPort = $this->serverData['vpn_port'] ?? 51820;
                $blockCmd = "docker exec $containerName iptables -C INPUT -s $ip -p udp --dport $wgPort -j DROP 2>/dev/null || docker exec $containerName iptables -I INPUT -s $ip -p udp --dport $wgPort -j DROP";
                $this->execSSH($blockCmd);
            }
        }

        // Remove blocks for IPs that are now the locked endpoint (old device disconnected)
        $wgPort = $this->serverData['vpn_port'] ?? 51820;
        $listRulesCmd = "docker exec $containerName iptables -L INPUT -n --line-numbers | grep 'DROP.*udp dpt:$wgPort' | awk '{print \$1, \$4}'";
        $rulesResult = $this->execSSH($listRulesCmd);
        if ($rulesResult) {
            $rulesToRemove = [];
            foreach (explode("\n", trim($rulesResult)) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2) {
                    $ruleNum = $parts[0];
                    $blockedIp = $parts[1];
                    // If this IP is now the locked endpoint for any peer, remove the block
                    if (in_array($blockedIp, $lockedEndpoints)) {
                        $rulesToRemove[] = $ruleNum;
                    }
                }
            }
            // Remove rules in reverse order (highest number first)
            rsort($rulesToRemove);
            foreach ($rulesToRemove as $ruleNum) {
                $rmCmd = "docker exec $containerName iptables -D INPUT $ruleNum 2>/dev/null || true";
                $this->execSSH($rmCmd);
            }
        }
    }

    /**
     * Count total online clients across all Xray servers
     * Returns array with 'total' count and 'users' list
     */
    public static function countOnlineClients(): array
    {
        $result = ['total' => 0, 'users' => []];
        
        // Get all active servers
        $servers = VpnServer::listAll();
        $db = DB::conn();
        
        foreach ($servers as $serverData) {
            // Check if this server has any XRay clients
            $stmt = $db->prepare("
                SELECT COUNT(*) as cnt FROM vpn_clients vc
                JOIN protocols p ON vc.protocol_id = p.id
                WHERE vc.server_id = ? AND p.slug LIKE '%xray%'
            ");
            $stmt->execute([$serverData['id']]);
            $hasXrayClients = (int)$stmt->fetchColumn() > 0;
            
            // Also check container_name as fallback
            $containerName = $serverData['container_name'] ?? '';
            $isXrayServer = strpos($containerName, 'xray') !== false;
            
            if (!$hasXrayClients && !$isXrayServer) {
                continue;
            }
            
            // Build SSH command
            $host = $serverData['host'];
            $port = (int)($serverData['port'] ?? 22);
            $username = $serverData['username'] ?? 'root';
            $password = $serverData['password'] ?? '';
            
            $xrayContainer = $isXrayServer ? $containerName : 'amnezia-xray';
            $cmd = "docker exec $xrayContainer xray api statsgetallonlineusers --server=127.0.0.1:10085";
            
            $sshOptions = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5';
            $sshCmd = sprintf(
                "sshpass -p '%s' ssh -p %d %s %s@%s %s 2>/dev/null",
                $password,
                $port,
                $sshOptions,
                $username,
                $host,
                escapeshellarg($cmd)
            );
            
            $output = shell_exec($sshCmd);
            if (!$output) {
                continue;
            }
            
            $data = json_decode($output, true);
            if (!isset($data['users']) || !is_array($data['users'])) {
                continue;
            }
            
            foreach ($data['users'] as $user) {
                // Parse format: "user>>>email>>>online" or object with email/count
                if (is_string($user)) {
                    // Format: "user>>>olegtest3>>>online"
                    $parts = explode('>>>', $user);
                    if (count($parts) >= 2) {
                        $email = $parts[1];
                        $result['total'] += 1;
                        $result['users'][] = [
                            'server_id' => $serverData['id'],
                            'email' => $email,
                            'count' => 1
                        ];
                    }
                } else {
                    // Object format
                    $email = $user['email'] ?? 'unknown';
                    $count = (int)($user['count'] ?? 1);
                    $result['total'] += $count;
                    $result['users'][] = [
                        'server_id' => $serverData['id'],
                        'email' => $email,
                        'count' => $count
                    ];
                }
            }
        }
        
        return $result;
    }

    /**
     * Get online clients for a specific server
     * Returns array of online client logins/emails
     */
    public static function getOnlineClientsForServer(array $serverData): array
    {
        $result = [];
        $db = DB::conn();
        
        // 1. Get XRay online clients from Xray API
        $stmt = $db->prepare("
            SELECT COUNT(*) as cnt FROM vpn_clients vc
            JOIN protocols p ON vc.protocol_id = p.id
            WHERE vc.server_id = ? AND p.slug LIKE '%xray%'
        ");
        $stmt->execute([$serverData['id']]);
        $hasXrayClients = (int)$stmt->fetchColumn() > 0;
        
        $containerName = $serverData['container_name'] ?? '';
        $isXrayServer = strpos($containerName, 'xray') !== false;
        
        if ($hasXrayClients || $isXrayServer) {
            $host = $serverData['host'];
            $port = (int)($serverData['port'] ?? 22);
            $username = $serverData['username'] ?? 'root';
            $password = $serverData['password'] ?? '';
            
            $xrayContainer = $isXrayServer ? $containerName : 'amnezia-xray';
            $cmd = "docker exec $xrayContainer xray api statsgetallonlineusers --server=127.0.0.1:10085";
            
            $sshOptions = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5';
            $sshCmd = sprintf(
                "sshpass -p '%s' ssh -p %d %s %s@%s %s 2>/dev/null",
                $password,
                $port,
                $sshOptions,
                $username,
                $host,
                escapeshellarg($cmd)
            );
            
            $output = shell_exec($sshCmd);
            if ($output) {
                $data = json_decode($output, true);
                if (isset($data['users']) && is_array($data['users'])) {
                    foreach ($data['users'] as $user) {
                        if (is_string($user)) {
                            $parts = explode('>>>', $user);
                            if (count($parts) >= 2) {
                                $result[] = $parts[1];
                            }
                        } else {
                            $email = $user['email'] ?? null;
                            if ($email) {
                                $result[] = $email;
                            }
                        }
                    }
                }
            }
        }
        
        // 2. Add WireGuard/AWG clients with recent handshake (< 5 minutes)
        // Exclude XRay clients - they use Xray API for online status
        $stmt = $db->prepare("
            SELECT vc.name FROM vpn_clients vc
            LEFT JOIN protocols p ON vc.protocol_id = p.id
            WHERE vc.server_id = ? 
              AND vc.status = 'active'
              AND vc.last_handshake IS NOT NULL 
              AND vc.last_handshake >= DATE_SUB(NOW(), INTERVAL 300 SECOND)
              AND (p.slug IS NULL OR p.slug NOT LIKE '%xray%')
        ");
        $stmt->execute([$serverData['id']]);
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (!in_array($row['name'], $result)) {
                $result[] = $row['name'];
            }
        }
        
        return $result;
    }
}
