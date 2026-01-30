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
        $clients = VpnClient::listByServer($this->serverData['id']);
        $results = [];

        foreach ($clients as $client) {
            if ($client['status'] !== 'active')
                continue;

            $stats = $this->getClientStats($client);
            if ($stats) {
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

        // Get current stats from server
        $containerName = $this->serverData['container_name'];
        $publicKey = $client['public_key'];

        $cmd = "docker exec {$containerName} wg show all dump | grep '{$publicKey}' | awk '{print \$6, \$7}'";
        $result = $this->execSSH($cmd);

        if (!$result)
            return null;

        list($bytesReceived, $bytesSent) = explode(' ', trim($result));

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
            if ($timeDiff > 0) {
                // Calculate speed in Kbps
                $bytesDiffSent = (int) $bytesSent - (int) $previous['bytes_sent'];
                $bytesDiffReceived = (int) $bytesReceived - (int) $previous['bytes_received'];

                $speedUp = round(($bytesDiffSent * 8) / $timeDiff / 1000, 2);
                $speedDown = round(($bytesDiffReceived * 8) / $timeDiff / 1000, 2);
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

        // Update vpn_clients table with latest stats
        $stmt = $db->prepare("
            UPDATE vpn_clients 
            SET bytes_sent = ?, bytes_received = ?, speed_up = ?, speed_down = ?, current_speed = ?, last_handshake = NOW(), last_sync_at = NOW()
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
        $port = $this->serverData['port'];
        $username = $this->serverData['username'];
        $password = $this->serverData['password'];

        $sshCmd = sprintf(
            'sshpass -p %s ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p %d %s@%s %s 2>/dev/null',
            escapeshellarg($password),
            $port,
            escapeshellarg($username),
            escapeshellarg($host),
            escapeshellarg($cmd)
        );

        $output = shell_exec($sshCmd);

        return $output ?: null;
    }
}
