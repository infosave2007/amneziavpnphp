<?php
/**
 * VPN Server Management Class
 * Handles deployment and management of Amnezia VPN servers
 * Based on amnezia_deploy_v2.php
 */
class VpnServer
{
    private $serverId;
    private $data;

    public function __construct(?int $serverId = null)
    {
        $this->serverId = $serverId;
        if ($serverId) {
            $this->load();
        }
    }

    public function getId(): int
    {
        return (int) $this->serverId;
    }

    public function refresh(): void
    {
        if ($this->serverId === null) {
            throw new Exception('Server ID is not set');
        }
        $this->load();
    }

    /**
     * Load server data from database
     */
    private function load(): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->serverId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Server not found');
        }
    }

    /**
     * Create new VPN server in database
     */
    public static function create(array $data): int
    {
        $pdo = DB::conn();

        // Validate required fields
        $required = ['user_id', 'name', 'host', 'port', 'username'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field {$field} is required");
            }
        }

        if (empty($data['password']) && empty($data['ssh_key'])) {
            throw new Exception("Either password or SSH key is required");
        }

        $protocolSlug = trim((string) ($data['install_protocol'] ?? ''));
        if ($protocolSlug === '') {
            throw new Exception('Install protocol must be selected');
        }
        $installOptions = $data['install_options'] ?? null;

        if (is_array($installOptions)) {
            $installOptions = json_encode($installOptions);
        } elseif (is_string($installOptions)) {
            $installOptions = trim($installOptions) === '' ? null : $installOptions;
        }

        $stmt = $pdo->prepare('
            INSERT INTO vpn_servers 
            (user_id, name, host, port, username, password, ssh_key, container_name, install_protocol, install_options, vpn_subnet, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $stmt->execute([
            $data['user_id'],
            $data['name'],
            $data['host'],
            $data['port'],
            $data['username'],
            $data['password'] ?? null,
            $data['ssh_key'] ?? null,
            $data['container_name'] ?? 'amnezia-awg',
            $protocolSlug,
            $installOptions,
            $data['vpn_subnet'] ?? '10.8.1.0/24',
            'deploying'
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Import existing VPN server from backup payload without deployment.
     */
    public static function importFromBackup(int $userId, array $serverData): int
    {
        $pdo = DB::conn();

        $name = trim($serverData['name'] ?? '');
        $host = trim($serverData['host'] ?? '');
        if ($name === '' || $host === '') {
            throw new Exception('Backup is missing server name or host');
        }

        $port = isset($serverData['ssh_port']) ? (int) $serverData['ssh_port'] : 22;
        $username = trim($serverData['ssh_username'] ?? 'root') ?: 'root';
        $password = (string) ($serverData['ssh_password'] ?? '');
        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $vpnPort = isset($serverData['vpn_port']) && $serverData['vpn_port'] !== null
            ? (int) $serverData['vpn_port']
            : null;
        $vpnSubnet = $serverData['vpn_subnet'] ?? '10.8.1.0/24';
        $serverPublicKey = $serverData['server_public_key'] ?? null;
        $presharedKey = $serverData['preshared_key'] ?? null;

        $awgParams = $serverData['awg_params'] ?? null;
        if (is_array($awgParams)) {
            $awgParams = json_encode($awgParams);
        }

        $installProtocol = $serverData['install_protocol'] ?? 'amnezia-wg';
        $installOptions = $serverData['install_options'] ?? null;
        if (is_array($installOptions)) {
            $installOptions = json_encode($installOptions);
        }

        $stmt = $pdo->prepare('
            INSERT INTO vpn_servers 
            (user_id, name, host, port, username, password, container_name, install_protocol, install_options, vpn_port, vpn_subnet, 
             server_public_key, preshared_key, awg_params, status, deployed_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NULL)
        ');

        $stmt->execute([
            $userId,
            $name,
            $host,
            $port,
            $username,
            $password,
            $containerName,
            $installProtocol,
            $installOptions,
            $vpnPort,
            $vpnSubnet,
            $serverPublicKey,
            $presharedKey,
            $awgParams,
            'active'
        ]);

        return (int) $pdo->lastInsertId();
    }

    /**
     * Apply server configuration from backup payload to an existing record.
     */
    public function applyBackupData(array $serverData, int $userId, bool $replaceClients = true): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $updates = [];
        $params = [];
        $updatedFields = [];

        $mapString = function (?string $value): ?string {
            $value = trim((string) $value);
            return $value === '' ? null : $value;
        };

        $stringFields = [
            'name' => $mapString($serverData['name'] ?? null),
            'host' => $mapString($serverData['host'] ?? null),
            'username' => $mapString($serverData['ssh_username'] ?? null),
            'password' => isset($serverData['ssh_password']) ? (string) $serverData['ssh_password'] : null,
            'container_name' => $mapString($serverData['container_name'] ?? null),
            'vpn_subnet' => $mapString($serverData['vpn_subnet'] ?? null),
            'server_public_key' => $mapString($serverData['server_public_key'] ?? null),
            'preshared_key' => isset($serverData['preshared_key']) ? (string) $serverData['preshared_key'] : null,
            'install_protocol' => $mapString($serverData['install_protocol'] ?? null),
        ];

        foreach ($stringFields as $column => $value) {
            if ($value !== null) {
                $updates[] = $column . ' = ?';
                $params[] = $value;
                $updatedFields[] = $column;
            }
        }

        if (isset($serverData['ssh_port']) && $serverData['ssh_port'] !== null) {
            $port = (int) $serverData['ssh_port'];
            if ($port > 0) {
                $updates[] = 'port = ?';
                $params[] = $port;
                $updatedFields[] = 'port';
            }
        }

        if (isset($serverData['vpn_port']) && $serverData['vpn_port'] !== null) {
            $vpnPort = (int) $serverData['vpn_port'];
            if ($vpnPort > 0) {
                $updates[] = 'vpn_port = ?';
                $params[] = $vpnPort;
                $updatedFields[] = 'vpn_port';
            }
        }

        if (isset($serverData['awg_params'])) {
            $awgParams = $serverData['awg_params'];
            if (is_array($awgParams)) {
                $awgParams = json_encode($awgParams);
            }
            if (is_string($awgParams)) {
                $updates[] = 'awg_params = ?';
                $params[] = $awgParams;
                $updatedFields[] = 'awg_params';
            }
        }

        if (isset($serverData['install_options'])) {
            $installOptions = $serverData['install_options'];
            if (is_array($installOptions)) {
                $installOptions = json_encode($installOptions);
            }
            if (is_string($installOptions)) {
                $updates[] = 'install_options = ?';
                $params[] = $installOptions;
                $updatedFields[] = 'install_options';
            }
        }

        if ($updates) {
            $params[] = $this->serverId;
            $sql = 'UPDATE vpn_servers SET ' . implode(', ', $updates) . ' WHERE id = ?';
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $this->load();
        }

        $imported = 0;
        $failed = [];
        $clients = $serverData['clients'] ?? [];
        $shouldReplaceClients = $replaceClients && is_array($clients) && !empty($clients) && ($this->data['status'] ?? '') !== 'active';

        if ($shouldReplaceClients) {
            $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ?')->execute([$this->serverId]);
            $this->load();
        }

        if (is_array($clients) && !empty($clients)) {
            $serverRecord = $this->getData();
            foreach ($clients as $clientData) {
                try {
                    $id = VpnClient::importFromBackup($serverRecord, $userId, $clientData);
                    if ($id !== null) {
                        $imported++;
                    }
                } catch (Exception $e) {
                    $failed[] = $e->getMessage();
                }
            }
        }

        return [
            'updated_fields' => $updatedFields,
            'imported_clients' => $imported,
            'client_errors' => $failed,
        ];
    }

    /**
     * Deploy VPN server using amnezia_deploy_v2.php logic
     */
    public function deploy(array $options = []): array
    {
        return InstallProtocolManager::deploy($this, $options);
    }

    /**
     * Legacy AmneziaWG deployment routine kept for backward compatibility.
     */
    public function runAwgInstall(array $options = []): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $errors = [];

        try {
            // Update status to deploying
            $pdo->prepare('UPDATE vpn_servers SET status = ? WHERE id = ?')
                ->execute(['deploying', $this->serverId]);

            // Test SSH connection
            if (!$this->testConnection()) {
                throw new Exception('SSH connection failed');
            }

            // Install Docker if needed
            $this->installDocker();

            // Create directories
            $this->executeCommand('mkdir -p /opt/amnezia/amnezia-awg', true);

            // Find free UDP port
            $vpnPort = $this->findFreeUdpPort();

            // Create Dockerfile
            $this->createDockerfile();

            // Create start script
            $this->createStartScript();

            // Build Docker image
            $this->buildDockerImage();

            // Run container
            $this->runContainer($vpnPort);

            // Initialize server config
            $keys = $this->initializeServerConfig($vpnPort);

            // Update database with deployment info
            $stmt = $pdo->prepare('
                UPDATE vpn_servers 
                SET vpn_port = ?, 
                    server_public_key = ?, 
                    preshared_key = ?, 
                    awg_params = ?,
                    status = ?,
                    deployed_at = NOW(),
                    error_message = NULL
                WHERE id = ?
            ');

            $stmt->execute([
                $vpnPort,
                $keys['public_key'],
                $keys['preshared_key'],
                json_encode($keys['awg_params']),
                'active',
                $this->serverId
            ]);

            // Reload data
            $this->load();

            return [
                'success' => true,
                'vpn_port' => $vpnPort,
                'public_key' => $keys['public_key']
            ];

        } catch (Exception $e) {
            // Update status to error
            $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?')
                ->execute(['error', $e->getMessage(), $this->serverId]);

            throw $e;
        }
    }

    /**
     * Test SSH connection to server
     */
    public function testConnection(): bool
    {
        // Determine auth method
        $sshOptions = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10';
        $credentials = '';
        $keyFile = '';

        if (!empty($this->data['ssh_key'])) {
            $keyFile = tempnam(sys_get_temp_dir(), 'sshkey');
            file_put_contents($keyFile, $this->data['ssh_key']);
            chmod($keyFile, 0600);
            $sshOptions .= " -i {$keyFile} -o IdentitiesOnly=yes -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey";
            // sshpass is not needed for key-based auth
            $baseCmd = "ssh -p %d %s %s@%s";

            $testCommand = sprintf(
                "ssh -p %d %s %s@%s 'echo test' 2>/dev/null",
                $this->data['port'],
                $sshOptions,
                $this->data['username'],
                $this->data['host']
            );
        } else {
            $sshOptions .= " -o PreferredAuthentications=password -o PubkeyAuthentication=no";
            $testCommand = sprintf(
                "sshpass -p '%s' ssh -p %d %s %s@%s 'echo test' 2>/dev/null",
                $this->data['password'],
                $this->data['port'],
                $sshOptions,
                $this->data['username'],
                $this->data['host']
            );
        }

        $result = shell_exec($testCommand);

        if ($keyFile && file_exists($keyFile)) {
            unlink($keyFile);
        }

        return trim($result) === 'test';
    }

    /**
     * Execute command on remote server
     */
    public function executeCommand(string $command, bool $sudo = false): string
    {
        $baseCommand = $command;
        $pathPrefix = 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; ';
        $escapedCommand = '';
        $needsSudo = false;

        // Determine auth method
        $sshOptions = '-o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no';
        $keyFile = '';

        if (!empty($this->data['ssh_key'])) {
            $keyFile = tempnam(sys_get_temp_dir(), 'sshkey');
            file_put_contents($keyFile, $this->data['ssh_key']);
            chmod($keyFile, 0600);
            $sshOptions .= " -i {$keyFile} -o IdentitiesOnly=yes -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey";

            $preparedCommand = $pathPrefix . $command;
            $escapedCommand = escapeshellarg($preparedCommand);

            $sshCommand = sprintf(
                "ssh -p %d %s %s@%s %s 2>&1",
                $this->data['port'],
                $sshOptions,
                $this->data['username'],
                $this->data['host'],
                $escapedCommand
            );
        } else {
            $needsSudo = $sudo && strtolower((string) ($this->data['username'] ?? '')) !== 'root';
            if ($needsSudo) {
                // Suppress sudo prompt text to keep command output machine-parseable.
                $command = "echo '{$this->data['password']}' | sudo -S -p '' " . $command;
            }

            $preparedCommand = $pathPrefix . $command;
            $escapedCommand = escapeshellarg($preparedCommand);

            $sshOptions .= " -o PreferredAuthentications=password -o PubkeyAuthentication=no";
            $sshCommand = sprintf(
                "sshpass -p '%s' ssh -p %d %s %s@%s %s 2>&1",
                $this->data['password'],
                $this->data['port'],
                $sshOptions,
                $this->data['username'],
                $this->data['host'],
                $escapedCommand
            );
        }

        $output = shell_exec($sshCommand) ?? '';

        // If sudo auth fails but user can run docker without sudo, retry docker commands directly.
        if (
            empty($this->data['ssh_key'])
            && !empty($needsSudo)
            && preg_match('/(^|\\n)docker(\\s|$)/', ltrim($baseCommand))
            && preg_match('/incorrect password attempts|sorry, try again|a password is required/i', $output)
        ) {
            $escapedBaseCommand = escapeshellarg($pathPrefix . $baseCommand);
            $sshCommandNoSudo = sprintf(
                "sshpass -p '%s' ssh -p %d %s %s@%s %s 2>&1",
                $this->data['password'],
                $this->data['port'],
                $sshOptions,
                $this->data['username'],
                $this->data['host'],
                $escapedBaseCommand
            );
            $output = shell_exec($sshCommandNoSudo) ?? '';
        }

        if ($keyFile && file_exists($keyFile)) {
            unlink($keyFile);
        }

        return $output;
    }

    /**
     * Install Docker on remote server
     */
    private function installDocker(): void
    {
        $dockerVersion = $this->executeCommand('docker --version');
        if (stripos($dockerVersion, 'version') !== false) {
            return; // Docker already installed
        }

        $this->executeCommand('curl -fsSL https://get.docker.com | sh', true);
        $this->executeCommand('systemctl enable --now docker', true);
    }

    /**
     * Find free UDP port on remote server
     */
    private function findFreeUdpPort(): int
    {
        $min = 30000;
        $max = 65000;

        for ($attempt = 0; $attempt < 30; $attempt++) {
            $candidate = random_int($min, $max);
            $cmd = "ss -lun | awk '{print \$4}' | grep -E ':(" . $candidate . ")($| )' || true";
            $out = $this->executeCommand($cmd, false);
            if (trim($out) === '') {
                return $candidate;
            }
        }

        throw new Exception('Could not find free UDP port');
    }

    /**
     * Create Dockerfile on remote server
     */
    private function createDockerfile(): void
    {
        $dockerfile = <<<'DOCKERFILE'
FROM amneziavpn/amnezia-wg:latest

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache bash curl dumb-init
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo -e "#!/bin/bash\ntail -f /dev/null" > /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
CMD [ "" ]
DOCKERFILE;

        $escaped = addslashes(trim($dockerfile));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/Dockerfile", true);
    }

    /**
     * Create start script on remote server
     */
    private function createStartScript(): void
    {
        $script = <<<'BASH'
#!/bin/bash

echo "Container startup"

# Wait for config if not exists yet
for i in {1..30}; do
    if [ -f /opt/amnezia/awg/wg0.conf ]; then
        break
    fi
    sleep 1
done

# Kill daemons in case of restart
wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null || true

# Start daemons if configured
if [ -f /opt/amnezia/awg/wg0.conf ]; then
    wg-quick up /opt/amnezia/awg/wg0.conf
    echo "WireGuard started"
else
    echo "No wg0.conf found, skipping WireGuard startup"
fi

# Allow traffic on the TUN interface
iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -o eth1 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth1 -j MASQUERADE 2>/dev/null || true

tail -f /dev/null
BASH;

        $escaped = addslashes(trim($script));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/start.sh", true);
        $this->executeCommand("chmod +x /opt/amnezia/amnezia-awg/start.sh", true);
    }

    /**
     * Build Docker image
     */
    private function buildDockerImage(): void
    {
        $containerName = $this->data['container_name'];

        // Cleanup old container/image
        $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rmi {$containerName} 2>/dev/null || true", true);

        // Build new image
        $buildCmd = sprintf(
            'docker build --no-cache --pull -t %s /opt/amnezia/amnezia-awg',
            $containerName
        );
        $this->executeCommand($buildCmd, true);
    }

    /**
     * Run Docker container
     */
    private function runContainer(int $vpnPort): void
    {
        $containerName = $this->data['container_name'];

        $runCmd = sprintf(
            'docker run -d --log-driver none --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p %d:%d/udp -v /lib/modules:/lib/modules --name %s %s',
            $vpnPort,
            $vpnPort,
            $containerName,
            $containerName
        );

        $this->executeCommand($runCmd, true);
        sleep(3); // Wait for container to start
    }

    /**
     * Initialize server configuration with AWG parameters
     */
    private function initializeServerConfig(int $vpnPort): array
    {
        $containerName = $this->data['container_name'];

        // Create directory
        $this->executeCommand("docker exec -i {$containerName} mkdir -p /opt/amnezia/awg", true);

        // Generate keys
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && umask 077 && wg genkey | tee server_private.key | wg pubkey > wireguard_server_public_key.key'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && wg genpsk > wireguard_psk.key'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/server_private.key /opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_server_public_key.key", true);

        // Get keys
        $privKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/server_private.key", true));
        $pubKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_server_public_key.key", true));
        $psk = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_psk.key", true));

        // Generate AWG parameters
        $awgParams = [
            'Jc' => 3,
            'Jmin' => 10,
            'Jmax' => 50,
            'S1' => rand(50, 250),
            'S2' => rand(50, 250),
            'H1' => rand(100000, 2000000000),
            'H2' => rand(100000, 2000000000),
            'H3' => rand(100000, 2000000000),
            'H4' => rand(100000, 2000000000)
        ];

        // Create wg0.conf
        $wgConfig = "[Interface]\n";
        $wgConfig .= "PrivateKey = {$privKey}\n";
        $wgConfig .= "Address = {$this->data['vpn_subnet']}\n";
        $wgConfig .= "ListenPort = {$vpnPort}\n";
        foreach ($awgParams as $key => $value) {
            $wgConfig .= "{$key} = {$value}\n";
        }
        $wgConfig .= "\n";

        $escaped = addslashes($wgConfig);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"{$escaped}\" > /opt/amnezia/awg/wg0.conf'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/wg0.conf", true);

        // Create clientsTable
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"[]\" > /opt/amnezia/awg/clientsTable'", true);

        // Start WireGuard
        $this->executeCommand("docker exec -i {$containerName} wg-quick up /opt/amnezia/awg/wg0.conf 2>&1", true);

        // Apply firewall rules
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true'", true);

        // Ensure host-level forwarding/NAT for AWG subnet as well (required on some Docker host setups).
        $vpnSubnet = (string) ($this->data['vpn_subnet'] ?? '10.8.1.0/24');
        $vpnSubnetEsc = escapeshellarg($vpnSubnet);
        $hostNatCmd = "bash -lc 'IFACE=\\$(ip route | awk \"{if (\\$1==\\\"default\\\") {print \\$5; exit}}\"); " .
            "iptables -t nat -C POSTROUTING -s " . $vpnSubnetEsc . " -o \\\"\\$IFACE\\\" -j MASQUERADE 2>/dev/null || " .
            "iptables -t nat -I POSTROUTING 1 -s " . $vpnSubnetEsc . " -o \\\"\\$IFACE\\\" -j MASQUERADE; " .
            "iptables -C FORWARD -s " . $vpnSubnetEsc . " -o \\\"\\$IFACE\\\" -j ACCEPT 2>/dev/null || " .
            "iptables -I FORWARD 1 -s " . $vpnSubnetEsc . " -o \\\"\\$IFACE\\\" -j ACCEPT; " .
            "iptables -C FORWARD -d " . $vpnSubnetEsc . " -m conntrack --ctstate RELATED,ESTABLISHED -i \\\"\\$IFACE\\\" -j ACCEPT 2>/dev/null || " .
            "iptables -I FORWARD 1 -d " . $vpnSubnetEsc . " -m conntrack --ctstate RELATED,ESTABLISHED -i \\\"\\$IFACE\\\" -j ACCEPT; " .
            "sysctl -w net.ipv4.ip_forward=1 >/dev/null'";
        $this->executeCommand($hostNatCmd, true);

        sleep(2);

        return [
            'public_key' => $pubKey,
            'preshared_key' => $psk,
            'awg_params' => $awgParams
        ];
    }

    /**
     * Get server status from database
     */
    public function getStatus(): string
    {
        return $this->data['status'] ?? 'unknown';
    }

    /**
     * Get all servers for a user
     */
    public static function listByUser(int $userId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /**
     * Get all servers (admin only)
     */
    public static function listAll(): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->query('SELECT s.*, u.email as user_email FROM vpn_servers s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC');
        return $stmt->fetchAll();
    }

    /**
     * Delete server
     */
    public function delete(): bool
    {
        // Stop and remove container
        try {
            $containerName = $this->data['container_name'];
            $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
            $this->executeCommand("rm -rf /opt/amnezia/amnezia-awg", true);
        } catch (Exception $e) {
            // Ignore errors during cleanup
        }

        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_servers WHERE id = ?');
        return $stmt->execute([$this->serverId]);
    }

    /**
     * Get server data
     */
    public function getData(): ?array
    {
        return $this->data;
    }

    /**
     * Create backup of server configuration and all clients
     * 
     * @param int $userId User who creates the backup
     * @param string $backupType Type: 'manual' or 'automatic'
     * @return int Backup ID
     */
    public function createBackup(int $userId, string $backupType = 'manual'): int
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $backupName = 'backup_' . $this->serverId . '_' . date('Y-m-d_His') . '.json';
        $backupDir = '/var/www/html/backups';
        $backupPath = $backupDir . '/' . $backupName;

        // Create backups directory if not exists
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0755, true);
        }

        try {
            // Get all clients for this server
            $stmt = $pdo->prepare('
                SELECT id, name, client_ip, public_key, private_key, preshared_key, 
                       config, status, expires_at, created_at
                FROM vpn_clients 
                WHERE server_id = ?
            ');
            $stmt->execute([$this->serverId]);
            $clients = $stmt->fetchAll();

            // Prepare backup data
            $backupData = [
                'server' => [
                    'name' => $this->data['name'],
                    'host' => $this->data['host'],
                    'port' => $this->data['port'],
                    'vpn_port' => $this->data['vpn_port'],
                    'vpn_subnet' => $this->data['vpn_subnet'],
                    'container_name' => $this->data['container_name'],
                    'install_protocol' => $this->data['install_protocol'] ?? null,
                    'install_options' => $this->data['install_options'] ? json_decode($this->data['install_options'], true) : null,
                    'server_public_key' => $this->data['server_public_key'],
                    'preshared_key' => $this->data['preshared_key'],
                    'awg_params' => $this->data['awg_params'],
                ],
                'clients' => $clients,
                'backup_date' => date('Y-m-d H:i:s'),
                'version' => '1.0'
            ];

            // Write backup to file
            $json = json_encode($backupData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            file_put_contents($backupPath, $json);

            $backupSize = filesize($backupPath);

            // Insert backup record
            $stmt = $pdo->prepare('
                INSERT INTO server_backups 
                (server_id, backup_name, backup_path, backup_size, clients_count, backup_type, status, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ');

            $stmt->execute([
                $this->serverId,
                $backupName,
                $backupPath,
                $backupSize,
                count($clients),
                $backupType,
                'completed',
                $userId
            ]);

            return (int) $pdo->lastInsertId();

        } catch (Exception $e) {
            // Mark backup as failed
            if (isset($stmt)) {
                $stmt = $pdo->prepare('
                    INSERT INTO server_backups 
                    (server_id, backup_name, backup_path, backup_type, status, error_message, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ');

                $stmt->execute([
                    $this->serverId,
                    $backupName,
                    $backupPath,
                    $backupType,
                    'failed',
                    $e->getMessage(),
                    $userId
                ]);
            }

            throw $e;
        }
    }

    /**
     * List all backups for this server
     * 
     * @return array List of backups
     */
    public function listBackups(): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT b.*, u.name as created_by_name, u.email as created_by_email
            FROM server_backups b
            LEFT JOIN users u ON b.created_by = u.id
            WHERE b.server_id = ?
            ORDER BY b.created_at DESC
        ');
        $stmt->execute([$this->serverId]);
        return $stmt->fetchAll();
    }

    /**
     * Restore server from backup
     * Note: This only restores client configurations to database
     * Server must already be deployed
     * 
     * @param int $backupId Backup ID
     * @return array Restoration results
     */
    public function restoreBackup(int $backupId): array
    {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        if ($this->data['status'] !== 'active') {
            throw new Exception('Server must be active to restore backup');
        }

        $pdo = DB::conn();

        // Get backup record
        $stmt = $pdo->prepare('SELECT * FROM server_backups WHERE id = ? AND server_id = ?');
        $stmt->execute([$backupId, $this->serverId]);
        $backup = $stmt->fetch();

        if (!$backup) {
            throw new Exception('Backup not found');
        }

        if (!file_exists($backup['backup_path'])) {
            throw new Exception('Backup file not found');
        }

        // Read backup data
        $backupData = json_decode(file_get_contents($backup['backup_path']), true);

        if (!$backupData || !isset($backupData['clients'])) {
            throw new Exception('Invalid backup format');
        }

        $restored = 0;
        $failed = 0;
        $errors = [];

        foreach ($backupData['clients'] as $clientData) {
            try {
                // Check if client already exists by IP
                $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ?');
                $stmt->execute([$this->serverId, $clientData['client_ip']]);
                $existing = $stmt->fetch();

                if ($existing) {
                    $errors[] = "Client {$clientData['name']} already exists";
                    $failed++;
                    continue;
                }

                // Insert client
                $stmt = $pdo->prepare('
                    INSERT INTO vpn_clients 
                    (server_id, user_id, name, client_ip, public_key, private_key, preshared_key, 
                     config, status, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ');

                $stmt->execute([
                    $this->serverId,
                    $this->data['user_id'],
                    $clientData['name'],
                    $clientData['client_ip'],
                    $clientData['public_key'],
                    $clientData['private_key'],
                    $clientData['preshared_key'],
                    $clientData['config'],
                    'disabled', // Restore as disabled for safety
                    $clientData['expires_at']
                ]);

                // Add client to server container
                VpnClient::addClientToServer($this->data, $clientData['public_key'], $clientData['client_ip']);

                $restored++;

            } catch (Exception $e) {
                $failed++;
                $errors[] = "Failed to restore {$clientData['name']}: " . $e->getMessage();
            }
        }

        return [
            'success' => true, // Always success if process completed
            'restored' => $restored,
            'failed' => $failed,
            'total' => count($backupData['clients']),
            'errors' => $errors,
            'message' => $restored > 0 ? "Restored $restored clients" : "No clients restored"
        ];
    }

    /**
     * Delete backup
     * 
     * @param int $backupId Backup ID
     * @return bool Success
     */
    public static function deleteBackup(int $backupId): bool
    {
        $pdo = DB::conn();

        // Get backup path
        $stmt = $pdo->prepare('SELECT backup_path FROM server_backups WHERE id = ?');
        $stmt->execute([$backupId]);
        $backup = $stmt->fetch();

        if (!$backup) {
            return false;
        }

        // Delete file
        if (file_exists($backup['backup_path'])) {
            unlink($backup['backup_path']);
        }

        // Delete record
        $stmt = $pdo->prepare('DELETE FROM server_backups WHERE id = ?');
        return $stmt->execute([$backupId]);
    }

    /**
     * Get backup by ID
     * 
     * @param int $backupId Backup ID
     * @return array|null Backup data
     */
    public static function getBackup(int $backupId): ?array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM server_backups WHERE id = ?');
        $stmt->execute([$backupId]);
        return $stmt->fetch() ?: null;
    }
}
