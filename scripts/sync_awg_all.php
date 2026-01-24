<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (php_sapi_name() !== 'cli') {
    die("CLI only");
}

require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/VpnServer.php';

echo "Starting AmneziaWG Sync (DB -> Server)...\n";

try {
    // Assuming Server ID 1 for now (or pass as arg)
    $serverId = 1;
    $server = new VpnServer($serverId);
    $data = $server->getData();

    if (!$data) {
        die("Server not found\n");
    }

    $containerName = $data['container_name'] ?? 'amnezia-awg';

    // 1. Get Server Params
    $awgParams = json_decode($data['awg_params'] ?? '[]', true);
    if (empty($awgParams)) {
        // Safe Fallback if DB empty? Or error?
        // Better error out to avoid breakage, but user wants FIX.
        // If empty, generate new randoms?
        // Let's assume params exist or fetch from current wg0 check.
        // For now, fail if missing.
        echo "Warning: AWG Params missing in DB. Fetching defaults/randoms...\n";
        $awgParams = [
            'Jc' => 5,
            'Jmin' => 50,
            'Jmax' => 1000,
            'S1' => 100,
            'S2' => 200,
            'H1' => 18274619,
            'H2' => 2938471,
            'H3' => 918273,
            'H4' => 1928374
        ];
    }

    // 2. Get Keys (Interface)
    // Server Private Key should be in DB?
    // vpn_servers table has server_public_key... but usually NOT private key?
    // Start script puts keys in /opt/amnezia/awg/....key
    // We should READ them from file to be safe.

    $privKey = trim($server->executeCommand("docker exec -i $containerName cat /opt/amnezia/awg/server_private.key", true));
    if (!$privKey) {
        // Try file mapping
        $privKey = trim($server->executeCommand("cat /opt/amnezia/amnezia-awg/server_private.key", true));
    }

    if (!$privKey) {
        die("Fatal: Could not retrieve Server Private Key from keys files.\n");
    }

    $vpnPort = $data['vpn_port'] ?? 51820;

    // 3. Build Interface Block
    $conf = "[Interface]\n";
    $conf .= "PrivateKey = $privKey\n";
    $conf .= "Address = 10.8.1.1/24\n"; // Hardcoded or from DB? vpn_subnet usually.
    $conf .= "ListenPort = $vpnPort\n";

    // Normalize params
    $cleanParams = [];
    foreach ($awgParams as $k => $v)
        $cleanParams[strtoupper($k)] = $v;

    $conf .= "Jc = " . ($cleanParams['JC'] ?? 5) . "\n";
    $conf .= "Jmin = " . ($cleanParams['JMIN'] ?? 50) . "\n";
    $conf .= "Jmax = " . ($cleanParams['JMAX'] ?? 1000) . "\n";
    $conf .= "S1 = " . ($cleanParams['S1'] ?? 50) . "\n";
    $conf .= "S2 = " . ($cleanParams['S2'] ?? 100) . "\n";
    $conf .= "H1 = " . ($cleanParams['H1'] ?? 1) . "\n";
    $conf .= "H2 = " . ($cleanParams['H2'] ?? 2) . "\n";
    $conf .= "H3 = " . ($cleanParams['H3'] ?? 3) . "\n";
    $conf .= "H4 = " . ($cleanParams['H4'] ?? 4) . "\n";

    $conf .= "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n";
    $conf .= "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n";

    // 4. Load Clients
    $pdo = DB::conn();
    $stmt = $pdo->prepare("SELECT * FROM vpn_clients WHERE server_id = ? AND status = 'active'");
    $stmt->execute([$serverId]);
    $clients = $stmt->fetchAll();

    echo "Found " . count($clients) . " clients in DB.\n";

    foreach ($clients as $client) {
        $pub = $client['public_key'];
        $psk = $client['preshared_key'];
        $ip = $client['client_ip'];
        $allowed = $client['allowed_ips'] ?? "$ip/32"; // Fallback to IP/32

        $conf .= "[Peer]\n";
        $conf .= "PublicKey = $pub\n";
        if ($psk)
            $conf .= "PresharedKey = $psk\n";
        $conf .= "AllowedIPs = $allowed\n\n";
    }

    // 5. Write Config
    // Use host path if possible for safety
    $hostConfPath = '/opt/amnezia/amnezia-awg/wg0.conf';

    $escaped = addslashes($conf);
    $server->executeCommand("echo \"$escaped\" > $hostConfPath", true);
    // Also copy to container path if mounted (usually same file via bind mount)

    // 6. Restart Interface
    echo "Restarting WireGuard interface...\n";
    $server->executeCommand("docker exec -i $containerName wg-quick down wg0 || true", true);
    $server->executeCommand("docker exec -i $containerName wg-quick up wg0", true);

    echo "Sync Complete.\n";

} catch (Throwable $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}
