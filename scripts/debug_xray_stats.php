<?php
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/VpnServer.php';

$pdo = DB::conn();
$clientId = 4;

echo "Loading client $clientId...\n";
$client = new VpnClient($clientId);
$data = $client->getData();

if (!$data) {
    die("Client not found\n");
}

echo "Client Name: " . $data['name'] . "\n";
echo "Config: " . substr($data['config'], 0, 50) . "...\n";

echo "Running syncStats()...\n";
try {
    $res = $client->syncStats();
    echo "Sync Result: " . ($res ? 'TRUE' : 'FALSE') . "\n";

    // Check DB
    $fresh = new VpnClient($clientId);
    $d = $fresh->getData();
    echo "Bytes Sent: " . $d['bytes_sent'] . "\n";
    echo "Bytes Recv: " . $d['bytes_received'] . "\n";
    echo "Last Handshake: " . $d['last_handshake'] . "\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
