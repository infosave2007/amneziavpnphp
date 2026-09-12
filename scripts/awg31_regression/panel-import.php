<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
require __DIR__ . '/../../inc/BackupLibrary.php';

final class QrUtil
{
    public static function encodeOldPayloadFromConf(string $config, string $slug): string { return 'mock-old-' . $slug; }
    public static function pngBase64(string $payload, int $size = 300, int $margin = 1, string $label = ''): string { return 'mock-qr:' . hash('sha256', $payload); }
}

loadCapturedClass(__DIR__ . '/../../inc/VpnServer.php');
loadCapturedClass(__DIR__ . '/../../inc/VpnClient.php');

$passed = 0; $failed = 0;
$pdo = newDb(__DIR__ . '/panel-import.sqlite');
$pdo->exec('CREATE TABLE protocols (id INTEGER PRIMARY KEY, slug TEXT UNIQUE, definition TEXT, output_template TEXT)');
$pdo->exec('CREATE TABLE vpn_servers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, host TEXT, port INTEGER, username TEXT, password TEXT, container_name TEXT, install_protocol TEXT, install_options TEXT, vpn_port INTEGER, vpn_subnet TEXT, server_public_key TEXT, preshared_key TEXT, awg_params TEXT, status TEXT, deployed_at TEXT, error_message TEXT)');
$pdo->exec('CREATE TABLE server_protocols (server_id INTEGER, protocol_id INTEGER, config_data TEXT, applied_at TEXT, created_at TEXT, UNIQUE(server_id, protocol_id))');
$pdo->exec('CREATE TABLE vpn_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, user_id INTEGER, protocol_id INTEGER, name TEXT, client_ip TEXT, public_key TEXT, private_key TEXT, preshared_key TEXT, config TEXT, qr_code TEXT, status TEXT, expires_at TEXT, UNIQUE(server_id, client_ip))');
$pdo->exec("INSERT INTO protocols(id,slug,definition) VALUES (3,'amnezia-wg','{}'),(909,'awg31','{}')");

$keyA = base64_encode(str_repeat('a', 32));
$keyB = base64_encode(str_repeat('b', 32));
$keyC = base64_encode(str_repeat('c', 32));
$rawConfig = "[Interface]\nPrivateKey = $keyA\nHeaderProtectionKey = $keyB\nContentPaddingAddition = 0-0\n[Peer]\nPublicKey = $keyB\nPresharedKey = $keyC\n";
$secondary = [
    'server_host' => '198.51.100.8', 'server_port' => 53131,
    'extras' => [
        'container_name' => 'amnezia-awg31', 'vpn_port' => 53131,
        'runtime_commit' => 'engine-sentinel', 'tools_commit' => 'tools-sentinel',
        'awg_params' => ['Jc' => '6', 'HeaderProtectionKey' => $keyB, 'ContentPaddingAddition' => '0-0', 'DisableCookies' => 'on'],
    ],
];
$panel = [
    'server' => [
        'name' => 'portable', 'host' => '198.51.100.8', 'port' => 22, 'username' => 'root', 'password' => 'fixture',
        'container_name' => 'primary-container', 'install_protocol' => 'amnezia-wg', 'vpn_port' => 41111,
        'vpn_subnet' => '10.8.1.0/24', 'server_public_key' => 'primary-pub', 'preshared_key' => 'primary-psk',
        'awg_params' => ['primary' => 'sentinel'],
    ],
    'server_protocols' => [
        ['slug' => 'amnezia-wg', 'protocol_id' => 7, 'config_data' => ['server_port' => 41111, 'extras' => ['container_name' => 'primary-container', 'primary_blob' => 'unchanged']]],
        ['slug' => 'awg31', 'protocol_id' => 41, 'config_data' => $secondary],
    ],
    'clients' => [[
        'name' => 'secondary-client', 'client_ip' => '10.8.31.9', 'public_key' => $keyB, 'private_key' => $keyA,
        'preshared_key' => $keyC, 'config' => $rawConfig, 'status' => 'active', 'expires_at' => null,
        'protocol_id' => 41, 'protocol_slug' => 'awg31',
    ]],
];
$path = __DIR__ . '/panel.backup.json';
file_put_contents($path, json_encode($panel, JSON_UNESCAPED_SLASHES));
$parsed = BackupParser::parse($path);
$serverData = $parsed['servers'][0];
$serverId = VpnServer::importFromBackup(77, $serverData);
$server = $pdo->query('SELECT * FROM vpn_servers WHERE id=' . (int)$serverId)->fetch(PDO::FETCH_ASSOC);
foreach ($serverData['clients'] as $client) VpnClient::importFromBackup($server, 77, $client);

$bindings = $pdo->query('SELECT p.slug,sp.protocol_id,sp.config_data FROM server_protocols sp JOIN protocols p ON p.id=sp.protocol_id ORDER BY p.slug')->fetchAll(PDO::FETCH_ASSOC);
$bySlug = [];
foreach ($bindings as $row) $bySlug[$row['slug']] = $row;
$client = $pdo->query('SELECT * FROM vpn_clients')->fetch(PDO::FETCH_ASSOC);

check(isset($bySlug['awg31']) && (int)$bySlug['awg31']['protocol_id'] === 909, 'secondary binding maps stable slug to destination id 909');
check(isset($bySlug['amnezia-wg']) && (int)$bySlug['amnezia-wg']['protocol_id'] === 3, 'primary binding maps stable slug to destination id 3');
check(!in_array(41, array_map(fn($r) => (int)$r['protocol_id'], $bindings), true), 'source numeric protocol id 41 is ignored');
check((int)$client['protocol_id'] === 909, 'client maps protocol_slug to destination id');
check($client['config'] === $rawConfig, 'raw client config preserved byte-for-byte');
check($client['qr_code'] === 'mock-qr:' . hash('sha256', $rawConfig), 'secondary client QR encodes restored raw config');
check(json_decode($bySlug['awg31']['config_data'], true) === $secondary, 'complete secondary config/settings/provenance preserved');
check($server['container_name'] === 'primary-container' && $server['vpn_port'] == 41111 && $server['awg_params'] === json_encode(['primary'=>'sentinel']), 'unrelated primary row preserved');
check(json_decode($bySlug['amnezia-wg']['config_data'], true)['extras']['primary_blob'] === 'unchanged', 'unrelated primary binding preserved');

echo "SUMMARY panel-import passed=$passed failed=$failed\n";
exit($failed === 0 ? 0 : 1);
