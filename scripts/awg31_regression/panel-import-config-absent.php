<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
require __DIR__ . '/../../inc/BackupLibrary.php';

class VpnServer
{
    public static array $commands = [];
    public function executeCommand(string $command, bool $sudo = false): string
    {
        self::$commands[] = $command;
        throw new RuntimeException('local import must not execute a remote command');
    }
}

final class QrUtil
{
    public static array $calls = [];
    public static function encodeOldPayloadFromConf(string $config, string $slug): string
    {
        self::$calls[] = ['config' => $config, 'slug' => $slug];
        return 'mock-old-' . $slug . ':' . hash('sha256', $config);
    }
    public static function pngBase64(string $payload, int $size = 300, int $margin = 1, string $label = ''): string
    {
        self::$calls[] = ['config' => $payload, 'size' => $size, 'margin' => $margin];
        return 'mock-qr:' . hash('sha256', $payload);
    }
}

$serverSource = file_get_contents(__DIR__ . '/../../inc/VpnServer.php');
if (!is_string($serverSource)) throw new RuntimeException('cannot load captured VpnServer');
$serverSource = preg_replace('/^<\?php\s*/', '', $serverSource, 1);
$serverSource = preg_replace('/^[ \t]*require_once __DIR__ .*;\R/m', '', $serverSource);
$serverSource = preg_replace('/class VpnServer\s*\{/', 'class MaintainedVpnServer extends VpnServer {', $serverSource, 1);
$serverSource = preg_replace('/public function executeCommand\(/', 'public function capturedExecuteCommandDisabled(', $serverSource, 1);
eval($serverSource);
loadCapturedClass(__DIR__ . '/../../inc/VpnClient.php');

$passed = 0;
$failed = 0;
$pdo = newDb(__DIR__ . '/panel-import-config-absent.sqlite');
$pdo->exec('CREATE TABLE protocols (id INTEGER PRIMARY KEY, slug TEXT UNIQUE, definition TEXT, output_template TEXT)');
$pdo->exec('CREATE TABLE vpn_servers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, host TEXT, port INTEGER, username TEXT, password TEXT, container_name TEXT, install_protocol TEXT, install_options TEXT, vpn_port INTEGER, vpn_subnet TEXT, server_public_key TEXT, preshared_key TEXT, awg_params TEXT, status TEXT, deployed_at TEXT, error_message TEXT)');
$pdo->exec('CREATE TABLE server_protocols (server_id INTEGER, protocol_id INTEGER, config_data TEXT, applied_at TEXT, created_at TEXT, UNIQUE(server_id, protocol_id))');
$pdo->exec('CREATE TABLE vpn_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, user_id INTEGER, protocol_id INTEGER, name TEXT, client_ip TEXT, public_key TEXT, private_key TEXT, preshared_key TEXT, config TEXT, qr_code TEXT, status TEXT, expires_at TEXT, UNIQUE(server_id, client_ip))');
$pdo->exec("INSERT INTO protocols(id,slug,definition) VALUES (3,'amnezia-wg','{}'),(909,'awg31','{}')");

$primaryPublic = base64_encode(str_repeat('a', 32));
$primaryPsk = base64_encode(str_repeat('b', 32));
$selectedPublic = base64_encode(str_repeat('c', 32));
$selectedPsk = base64_encode(str_repeat('d', 32));
$clientPrivate = base64_encode(str_repeat('e', 32));
$clientPublic = base64_encode(str_repeat('f', 32));
$headerKey = base64_encode(str_repeat('h', 32));
$selectedParams = [
    'Jc' => '6', 'Jmin' => '21', 'Jmax' => '61',
    'S1' => '31', 'S2' => '32', 'S3' => '33', 'S4' => '34',
    'H1' => '101', 'H2' => '102', 'H3' => '103', 'H4' => '104',
    'HeaderProtectionKey' => $headerKey,
    'RandomTrailers' => 'off', 'DisableCookies' => 'on',
];
$selectedBinding = [
    'server_host' => '198.51.100.44',
    'server_port' => 53131,
    'extras' => [
        'container_name' => 'amnezia-awg31',
        'vpn_port' => 53131,
        'server_public_key' => $selectedPublic,
        'preshared_key' => $selectedPsk,
        'awg_params' => $selectedParams,
        'provenance_sentinel' => 'keep-selected',
    ],
];
$panel = [
    'server' => [
        'name' => 'portable-config-absent', 'host' => '198.51.100.44', 'port' => 22,
        'username' => 'root', 'password' => 'fixture', 'container_name' => 'primary-container',
        'install_protocol' => 'amnezia-wg', 'vpn_port' => 41001, 'vpn_subnet' => '10.8.1.0/24',
        'server_public_key' => $primaryPublic, 'preshared_key' => $primaryPsk,
        'awg_params' => ['Jc' => '4', 'ContentPaddingAddition' => 'primary-must-not-leak'],
    ],
    'server_protocols' => [
        ['slug' => 'amnezia-wg', 'protocol_id' => 7, 'config_data' => ['server_port' => 41001, 'extras' => ['container_name' => 'primary-container']]],
        ['slug' => 'awg31', 'protocol_id' => 41, 'config_data' => $selectedBinding],
    ],
    'clients' => [[
        'name' => 'secondary-no-config', 'client_ip' => '10.8.31.9',
        'public_key' => $clientPublic, 'private_key' => $clientPrivate,
        // Deliberately omit preshared_key and provide an empty config.
        'config' => '', 'status' => 'active', 'expires_at' => null,
        'protocol_id' => 41, 'protocol_slug' => 'awg31',
    ]],
];
$backupPath = __DIR__ . '/panel-config-absent.backup.json';
file_put_contents($backupPath, json_encode($panel, JSON_UNESCAPED_SLASHES));
$parsed = BackupParser::parse($backupPath);
$serverData = $parsed['servers'][0];
$serverId = MaintainedVpnServer::importFromBackup(77, $serverData);
$server = $pdo->query('SELECT * FROM vpn_servers WHERE id=' . (int) $serverId)->fetch(PDO::FETCH_ASSOC);
$importedId = VpnClient::importFromBackup($server, 77, $serverData['clients'][0]);
$client = $pdo->query('SELECT * FROM vpn_clients WHERE id=' . (int) $importedId)->fetch(PDO::FETCH_ASSOC);
$bindings = $pdo->query('SELECT p.slug,sp.protocol_id,sp.config_data FROM server_protocols sp JOIN protocols p ON p.id=sp.protocol_id')->fetchAll(PDO::FETCH_ASSOC);
$bySlug = [];
foreach ($bindings as $row) $bySlug[$row['slug']] = $row;
$config = (string) $client['config'];

check((int) $bySlug['amnezia-wg']['protocol_id'] === 3 && (int) $bySlug['awg31']['protocol_id'] === 909, 'portable bindings map different source IDs by stable slug');
check((int) $client['protocol_id'] === 909, 'config-absent client maps to destination AWG31 id');
check($client['preshared_key'] === $selectedPsk, 'absent client PSK falls back to selected binding PSK');
check(str_contains($config, 'PublicKey = ' . $selectedPublic), 'generated config uses selected binding server public key');
check(str_contains($config, 'PresharedKey = ' . $selectedPsk), 'generated config uses selected binding PSK');
check(str_contains($config, 'Endpoint = 198.51.100.44:53131'), 'generated config uses selected binding port');
check(!str_contains($config, $primaryPublic), 'conflicting primary public key does not leak');
check(!str_contains($config, $primaryPsk), 'conflicting primary PSK does not leak');
check(!str_contains($config, ':41001'), 'conflicting primary port does not leak');
foreach ($selectedParams as $field => $value) {
    check(str_contains($config, $field . ' = ' . $value), 'generated config preserves selected parameter ' . $field);
}
check(!str_contains($config, 'ContentPaddingAddition'), 'optional absent in selected binding stays absent despite primary value');
check(count(QrUtil::$calls) === 1 && QrUtil::$calls[0]['config'] === $config, 'QR uses exact generated raw AWG config');
check($client['qr_code'] === 'mock-qr:' . hash('sha256', $config), 'stored QR is generated from raw AWG config');
check(json_decode($bySlug['awg31']['config_data'], true) === $selectedBinding, 'complete selected binding remains structurally equal');
check(VpnServer::$commands === [], 'documented local import path emits no remote command');

echo 'DIAGNOSTIC stored_psk_source=' . ($client['preshared_key'] === $selectedPsk ? 'selected' : ($client['preshared_key'] === $primaryPsk ? 'primary' : 'other'))
    . ' config_selected_psk=' . (str_contains($config, $selectedPsk) ? 'yes' : 'no')
    . ' config_primary_psk=' . (str_contains($config, $primaryPsk) ? 'yes' : 'no') . "\n";
echo "SUMMARY panel-import-config-absent passed=$passed failed=$failed\n";
echo "BOUNDARY real=captured_BackupParser+captured_VpnServer_import+captured_VpnClient_import+captured_buildClientConfig+PDO_SQLite mocked=QR_and_remote_guard\n";
exit($failed === 0 ? 0 : 1);
