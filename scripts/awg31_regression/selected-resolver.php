<?php
declare(strict_types=1);

final class DB
{
    public static PDO $pdo;
    public static function conn(): PDO { return self::$pdo; }
}

final class Ssh
{
    public static function remoteArg(string $value): string { return escapeshellarg($value); }
}

final class QrUtil
{
    public static function encodeOldPayloadFromConf(string $config, string $slug = ''): string { return ''; }
    public static function pngBase64(string $payload): string { return ''; }
}

final class VpnServer
{
    public static array $commands = [];
    public function __construct(private int $id, private array $data) {}
    public function getId(): int { return $this->id; }
    public function getData(): array { return $this->data; }
    public function executeCommand(string $command, bool $sudo = false): string
    {
        self::$commands[] = $command;
        if (!str_contains($command, 'metadata-native-container')) {
            throw new RuntimeException('resolver targeted wrong container');
        }
        if (str_contains($command, 'wireguard_server_public_key.key')) return "LIVE_SELECTED_PUBLIC\n";
        if (str_contains($command, 'wireguard_psk.key')) return "LIVE_SELECTED_PSK\n";
        if (str_contains($command, 'awg0.conf')) return "[Interface]\nListenPort = 53131\nJc = 6\nDisableCookies = on\n";
        throw new RuntimeException('unexpected resolver command');
    }
}

final class Assertions
{
    public int $passed = 0;
    public int $failed = 0;
    public function check(bool $condition, string $label): void
    {
        if ($condition) { $this->passed++; echo "PASS $label\n"; }
        else { $this->failed++; echo "FAIL $label\n"; }
    }
}

$awgSource = file_get_contents(__DIR__ . '/../../inc/Awg31Parameters.php');
if (!is_string($awgSource)) throw new RuntimeException('cannot load captured Awg31Parameters');
eval(substr($awgSource, 5));
$vpnSource = file_get_contents(__DIR__ . '/../../inc/VpnClient.php');
if (!is_string($vpnSource)) throw new RuntimeException('cannot load captured VpnClient');
$vpnSource = preg_replace("/^require_once __DIR__ \. '\/(?:Ssh|Awg31Parameters)\\.php';\\R/m", '', $vpnSource, -1, $removed);
if ($removed !== 2) throw new RuntimeException('unexpected captured dependency shape');
eval(substr((string) $vpnSource, 5));

$dbPath = __DIR__ . '/selected-resolver.sqlite';
if (is_file($dbPath)) unlink($dbPath);
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
DB::$pdo = $pdo;
$pdo->exec('CREATE TABLE protocols (id INTEGER PRIMARY KEY, slug TEXT, definition TEXT)');
$pdo->exec('CREATE TABLE server_protocols (server_id INTEGER, protocol_id INTEGER, config_data TEXT, UNIQUE(server_id,protocol_id))');
$definition = json_encode(['metadata' => ['container_name' => 'metadata-native-container', 'vpn_subnet' => '10.8.99.0/24']]);
$pdo->prepare('INSERT INTO protocols VALUES (909,?,?)')->execute(['awg31', $definition]);
$binding = [
    'server_host' => '198.51.100.91',
    'server_port' => 53131,
    'extras' => [
        // Omit container_name so decoded array metadata must supply it.
        'vpn_subnet' => '10.8.31.0/24',
        'vpn_port' => 53131,
        'server_public_key' => 'STORED_SELECTED_PUBLIC',
        'preshared_key' => 'STORED_SELECTED_PSK',
        'imported_native_runtime' => true,
    ],
];
$pdo->prepare('INSERT INTO server_protocols VALUES (1,909,?)')->execute([json_encode($binding)]);
$primary = [
    'id' => 1, 'host' => '198.51.100.91', 'status' => 'active',
    'install_protocol' => 'amnezia-wg', 'container_name' => 'primary-container',
    'vpn_subnet' => '10.8.1.0/24', 'vpn_port' => 41001,
    'server_public_key' => 'PRIMARY_PUBLIC', 'preshared_key' => 'PRIMARY_PSK', 'awg_params' => '{}',
];
$server = new VpnServer(1, $primary);
$resolved = VpnClient::resolveProtocolServerData($server, 909);
$a = new Assertions();
$a->check($resolved['container_name'] === 'metadata-native-container', 'public resolver consumes array-decoded definition metadata container');
$a->check($resolved['vpn_subnet'] === '10.8.31.0/24', 'selected extras custom native subnet overrides metadata and primary subnet');
$a->check((int) $resolved['vpn_port'] === 53131, 'selected resolver uses selected port');
$a->check($resolved['install_protocol'] === 'awg31', 'selected resolver applies selected stable slug');
$a->check($resolved['server_public_key'] === 'STORED_SELECTED_PUBLIC', 'short mock live public key cannot replace stored selected key');
$a->check($resolved['preshared_key'] === 'STORED_SELECTED_PSK', 'short mock live PSK cannot replace stored selected PSK');
$a->check(count(VpnServer::$commands) === 3, 'resolver performs bounded config and key reads');
$a->check(count(array_filter(VpnServer::$commands, fn($c) => str_contains($c, 'metadata-native-container'))) === 3, 'every resolver command targets metadata container');
echo 'DIAGNOSTIC container=' . $resolved['container_name'] . ' subnet=' . $resolved['vpn_subnet'] . ' port=' . $resolved['vpn_port'] . "\n";
echo "SUMMARY selected-resolver passed={$a->passed} failed={$a->failed}\n";
echo "BOUNDARY real=captured_VpnClient_resolveProtocolServerData+applyProtocolServerData+PDO_SQLite mocked=VpnServer_remote_reads\n";
exit($a->failed === 0 ? 0 : 1);
