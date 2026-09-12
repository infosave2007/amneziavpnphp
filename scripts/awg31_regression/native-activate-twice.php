<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
require __DIR__ . '/../../inc/Awg31Parameters.php';

final class Logger
{
    public static array $lines = [];
    public static function appendInstall(int $serverId, string $message): void { self::$lines[] = [$serverId, $message]; }
}

final class VpnClient
{
    public static function buildClientConfig(...$args): string { throw new RuntimeException('unexpected client config build'); }
}

final class VpnServer
{
    public static array $commands = [];
    public static int $freshInstallCalls = 0;
    private int $id;
    private array $data = [];
    public function __construct(int $id) { $this->id = $id; $this->refresh(); }
    public function getId(): int { return $this->id; }
    public function getData(): array { return $this->data; }
    public function refresh(): void
    {
        $stmt = DB::conn()->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->id]);
        $this->data = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }
    public function runAwgInstall(array $options = []): array
    {
        self::$freshInstallCalls++;
        throw new RuntimeException('fresh builtin install must not be called');
    }
    public function executeCommand(string $command, bool $sudo = false): string
    {
        self::$commands[] = $command;
        if (str_contains($command, "docker ps -a --filter name='^amnezia-awg$'")) return "amnezia-awg\n";
        if (str_contains($command, "docker inspect --format '{{.State.Status}}' 'amnezia-awg'")) return "running\n";
        if (str_contains($command, 'cat /opt/amnezia/awg/awg0.conf')) {
            return "[Interface]\nPrivateKey = fixture-server-private\nAddress = 10.8.31.1/24\nListenPort = 53131\nJc = 6\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nDisableCookies = on\n";
        }
        if (str_contains($command, 'wireguard_server_public_key.key')) return base64_encode(str_repeat('p', 32)) . "\n";
        if (str_contains($command, 'wireguard_psk.key')) return base64_encode(str_repeat('s', 32)) . "\n";
        if (str_contains($command, 'clientsTable')) return "[]\n";
        if (str_contains($command, "docker start 'amnezia-awg'") || str_contains($command, "docker exec -i 'amnezia-awg' awg-quick")) return '';
        throw new RuntimeException('unexpected remote command: ' . $command);
    }
}

$managerSource = file_get_contents(__DIR__ . '/../../inc/InstallProtocolManager.php');
if (!is_string($managerSource)) throw new RuntimeException('cannot load captured InstallProtocolManager');
$managerSource = preg_replace('/^<\?php\s*/', '', $managerSource, 1);
$managerSource = preg_replace('/^[ \t]*require_once __DIR__ .*;\R/m', '', $managerSource);
eval($managerSource);

$passed = 0;
$failed = 0;
$pdo = newDb(__DIR__ . '/native-activate-twice.sqlite');
$pdo->exec('CREATE TABLE protocols (id INTEGER PRIMARY KEY, slug TEXT UNIQUE, definition TEXT)');
$pdo->exec('CREATE TABLE vpn_servers (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, host TEXT, port INTEGER, username TEXT, password TEXT, container_name TEXT, install_protocol TEXT, install_options TEXT, vpn_port INTEGER, vpn_subnet TEXT, server_public_key TEXT, preshared_key TEXT, awg_params TEXT, status TEXT, deployed_at TEXT, error_message TEXT)');
$pdo->exec('CREATE TABLE server_protocols (server_id INTEGER, protocol_id INTEGER, config_data TEXT, applied_at TEXT, created_at TEXT, UNIQUE(server_id, protocol_id))');
$pdo->exec('CREATE TABLE vpn_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, user_id INTEGER, protocol_id INTEGER, name TEXT, client_ip TEXT, public_key TEXT, private_key TEXT, preshared_key TEXT, config TEXT, status TEXT, created_at TEXT)');

$definition = ['engine' => 'builtin_awg', 'metadata' => ['container_name' => 'amnezia-awg31', 'vpn_subnet' => '10.8.31.0/24']];
$pdo->prepare("INSERT INTO protocols(id,slug,definition) VALUES (909,'awg31',?)")->execute([json_encode($definition)]);
$pdo->prepare('INSERT INTO vpn_servers VALUES (1,77,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')->execute([
    'native', '198.51.100.77', 22, 'root', 'fixture', 'amnezia-awg', 'awg31', null,
    53131, '10.8.31.0/24', 'old-native-public', 'old-native-psk', '{}', 'active', '2026-01-01', null,
]);
$initial = [
    'server_host' => '198.51.100.77',
    'server_port' => 53131,
    'extras' => [
        'container_name' => 'amnezia-awg',
        'vpn_subnet' => '10.8.31.0/24',
        'vpn_port' => 53131,
        'imported_native_runtime' => true,
        'provenance_sentinel' => ['source' => 'native-import', 'unknown' => 'retain-me'],
    ],
];
$pdo->prepare('INSERT INTO server_protocols VALUES (1,909,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)')->execute([json_encode($initial)]);
$protocol = ['id' => 909, 'slug' => 'awg31', 'definition' => $definition, 'install_script' => 'FRESH_INSTALL_MUST_NOT_RUN'];
$server = new VpnServer(1);

$results = [];
$bindings = [];
for ($attempt = 1; $attempt <= 2; $attempt++) {
    $results[$attempt] = InstallProtocolManager::activate($server, $protocol, []);
    $raw = (string) $pdo->query('SELECT config_data FROM server_protocols WHERE server_id=1 AND protocol_id=909')->fetchColumn();
    $bindings[$attempt] = json_decode($raw, true);
    check(($results[$attempt]['mode'] ?? '') === 'restore_existing', "activation $attempt restores existing native runtime");
    check(($bindings[$attempt]['extras']['imported_native_runtime'] ?? false) === true, "activation $attempt preserves imported-native flag");
    check(($bindings[$attempt]['extras']['container_name'] ?? '') === 'amnezia-awg', "activation $attempt preserves observed native container");
    check(($bindings[$attempt]['extras']['provenance_sentinel']['unknown'] ?? '') === 'retain-me', "activation $attempt preserves unrelated selected extras");
    check(($bindings[$attempt]['server_host'] ?? null) === '198.51.100.77', "activation $attempt preserves required server_host");
    check(($bindings[$attempt]['extras']['vpn_subnet'] ?? null) === '10.8.31.0/24', "activation $attempt preserves selected native subnet");
}

check(VpnServer::$freshInstallCalls === 0, 'two activations never invoke fresh builtin install');
check(!(bool) array_filter(VpnServer::$commands, fn($c) => str_contains($c, 'amnezia-awg31')), 'two activations never target fresh awg31 namespace');
check(count(VpnServer::$commands) > 0 && count(array_filter(VpnServer::$commands, fn($c) => str_contains($c, 'amnezia-awg'))) === count(VpnServer::$commands), 'all remote mock calls target observed native container');

foreach ([1, 2] as $attempt) {
    echo 'DIAGNOSTIC activation=' . $attempt
        . ' mode=' . ($results[$attempt]['mode'] ?? 'none')
        . ' server_host=' . json_encode($bindings[$attempt]['server_host'] ?? null)
        . ' vpn_subnet=' . json_encode($bindings[$attempt]['extras']['vpn_subnet'] ?? null)
        . ' container=' . json_encode($bindings[$attempt]['extras']['container_name'] ?? null)
        . ' native_flag=' . json_encode($bindings[$attempt]['extras']['imported_native_runtime'] ?? null) . "\n";
}
echo 'REMOTE_COMMAND_COUNT ' . count(VpnServer::$commands) . "\n";
echo "SUMMARY native-activate-twice passed=$passed failed=$failed\n";
echo "BOUNDARY real=captured_InstallProtocolManager_activate+detectBuiltinAwg+restoreBuiltinAwg+PDO_SQLite mocked=VpnServer_remote_and_Logger_and_empty_client_dependency\n";
exit($failed === 0 ? 0 : 1);
