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

final class VpnServer
{
    public static string $mode = '';
    public static string $allocatorConfig = '';
    public static string $selectedConfig = '';
    public static string $selectedPublicKey = '';
    public static string $selectedFallbackPsk = '';
    public static string $selectedPeerPublicKey = '';
    public static string $selectedPeerPsk = '';
    public static array $commands = [];

    private int $id;
    private array $data = [];

    public function __construct(int $id)
    {
        $this->id = $id;
        $this->refresh();
    }

    public function getId(): int { return $this->id; }
    public function getData(): array { return $this->data; }

    public function refresh(): void
    {
        $stmt = DB::conn()->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->id]);
        $this->data = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    public function executeCommand(string $command, bool $sudo = false): string
    {
        self::$commands[] = ['mode' => self::$mode, 'command' => $command, 'sudo' => $sudo];
        if (self::$mode === 'allocator') {
            if (str_contains($command, 'cat') && str_contains($command, 'awg0.conf')) {
                return self::$allocatorConfig;
            }
            throw new RuntimeException('Unexpected allocator command: ' . $command);
        }
        if (self::$mode !== 'regenerate') {
            throw new RuntimeException('Unknown mock mode');
        }
        if (str_contains($command, 'show awg0 dump')) {
            return implode("\t", ['server-private', self::$selectedPublicKey, '53131', 'off']) . "\n"
                . implode("\t", ['other-peer', 'other-peer-psk', '(none)', '10.8.31.88/32', '0', '0', '0', 'off']) . "\n"
                . implode("\t", [self::$selectedPeerPublicKey, self::$selectedPeerPsk, '(none)', '10.8.31.9/32', '0', '0', '0', 'off']) . "\n";
        }
        if (str_contains($command, 'wireguard_server_public_key.key')) {
            return self::$selectedPublicKey . "\n";
        }
        if (str_contains($command, 'wireguard_psk.key')) {
            return self::$selectedFallbackPsk . "\n";
        }
        if (str_contains($command, 'awg0.conf') || str_contains($command, 'wg0.conf')) {
            return self::$selectedConfig;
        }
        throw new RuntimeException('Unexpected regeneration command: ' . $command);
    }
}

final class Assertions
{
    public int $passed = 0;
    public int $failed = 0;
    public array $lines = [];

    public function check(bool $condition, string $label, string $detail = ''): void
    {
        if ($condition) {
            $this->passed++;
            $this->lines[] = 'PASS ' . $label . ($detail !== '' ? ' -- ' . $detail : '');
        } else {
            $this->failed++;
            $this->lines[] = 'FAIL ' . $label . ($detail !== '' ? ' -- ' . $detail : '');
        }
    }
}

function createSchema(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE vpn_servers (
        id INTEGER PRIMARY KEY,
        host TEXT, port INTEGER, username TEXT, password TEXT, ssh_key TEXT,
        status TEXT, install_protocol TEXT, container_name TEXT,
        vpn_subnet TEXT, vpn_port INTEGER, server_public_key TEXT,
        preshared_key TEXT, awg_params TEXT, dns_servers TEXT,
        primary_blob BLOB
    )');
    $pdo->exec('CREATE TABLE protocols (
        id INTEGER PRIMARY KEY, slug TEXT, definition TEXT, output_template TEXT
    )');
    $pdo->exec('CREATE TABLE server_protocols (
        server_id INTEGER, protocol_id INTEGER, config_data TEXT,
        UNIQUE(server_id, protocol_id)
    )');
    $pdo->exec('CREATE TABLE vpn_clients (
        id INTEGER PRIMARY KEY, server_id INTEGER, user_id INTEGER,
        protocol_id INTEGER, name TEXT, client_ip TEXT,
        public_key TEXT, private_key TEXT, preshared_key TEXT,
        config TEXT, qr_code TEXT, status TEXT, expires_at TEXT,
        UNIQUE(server_id, client_ip)
    )');
}

$a = new Assertions();
$vpnSource = file_get_contents(__DIR__ . '/../../inc/VpnClient.php');
$a->check(is_string($vpnSource), 'loaded repository VpnClient source');
$awgSource = file_get_contents(__DIR__ . '/../../inc/Awg31Parameters.php');
eval(substr($awgSource, 5));

// Loader-only adaptation: the captured class's two require_once directives
// point to production dependencies. Ssh is mocked above and Awg31Parameters is
// loaded byte-for-byte from the same tar. All VpnClient method bodies remain
// byte-for-byte captured source.
$loadedSource = preg_replace("/^require_once __DIR__ \. '\/(?:Ssh|Awg31Parameters)\\.php';\\R/m", '', $vpnSource, -1, $removedRequires);
$a->check($removedRequires === 2, 'loader removed exactly two dependency require lines');
eval(substr((string) $loadedSource, 5));

$dbPath = __DIR__ . '/fixture.sqlite';
if (file_exists($dbPath)) {
    unlink($dbPath);
}
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
DB::$pdo = $pdo;
createSchema($pdo);

$pdo->prepare('INSERT INTO vpn_servers
    (id, host, port, username, password, status, install_protocol, container_name, vpn_subnet, vpn_port, server_public_key, preshared_key, awg_params, dns_servers, primary_blob)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    ->execute([1, '198.51.100.10', 22, 'fixture', 'fixture', 'active', 'amnezia-wg', 'primary-awg', '10.8.0.0/24', 51000,
        'PRIMARY_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234',
        'PRIMARY_PSK_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
        '{"PRIMARY":"UNCHANGED"}', '9.9.9.9', "primary\0bytes\xff"]);

VpnServer::$mode = 'allocator';
VpnServer::$allocatorConfig = "[Interface]\nAddress = 10.8.31.1/24\n";
$allocatorData = [
    'id' => 1,
    'vpn_subnet' => '10.8.31.0/24',
    'container_name' => 'selected-awg31',
    'install_protocol' => 'awg31',
];
$first = VpnClient::getNextClientIP($allocatorData);
$a->check($first === '10.8.31.2', 'allocator starts at first host after reserved network/gateway', 'actual=' . $first);

$insertClient = $pdo->prepare('INSERT INTO vpn_clients
    (id, server_id, user_id, protocol_id, name, client_ip, public_key, private_key, preshared_key, config, qr_code, status)
    VALUES (?, ?, 1, 31, ?, ?, ?, ?, ?, ?, ?, ?)');
$insertClient->execute([1, 1, 'active-db', '10.8.31.2', 'pub-active', 'priv-active', 'psk-active', '', '', 'active']);
$insertClient->execute([2, 1, 'revoked-db', '10.8.31.3', 'pub-revoked', 'priv-revoked', 'psk-revoked', '', '', 'revoked']);
VpnServer::$allocatorConfig = "[Interface]\nAddress = 10.8.31.1/24\n\n[Peer]\nPublicKey = live-only\nAllowedIPs = 10.8.31.4/32\n";
$next = VpnClient::getNextClientIP($allocatorData);
$a->check($next === '10.8.31.5', 'allocator skips active, revoked, and live-only reservations', 'actual=' . $next);
$insertClient->execute([3, 1, 'allocated', $next, 'pub-new', 'priv-new', 'psk-new', '', '', 'active']);
$a->check((int) $pdo->query("SELECT COUNT(*) FROM vpn_clients WHERE server_id=1 AND client_ip='10.8.31.5'")->fetchColumn() === 1,
    'allocated address inserts under real SQLite UNIQUE(server_id, client_ip) constraint');

$fields = [
    'Jc' => '6', 'Jmin' => '21', 'Jmax' => '61',
    'S1' => '31', 'S2' => '32', 'S3' => '33', 'S4' => '34',
    'H1' => '101', 'H2' => '102', 'H3' => '103', 'H4' => '104',
    'I1' => 'sentinel-i1', 'I2' => 'sentinel-i2', 'I3' => 'sentinel-i3', 'I4' => 'sentinel-i4', 'I5' => 'sentinel-i5',
    'HeaderProtectionKey' => base64_encode(str_repeat('H', 32)),
    'RekeyAfterTime' => '111-112', 'RekeyTimeout' => '7-8',
    'RejectAfterTime' => '171-172', 'KeepaliveTimeout' => '13-14',
    'MaxHandshakeAttempts' => '19-20', 'RandomTrailers' => 'off', 'DisableCookies' => 'on',
];
$confLines = ["[Interface]", 'PrivateKey = remote-server-private', 'Address = 10.8.31.1/24', 'ListenPort = 53131'];
foreach ($fields as $key => $value) {
    $confLines[] = $key . ' = ' . $value;
}
VpnServer::$selectedConfig = implode("\n", $confLines) . "\n";
VpnServer::$selectedPublicKey = 'SELECTED_SERVER_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
VpnServer::$selectedFallbackPsk = 'SELECTED_FALLBACK_PSK_ABCDEFGHIJKLMNOPQRSTUVWXYZ12';
VpnServer::$selectedPeerPublicKey = 'TARGET_CLIENT_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
VpnServer::$selectedPeerPsk = 'TARGET_PEER_PSK_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456';
VpnServer::$mode = 'regenerate';

$definition = json_encode(['metadata' => ['container_name' => 'selected-awg31', 'vpn_subnet' => '10.8.31.0/24']], JSON_UNESCAPED_SLASHES);
$pdo->prepare('INSERT INTO protocols (id, slug, definition, output_template) VALUES (31, ?, ?, NULL)')->execute(['awg31', $definition]);
$initialSelected = json_encode([
    'server_port' => 51831,
    'extras' => [
        'container_name' => 'selected-awg31',
        'server_public_key' => 'STALE_SELECTED_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'preshared_key' => VpnServer::$selectedFallbackPsk,
        'provenance_sentinel' => 'preserve-me',
    ],
], JSON_UNESCAPED_SLASHES);
$pdo->prepare('INSERT INTO server_protocols (server_id, protocol_id, config_data) VALUES (1, 31, ?)')->execute([$initialSelected]);
$insertClient->execute([41, 1, 'regen-target', '10.8.31.9', VpnServer::$selectedPeerPublicKey,
    'TARGET_CLIENT_PRIVATE_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'old-client-psk', 'old-config', 'old-qr', 'active']);

$primaryBefore = $pdo->query('SELECT * FROM vpn_servers WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
$result = (new VpnClient(41))->regenerateConfigFromServer(true);
$primaryAfter = $pdo->query('SELECT * FROM vpn_servers WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
$clientAfter = $pdo->query('SELECT * FROM vpn_clients WHERE id = 41')->fetch(PDO::FETCH_ASSOC);
$selectedAfterRaw = (string) $pdo->query('SELECT config_data FROM server_protocols WHERE server_id = 1 AND protocol_id = 31')->fetchColumn();
$selectedAfter = json_decode($selectedAfterRaw, true);
$generated = (string) $clientAfter['config'];

$a->check(($result['success'] ?? false) === true, 'actual regeneration method returns success');
$a->check(($result['peer_psk_source'] ?? '') === 'wg_dump', 'regeneration reports selected dump PSK source');
$a->check(str_contains($generated, 'PresharedKey = ' . VpnServer::$selectedPeerPsk), 'generated config uses target peer PSK from selected awg dump');
$a->check(!str_contains($generated, 'PresharedKey = ' . VpnServer::$selectedFallbackPsk), 'generated config does not use selected server-wide fallback PSK');
$a->check($clientAfter['preshared_key'] === VpnServer::$selectedPeerPsk, 'client row persists target peer PSK');
$a->check(str_contains($generated, 'PublicKey = ' . VpnServer::$selectedPublicKey), 'generated config uses selected remote server public key');
$a->check(str_contains($generated, 'Endpoint = 198.51.100.10:53131'), 'generated config uses selected remote ListenPort');
foreach ($fields as $key => $value) {
    $a->check(str_contains($generated, $key . ' = ' . $value), 'generated config preserves remote sentinel ' . $key);
}
$a->check(!str_contains($generated, 'ContentPaddingAddition'), 'generated config keeps absent ContentPaddingAddition absent');
$a->check($primaryAfter === $primaryBefore, 'secondary regeneration leaves primary vpn_servers row byte-for-byte values unchanged');
$persistedParams = $selectedAfter['extras']['awg_params'] ?? null;
$a->check(is_array($persistedParams), 'secondary regeneration persists recovered AWG31 params to selected server_protocols binding',
    'config_data_changed=' . ($selectedAfterRaw === $initialSelected ? 'no' : 'yes'));
if (is_array($persistedParams)) {
    $persistedByLower = [];
    foreach ($persistedParams as $persistedKey => $persistedValue) {
        $persistedByLower[strtolower((string) $persistedKey)] = $persistedValue;
    }
    foreach ($fields as $key => $value) {
        $lowerKey = strtolower($key);
        $a->check(array_key_exists($lowerKey, $persistedByLower) && (string) $persistedByLower[$lowerKey] === $value,
            'selected binding persists sentinel ' . $key);
    }
    $a->check(!array_key_exists('contentpaddingaddition', $persistedByLower), 'selected binding keeps absent ContentPaddingAddition absent');
}
$a->check(($selectedAfter['extras']['provenance_sentinel'] ?? '') === 'preserve-me', 'selected binding preserves unrelated stored provenance');
$storedOnlyLines = ["[Interface]", 'PrivateKey = remote-server-private', 'Address = 10.8.31.1/24', 'ListenPort = 53131'];
VpnServer::$selectedConfig = implode("\n", $storedOnlyLines) . "\n";
$storedReplay = (new VpnClient(41))->regenerateConfigFromServer(true);
$storedReplayClient = $pdo->query('SELECT * FROM vpn_clients WHERE id = 41')->fetch(PDO::FETCH_ASSOC);
$storedReplayConfig = (string) $storedReplayClient['config'];
$a->check(($storedReplay['success'] ?? false) === true, 'maintained reader regenerates from selected binding when live config has no AWG params');
foreach ($fields as $key => $value) {
    $a->check(str_contains($storedReplayConfig, $key . ' = ' . $value), 'maintained reader restores persisted sentinel ' . $key);
}
$a->check(!str_contains($storedReplayConfig, 'ContentPaddingAddition'), 'maintained reader keeps absent ContentPaddingAddition absent');
$a->check($storedReplayClient['preshared_key'] === VpnServer::$selectedPeerPsk, 'stored-binding replay still persists target dump PSK');
$primaryAfterReplay = $pdo->query('SELECT * FROM vpn_servers WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
$a->check($primaryAfterReplay === $primaryBefore, 'stored-binding replay leaves primary vpn_servers row byte-for-byte values unchanged');
$a->check(count(array_filter(VpnServer::$commands, fn(array $entry): bool => str_contains($entry['command'], 'selected-awg31'))) > 0,
    'remote mock observed commands bound to selected AWG31 container');

foreach ($a->lines as $line) {
    echo $line, "\n";
}
echo 'SUMMARY passed=', $a->passed, ' failed=', $a->failed, "\n";
echo 'BOUNDARY real=PDO_SQLite+captured_VpnClient+captured_Awg31Parameters mocked=VpnServer_remote_commands+QrUtil+DB_locator+Ssh_argument_helper', "\n";
echo 'DIAGNOSTIC result=', json_encode($result, JSON_UNESCAPED_SLASHES), "\n";
echo 'DIAGNOSTIC stored_client_psk=', $clientAfter['preshared_key'], "\n";
foreach (VpnServer::$commands as $index => $entry) {
    echo 'COMMAND ', $index + 1, ' ', $entry['command'], "\n";
}
exit($a->failed === 0 ? 0 : 1);
