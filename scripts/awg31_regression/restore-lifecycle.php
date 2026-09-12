<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
require __DIR__ . '/../../inc/Awg31Parameters.php';

class VpnServer
{
    public static array $commands = [];
    /** @var array<string,bool> */
    public static array $livePeers = [];
    public static ?string $throwOnRemovePublicKey = null;
    protected int $mockId;
    protected array $mockData;

    public function __construct(?int $id = null)
    {
        $this->mockId = (int) $id;
        $stmt = DB::conn()->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->mockId]);
        $this->mockData = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    public function getId(): int { return $this->mockId; }
    public function getData(): ?array { return $this->mockData; }
    public function refresh(): void { $this->__construct($this->mockId); }

    public function executeCommand(string $command, bool $sudo = false): string
    {
        self::$commands[] = $command;
        if (str_contains($command, 'cat /opt/amnezia/awg/awg0.conf')) {
            return "[Interface]\nListenPort = 53131\nJc = 6\n";
        }
        if (preg_match("/ awg set awg0 peer '([^']+)' remove/", $command, $m)) {
            if (self::$throwOnRemovePublicKey === $m[1]) {
                throw new RuntimeException('fixture remove failure');
            }
            unset(self::$livePeers[$m[1]]);
            return '';
        }
        if (preg_match("/ awg set awg0 peer '([^']+)' preshared-key /", $command, $m)) {
            self::$livePeers[$m[1]] = true;
            return '';
        }
        if (str_contains($command, 'clientsTable')) return '[]';
        return '';
    }
}

final class QrUtil
{
    public static function encodeOldPayloadFromConf(string $config, string $slug): string { return 'mock-' . $slug; }
    public static function pngBase64(string $payload): string { return 'mock-qr'; }
}

loadCapturedClass(__DIR__ . '/../../inc/VpnClient.php');
$source = file_get_contents(__DIR__ . '/../../inc/VpnServer.php');
if (!is_string($source)) throw new RuntimeException('cannot load captured VpnServer');
$source = preg_replace('/^<\?php\s*/', '', $source, 1);
$source = preg_replace('/^[ \t]*require_once __DIR__ .*;\R/m', '', $source);
$source = preg_replace('/class VpnServer\s*\{/', 'class MaintainedVpnServer extends VpnServer {', $source, 1);
$source = preg_replace('/public function executeCommand\(/', 'public function capturedExecuteCommandDisabled(', $source, 1);
eval($source);

$passed = 0;
$failed = 0;
$pdo = newDb(__DIR__ . '/restore-lifecycle.sqlite');
$pdo->exec('CREATE TABLE protocols (id INTEGER PRIMARY KEY, slug TEXT UNIQUE, definition TEXT)');
$pdo->exec('CREATE TABLE vpn_servers (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, host TEXT, port INTEGER, username TEXT, password TEXT, container_name TEXT, install_protocol TEXT, install_options TEXT, vpn_port INTEGER, vpn_subnet TEXT, server_public_key TEXT, preshared_key TEXT, awg_params BLOB, status TEXT, deployed_at TEXT, error_message TEXT)');
$pdo->exec('CREATE TABLE server_protocols (server_id INTEGER, protocol_id INTEGER, config_data TEXT, applied_at TEXT, created_at TEXT, UNIQUE(server_id, protocol_id))');
$pdo->exec('CREATE TABLE vpn_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, user_id INTEGER, protocol_id INTEGER, name TEXT, client_ip TEXT, public_key TEXT, private_key TEXT, preshared_key TEXT, config TEXT, status TEXT, expires_at TEXT, UNIQUE(server_id, client_ip))');
$pdo->exec('CREATE TABLE server_backups (id INTEGER PRIMARY KEY, server_id INTEGER, backup_path TEXT)');

$definition = json_encode(['metadata' => ['container_name' => 'amnezia-awg31', 'vpn_subnet' => '10.8.31.0/24']]);
$pdo->prepare("INSERT INTO protocols VALUES (5, 'amnezia-wg', '{}'), (812, 'awg31', ?)")->execute([$definition]);
$primaryBlob = "primary\0binary\xff";
$insertServer = $pdo->prepare('INSERT INTO vpn_servers VALUES (1,77,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
$insertServer->execute(['main', '198.51.100.9', 22, 'root', 'fixture', 'primary-container', 'amnezia-wg', null, 41111, '10.8.1.0/24', 'primary-pub', 'primary-psk', $primaryBlob, 'active', '2026-01-01', null]);

$clientPrivate = base64_encode(str_repeat('a', 32));
$clientPublic = base64_encode(str_repeat('b', 32));
$clientPsk = base64_encode(str_repeat('c', 32));
$serverFallbackPsk = base64_encode(str_repeat('d', 32));
$serverPublic = base64_encode(str_repeat('e', 32));
$historicalPublic = base64_encode(str_repeat('f', 32));
check($clientPsk !== $serverFallbackPsk, 'fixture individual client PSK differs from selected server fallback');

$selected = [
    'server_port' => 53131,
    'extras' => [
        'container_name' => 'amnezia-awg31',
        'vpn_port' => 53131,
        'vpn_subnet' => '10.8.31.0/24',
        'server_public_key' => $serverPublic,
        'preshared_key' => $serverFallbackPsk,
        'awg_params' => ['Jc' => '6', 'DisableCookies' => 'on'],
    ],
];
$pdo->prepare('INSERT INTO server_protocols VALUES (1,812,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)')->execute([json_encode($selected)]);
$rawConfig = "[Interface]\nPrivateKey = $clientPrivate\n[Peer]\nPublicKey = $serverPublic\nPresharedKey = $clientPsk\n";
$backup = [
    'server' => ['install_protocol' => 'amnezia-wg'],
    'clients' => [[
        'name' => 'restored-secondary',
        'client_ip' => '10.8.31.7',
        'public_key' => $clientPublic,
        'private_key' => $clientPrivate,
        'preshared_key' => $clientPsk,
        'config' => $rawConfig,
        'status' => 'active',
        'expires_at' => null,
        'protocol_id' => 41,
        'protocol_slug' => 'awg31',
    ]],
];
$backupPath = __DIR__ . '/same-server.backup.json';
file_put_contents($backupPath, json_encode($backup, JSON_UNESCAPED_SLASHES));
$pdo->prepare('INSERT INTO server_backups VALUES (9,1,?)')->execute([$backupPath]);

$primaryBefore = $pdo->query('SELECT * FROM vpn_servers WHERE id=1')->fetch(PDO::FETCH_ASSOC);
$restoreResult = (new MaintainedVpnServer(1))->restoreBackup(9);
$restored = $pdo->query("SELECT * FROM vpn_clients WHERE name='restored-secondary'")->fetch(PDO::FETCH_ASSOC);
check($restoreResult['restored'] === 1 && $restoreResult['failed'] === 0, 'actual restoreBackup reports one restored client');
check((int) $restored['protocol_id'] === 812, 'restoreBackup maps stable slug to destination protocol id');
check($restored['config'] === $rawConfig && $restored['status'] === 'disabled', 'restoreBackup preserves config and forces disabled status');
check($restored['preshared_key'] === $clientPsk, 'restoreBackup persists individual client PSK');
check(VpnServer::$livePeers === [] && !(bool) array_filter(VpnServer::$commands, fn($c) => str_contains($c, ' set awg0 peer ')), 'disabled restore performs no peer add and leaves no live peer');
check($pdo->query('SELECT * FROM vpn_servers WHERE id=1')->fetch(PDO::FETCH_ASSOC) === $primaryBefore, 'restoreBackup leaves primary row byte-for-byte values unchanged');

$restoredId = (int) $restored['id'];
$commandsBeforeExplicitRestore = count(VpnServer::$commands);
$explicitRestore = (new VpnClient($restoredId))->restore();
$afterExplicitRestore = $pdo->query("SELECT * FROM vpn_clients WHERE id=$restoredId")->fetch(PDO::FETCH_ASSOC);
$restoreCommands = array_slice(VpnServer::$commands, $commandsBeforeExplicitRestore);
check($explicitRestore && $afterExplicitRestore['status'] === 'active', 'explicit client restore marks row active');
check(isset(VpnServer::$livePeers[$clientPublic]), 'explicit restore creates selected-lane live peer');
check(count($restoreCommands) > 0 && count(array_filter($restoreCommands, fn($c) => str_contains($c, 'amnezia-awg31'))) === count($restoreCommands), 'explicit restore sends every remote command to selected AWG31 container');
check((bool) array_filter($restoreCommands, fn($c) => str_contains($c, 'echo "' . $clientPsk . '"')), 'explicit restore supplies individual client PSK to peer operation');
check(!(bool) array_filter($restoreCommands, fn($c) => str_contains($c, 'echo "' . $serverFallbackPsk . '"')), 'explicit restore does not substitute selected server fallback PSK');
check((bool) array_filter($restoreCommands, fn($c) => str_contains($c, ' awg set awg0 peer ')), 'explicit restore uses awg set on selected awg0 interface');

$deleteActive = (new VpnClient($restoredId))->delete();
check($deleteActive && (int) $pdo->query("SELECT COUNT(*) FROM vpn_clients WHERE id=$restoredId")->fetchColumn() === 0, 'delete removes explicitly restored client row');
check(!isset(VpnServer::$livePeers[$clientPublic]), 'delete removes explicitly restored live peer');

$insertHistorical = $pdo->prepare('INSERT INTO vpn_clients (server_id,user_id,protocol_id,name,client_ip,public_key,private_key,preshared_key,config,status,expires_at) VALUES (1,77,812,?,?,?,?,?,?,?,NULL)');
$insertHistorical->execute(['historical-disabled-live', '10.8.31.8', $historicalPublic, $clientPrivate, $clientPsk, $rawConfig, 'disabled']);
$historicalId = (int) $pdo->lastInsertId();
VpnServer::$livePeers[$historicalPublic] = true;
$historyCommandOffset = count(VpnServer::$commands);
$deleteHistorical = (new VpnClient($historicalId))->delete();
$historicalCommands = array_slice(VpnServer::$commands, $historyCommandOffset);
check($deleteHistorical && (int) $pdo->query("SELECT COUNT(*) FROM vpn_clients WHERE id=$historicalId")->fetchColumn() === 0, 'delete removes historical disabled client row');
check(!isset(VpnServer::$livePeers[$historicalPublic]), 'delete removes historical disabled-but-live peer');
check((bool) array_filter($historicalCommands, fn($c) => str_contains($c, ' awg set awg0 peer ') && str_contains($c, ' remove')), 'historical cleanup executes actual selected-lane peer removal');
check(count($historicalCommands) > 0 && count(array_filter($historicalCommands, fn($c) => str_contains($c, 'amnezia-awg31'))) === count($historicalCommands), 'historical cleanup sends every remote command to selected AWG31 container');
check(VpnServer::$livePeers === [], 'fixture remote live-peer set is empty after both delete paths');
check($pdo->query('SELECT * FROM vpn_servers WHERE id=1')->fetch(PDO::FETCH_ASSOC) === $primaryBefore, 'complete lifecycle leaves primary row byte-for-byte values unchanged');

// Failure-path contract: DB status must not claim a state that was not applied live.
$inactivePublic = base64_encode(str_repeat('g', 32));
$insertInactive = $pdo->prepare('INSERT INTO vpn_clients (server_id,user_id,protocol_id,name,client_ip,public_key,private_key,preshared_key,config,status,expires_at) VALUES (1,77,812,?,?,?,?,?,?,?,NULL)');
$insertInactive->execute(['inactive-server-client', '10.8.31.9', $inactivePublic, $clientPrivate, $clientPsk, $rawConfig, 'disabled']);
$inactiveId = (int) $pdo->lastInsertId();
$pdo->exec("UPDATE vpn_servers SET status='inactive' WHERE id=1");
$inactiveRestoreResult = false;
try { (new VpnClient($inactiveId))->restore(); } catch (Exception $e) { $inactiveRestoreResult = false; }
$inactiveStatus = (string) $pdo->query("SELECT status FROM vpn_clients WHERE id=$inactiveId")->fetchColumn();
check($inactiveRestoreResult === false && $inactiveStatus === 'disabled', 'restore on inactive server preserves disabled status and reports no live apply');
check(!isset(VpnServer::$livePeers[$inactivePublic]), 'restore on inactive server creates no live peer');

$pdo->exec("UPDATE vpn_servers SET status='active' WHERE id=1");
$revokePublic = base64_encode(str_repeat('h', 32));
$insertRevoke = $pdo->prepare('INSERT INTO vpn_clients (server_id,user_id,protocol_id,name,client_ip,public_key,private_key,preshared_key,config,status,expires_at) VALUES (1,77,812,?,?,?,?,?,?,?,NULL)');
$insertRevoke->execute(['remove-failure-client', '10.8.31.10', $revokePublic, $clientPrivate, $clientPsk, $rawConfig, 'active']);
$revokeId = (int) $pdo->lastInsertId();
VpnServer::$livePeers[$revokePublic] = true;
VpnServer::$throwOnRemovePublicKey = $revokePublic;
$revokeResult = false;
try { (new VpnClient($revokeId))->revoke(); } catch (Exception $e) { $revokeResult = false; }
$revokeStatus = (string) $pdo->query("SELECT status FROM vpn_clients WHERE id=$revokeId")->fetchColumn();
check($revokeResult === false && $revokeStatus === 'active', 'revoke remote-removal failure preserves active status and reports failure');
check(isset(VpnServer::$livePeers[$revokePublic]), 'revoke failure fixture confirms peer remains live');
VpnServer::$throwOnRemovePublicKey = null;

echo 'DIAGNOSTIC inactive_restore_result=' . ($inactiveRestoreResult ? 'true' : 'false')
    . ' db_status=' . $inactiveStatus
    . ' live_peer=' . (isset(VpnServer::$livePeers[$inactivePublic]) ? 'yes' : 'no') . "\n";
echo 'DIAGNOSTIC revoke_result=' . ($revokeResult ? 'true' : 'false')
    . ' db_status=' . $revokeStatus
    . ' live_peer=' . (isset(VpnServer::$livePeers[$revokePublic]) ? 'yes' : 'no') . "\n";

echo 'REMOTE_COMMAND_COUNT ' . count(VpnServer::$commands) . "\n";
echo "SUMMARY restore-lifecycle passed=$passed failed=$failed\n";
echo "BOUNDARY real=captured_restoreBackup+captured_restore+captured_delete+captured_protocol_resolution+PDO_SQLite mocked=remote_command_executor_and_live_peer_set\n";
exit($failed === 0 ? 0 : 1);
