<?php
/**
 * Preflight check for the SSH argument validation added alongside the command
 * injection fix.
 *
 * Validation is enforced when a server is created or imported, but existing
 * rows were stored before that. Run this after upgrading to find rows whose
 * host/username/port would now be refused, which would stop that server from
 * being reachable.
 *
 * Usage: php bin/check_server_ssh_fields.php
 */

require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/Ssh.php';
require_once __DIR__ . '/../inc/Logger.php';
require_once __DIR__ . '/../inc/VpnServer.php';

Config::load(__DIR__ . '/../.env');

$rows = DB::conn()
    ->query('SELECT id, name, host, username, port, container_name, vpn_subnet FROM vpn_servers ORDER BY id')
    ->fetchAll(PDO::FETCH_ASSOC);

$bad = 0;

foreach ($rows as $row) {
    $problems = [];

    $subnet = new ReflectionMethod('VpnServer', 'sanitizeSubnet');
    $subnet->setAccessible(true);
    $container = new ReflectionMethod('VpnServer', 'sanitizeContainerName');
    $container->setAccessible(true);

    foreach (
        [
            'host' => static fn() => Ssh::host((string) $row['host']),
            'username' => static fn() => Ssh::user((string) $row['username']),
            'port' => static fn() => Ssh::port($row['port']),
            'vpn_subnet' => static fn() => $subnet->invoke(null, $row['vpn_subnet']),
            'container_name' => static fn() => $container->invoke(null, $row['container_name']),
        ] as $field => $check
    ) {
        try {
            $check();
        } catch (InvalidArgumentException | Exception $e) {
            $problems[] = $field . '=' . var_export($row[$field], true) . ' (' . $e->getMessage() . ')';
        }
    }

    if ($problems) {
        $bad++;
        printf("server #%d %s\n  %s\n", $row['id'], $row['name'], implode("\n  ", $problems));
    }
}

printf("\n%d of %d servers need attention.\n", $bad, count($rows));

if ($bad > 0) {
    echo "Fix these rows before relying on the panel to reach those servers.\n";
    echo "A value that cannot be made valid means the row was never a usable SSH target.\n";
    exit(1);
}

echo "All stored SSH targets are valid.\n";
