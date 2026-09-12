<?php
declare(strict_types=1);

final class SqliteCompat
{
    public function __construct(public PDO $pdo) {}

    public function prepare(string $sql): PDOStatement
    {
        $sql = str_replace('NOW()', 'CURRENT_TIMESTAMP', $sql);
        $sql = preg_replace(
            '/ON DUPLICATE KEY UPDATE config_data = VALUES\(config_data\), applied_at = CURRENT_TIMESTAMP/i',
            'ON CONFLICT(server_id, protocol_id) DO UPDATE SET config_data = excluded.config_data, applied_at = CURRENT_TIMESTAMP',
            $sql
        );
        return $this->pdo->prepare($sql);
    }

    public function lastInsertId(): string|false { return $this->pdo->lastInsertId(); }
}

final class DB
{
    public static SqliteCompat $db;
    public static function conn(): SqliteCompat { return self::$db; }
}

final class Ssh
{
    public static function host(string $value): string { return $value; }
    public static function port(mixed $value): int { return (int) $value; }
    public static function user(string $value): string { return $value; }
    public static function remoteArg(string $value): string { return escapeshellarg($value); }
}

function loadCapturedClass(string $path): void
{
    $source = file_get_contents($path);
    if (!is_string($source)) throw new RuntimeException("cannot read $path");
    $source = preg_replace('/^<\?php\s*/', '', $source, 1);
    $source = preg_replace('/^[ \t]*require_once __DIR__ .*;\R/m', '', $source);
    eval($source);
}

function newDb(string $path): PDO
{
    if (is_file($path)) unlink($path);
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    DB::$db = new SqliteCompat($pdo);
    return $pdo;
}

function check(bool $condition, string $label): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "PASS $label\n";
    } else {
        $failed++;
        echo "FAIL $label\n";
    }
}
