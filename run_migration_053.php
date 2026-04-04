<?php
require_once __DIR__ . '/inc/Config.php';
Config::load(__DIR__ . '/.env');
require_once __DIR__ . '/inc/DB.php';

try {
    $pdo = DB::conn();
    $sql = file_get_contents(__DIR__ . '/migrations/053_split_speed.sql');
    $pdo->exec($sql);
    echo "Migration 053 applied successfully.\n";
} catch (Exception $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
}
