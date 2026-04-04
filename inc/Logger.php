<?php

class Logger {
    private const DEFAULT_LOGS_DIR = __DIR__ . '/../logs';

    private static function ensureDir(string $dir): void {
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
    }

    private static function getLogsDir(): string {
        // Fallback to project logs directory next to inc/
        $dir = self::DEFAULT_LOGS_DIR;
        self::ensureDir($dir);
        return $dir;
    }

    public static function appendInstall(int $serverId, string $message): void {
        $dir = self::getLogsDir();
        $file = $dir . '/install_server_' . $serverId . '.log';
        $line = '[' . date('Y-m-d H:i:s') . '] ' . $message . "\n";
        @file_put_contents($file, $line, FILE_APPEND);
    }
}