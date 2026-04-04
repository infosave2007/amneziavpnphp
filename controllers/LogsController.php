<?php

/**
 * LogsController
 * Manages application logs viewing and management
 * Admin-only access to application log files
 */
class LogsController {

    private const LOGS_DIR = __DIR__ . '/../logs';
    private const MAX_FILE_SIZE = 10485760; // 10 MB
    private const ALLOWED_EXTENSIONS = ['log', 'txt'];

    /**
     * List and view application logs
     * GET /admin/logs
     */
    public function index() {
        requireAdmin();

        $logFiles = $this->getLogFiles();
        $selectedFile = $_GET['file'] ?? null;
        $logContent = '';
        $logLines = [];
        $fileSize = 0;
        $lineCount = 0;

        if ($selectedFile && $this->isValidLogFile($selectedFile)) {
            $filePath = self::LOGS_DIR . '/' . basename($selectedFile);
            
            if (file_exists($filePath)) {
                $fileSize = filesize($filePath);
                
                // Read log file (last 1000 lines or complete if small)
                $logContent = $this->readLogFile($filePath);
                $logLines = array_filter(explode("\n", $logContent));
                $lineCount = count($logLines);
            }
        }

        View::render('settings/logs.twig', [
            'log_files' => $logFiles,
            'selected_file' => $selectedFile,
            'log_content' => $logContent,
            'log_lines' => $logLines,
            'line_count' => $lineCount,
            'file_size' => $fileSize,
            'section' => 'logs'
        ]);
    }

    /**
     * Get list of available log files
     */
    private function getLogFiles(): array {
        $files = [];

        if (!is_dir(self::LOGS_DIR)) {
            return $files;
        }

        $dirContents = @scandir(self::LOGS_DIR, SCANDIR_SORT_DESCENDING);
        
        if ($dirContents === false) {
            return $files;
        }

        foreach ($dirContents as $filename) {
            // Skip . and ..
            if ($filename === '.' || $filename === '..') {
                continue;
            }

            $filePath = self::LOGS_DIR . '/' . $filename;

            // Only regular files
            if (!is_file($filePath)) {
                continue;
            }

            // Check extension
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            if (!in_array($ext, self::ALLOWED_EXTENSIONS, true)) {
                continue;
            }

            $size = filesize($filePath);
            $modified = filemtime($filePath);

            $files[] = [
                'name' => $filename,
                'path' => $filename,
                'size' => $size,
                'size_formatted' => $this->formatBytes($size),
                'modified' => $modified,
                'modified_formatted' => date('Y-m-d H:i:s', $modified),
                'readable' => is_readable($filePath)
            ];
        }

        return $files;
    }

    /**
     * Read log file content (last N lines)
     */
    private function readLogFile(string $filePath, int $maxLines = 1000): string {
        if (!is_readable($filePath)) {
            return '';
        }

        $fileSize = filesize($filePath);

        // If file is small enough, read completely
        if ($fileSize <= self::MAX_FILE_SIZE) {
            return file_get_contents($filePath) ?: '';
        }

        // For large files, read last N lines
        $handle = fopen($filePath, 'r');
        if ($handle === false) {
            return '';
        }

        // Seek to end and read backwards
        fseek($handle, 0, SEEK_END);
        $lines = [];
        $lineCount = 0;

        while ($lineCount < $maxLines && ftell($handle) > 0) {
            $chunk = '';
            $pos = ftell($handle);

            // Read backwards in chunks
            $chunkSize = min(4096, $pos);
            fseek($handle, -$chunkSize, SEEK_CUR);
            $chunk = fread($handle, $chunkSize);
            fseek($handle, -$chunkSize, SEEK_CUR);

            $parts = explode("\n", $chunk);
            $lines = array_merge($parts, $lines);
            $lineCount = count($lines);

            if ($pos <= $chunkSize) {
                break;
            }
        }

        fclose($handle);

        // Take last N lines and rejoin
        $lines = array_slice($lines, -$maxLines);
        return implode("\n", $lines);
    }

    /**
     * Download log file
     * GET /admin/logs/download?file=filename
     */
    public function download() {
        requireAdmin();

        $file = $_GET['file'] ?? null;

        if (!$file || !$this->isValidLogFile($file)) {
            http_response_code(400);
            echo 'Invalid file';
            return;
        }

        $filePath = self::LOGS_DIR . '/' . basename($file);

        if (!file_exists($filePath) || !is_readable($filePath)) {
            http_response_code(404);
            echo 'File not found';
            return;
        }

        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($filePath));

        readfile($filePath);
        exit;
    }

    /**
     * Delete log file
     * POST /admin/logs/delete
     */
    public function delete() {
        requireAdmin();

        header('Content-Type: application/json');

        $file = $_POST['file'] ?? null;

        if (!$file || !$this->isValidLogFile($file)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid file']);
            return;
        }

        $filePath = self::LOGS_DIR . '/' . basename($file);

        if (!file_exists($filePath)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'File not found']);
            return;
        }

        if (@unlink($filePath)) {
            echo json_encode([
                'success' => true,
                'message' => 'Log file deleted successfully',
                'redirect' => '/admin/logs'
            ]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to delete file']);
        }
    }

    /**
     * Clear all log files
     * POST /admin/logs/clear-all
     */
    public function clearAll() {
        requireAdmin();

        header('Content-Type: application/json');

        $logFiles = $this->getLogFiles();
        $deleted = 0;
        $failed = 0;

        foreach ($logFiles as $file) {
            $filePath = self::LOGS_DIR . '/' . $file['path'];
            if (@unlink($filePath)) {
                $deleted++;
            } else {
                $failed++;
            }
        }

        echo json_encode([
            'success' => true,
            'deleted' => $deleted,
            'failed' => $failed,
            'message' => "Deleted $deleted log files" . ($failed > 0 ? ", failed to delete $failed" : ''),
            'redirect' => '/admin/logs'
        ]);
    }

    /**
     * Search logs
     * POST /admin/logs/search
     */
    public function search() {
        requireAdmin();

        header('Content-Type: application/json');

        $query = $_POST['query'] ?? '';
        $file = $_POST['file'] ?? null;
        $caseSensitive = isset($_POST['case_sensitive']) && $_POST['case_sensitive'] === 'on';

        if (empty($query) || strlen($query) < 2) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Search query too short']);
            return;
        }

        if (!$file || !$this->isValidLogFile($file)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid file']);
            return;
        }

        $filePath = self::LOGS_DIR . '/' . basename($file);

        if (!file_exists($filePath) || !is_readable($filePath)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'File not found']);
            return;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to read file']);
            return;
        }

        $lines = explode("\n", $content);
        $results = [];
        $flags = $caseSensitive ? 0 : PREG_GREP_INVERT;

        foreach ($lines as $lineNum => $line) {
            if (empty($line)) {
                continue;
            }

            // Case-sensitive or case-insensitive search
            $matches = $caseSensitive 
                ? (strpos($line, $query) !== false)
                : (stripos($line, $query) !== false);

            if ($matches) {
                $results[] = [
                    'line' => $lineNum + 1,
                    'content' => $line
                ];
            }
        }

        echo json_encode([
            'success' => true,
            'query' => $query,
            'results_count' => count($results),
            'results' => array_slice($results, 0, 100) // Limit to 100 results
        ]);
    }

    /**
     * Get log statistics
     * POST /admin/logs/stats
     */
    public function stats() {
        requireAdmin();

        header('Content-Type: application/json');

        $file = $_POST['file'] ?? null;

        if (!$file || !$this->isValidLogFile($file)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid file']);
            return;
        }

        $filePath = self::LOGS_DIR . '/' . basename($file);

        if (!file_exists($filePath) || !is_readable($filePath)) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'File not found']);
            return;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to read file']);
            return;
        }

        $lines = array_filter(explode("\n", $content));
        $errorCount = count(preg_grep('/error|exception|fatal|fail/i', $lines));
        $warningCount = count(preg_grep('/warning|warn/i', $lines));
        $successCount = count(preg_grep('/success|completed|ok/i', $lines));

        echo json_encode([
            'success' => true,
            'total_lines' => count($lines),
            'errors' => $errorCount,
            'warnings' => $warningCount,
            'success' => $successCount,
            'file_size' => filesize($filePath),
            'file_size_formatted' => $this->formatBytes(filesize($filePath)),
            'last_modified' => date('Y-m-d H:i:s', filemtime($filePath))
        ]);
    }

    /**
     * Validate log file name
     */
    private function isValidLogFile(string $filename): bool {
        // Prevent directory traversal
        if (strpos($filename, '/') !== false || strpos($filename, '\\') !== false) {
            return false;
        }

        if (strpos($filename, '..') !== false) {
            return false;
        }

        // Check extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!in_array($ext, self::ALLOWED_EXTENSIONS, true)) {
            return false;
        }

        return true;
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes(int $bytes, int $precision = 2): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
}
