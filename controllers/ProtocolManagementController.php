<?php

class ProtocolManagementController
{

    /**
     * Display protocols list and management interface
     */
    public function index(): void
    {
        requireAdmin();

        try {
            $protocols = $this->getAllProtocols();
            $selectedId = isset($_GET['id']) ? (int) $_GET['id'] : null;
            $isNew = isset($_GET['new']);
            $isTemplate = isset($_GET['template']);

            $editing = null;
            if (!$isNew && $selectedId) {
                $editing = $this->getProtocolById($selectedId);
            }

            $pdo = DB::conn();
            $stmt = $pdo->prepare("SELECT api_key FROM api_keys WHERE service_name = 'openrouter' AND is_active = 1 LIMIT 1");
            $stmt->execute();
            $openrouterKey = $stmt->fetchColumn() ?: '';

            if ($isTemplate && $editing) {
                View::render('settings/protocol_template_editor.twig', [
                    'protocol' => $editing,
                    'success' => $_SESSION['protocol_success'] ?? null,
                    'error' => $_SESSION['protocol_error'] ?? null,
                    'openrouter_key' => $openrouterKey,
                ]);
            } elseif ($editing || $isNew) {
                View::render('settings/protocol_form.twig', [
                    'editing' => $editing,
                    'success' => $_SESSION['protocol_success'] ?? null,
                    'error' => $_SESSION['protocol_error'] ?? null,
                    'openrouter_key' => $openrouterKey,
                ]);
            } else {
                View::render('settings/protocols_management.twig', [
                    'protocols' => $protocols,
                    'success' => $_SESSION['protocol_success'] ?? null,
                    'error' => $_SESSION['protocol_error'] ?? null,
                    'openrouter_key' => $openrouterKey,
                ]);
            }

            unset($_SESSION['protocol_success'], $_SESSION['protocol_error']);

        } catch (Exception $e) {
            error_log("Error in ProtocolManagementController::index: " . $e->getMessage());
            $_SESSION['protocol_error'] = 'Failed to load protocols: ' . $e->getMessage();
            redirect('/settings/protocols-management');
        }
    }

    /**
     * Create or update protocol
     */
    public function save(): void
    {
        requireAdmin();

        try {
            $id = isset($_POST['id']) && $_POST['id'] !== '' ? (int) $_POST['id'] : null;
            $name = trim($_POST['name'] ?? '');
            $slug = trim($_POST['slug'] ?? '');
            $description = trim($_POST['description'] ?? '');
            $installScript = trim($_POST['install_script'] ?? '');
            $passwordCommand = trim($_POST['password_command'] ?? '');
            $uninstallScript = trim($_POST['uninstall_script'] ?? '');
            $outputTemplate = trim($_POST['output_template'] ?? '');
            $qrCodeTemplate = trim($_POST['qr_code_template'] ?? '');
            $qrCodeFormat = trim($_POST['qr_code_format'] ?? 'amnezia_compressed');
            $ubuntuCompatible = isset($_POST['ubuntu_compatible']) ? 1 : 0;
            $showTextContent = isset($_POST['show_text_content']) ? 1 : 0;
            $isActive = isset($_POST['is_active']) ? 1 : 0;

            // Validation
            if ($name === '' || $slug === '') {
                throw new Exception('Name and slug are required');
            }

            if (!preg_match('/^[a-z0-9_-]+$/i', $slug)) {
                throw new Exception('Slug may contain only letters, numbers, dashes, and underscores');
            }

            // Check if slug is unique (for new protocols or when updating slug)
            if ($this->isSlugExists($slug, $id)) {
                throw new Exception('Protocol with this slug already exists');
            }

            $protocolData = [
                'name' => $name,
                'slug' => $slug,
                'description' => $description,
                'install_script' => $installScript,
                'output_template' => $outputTemplate,
                'qr_code_template' => $qrCodeTemplate,
                'qr_code_format' => $qrCodeFormat,
                'password_command' => $passwordCommand,
                'uninstall_script' => $uninstallScript,
                'ubuntu_compatible' => $ubuntuCompatible,
                'show_text_content' => $showTextContent,
                'is_active' => $isActive,
                'updated_at' => date('Y-m-d H:i:s')
            ];

            if ($id) {
                // Update existing protocol
                $this->updateProtocol($id, $protocolData);
                $savedId = $id;
                $_SESSION['protocol_success'] = 'Protocol updated successfully';
            } else {
                // Create new protocol
                $protocolData['created_at'] = date('Y-m-d H:i:s');
                $savedId = $this->createProtocol($protocolData);
                $_SESSION['protocol_success'] = 'Protocol created successfully';
            }

            redirect('/settings/protocols-management?id=' . $savedId);

        } catch (Exception $e) {
            $_SESSION['protocol_error'] = $e->getMessage();
            $id = isset($_POST['id']) ? (int) $_POST['id'] : null;
            redirect('/settings/protocols-management' . ($id ? '?id=' . $id : '?new=1'));
        }
    }

    /**
     * Delete protocol
     */
    public function delete(int $id): void
    {
        requireAdmin();

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            // Check if protocol is used by any servers
            if ($this->isProtocolUsed($id)) {
                throw new Exception('Cannot delete protocol that is currently used by servers');
            }

            $this->deleteProtocol($id);
            $_SESSION['protocol_success'] = 'Protocol deleted successfully';

        } catch (Exception $e) {
            $_SESSION['protocol_error'] = $e->getMessage();
        }

        redirect('/settings/protocols-management');
    }

    /**
     * API endpoint: Get all protocols (JSON)
     */
    public function apiGetProtocols(): void
    {
        requireAdmin();

        try {
            $protocols = $this->getAllProtocols();

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $protocols
            ]);

        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * API endpoint: Get single protocol (JSON)
     */
    public function apiGetProtocol(int $id): void
    {
        requireAdmin();

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $protocol
            ]);

        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * API endpoint: Create protocol (JSON)
     */
    public function apiCreateProtocol(): void
    {
        requireAdmin();

        try {
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }

            // Validate required fields
            $requiredFields = ['name', 'slug'];
            foreach ($requiredFields as $field) {
                if (empty($input[$field])) {
                    throw new Exception("Field '$field' is required");
                }
            }

            // Validate slug format
            if (!preg_match('/^[a-z0-9_-]+$/i', $input['slug'])) {
                throw new Exception('Slug may contain only letters, numbers, dashes, and underscores');
            }

            // Check if slug exists
            if ($this->isSlugExists($input['slug'])) {
                throw new Exception('Protocol with this slug already exists');
            }

            $protocolData = [
                'name' => trim($input['name']),
                'slug' => trim($input['slug']),
                'description' => trim($input['description'] ?? ''),
                'install_script' => trim($input['install_script'] ?? ''),
                'output_template' => trim($input['output_template'] ?? ''),
                'qr_code_template' => trim($input['qr_code_template'] ?? ''),
                'qr_code_format' => trim($input['qr_code_format'] ?? 'amnezia_compressed'),
                'ubuntu_compatible' => (bool) ($input['ubuntu_compatible'] ?? false),
                'show_text_content' => (bool) ($input['show_text_content'] ?? false),
                'is_active' => (bool) ($input['is_active'] ?? true),
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];

            $id = $this->createProtocol($protocolData);
            $protocol = $this->getProtocolById($id);

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $protocol,
                'message' => 'Protocol created successfully'
            ]);

        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * API endpoint: Update protocol (JSON)
     */
    public function apiUpdateProtocol(int $id): void
    {
        requireAdmin();

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }

            $protocolData = [];
            $allowedFields = ['name', 'slug', 'description', 'install_script', 'output_template', 'qr_code_template', 'qr_code_format', 'ubuntu_compatible', 'show_text_content', 'is_active'];

            foreach ($allowedFields as $field) {
                if (isset($input[$field])) {
                    if ($field === 'ubuntu_compatible' || $field === 'is_active') {
                        $protocolData[$field] = (bool) $input[$field];
                    } elseif ($field === 'slug') {
                        $slug = trim($input[$field]);
                        if (!preg_match('/^[a-z0-9_-]+$/i', $slug)) {
                            throw new Exception('Slug may contain only letters, numbers, dashes, and underscores');
                        }
                        if ($this->isSlugExists($slug, $id)) {
                            throw new Exception('Protocol with this slug already exists');
                        }
                        $protocolData[$field] = $slug;
                    } else {
                        $protocolData[$field] = trim($input[$field]);
                    }
                }
            }

            if (!empty($protocolData)) {
                $protocolData['updated_at'] = date('Y-m-d H:i:s');
                $this->updateProtocol($id, $protocolData);
                $protocol = $this->getProtocolById($id);
            }

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $protocol,
                'message' => 'Protocol updated successfully'
            ]);

        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * API endpoint: Delete protocol (JSON)
     */
    public function apiDeleteProtocol(int $id): void
    {
        requireAdmin();

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            if ($this->isProtocolUsed($id)) {
                throw new Exception('Cannot delete protocol that is currently used by servers');
            }

            $this->deleteProtocol($id);

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'message' => 'Protocol deleted successfully'
            ]);

        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    public function apiTestInstallProtocol(int $id): void
    {
        requireAdmin();

        // Suppress all errors and warnings to prevent HTML output before JSON
        @ini_set('display_errors', '0');
        error_reporting(0);

        // Clean any previous output
        if (ob_get_level())
            ob_end_clean();
        ob_start();

        header('Content-Type: application/json');

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            $script = trim($protocol['install_script'] ?? '');
            if ($script === '') {
                throw new Exception('Install script is empty');
            }

            $container = 'proto-test-' . $id;

            $this->runHostCommand('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
            $run = $this->runHostCommandChecked('docker run --privileged -d -v /var/run/docker.sock:/var/run/docker.sock --name ' . escapeshellarg($container) . ' ubuntu:22.04 sleep infinity');
            if ($run['rc'] !== 0) {
                throw new Exception('Docker not accessible: ' . trim($run['out']));
            }

            $cliPath = '/usr/local/bin/docker';
            $try1 = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '"');
            if ($try1['rc'] !== 0 || $try1['out'] === '') {
                $cliPath = '/usr/bin/docker';
                $try2 = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '"');
                if ($try2['rc'] !== 0 || $try2['out'] === '') {
                    throw new Exception('Failed to read docker CLI from docker:24-dind image');
                }
            }
            $cp = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '" | docker exec -i ' . escapeshellarg($container) . ' sh -lc "cat > /usr/local/bin/docker && chmod +x /usr/local/bin/docker"');
            if ($cp['rc'] !== 0) {
                throw new Exception('Failed to provide docker CLI to test container: ' . trim($cp['out']));
            }
            $this->execInContainerChecked($container, 'chmod +x /usr/local/bin/docker');
            $ver = $this->execInContainerChecked($container, 'docker --version');
            if ($ver['rc'] !== 0) {
                throw new Exception('Docker CLI not available in test container');
            }

            $prelude = <<<'SH'
set -euo pipefail
set -x
CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
wg() {
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker exec -i "$CONTAINER_NAME" wg "$@"
  else
    docker pull -q amneziavpn/amnezia-wg:latest >/dev/null 2>&1 || true
    docker run --rm -i --privileged --cap-add=NET_ADMIN amneziavpn/amnezia-wg:latest wg "$@"
  fi
}
SH;
            $wrapped = $prelude . "\n" . $script;
            $runScript = $this->execInContainerChecked($container, $wrapped);
            if ($runScript['rc'] !== 0) {
                throw new Exception("Install script failed: " . trim($runScript['out']));
            }
            $output = $runScript['out'];

            $extracted = $this->extractValuesFromOutput($output);

            $variables = $this->getProtocolVariables($id);
            foreach ($extracted as $k => $v) {
                if (array_key_exists($k, $variables)) {
                    $variables[$k] = $v;
                }
            }

            $preview = ProtocolService::generateProtocolOutput($protocol, $variables);

            // Cleanup test containers: proto-test and AWG if created
            $this->runHostCommand('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
            $this->runHostCommand('docker rm -f amnezia-awg >/dev/null 2>&1 || true');

            // Clean buffer and output JSON
            if (ob_get_level())
                ob_end_clean();
            echo json_encode([
                'success' => true,
                'logs' => $output,
                'extracted' => $extracted,
                'preview' => $preview
            ]);

        } catch (Exception $e) {
            // Clean buffer and output error JSON
            if (ob_get_level())
                ob_end_clean();
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    public function apiTestInstallProtocolStream(int $id): void
    {
        requireAdmin();

        // Suppress all errors and warnings to prevent HTML output
        @ini_set('display_errors', '0');
        error_reporting(0);

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        @ini_set('output_buffering', 'off');
        @ini_set('zlib.output_compression', '0');
        @ob_implicit_flush(true);
        // CRITICAL: Use ob_end_clean() instead of ob_end_flush() to DISCARD any
        // buffered warnings/errors that would corrupt the SSE stream
        while (ob_get_level()) {
            @ob_end_clean();
        }

        $send = function (array $data) {
            echo 'data: ' . json_encode($data) . "\n\n";
            @flush();
        };

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                $send(['type' => 'error', 'error' => 'Protocol not found']);
                return;
            }

            $script = trim($protocol['install_script'] ?? '');
            if ($script === '') {
                $send(['type' => 'error', 'error' => 'Install script is empty']);
                return;
            }

            $container = 'proto-test-' . $id;
            $send(['type' => 'start']);

            $send(['type' => 'cmd', 'cmd' => 'docker rm -f ' . $container]);
            $rm = $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
            $send(['type' => 'cmd_done', 'rc' => $rm['rc']]);

            $cmdRun = 'docker run --privileged -d --name ' . $container . ' ubuntu:22.04 sleep infinity';
            $send(['type' => 'cmd', 'cmd' => $cmdRun]);
            $run = $this->runHostCommandChecked('docker run --privileged -d -v /var/run/docker.sock:/var/run/docker.sock --name ' . escapeshellarg($container) . ' ubuntu:22.04 sleep infinity');
            if ($run['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Docker not accessible: ' . trim($run['out'])]);
                return;
            }
            $send(['type' => 'cmd_done', 'rc' => 0]);

            $send(['type' => 'cmd', 'cmd' => 'provide docker cli']);
            $cliPath = '/usr/local/bin/docker';
            $send(['type' => 'cmd', 'cmd' => 'provide docker cli from docker:24-dind image']);
            $try1 = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '"');
            if ($try1['rc'] !== 0 || $try1['out'] === '') {
                $cliPath = '/usr/bin/docker';
            }
            $cp = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '" | docker exec -i ' . escapeshellarg($container) . ' sh -lc "cat > /usr/local/bin/docker && chmod +x /usr/local/bin/docker"');
            if ($cp['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Failed to provide docker CLI to test container: ' . trim($cp['out'])]);
                return;
            }
            $this->execInContainerChecked($container, 'chmod +x /usr/local/bin/docker');
            $ver = $this->execInContainerChecked($container, 'docker --version');
            $send(['type' => 'out', 'line' => $ver['out']]);
            if ($ver['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Docker CLI not available in test container']);
                return;
            }

            $prelude = <<<'SH'
set -euo pipefail
set -x
CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
wg() {
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker exec -i "$CONTAINER_NAME" wg "$@"
  else
    docker pull -q amneziavpn/amnezia-wg:latest >/dev/null 2>&1 || true
    docker run --rm -i --privileged --cap-add=NET_ADMIN amneziavpn/amnezia-wg:latest wg "$@"
  fi
}
SH;
            $wrapped = $prelude . "\n" . $script;
            $send(['type' => 'cmd', 'cmd' => 'install_script']);
            $runScript = $this->execInContainerChecked($container, $wrapped);
            $outLines = explode("\n", trim($runScript['out']));
            foreach ($outLines as $line) {
                if ($line !== '')
                    $send(['type' => 'out', 'line' => $line]);
            }
            if ($runScript['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Install script failed: ' . trim($runScript['out'])]);
                $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
                return;
            }
            $send(['type' => 'cmd_done', 'rc' => 0]);

            $extracted = $this->extractValuesFromOutput($runScript['out']);
            $variables = $this->getProtocolVariables($id);
            // Merge all extracted variables (not just existing ones)
            $variables = array_merge($variables, $extracted);
            $preview = ProtocolService::generateProtocolOutput($protocol, $variables);
            $send(['type' => 'preview', 'preview' => $preview]);

            $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
            $this->runHostCommandChecked('docker rm -f amnezia-awg >/dev/null 2>&1 || true');
            $send(['type' => 'done']);

        } catch (Exception $e) {
            echo 'data: ' . json_encode(['type' => 'error', 'error' => $e->getMessage()]) . "\n\n";
            @flush();
        }
    }

    public function apiTestUninstallProtocolStream(int $id): void
    {
        requireAdmin();
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        @ini_set('output_buffering', 'off');
        @ini_set('zlib.output_compression', '0');
        @ob_implicit_flush(true);
        @ob_end_flush();

        $send = function (array $data) {
            echo 'data: ' . json_encode($data) . "\n\n";
            @flush();
        };

        try {
            $protocol = $this->getProtocolById($id);
            if (!$protocol) {
                $send(['type' => 'error', 'error' => 'Protocol not found']);
                return;
            }

            $installScript = trim($protocol['install_script'] ?? '');
            $uninstallScript = trim($protocol['uninstall_script'] ?? '');

            if ($installScript === '') {
                $send(['type' => 'error', 'error' => 'Install script is empty (required for setup)']);
                return;
            }
            if ($uninstallScript === '') {
                $send(['type' => 'error', 'error' => 'Uninstall script is empty']);
                return;
            }

            // Normalize uninstall script if needed? For now assume it's fine.

            $container = 'proto-test-uninstall-' . $id;
            $send(['type' => 'start']);

            // 1. Setup container
            $send(['type' => 'cmd', 'cmd' => 'Setting up test environment...']);
            $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');

            $run = $this->runHostCommandChecked('docker run --privileged -d -v /var/run/docker.sock:/var/run/docker.sock --name ' . escapeshellarg($container) . ' ubuntu:22.04 sleep infinity');
            if ($run['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Docker not accessible: ' . trim($run['out'])]);
                return;
            }

            // Provide docker CLI
            $cliPath = '/usr/local/bin/docker';
            $try1 = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '"');
            if ($try1['rc'] !== 0 || $try1['out'] === '') {
                $cliPath = '/usr/bin/docker';
            }
            $cp = $this->runHostCommandChecked('docker run --rm docker:24-dind sh -lc "cat ' . $cliPath . '" | docker exec -i ' . escapeshellarg($container) . ' sh -lc "cat > /usr/local/bin/docker && chmod +x /usr/local/bin/docker"');
            if ($cp['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Failed to provide docker CLI']);
                return;
            }
            $this->execInContainerChecked($container, 'chmod +x /usr/local/bin/docker');

            $prelude = <<<'SH'
set -euo pipefail
set -x
CONTAINER_NAME="${CONTAINER_NAME:-amnezia-awg}"
wg() {
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker exec -i "$CONTAINER_NAME" wg "$@"
  else
    docker pull -q amneziavpn/amnezia-wg:latest >/dev/null 2>&1 || true
    docker run --rm -i --privileged --cap-add=NET_ADMIN amneziavpn/amnezia-wg:latest wg "$@"
  fi
}
SH;

            // 2. Run Install Script
            $send(['type' => 'cmd', 'cmd' => 'Running installation script...']);
            $wrappedInstall = $prelude . "\n" . $installScript;
            $runInstall = $this->execInContainerChecked($container, $wrappedInstall);

            if ($runInstall['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Setup (install) failed: ' . trim($runInstall['out'])]);
                $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
                return;
            }
            $send(['type' => 'out', 'line' => 'Installation successful. Now running uninstall...']);

            // 3. Run Uninstall Script
            $send(['type' => 'cmd', 'cmd' => 'Running uninstallation script...']);
            $wrappedUninstall = $prelude . "\n" . $uninstallScript;
            $runUninstall = $this->execInContainerChecked($container, $wrappedUninstall);

            $outLines = explode("\n", trim($runUninstall['out']));
            foreach ($outLines as $line) {
                if ($line !== '')
                    $send(['type' => 'out', 'line' => $line]);
            }

            if ($runUninstall['rc'] !== 0) {
                $send(['type' => 'error', 'error' => 'Uninstall script failed: ' . trim($runUninstall['out'])]);
            } else {
                $send(['type' => 'cmd_done', 'rc' => 0]);
                $send(['type' => 'out', 'line' => 'Uninstallation completed successfully.']);
            }

            // Cleanup
            $this->runHostCommandChecked('docker rm -f ' . escapeshellarg($container) . ' >/dev/null 2>&1 || true');
            $this->runHostCommandChecked('docker rm -f amnezia-awg >/dev/null 2>&1 || true'); // Cleanup potential leftover
            $send(['type' => 'done']);

        } catch (Exception $e) {
            echo 'data: ' . json_encode(['type' => 'error', 'error' => $e->getMessage()]) . "\n\n";
            @flush();
        }
    }

    private function runHostCommand(string $cmd): void
    {
        $out = shell_exec($cmd);
    }

    private function runHostCommandChecked(string $cmd): array
    {
        $lines = [];
        $rc = 0;
        exec($cmd . ' 2>&1', $lines, $rc);
        return ['out' => implode("\n", $lines), 'rc' => $rc];
    }

    private function execInContainer(string $container, string $cmd): string
    {
        $full = 'docker exec ' . escapeshellarg($container) . ' bash -lc ' . escapeshellarg($cmd);
        $out = shell_exec($full . ' 2>&1');
        return $out ?? '';
    }

    private function execInContainerChecked(string $container, string $cmd): array
    {
        $lines = [];
        $rc = 0;
        $full = 'docker exec ' . escapeshellarg($container) . ' bash -lc ' . escapeshellarg($cmd);
        exec($full . ' 2>&1', $lines, $rc);
        return ['out' => implode("\n", $lines), 'rc' => $rc];
    }

    private function normalizeAwgInstallScript(string $script): string
    {
        // Script in DB already has #!/bin/bash and set -euo pipefail
        // Just return it as-is since variables are already defined in the script
        return $script;
    }

    private function extractValuesFromOutput(string $output): array
    {
        $res = [];

        // Extract port
        if (preg_match('/Port:\s*(\d+)/i', $output, $m)) {
            $res['server_port'] = $m[1];
        }

        // Extract server public key
        if (preg_match('/Server Public Key:\s*([A-Za-z0-9+\/=]+)/i', $output, $m)) {
            $res['server_public_key'] = $m[1];
        }

        // Extract preshared key
        if (preg_match('/PresharedKey\s*=\s*([A-Za-z0-9+\/=]+)/i', $output, $m)) {
            $res['preshared_key'] = $m[1];
        }

        // Extract subnet (format: "Subnet: 10.8.1.1/24")
        if (preg_match('/Subnet:\s*([0-9.]+)\/(\d+)/i', $output, $m)) {
            $res['subnet_ip'] = $m[1];
            $res['subnet_cidr'] = $m[2];
        }

        // Extract password (for non-WireGuard protocols)
        if (preg_match('/Password:\s*(\S+)/i', $output, $m)) {
            $res['password'] = $m[1];
        }

        // Extract method (for protocols like Shadowsocks)
        if (preg_match('/Method:\s*(\S+)/i', $output, $m)) {
            $res['method'] = $m[1];
        }

        // Extract client ID (for protocols that use it)
        if (preg_match('/ClientID\s*:\s*([0-9a-fA-F-]+)/i', $output, $m)) {
            $res['client_id'] = $m[1];
        }

        // Generic variable extraction (Variable: KEY=VALUE)
        if (preg_match_all('/Variable:\\s*([a-zA-Z0-9_]+)=(.*)/', $output, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $key = trim($m[1]);
                $val = trim($m[2]);
                // Remove surrounding quotes if present
                $val = trim($val, "'\"");
                $res[$key] = $val;
            }
        }

        return $res;
    }

    private function getProtocolVariables(int $protocolId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT variable_name, COALESCE(default_value, "") as val FROM protocol_variables WHERE protocol_id = ?');
        $stmt->execute([$protocolId]);
        $vars = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $vars[$row['variable_name']] = $row['val'] ?? '';
        }
        return $vars;
    }
    /**
     * Database methods
     */

    private function getAllProtocols(): array
    {
        return ProtocolService::getAllProtocolsWithStats();
    }

    private function getProtocolById(int $id): ?array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT p.*, 
                   COUNT(DISTINCT sp.server_id) as server_count
            FROM protocols p
            LEFT JOIN server_protocols sp ON p.id = sp.protocol_id
            WHERE p.id = ?
            GROUP BY p.id
        ');
        $stmt->execute([$id]);
        $protocol = $stmt->fetch(PDO::FETCH_ASSOC);

        return $protocol ?: null;
    }

    private function createProtocol(array $data): int
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            INSERT INTO protocols (name, slug, description, install_script, uninstall_script, password_command, output_template, ubuntu_compatible, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $data['name'],
            $data['slug'],
            $data['description'],
            $data['install_script'],
            $data['uninstall_script'],
            $data['password_command'] ?? '',
            $data['output_template'],
            $data['ubuntu_compatible'],
            $data['is_active'],
            $data['created_at'],
            $data['updated_at']
        ]);

        return (int) $pdo->lastInsertId();
    }

    private function updateProtocol(int $id, array $data): void
    {
        $setParts = [];
        $values = [];

        foreach ($data as $key => $value) {
            $setParts[] = "$key = ?";
            $values[] = $value;
        }

        $values[] = $id;
        $sql = 'UPDATE protocols SET ' . implode(', ', $setParts) . ' WHERE id = ?';

        $pdo = DB::conn();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($values);
    }

    private function deleteProtocol(int $id): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM protocols WHERE id = ?');
        $stmt->execute([$id]);
    }

    private function isSlugExists(string $slug, ?int $excludeId = null): bool
    {
        $pdo = DB::conn();

        if ($excludeId) {
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM protocols WHERE slug = ? AND id != ?');
            $stmt->execute([$slug, $excludeId]);
        } else {
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM protocols WHERE slug = ?');
            $stmt->execute([$slug]);
        }

        return (bool) $stmt->fetchColumn();
    }

    private function isProtocolUsed(int $id): bool
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM server_protocols WHERE protocol_id = ?');
        $stmt->execute([$id]);

        return (bool) $stmt->fetchColumn();
    }
}