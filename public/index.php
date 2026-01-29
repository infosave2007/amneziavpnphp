<?php
/**
 * Amnezia VPN Web Panel
 * Main entry point
 */

// Suppress errors for API endpoints to prevent HTML output
if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/api/') !== false) {
    @ini_set('display_errors', '0');
    error_reporting(0);
}

session_name(getenv('SESSION_NAME') ?: 'amnezia_panel_session');
session_start();

// Load dependencies
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/Auth.php';
require_once __DIR__ . '/../inc/Router.php';
require_once __DIR__ . '/../inc/View.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/Translator.php';
require_once __DIR__ . '/../inc/JWT.php';
require_once __DIR__ . '/../inc/PanelImporter.php';
require_once __DIR__ . '/../inc/ServerMonitoring.php';
require_once __DIR__ . '/../inc/BackupLibrary.php';
require_once __DIR__ . '/../inc/InstallProtocolManager.php';
require_once __DIR__ . '/../inc/ProtocolService.php';
require_once __DIR__ . '/../inc/OpenRouterService.php';

// Load environment configuration
Config::load(__DIR__ . '/../.env');

// Test database connection
try {
    DB::conn();
} catch (Throwable $e) {
    die('Database connection error: ' . $e->getMessage());
}

// Seed admin user if not exists
try {
    $adminEmail = Config::get('ADMIN_EMAIL');
    $adminPass = Config::get('ADMIN_PASSWORD');
    if ($adminEmail && $adminPass) {
        Auth::seedAdmin($adminEmail, $adminPass);
    }
} catch (Throwable $e) {
    // Ignore errors
}

// Initialize translator
Translator::init();
InstallProtocolManager::ensureDefaults();

// Initialize template engine
$user = Auth::user();
$appName = Config::get('APP_NAME', 'Amnezia VPN Panel');

/**
 * Helper function to authenticate user from JWT or session
 * Returns user array or null if unauthorized
 */
function authenticateRequest(): ?array
{
    // Check JWT token in Authorization header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $token = $matches[1];
        $user = JWT::verify($token);
        if ($user) {
            return $user;
        }
    }

    // Fallback to session
    if (isset($_SESSION['user_id'])) {
        return Auth::user();
    }

    return null;
}

View::init(__DIR__ . '/../templates', [
    'app_name' => $appName,
    'user' => $user,
    'current_language' => Translator::getCurrentLanguage(),
    'languages' => Translator::getSupportedLanguages(),
    'current_uri' => $_SERVER['REQUEST_URI'] ?? '/dashboard',
    't' => function ($key, $params = []) {
        return Translator::t($key, $params);
    }
]);

// Helper function for redirects
function redirect(string $to): void
{
    header('Location: ' . $to);
    exit;
}

// Helper function to require authentication
function requireAuth(): void
{
    if (!Auth::check()) {
        redirect('/login');
    }
}

// Helper function to require admin
function requireAdmin(): void
{
    requireAuth();
    if (!Auth::isAdmin()) {
        http_response_code(403);
        echo 'Forbidden: Admin access required';
        exit;
    }
}

function debugRoutesEnabled(): bool
{
    $val = strtolower((string) (getenv('ENABLE_DEBUG_ROUTES') ?: ''));
    return in_array($val, ['1', 'true', 'yes', 'on'], true);
}

function requireDebugEnabledOrAdmin(): void
{
    requireAuth();

    if (Auth::isAdmin()) {
        return;
    }

    if (!debugRoutesEnabled()) {
        http_response_code(404);
        echo 'Not Found';
        exit;
    }
}

// Helper function to get authenticated user (JWT or session)
function getAuthUser(): ?array
{
    // Try JWT first
    $token = JWT::getTokenFromHeader();
    if ($token !== null) {
        $user = JWT::verify($token);
        if ($user !== null) {
            return $user;
        }
    }

    // Fall back to session
    if (Auth::check()) {
        return Auth::user();
    }

    return null;
}

// Helper function to require authentication (JWT or session) for API
function requireApiAuth(): ?array
{
    $user = getAuthUser();

    if ($user === null) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        return null;
    }

    return $user;
}

/**
 * PUBLIC ROUTES
 */

// Home page
Router::get('/', function () {
    if (!Auth::check()) {
        redirect('/login');
    }
    redirect('/dashboard');
});

// Login page
Router::get('/login', function () {
    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('login.twig');
});

Router::post('/login', function () {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (Auth::login($email, $password)) {
        redirect('/dashboard');
    }

    View::render('login.twig', ['error' => 'Invalid credentials']);
});

// Register page
Router::get('/register', function () {
    if (Auth::check()) {
        redirect('/dashboard');
    }
    View::render('register.twig');
});

Router::post('/register', function () {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        View::render('register.twig', ['error' => 'Invalid email address']);
        return;
    }

    if (strlen($password) < 6) {
        View::render('register.twig', ['error' => 'Password must be at least 6 characters']);
        return;
    }

    try {
        $success = Auth::register($name, $email, $password);
        if ($success) {
            Auth::login($email, $password);
            redirect('/dashboard');
        }
    } catch (Throwable $e) {
        // Email already exists or other error
    }

    View::render('register.twig', ['error' => 'Registration failed. Email may already be in use.']);
});

// Logout
Router::get('/logout', function () {
    Auth::logout();
    redirect('/login');
});

/**
 * AUTHENTICATED ROUTES
 */

// Dashboard
Router::get('/dashboard', function () {
    requireAuth();
    $user = Auth::user();

    // Get user's servers
    $servers = VpnServer::listByUser($user['id']);

    // Get user's clients
    $clients = VpnClient::listByUser($user['id']);

    View::render('dashboard.twig', [
        'servers' => $servers,
        'clients' => $clients,
    ]);
});

Router::get('/tools/qr-decode', function () {
    requireAuth();
    View::render('tools/qr_decode.twig');
});

// Servers list
Router::get('/servers', function () {
    requireAuth();
    $user = Auth::user();

    $servers = Auth::isAdmin()
        ? VpnServer::listAll()
        : VpnServer::listByUser($user['id']);

    View::render('servers/index.twig', ['servers' => $servers]);
});

// Create server page
Router::get('/servers/create', function () {
    requireAuth();
    $protocols = InstallProtocolManager::listActive();
    $defaultProtocol = !empty($protocols) ? ($protocols[0]['slug'] ?? InstallProtocolManager::getDefaultSlug()) : InstallProtocolManager::getDefaultSlug();
    View::render('servers/create.twig', [
        'selected_mode' => 'manual',
        'form_data' => [],
        'protocols' => $protocols,
        'default_protocol' => $defaultProtocol
    ]);
});

// Create server action
Router::post('/servers/create', function () {
    requireAuth();
    $user = Auth::user();
    $creationMode = $_POST['creation_mode'] ?? 'manual';
    $formData = $_POST;
    $formData['backup_upload_type'] = $_POST['backup_upload_type'] ?? 'auto';
    $formData['backup_server_index'] = $_POST['backup_server_index'] ?? '';
    $protocols = InstallProtocolManager::listActive();
    $defaultProtocol = InstallProtocolManager::getDefaultSlug();
    $formData['install_protocol'] = $_POST['install_protocol'] ?? $defaultProtocol;

    if ($creationMode === 'backup') {
        $token = $_POST['backup_token'] ?? '';
        $serverIndexRaw = $_POST['backup_server_index'] ?? '';
        $serverIndex = $serverIndexRaw === '' ? -1 : (int) $serverIndexRaw;
        $uploadType = $_POST['backup_upload_type'] ?? 'auto';
        $serversMeta = [];

        if (isset($_FILES['backup_upload']) && $_FILES['backup_upload']['error'] === UPLOAD_ERR_OK) {
            $originalName = $_FILES['backup_upload']['name'] ?? 'uploaded-backup.json';
            $tmpPath = $_FILES['backup_upload']['tmp_name'];
            $storagePath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'amnezia_backup_' . bin2hex(random_bytes(16));

            if (!move_uploaded_file($tmpPath, $storagePath)) {
                View::render('servers/create.twig', [
                    'error' => 'Failed to store uploaded backup file',
                    'selected_mode' => 'backup',
                    'form_data' => $formData,
                    'protocols' => $protocols,
                    'default_protocol' => $defaultProtocol
                ]);
                return;
            }

            try {
                $parsed = BackupParser::parse($storagePath);
                if ($uploadType !== 'auto' && $parsed['type'] !== $uploadType) {
                    throw new Exception('Uploaded backup type does not match selection');
                }
            } catch (Exception $e) {
                @unlink($storagePath);
                View::render('servers/create.twig', [
                    'error' => $e->getMessage(),
                    'selected_mode' => 'backup',
                    'form_data' => $formData,
                    'protocols' => $protocols,
                    'default_protocol' => $defaultProtocol
                ]);
                return;
            }

            if ($token && BackupLibrary::isUploadToken($token)) {
                BackupLibrary::forgetUpload($token);
            }

            $uploadRecord = BackupLibrary::registerUploaded($originalName, $storagePath, $parsed);
            $token = $uploadRecord['token'];
            $formData['backup_token'] = $token;
            $serversMeta = $uploadRecord['servers'] ?? [];
        } else {
            $serversMeta = $token ? BackupLibrary::getUploadServers($token) : [];
        }

        try {
            if ($token === '') {
                throw new Exception('Upload a backup file before importing');
            }

            if ($serverIndex < 0) {
                if (!empty($serversMeta)) {
                    if (count($serversMeta) === 1) {
                        $serverIndex = (int) $serversMeta[0]['index'];
                        $formData['backup_server_index'] = (string) $serverIndex;
                    } else {
                        $formData['uploaded_servers'] = $serversMeta;
                        View::render('servers/create.twig', [
                            'error' => 'Select a server entry from the uploaded backup',
                            'selected_mode' => 'backup',
                            'form_data' => $formData,
                            'protocols' => $protocols,
                            'default_protocol' => $defaultProtocol
                        ]);
                        return;
                    }
                } else {
                    throw new Exception('Unable to read servers from uploaded backup');
                }
            } else {
                if (!empty($serversMeta)) {
                    $formData['uploaded_servers'] = $serversMeta;
                }
            }

            $serverData = BackupLibrary::loadServer($token, $serverIndex);
            $serverId = VpnServer::importFromBackup($user['id'], $serverData);

            $serverModel = new VpnServer($serverId);
            $serverRecord = $serverModel->getData();

            foreach ($serverData['clients'] as $clientData) {
                try {
                    VpnClient::importFromBackup($serverRecord, $user['id'], $clientData);
                } catch (Exception $clientError) {
                    error_log('Client import failed: ' . $clientError->getMessage());
                }
            }

            if (BackupLibrary::isUploadToken($token)) {
                BackupLibrary::forgetUpload($token);
            }

            $_SESSION['success_message'] = 'Server imported from backup';
            redirect('/servers/' . $serverId);
        } catch (Exception $e) {
            if (!empty($serversMeta)) {
                $formData['uploaded_servers'] = $serversMeta;
            }
            View::render('servers/create.twig', [
                'error' => $e->getMessage(),
                'selected_mode' => 'backup',
                'form_data' => $formData,
                'protocols' => $protocols,
                'default_protocol' => $defaultProtocol
            ]);
        }

        return;
    }

    $name = trim($_POST['name'] ?? '');
    $host = trim($_POST['host'] ?? '');
    $port = (int) ($_POST['port'] ?? 22);
    $username = trim($_POST['username'] ?? 'root');
    $password = $_POST['password'] ?? '';
    // ssh_key handling
    $sshKey = trim($_POST['ssh_key'] ?? '');

    $protocolSlug = $formData['install_protocol'] ?? $defaultProtocol;
    $protocolRecord = InstallProtocolManager::getBySlug($protocolSlug);
    if (!$protocolRecord) {
        View::render('servers/create.twig', [
            'error' => 'Selected protocol not found or inactive',
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
        return;
    }
    $protocolMetadata = $protocolRecord['definition']['metadata'] ?? [];
    $containerName = $protocolMetadata['container_name'] ?? 'amnezia-awg';
    $defaultSubnet = $protocolMetadata['vpn_subnet'] ?? '10.8.1.0/24';
    $vpnSubnet = $formData['vpn_subnet'] ?? $defaultSubnet;
    $installOptions = $protocolRecord['definition']['defaults'] ?? null;

    if (empty($name) || empty($host) || (empty($password) && empty($sshKey))) {
        View::render('servers/create.twig', [
            'error' => 'All fields are required (either Password or SSH Key)',
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
        return;
    }

    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
            'ssh_key' => $sshKey,
            'container_name' => $containerName,
            'vpn_subnet' => $vpnSubnet,
            'install_protocol' => $protocolSlug,
            'install_options' => $installOptions,
        ]);

        redirect('/servers/' . $serverId . '/deploy');
    } catch (Exception $e) {
        View::render('servers/create.twig', [
            'error' => $e->getMessage(),
            'selected_mode' => $creationMode,
            'form_data' => $formData,
            'protocols' => $protocols,
            'default_protocol' => $defaultProtocol
        ]);
    }
});

// Delete server action
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    $user = Auth::user();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $server->delete();
        $_SESSION['success_message'] = 'Server deleted successfully';
        redirect('/servers');
    } catch (Exception $e) {
        $_SESSION['error_message'] = $e->getMessage();
        redirect('/servers');
    }
});

// Deploy server page
Router::get('/servers/{id}/deploy', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        View::render('servers/deploy.twig', ['server' => $serverData]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Deploy server action (AJAX)
Router::post('/servers/{id}/deploy', function ($params) {
    requireAuth();
    header('Content-Type: application/json');

    $serverId = (int) $params['id'];
    $rawBody = file_get_contents('php://input');
    $options = [];
    if ($rawBody !== false && trim($rawBody) !== '') {
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded)) {
            $options = $decoded;
        }
    }
    if (empty($options) && !empty($_POST)) {
        $options = $_POST;
    }
    if (!is_array($options)) {
        $options = [];
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $server->deploy($options);
        if (!isset($result['success']) && empty($result['requires_action'])) {
            $result['success'] = true;
        }
        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
});

// Uninstall all protocols from server (mass cleanup) - MUST be before {slug}/uninstall
Router::post('/servers/{id}/protocols/uninstall-all', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    $serverId = (int) $params['id'];
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Forbidden']);
            return;
        }
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT p.* FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$serverId]);
        $protocols = $stmt->fetchAll();
        $removedClients = 0;
        foreach ($protocols as $protocol) {
            try {
                $res = InstallProtocolManager::uninstall($server, $protocol, []);
                $pid = (int) $protocol['id'];
                $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?')->execute([$serverId, $pid]);
                // Remove clients bound to this protocol
                $stmtDel = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
                $stmtDel->execute([$serverId, $pid]);
                $removedClients += (int) $stmtDel->rowCount();
            } catch (Exception $e) {
                // continue with next protocol
            }
        }
        echo json_encode(['success' => true, 'clients_removed' => $removedClients, 'message' => 'All protocols uninstalled']);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

// Uninstall a specific protocol on server (AJAX)
Router::post('/servers/{id}/protocols/{slug}/uninstall', function ($params) {
    requireAuth();
    header('Content-Type: application/json');

    $serverId = (int) $params['id'];
    $slug = $params['slug'] ?? '';

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $protocol = InstallProtocolManager::getBySlug($slug);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            return;
        }

        $result = InstallProtocolManager::uninstall($server, $protocol);

        $pdo = DB::conn();
        $stmtId = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
        $stmtId->execute([$slug]);
        $pid = (int) $stmtId->fetchColumn();
        $deletedClients = 0;
        $deletedBindings = 0;
        if ($pid) {
            $stmtDelSp = $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $stmtDelSp->execute([$serverId, $pid]);
            $deletedBindings = $stmtDelSp->rowCount();
            $stmtDelClients = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
            $stmtDelClients->execute([$serverId, $pid]);
            $deletedClients = $stmtDelClients->rowCount();
        }

        // Update server status
        $stmtCount = $pdo->prepare('SELECT COUNT(*) FROM server_protocols WHERE server_id = ?');
        $stmtCount->execute([$serverId]);
        $remaining = (int) $stmtCount->fetchColumn();

        // If we successfully uninstalled, we can clear the error state
        // If no protocols remain, status is 'absent', otherwise 'active'
        $newStatus = 'active';
        $stmtUpdate = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
        $stmtUpdate->execute([$newStatus, $serverId]);

        echo json_encode(array_merge($result, [
            'bindings_removed' => $deletedBindings,
            'clients_removed' => $deletedClients
        ]));
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Activate protocol on server (AJAX)
Router::post('/servers/{id}/protocols/activate', function ($params) {
    requireAuth();

    // Suppress errors and clean output buffer to prevent HTML corruption of JSON
    @ini_set('display_errors', '0');
    error_reporting(0);
    while (ob_get_level()) {
        @ob_end_clean();
    }

    header('Content-Type: application/json');

    $serverId = (int) $params['id'];
    $protocolId = isset($_POST['protocol_id']) ? (int) $_POST['protocol_id'] : 0;
    Logger::appendInstall($serverId, 'HTTP activate requested protocol_id=' . $protocolId);

    if ($protocolId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'protocol_id required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            Logger::appendInstall($serverId, 'HTTP activate forbidden user=' . ($user['id'] ?? 0));
            return;
        }

        $protocol = InstallProtocolManager::getById($protocolId);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            Logger::appendInstall($serverId, 'HTTP activate protocol not found id=' . $protocolId);
            return;
        }

        $result = InstallProtocolManager::activate($server, $protocol, []);
        echo json_encode($result);
        Logger::appendInstall($serverId, 'HTTP activate finished ok');
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
        Logger::appendInstall($serverId, 'HTTP activate failed: ' . $e->getMessage());
    }
});

// View server
Router::get('/servers/{id}', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $pdo = DB::conn();
        $serverProtocols = [];
        try {
            $stmt = $pdo->prepare('SELECT sp.protocol_id, sp.config_data, sp.applied_at, p.name, p.slug, p.description FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ? ORDER BY p.name');
            $stmt->execute([$serverId]);
            $serverProtocols = $stmt->fetchAll();
            foreach ($serverProtocols as &$sp) {
                $cfg = [];
                if (!empty($sp['config_data'])) {
                    $cfg = is_string($sp['config_data']) ? json_decode($sp['config_data'], true) : $sp['config_data'];
                }
                $sp['server_host'] = is_array($cfg) ? ($cfg['server_host'] ?? '') : '';
                $sp['server_port'] = is_array($cfg) ? ($cfg['server_port'] ?? '') : '';
                $sp['extras'] = (is_array($cfg) && isset($cfg['extras']) && is_array($cfg['extras'])) ? $cfg['extras'] : [];
                $sp['result_json'] = '';
                if (is_array($sp['extras']) && isset($sp['extras']['result']) && is_array($sp['extras']['result'])) {
                    $sp['result_json'] = json_encode($sp['extras']['result'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                }
            }
            unset($sp);
        } catch (Exception $e) {
            $serverProtocols = [];
        }

        $allActive = InstallProtocolManager::listActive();
        $installedIds = array_map(function ($row) {
            return (int) $row['protocol_id'];
        }, $serverProtocols);
        $availableProtocols = array_values(array_filter($allActive, function ($p) use ($installedIds) {
            $pid = (int) ($p['id'] ?? 0);
            return $pid > 0 && !in_array($pid, $installedIds, true);
        }));

        $selectedProtocolId = isset($_GET['protocol_id']) ? (int) $_GET['protocol_id'] : 0;
        if ($selectedProtocolId > 0) {
            $clients = VpnClient::listByServerAndProtocol($serverId, $selectedProtocolId);
        } else {
            $clients = VpnClient::listByServer($serverId);
        }

        // Flash message from manual config import
        $importMessage = $_SESSION['import_message'] ?? null;
        if ($importMessage) {
            unset($_SESSION['import_message']);
        }

        // Check for pending import if no flash message was set
        if ($importMessage === null && !empty($_SESSION['pending_import']) && $_SESSION['pending_import']['server_id'] == $serverId) {
            $pendingImport = $_SESSION['pending_import'];

            // Only process import if server is active
            if ($serverData['status'] === 'active') {
                try {
                    $backupContent = file_get_contents($pendingImport['backup_file']);

                    $importer = new PanelImporter($serverId, $user['id'], $pendingImport['panel_type']);
                    $importer->parseBackupFile($backupContent);
                    $result = $importer->import();

                    if ($result['success']) {
                        $importMessage = [
                            'type' => 'success',
                            'text' => "Successfully imported {$result['imported_count']} clients"
                        ];
                    }

                    // Clean up
                    @unlink($pendingImport['backup_file']);
                    unset($_SESSION['pending_import']);

                } catch (Exception $e) {
                    $importMessage = [
                        'type' => 'error',
                        'text' => 'Import failed: ' . $e->getMessage()
                    ];
                    unset($_SESSION['pending_import']);
                }

                // Refresh clients list after import
                $clients = VpnClient::listByServer($serverId);
            }
        }

        View::render('servers/view.twig', [
            'server' => $serverData,
            'clients' => $clients,
            'import_message' => $importMessage,
            'server_protocols' => $serverProtocols,
            'selected_protocol_id' => $selectedProtocolId,
            'available_protocols' => $availableProtocols,
        ]);
    } catch (Exception $e) {
        error_log('Server view error: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
        http_response_code(404);
        echo 'Server not found: ' . htmlspecialchars($e->getMessage());
    }
});



// Server monitoring page
Router::get('/servers/{id}/monitoring', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        // Get clients for this server
        $clients = VpnClient::listByServer($serverId);

        View::render('servers/monitoring.twig', [
            'server' => $serverData,
            'clients' => $clients,
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Server not found';
    }
});

// Import server configuration from uploaded backup
Router::post('/servers/{id}/config/import', function ($params) {
    requireAuth();
    $user = Auth::user();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (!$serverData) {
            throw new Exception('Server not found');
        }

        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            throw new Exception('Недостаточно прав для импорта конфигурации');
        }

        if (!isset($_FILES['config_file']) || $_FILES['config_file']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('Файл конфигурации не загружен');
        }

        $tmpPath = $_FILES['config_file']['tmp_name'];
        if (!is_uploaded_file($tmpPath)) {
            throw new Exception('Не удалось прочитать загруженный файл');
        }

        $storagePath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'config_import_' . bin2hex(random_bytes(16));
        if (!move_uploaded_file($tmpPath, $storagePath)) {
            throw new Exception('Не удалось сохранить загруженный файл');
        }

        try {
            $parsed = BackupParser::parse($storagePath);
        } finally {
            @unlink($storagePath);
        }

        $type = $parsed['type'] ?? '';
        if (!in_array($type, ['panel_backup', 'amnezia_app'], true)) {
            throw new Exception('Этот тип бэкапа пока не поддерживается для импорта конфигурации');
        }

        $servers = $parsed['servers'] ?? [];
        if (!is_array($servers) || empty($servers)) {
            throw new Exception('В бэкапе не найдено конфигураций серверов');
        }

        $selectedServer = null;
        if ($type === 'panel_backup') {
            $selectedServer = $servers[0];
        } else {
            $currentHost = strtolower(trim($serverData['host'] ?? ''));
            foreach ($servers as $candidate) {
                $candidateHost = strtolower(trim($candidate['host'] ?? ''));
                if ($candidateHost !== '' && $candidateHost === $currentHost) {
                    $selectedServer = $candidate;
                    break;
                }
            }

            if ($selectedServer === null && count($servers) === 1) {
                $selectedServer = $servers[0];
            }

            if ($selectedServer === null) {
                throw new Exception('Не удалось сопоставить сервер в бэкапе с текущим хостом ' . $serverData['host']);
            }
        }

        $replaceClients = $type === 'panel_backup';
        $result = $server->applyBackupData($selectedServer, $user['id'], $replaceClients);

        $importedClients = $result['imported_clients'] ?? 0;
        $clientErrors = $result['client_errors'] ?? [];

        $messageParts = [];
        if (!empty($result['updated_fields'])) {
            $messageParts[] = 'Обновлены поля: ' . implode(', ', $result['updated_fields']);
        }
        if ($importedClients > 0) {
            $messageParts[] = 'Импортировано клиентов: ' . $importedClients;
        }
        if (empty($messageParts)) {
            $messageParts[] = 'Конфигурация обработана';
        }

        $_SESSION['import_message'] = [
            'type' => empty($clientErrors) ? 'success' : 'warning',
            'text' => implode('. ', $messageParts)
        ];

        if (!empty($clientErrors)) {
            $_SESSION['import_message']['text'] .= '. Ошибки: ' . implode('; ', array_slice($clientErrors, 0, 3));
        }

    } catch (Exception $e) {
        $_SESSION['import_message'] = [
            'type' => 'error',
            'text' => $e->getMessage()
        ];
    }

    redirect('/servers/' . $serverId);
});

// Delete server
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $server->delete();
        redirect('/servers');
    } catch (Exception $e) {
        redirect('/servers');
    }
});

// Create client for server
Router::post('/servers/{id}/clients/create', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];
    $clientName = trim($_POST['name'] ?? '');
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $login = isset($_POST['login']) ? trim($_POST['login']) : '';

    // Handle expiration: either from dropdown (days) or custom input (seconds)
    $expiresInDays = null;
    if (!empty($_POST['expires_in_seconds'])) {
        // Convert seconds to days (round up)
        $expiresInDays = (int) ceil((int) $_POST['expires_in_seconds'] / 86400);
    } elseif (!empty($_POST['expires_in_days']) && $_POST['expires_in_days'] !== 'custom') {
        $expiresInDays = (int) $_POST['expires_in_days'];
    }

    // Handle traffic limit: either from dropdown (GB) or custom input (MB)
    $trafficLimitBytes = null;
    if (!empty($_POST['traffic_limit_mb'])) {
        // Convert MB to bytes
        $trafficLimitBytes = (int) ((float) $_POST['traffic_limit_mb'] * 1048576);
    } elseif (!empty($_POST['traffic_limit_gb']) && $_POST['traffic_limit_gb'] !== 'custom') {
        // Convert GB to bytes
        $trafficLimitBytes = (int) ((float) $_POST['traffic_limit_gb'] * 1073741824);
    }

    if (empty($clientName)) {
        redirect('/servers/' . $serverId . '?error=Client+name+is+required');
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $protocolId = isset($_POST['protocol_id']) && $_POST['protocol_id'] !== '' ? (int) $_POST['protocol_id'] : null;
        if ($protocolId) {
            try {
                $pdo = DB::conn();
                $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $chk->execute([$serverId, $protocolId]);
                if (!$chk->fetchColumn()) {
                    $protocolId = null;
                }
            } catch (Exception $e) {
                $protocolId = null;
            }
        }
        $clientId = VpnClient::create($serverId, $user['id'], $clientName, $expiresInDays, $protocolId, $username, $login);

        // Set traffic limit if specified
        if ($trafficLimitBytes !== null && $trafficLimitBytes > 0) {
            $client = new VpnClient($clientId);
            $client->setTrafficLimit($trafficLimitBytes);
        }

        redirect('/clients/' . $clientId);
    } catch (Exception $e) {
        redirect('/servers/' . $serverId . '?error=' . urlencode($e->getMessage()));
    }
});

// View client
Router::get('/clients/{id}', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        $server = new VpnServer((int) $clientData['server_id']);
        $serverData = $server->getData();
        $protocolOutput = '';
        try {
            $pdo = DB::conn();
            $protocol = null;
            if (!empty($clientData['protocol_id'])) {
                $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ? LIMIT 1');
                $stmt->execute([(int) $clientData['protocol_id']]);
                $protocol = $stmt->fetch();
            } else {
                $stmt = $pdo->prepare('SELECT * FROM protocols WHERE slug = ? LIMIT 1');
                $stmt->execute([$serverData['install_protocol'] ?? '']);
                $protocol = $stmt->fetch();
            }

            if ($protocol) {
                $clientData['show_text_content'] = !empty($protocol['show_text_content']);
            }
            if ($protocol && ($protocol['output_template'] ?? '') !== '') {
                $slug = $protocol['slug'] ?? '';
                $isWireguard = in_array($slug, ['amnezia-wg-advanced', 'wireguard-standard', 'amnezia-wg'], true);
                if ($isWireguard) {
                    // For WG, we don’t render protocol_output; config is downloadable
                    $protocolOutput = '';
                } else {
                    // For non-WG protocols, reuse stored generated output in config
                    $protocolOutput = $clientData['config'] ?? '';
                }
            }
        } catch (Exception $e) {
            $protocolOutput = '';
        }
        View::render('clients/view.twig', ['client' => $clientData, 'protocol_output' => $protocolOutput]);
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Download client config
Router::get('/clients/{id}/download', function ($params) {
    requireAuth();

    // Clean any output buffer to prevent header issues
    while (ob_get_level()) {
        ob_end_clean();
    }

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        // For WireGuard/AWG clients, regenerate config from current server state
        // to avoid stale AWG parameters after reinstall/recreate.
        // IMPORTANT: for amnezia-wg-advanced, never serve a config built with defaults.
        try {
            $regen = $client->regenerateConfigFromServer(true);
            if (is_array($regen) && empty($regen['success']) && ($regen['error'] ?? '') === 'awg_params_missing') {
                http_response_code(500);
                echo 'AWG params are missing on server; cannot generate a valid config. Reinstall/repair AWG or check /opt/amnezia/awg/wg0.conf on the server.';
                return;
            }
        } catch (Throwable $e) {
            error_log('Failed to regenerate client config: ' . $e->getMessage());
        }

        $config = $client->getConfig();

        // Use login if available, fallback to name
        $baseName = !empty($clientData['login']) ? $clientData['login'] : $clientData['name'];

        // Sanitize filename: remove non-safe characters
        $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $baseName);

        // If sanitization resulted in empty string, use fallback
        if (empty($safeName)) {
            $safeName = 'user_' . $clientData['id'] . '_s' . $clientData['server_id'];
        }

        $filename = $safeName . '.conf';

        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($config));
        echo $config;
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Debug: one-shot AWG advanced smoke test (requires session auth)
// Usage example (while logged in): /debug/awg-smoke?server_id=5&client_name=olegnew14&duration_seconds=10
Router::get('/debug/awg-smoke', function () {
    requireDebugEnabledOrAdmin();
    header('Content-Type: application/json');

    $serverId = (int) ($_GET['server_id'] ?? 0);
    $clientId = (int) ($_GET['client_id'] ?? 0);
    $clientName = trim((string) ($_GET['client_name'] ?? ''));
    $duration = (int) ($_GET['duration_seconds'] ?? 10);
    if ($duration < 0)
        $duration = 0;
    if ($duration > 30)
        $duration = 30;

    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id is required']);
        return;
    }
    if ($clientId <= 0 && $clientName === '') {
        http_response_code(400);
        echo json_encode(['error' => 'client_id or client_name is required']);
        return;
    }

    try {
        $user = Auth::user();

        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (!$serverData) {
            http_response_code(404);
            echo json_encode(['error' => 'Server not found']);
            return;
        }
        if (($serverData['user_id'] ?? null) != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($clientId <= 0) {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND name = ? ORDER BY id DESC LIMIT 1');
            $stmt->execute([$serverId, $clientName]);
            $clientId = (int) $stmt->fetchColumn();
        }

        if ($clientId <= 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Client not found']);
            return;
        }

        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        if (!$clientData) {
            http_response_code(404);
            echo json_encode(['error' => 'Client not found']);
            return;
        }
        if (($clientData['user_id'] ?? null) != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Regenerate config from live server state (critical after reinstall)
        $regen = $client->regenerateConfigFromServer(true);

        $server->refresh();
        $serverData = $server->getData();

        $containerName = $serverData['container_name'] ?? 'amnezia-awg';
        $vpnPort = (int) ($serverData['vpn_port'] ?? 0);

        $cmdShow = sprintf('docker exec %s wg show wg0 2>/dev/null || true', escapeshellarg($containerName));
        $cmdDump = sprintf('docker exec %s wg show wg0 dump 2>/dev/null || true', escapeshellarg($containerName));
        $cmdAwgConfParams = sprintf(
            'docker exec %s sh -c "grep -E \"^[[:space:]]*(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)[[:space:]]*=\" /opt/amnezia/awg/wg0.conf 2>/dev/null || true"',
            escapeshellarg($containerName)
        );
        $cmdListen = $vpnPort > 0
            ? sprintf('docker exec %s sh -c "ss -lunp 2>/dev/null | grep -E \"[:.]%d\\b\" || true"', escapeshellarg($containerName), $vpnPort)
            : '';

        // Host-level checks (outside container)
        // Use sed (not awk) to avoid shell-quoting pitfalls.
        $cmdHostIps = 'sh -c "ip -4 -o addr show scope global 2>/dev/null | sed -E \"s/^[0-9]+: ([^ ]+) +inet ([0-9\\./]+).*/\\1 \\2/\" || true"';
        $cmdDockerPort = $vpnPort > 0
            ? sprintf('sh -c "docker port %s %d/udp 2>/dev/null || true"', escapeshellarg($containerName), $vpnPort)
            : sprintf('sh -c "docker port %s 2>/dev/null || true"', escapeshellarg($containerName));
        $cmdHostSs = $vpnPort > 0
            ? sprintf('sh -c "ss -lunp 2>/dev/null | grep -E \"[:.]%d\\b\" || true"', $vpnPort)
            : 'sh -c "ss -lunp 2>/dev/null || true"';
        $cmdNftFiltered = $vpnPort > 0
            ? sprintf('sh -c "nft list ruleset 2>/dev/null | grep -E \"(dport|udp).*(%d)\" | head -200 || true"', $vpnPort)
            : 'sh -c "nft list ruleset 2>/dev/null | head -200 || true"';
        $cmdIptFiltered = $vpnPort > 0
            ? sprintf('sh -c "iptables -vnL 2>/dev/null | grep -E \"(udp|%d)\" | head -200 || true"', $vpnPort)
            : 'sh -c "iptables -vnL 2>/dev/null | head -200 || true"';

        // BEFORE snapshots
        $wgShowBefore = (string) $server->executeCommand($cmdShow, true);
        $wgDumpBefore = (string) $server->executeCommand($cmdDump, true);
        $awgConfLines = (string) $server->executeCommand($cmdAwgConfParams, true);
        $listenLines = $cmdListen !== '' ? (string) $server->executeCommand($cmdListen, true) : '';
        $hostIps = (string) $server->executeCommand($cmdHostIps, true);
        $dockerPort = (string) $server->executeCommand($cmdDockerPort, true);
        $hostSsBefore = (string) $server->executeCommand($cmdHostSs, true);
        $nftBefore = (string) $server->executeCommand($cmdNftFiltered, true);
        $iptablesBefore = (string) $server->executeCommand($cmdIptFiltered, true);

        // Extract this peer line from dump (before)
        $peerLineBefore = '';
        foreach (preg_split('/\r?\n/', trim($wgDumpBefore)) as $ln) {
            if ($ln !== '' && strpos($ln, ($clientData['public_key'] ?? '') . "\t") === 0) {
                $peerLineBefore = $ln;
                break;
            }
        }

        if ($duration > 0) {
            sleep($duration);
        }

        // AFTER snapshots
        $wgShowAfter = (string) $server->executeCommand($cmdShow, true);
        $wgDumpAfter = (string) $server->executeCommand($cmdDump, true);
        $hostSsAfter = (string) $server->executeCommand($cmdHostSs, true);
        $nftAfter = (string) $server->executeCommand($cmdNftFiltered, true);
        $iptablesAfter = (string) $server->executeCommand($cmdIptFiltered, true);

        // Parse firewall counters for this UDP port (best-effort)
        $nftPacketsBefore = null;
        $nftBytesBefore = null;
        if ($vpnPort > 0 && preg_match('/udp dport\s+' . preg_quote((string) $vpnPort, '/') . '\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)/', $nftBefore, $m)) {
            $nftPacketsBefore = (int) $m[1];
            $nftBytesBefore = (int) $m[2];
        }
        $nftPacketsAfter = null;
        $nftBytesAfter = null;
        if ($vpnPort > 0 && preg_match('/udp dport\s+' . preg_quote((string) $vpnPort, '/') . '\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)/', $nftAfter, $m)) {
            $nftPacketsAfter = (int) $m[1];
            $nftBytesAfter = (int) $m[2];
        }

        $iptPacketsBefore = null;
        $iptBytesBefore = null;
        if (preg_match('/^\s*(\d+)\s+(\d+)\s+ACCEPT\b/m', $iptablesBefore, $m)) {
            $iptPacketsBefore = (int) $m[1];
            $iptBytesBefore = (int) $m[2];
        }
        $iptPacketsAfter = null;
        $iptBytesAfter = null;
        if (preg_match('/^\s*(\d+)\s+(\d+)\s+ACCEPT\b/m', $iptablesAfter, $m)) {
            $iptPacketsAfter = (int) $m[1];
            $iptBytesAfter = (int) $m[2];
        }

        // Extract this peer line from dump (after)
        $peerLineAfter = '';
        foreach (preg_split('/\r?\n/', trim($wgDumpAfter)) as $ln) {
            if ($ln !== '' && strpos($ln, ($clientData['public_key'] ?? '') . "\t") === 0) {
                $peerLineAfter = $ln;
                break;
            }
        }

        // Compare PSK in client config vs wg dump (redacted)
        $configText = $client->getConfig();
        $configPsk = '';
        if (preg_match('/^PresharedKey\s*=\s*(\S+)/mi', $configText, $m)) {
            $configPsk = (string) $m[1];
        }
        $dumpPskAfter = '';
        if ($peerLineAfter !== '') {
            $parts = explode("\t", $peerLineAfter);
            if (count($parts) >= 2) {
                $dumpPskAfter = (string) $parts[1];
            }
        }
        $pskMatches = ($configPsk !== '' && $dumpPskAfter !== '' && $configPsk === $dumpPskAfter);

        echo json_encode([
            'success' => true,
            'server' => [
                'id' => (int) $serverId,
                'host' => (string) ($serverData['host'] ?? ''),
                'container_name' => (string) $containerName,
                'vpn_port' => $vpnPort,
                'awg_params_db' => json_decode($serverData['awg_params'] ?? '{}', true),
            ],
            'client' => [
                'id' => (int) $clientId,
                'name' => (string) ($clientData['name'] ?? ''),
                'public_key' => (string) ($clientData['public_key'] ?? ''),
                'client_ip' => (string) ($clientData['client_ip'] ?? ''),
            ],
            'regen' => $regen,
            'awg_conf_param_lines' => $awgConfLines,
            'container_listen' => $listenLines,
            'host_global_ips' => $hostIps,
            'docker_port_publish' => $dockerPort,
            'host_ss_udp_before' => $hostSsBefore,
            'host_ss_udp_after' => $hostSsAfter,
            'nft_filtered_before' => $nftBefore,
            'nft_filtered_after' => $nftAfter,
            'iptables_filtered_before' => $iptablesBefore,
            'iptables_filtered_after' => $iptablesAfter,
            'nft_counter_packets_before' => $nftPacketsBefore,
            'nft_counter_packets_after' => $nftPacketsAfter,
            'nft_counter_packets_delta' => ($nftPacketsBefore !== null && $nftPacketsAfter !== null) ? ($nftPacketsAfter - $nftPacketsBefore) : null,
            'nft_counter_bytes_before' => $nftBytesBefore,
            'nft_counter_bytes_after' => $nftBytesAfter,
            'nft_counter_bytes_delta' => ($nftBytesBefore !== null && $nftBytesAfter !== null) ? ($nftBytesAfter - $nftBytesBefore) : null,
            'iptables_counter_packets_before' => $iptPacketsBefore,
            'iptables_counter_packets_after' => $iptPacketsAfter,
            'iptables_counter_packets_delta' => ($iptPacketsBefore !== null && $iptPacketsAfter !== null) ? ($iptPacketsAfter - $iptPacketsBefore) : null,
            'iptables_counter_bytes_before' => $iptBytesBefore,
            'iptables_counter_bytes_after' => $iptBytesAfter,
            'iptables_counter_bytes_delta' => ($iptBytesBefore !== null && $iptBytesAfter !== null) ? ($iptBytesAfter - $iptBytesBefore) : null,
            'peer_dump_line_before' => $peerLineBefore,
            'peer_dump_line_after' => $peerLineAfter,
            'psk_match' => $pskMatches,
            'client_config_psk_prefix' => $configPsk !== '' ? substr($configPsk, 0, 8) : '',
            'dump_psk_prefix' => $dumpPskAfter !== '' ? substr($dumpPskAfter, 0, 8) : '',
            'wg_show_before' => $wgShowBefore,
            'wg_dump_before' => $wgDumpBefore,
            'wg_show_after' => $wgShowAfter,
            'wg_dump_after' => $wgDumpAfter,
            'duration_seconds' => $duration,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Revoke client access
Router::post('/clients/{id}/revoke', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        if ($client->revoke()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+revoked');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+revoke+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Restore client access
Router::post('/clients/{id}/restore', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        if ($client->restore()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+restored');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+restore+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Delete client
Router::post('/clients/{id}/delete', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $serverId = $clientData['server_id'];

        if ($client->delete()) {
            redirect('/servers/' . $serverId . '?success=Client+deleted');
        } else {
            redirect('/servers/' . $serverId . '?error=Failed+to+delete+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Sync client stats
Router::post('/clients/{id}/sync-stats', function ($params) {
    requireAuth();
    $clientId = (int) $params['id'];

    header('Content-Type: application/json');

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->syncStats()) {
            // Reload client data
            $client = new VpnClient($clientId);
            $stats = $client->getFormattedStats();
            echo json_encode(['success' => true, 'stats' => $stats]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to sync stats']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Sync all stats for server
Router::post('/servers/{id}/sync-stats', function ($params) {
    requireAuth();
    $serverId = (int) $params['id'];

    header('Content-Type: application/json');

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $synced = VpnClient::syncAllStatsForServer($serverId);
        echo json_encode(['success' => true, 'synced' => $synced]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * API ROUTES (for Telegram bot integration)
 */

// API: Generate JWT token
Router::post('/api/auth/token', function () {
    header('Content-Type: application/json');

    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        return;
    }

    $user = Auth::getUserByEmail($email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }

    try {
        $token = JWT::generate($user['id']);
        echo json_encode([
            'success' => true,
            'token' => $token,
            'type' => 'Bearer',
            'expires_in' => 30 * 24 * 3600 // 30 days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Token generation failed']);
    }
});

// API: Create persistent API token
Router::post('/api/tokens', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $name = $_POST['name'] ?? 'API Token';
    $expiresIn = isset($_POST['expires_in']) ? (int) $_POST['expires_in'] : 2592000; // 30 days default

    try {
        $tokenData = JWT::createApiToken($user['id'], $name, $expiresIn);
        echo json_encode([
            'success' => true,
            'token' => $tokenData
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List user's API tokens
Router::get('/api/tokens', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $stmt = DB::conn()->prepare("
        SELECT id, name, token, expires_at, created_at, last_used_at
        FROM api_tokens
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
    ");
    $stmt->execute([$user['id']]);
    $tokens = $stmt->fetchAll();

    // Don't expose full token in list
    foreach ($tokens as &$token) {
        $token['token'] = substr($token['token'], 0, 10) . '...';
    }

    echo json_encode(['tokens' => $tokens]);
});

// API: Revoke API token
Router::delete('/api/tokens/{id}', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    try {
        JWT::revokeApiToken($params['id'], $user['id']);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List servers
Router::get('/api/servers', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $servers = VpnServer::listByUser($user['id']);

    // Enrich with installed protocols
    $pdo = DB::conn();
    foreach ($servers as &$server) {
        $stmt = $pdo->prepare('SELECT p.id, p.slug, p.name FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$server['id']]);
        $server['protocols'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($server);

    echo json_encode(['servers' => $servers]);
});

// API: Create server
Router::post('/api/servers/create', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $input = json_decode(file_get_contents('php://input'), true);

    $name = trim($input['name'] ?? '');
    $host = trim($input['host'] ?? '');
    $port = (int) ($input['port'] ?? 22);
    $username = trim($input['username'] ?? 'root');
    $password = $input['password'] ?? '';

    if (empty($name) || empty($host) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields: name, host, password']);
        return;
    }

    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
        ]);

        http_response_code(201);
        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'message' => 'Server created successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete server
Router::delete('/api/servers/{id}/delete', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $server->delete();
        echo json_encode([
            'success' => true,
            'message' => 'Server deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Import from existing panel
Router::post('/api/servers/{id}/import', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    // Validate server ownership
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    if ($serverData['user_id'] != $user['id']) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $panelType = $_POST['panel_type'] ?? '';

    if (!in_array($panelType, ['wg-easy', '3x-ui'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid panel type. Supported: wg-easy, 3x-ui']);
        return;
    }

    // Handle file upload
    if (!isset($_FILES['backup_file']) || $_FILES['backup_file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['error' => 'No backup file uploaded']);
        return;
    }

    $backupContent = file_get_contents($_FILES['backup_file']['tmp_name']);

    try {
        $importer = new PanelImporter($serverId, $user['id'], $panelType);

        if (!$importer->parseBackupFile($backupContent)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid backup file format']);
            return;
        }

        $result = $importer->import();

        echo json_encode($result);

    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
});

// API: Get import history
Router::get('/api/servers/{id}/imports', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    // Validate server ownership
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    if ($serverData['user_id'] != $user['id']) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $imports = PanelImporter::getImportHistory($serverId);

    echo json_encode([
        'success' => true,
        'imports' => $imports
    ]);
});

// API: Create backup
Router::post('/api/servers/{id}/backup', function ($params) {
    header('Content-Type: application/json');

    $user = requireApiAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $backupId = $server->createBackup($user['id'], 'manual');
        $backup = VpnServer::getBackup($backupId);

        echo json_encode([
            'success' => true,
            'backup' => $backup
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List backups
Router::get('/api/servers/{id}/backups', function ($params) {
    header('Content-Type: application/json');

    $user = requireApiAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $backups = $server->listBackups();

        echo json_encode([
            'success' => true,
            'backups' => $backups,
            'count' => count($backups)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore backup
Router::post('/api/servers/{id}/restore', function ($params) {
    header('Content-Type: application/json');

    $user = requireApiAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $backupId = (int) ($data['backup_id'] ?? 0);

    if ($backupId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'backup_id is required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $server->restoreBackup($backupId);

        // Log the result for debugging
        error_log('Restore backup result: ' . json_encode($result));

        // Always return the result, even if success is false
        echo json_encode($result);
    } catch (Exception $e) {
        error_log('Restore backup exception: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage(), 'success' => false]);
    }
});

// API: Delete backup
Router::delete('/api/backups/{id}', function ($params) {
    header('Content-Type: application/json');

    $user = requireApiAuth();
    if (!$user)
        return;

    $backupId = (int) $params['id'];

    try {
        $backup = VpnServer::getBackup($backupId);

        if (!$backup) {
            http_response_code(404);
            echo json_encode(['error' => 'Backup not found']);
            return;
        }

        // Get server to check ownership
        $server = new VpnServer($backup['server_id']);
        $serverData = $server->getData();

        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        VpnServer::deleteBackup($backupId);

        echo json_encode([
            'success' => true,
            'message' => 'Backup deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List clients
Router::get('/api/clients', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clients = VpnClient::listByUser($user['id']);
    echo json_encode(['clients' => $clients]);
});

// API: Get client details with stats
Router::get('/api/clients/{id}/details', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Sync stats before returning
        $client->syncStats();

        // Reload data
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        $stats = $client->getFormattedStats();

        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Get client QR code
Router::get('/api/clients/{id}/qr', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        echo json_encode([
            'success' => true,
            'qr_code' => $clientData['qr_code'],
            'client_name' => $clientData['name']
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Revoke client
Router::post('/api/clients/{id}/revoke', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->revoke()) {
            echo json_encode(['success' => true, 'message' => 'Client revoked']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to revoke client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore client
Router::post('/api/clients/{id}/restore', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->restore()) {
            echo json_encode(['success' => true, 'message' => 'Client restored']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to restore client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete client
Router::delete('/api/clients/{id}/delete', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->delete()) {
            echo json_encode(['success' => true, 'message' => 'Client deleted']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to delete client']);
        }
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Get server metrics
Router::get('/api/servers/{id}/metrics', function ($params) {
    header('Content-Type: application/json');

    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }

    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];
    $hours = isset($_GET['hours']) ? (float) $_GET['hours'] : 24;

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $metrics = ServerMonitoring::getServerMetrics($serverId, $hours);

        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get client metrics
Router::get('/api/clients/{id}/metrics', function ($params) {
    header('Content-Type: application/json');

    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }

    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $clientId = (int) $params['id'];
    $hours = isset($_GET['hours']) ? (float) $_GET['hours'] : 24;

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Get server to check ownership
        $server = new VpnServer($clientData['server_id']);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $metrics = ServerMonitoring::getClientMetrics($clientId, $hours);

        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server clients
Router::get('/api/servers/{id}/clients', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Sync all stats first
        VpnClient::syncAllStatsForServer($serverId);

        $clients = VpnClient::listByServer($serverId);
        $clientsData = [];

        foreach ($clients as $clientData) {
            $client = new VpnClient($clientData['id']);
            $stats = $client->getFormattedStats();

            $clientsData[] = [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
            ];
        }

        echo json_encode(['success' => true, 'clients' => $clientsData]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List server protocols
Router::get('/api/servers/{id}/protocols', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT sp.protocol_id, sp.config_data, sp.applied_at, p.name, p.slug, p.description FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ? ORDER BY p.name');
        $stmt->execute([$serverId]);
        $rows = $stmt->fetchAll();

        echo json_encode(['success' => true, 'protocols' => $rows], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List active (installable) protocols
Router::get('/api/protocols/active', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $protocols = InstallProtocolManager::listActive();
    $list = array_map(function ($p) {
        return [
            'id' => (int) ($p['id'] ?? 0),
            'slug' => $p['slug'] ?? '',
            'name' => $p['name'] ?? '',
            'description' => $p['description'] ?? null,
        ];
    }, $protocols);

    echo json_encode(['success' => true, 'protocols' => $list], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
});

// API: Install/activate protocol on server
Router::post('/api/servers/{id}/protocols/install', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];
    $rawBody = file_get_contents('php://input');
    $input = [];
    if ($rawBody !== false && trim($rawBody) !== '') {
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded)) {
            $input = $decoded;
        }
    }
    if (empty($input) && !empty($_POST)) {
        $input = $_POST;
    }
    $protocolId = isset($input['protocol_id']) ? (int) $input['protocol_id'] : 0;

    if ($protocolId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'protocol_id required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $protocol = InstallProtocolManager::getById($protocolId);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            return;
        }

        $result = InstallProtocolManager::activate($server, $protocol, []);
        echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Self-test WireGuard/AWG install + client config correctness
// Creates a client (optional) and verifies that:
// - Client private key derives the same public key as stored in DB
// - Server wg0 knows the peer and has matching PSK/AllowedIPs
// - Server public key/listening port match what client config contains
// - Reports current handshake/endpoint state
Router::post('/api/servers/{id}/protocols/selftest', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) ($params['id'] ?? 0);
    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid server id']);
        return;
    }

    $raw = file_get_contents('php://input');
    $data = [];
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }
    if (empty($data) && !empty($_POST)) {
        $data = $_POST;
    }
    if (!is_array($data)) {
        $data = [];
    }

    $protocolId = isset($data['protocol_id']) ? (int) $data['protocol_id'] : 0;
    $install = !empty($data['install']);
    $clientId = isset($data['client_id']) ? (int) $data['client_id'] : 0;
    $createClient = array_key_exists('create_client', $data) ? (bool) $data['create_client'] : true;
    $clientName = trim((string) ($data['client_name'] ?? 'selftest-' . date('Ymd-His')));
    $includeSecrets = !empty($data['include_secrets']) && (($user['role'] ?? '') === 'admin');

    $extract = function (string $config, string $key): string {
        $pattern = '/^\s*' . preg_quote($key, '/') . '\s*=\s*(.+)\s*$/mi';
        if (preg_match($pattern, $config, $m)) {
            return trim($m[1]);
        }
        return '';
    };

    $deriveWgPublicKey = function (string $privateKeyB64): array {
        $privateKeyB64 = trim($privateKeyB64);
        if ($privateKeyB64 === '') {
            return ['ok' => false, 'error' => 'empty_private_key'];
        }

        $raw = base64_decode($privateKeyB64, true);
        if ($raw === false || strlen($raw) !== 32) {
            return ['ok' => false, 'error' => 'invalid_private_key_base64_or_length'];
        }

        if (!function_exists('sodium_crypto_scalarmult_base')) {
            return ['ok' => false, 'error' => 'libsodium_not_available'];
        }

        try {
            $pubRaw = sodium_crypto_scalarmult_base($raw);
            return ['ok' => true, 'public_key' => base64_encode($pubRaw)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => 'derive_failed: ' . $e->getMessage()];
        }
    };

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($protocolId > 0 && $install) {
            $protocol = InstallProtocolManager::getById($protocolId);
            if (!$protocol) {
                http_response_code(404);
                echo json_encode(['error' => 'Protocol not found']);
                return;
            }
            InstallProtocolManager::activate($server, $protocol, []);
        }

        $client = null;
        if ($clientId > 0) {
            $client = new VpnClient($clientId);
            $clientData = $client->getData();
            if (($clientData['server_id'] ?? null) != $serverId) {
                http_response_code(400);
                echo json_encode(['error' => 'client_id does not belong to server']);
                return;
            }
            if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden']);
                return;
            }
        } elseif ($createClient) {
            $bindProtocolId = $protocolId > 0 ? $protocolId : null;
            if ($bindProtocolId !== null) {
                $pdo = DB::conn();
                $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $chk->execute([$serverId, $bindProtocolId]);
                if (!$chk->fetchColumn()) {
                    http_response_code(400);
                    echo json_encode(['error' => 'protocol_id is not installed on this server']);
                    return;
                }
            }
            $newClientId = VpnClient::create($serverId, (int) $user['id'], $clientName, null, $bindProtocolId);
            $client = new VpnClient($newClientId);
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Provide client_id or set create_client=true']);
            return;
        }

        $clientData = $client->getData();
        $config = $client->getConfig();

        $cfgPrivate = $extract($config, 'PrivateKey');
        $cfgPsk = $extract($config, 'PresharedKey');
        $cfgServerPub = $extract($config, 'PublicKey');
        $cfgEndpoint = $extract($config, 'Endpoint');
        $cfgAddress = $extract($config, 'Address');

        if ($cfgPrivate === '') {
            http_response_code(500);
            echo json_encode([
                'error' => 'Generated config missing PrivateKey',
                'client_id' => (int) ($clientData['id'] ?? 0),
            ]);
            return;
        }

        $containerName = (string) ($serverData['container_name'] ?? 'amnezia-awg');

        $derived = $deriveWgPublicKey($cfgPrivate);
        $computedClientPub = '';
        if (!empty($derived['ok']) && !empty($derived['public_key'])) {
            $computedClientPub = (string) $derived['public_key'];
        } else {
            $err = (string) ($derived['error'] ?? 'derive_failed');
            // If we can't derive locally (e.g., libsodium missing), fall back to wg inside container.
            if ($err === 'libsodium_not_available') {
                $shComputePub = "set -e; priv=" . escapeshellarg($cfgPrivate) . "; printf '%s' \"$priv\" | wg pubkey";
                $cmdComputePub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg($shComputePub);
                $computedClientPub = trim($server->executeCommand($cmdComputePub, true));
            } else {
                $computedClientPub = $err;
            }
        }

        $cmdServerPub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null | awk '/public key:/ {print \$3; exit}' || true");
        $serverPubLive = trim($server->executeCommand($cmdServerPub, true));

        $cmdServerPort = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null | awk '/listening port:/ {print \$3; exit}' || true");
        $serverPortLive = trim($server->executeCommand($cmdServerPort, true));

        $cmdPskFile = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || true");
        $serverPskFile = trim($server->executeCommand($cmdPskFile, true));

        $cmdDump = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 dump 2>/dev/null || true");
        $dump = (string) $server->executeCommand($cmdDump, true);

        $targetPeerPub = $computedClientPub;
        $looksLikeB64Key = (bool) preg_match('/^[A-Za-z0-9+\/]{42,44}={0,2}$/', $targetPeerPub);
        $isDeriveError = ($targetPeerPub === ''
            || !$looksLikeB64Key
            || strpos($targetPeerPub, 'invalid_') === 0
            || strpos($targetPeerPub, 'derive_failed') === 0
            || strpos($targetPeerPub, 'wg:') === 0
            || $targetPeerPub === 'libsodium_not_available'
            || $targetPeerPub === 'empty_private_key');
        if ($isDeriveError) {
            $targetPeerPub = (string) ($clientData['public_key'] ?? '');
        }

        $peer = null;
        $lines = preg_split('/\r?\n/', trim($dump));
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $parts = preg_split('/\s+/', $line);
            // Peer line format: public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
            if (!$parts || count($parts) < 8) {
                continue;
            }
            // Skip interface line: starts with interface name 'wg0'
            if ($parts[0] === 'wg0') {
                continue;
            }
            if ($targetPeerPub !== '' && hash_equals($parts[0], $targetPeerPub)) {
                $peer = [
                    'public_key' => $parts[0],
                    'preshared_key' => $parts[1],
                    'endpoint' => $parts[2],
                    'allowed_ips' => $parts[3],
                    'latest_handshake' => (int) $parts[4],
                    'transfer_rx' => (int) $parts[5],
                    'transfer_tx' => (int) $parts[6],
                    'persistent_keepalive' => $parts[7],
                ];
                break;
            }
        }

        $checks = [];
        $mismatches = [];

        $dbClientPub = (string) ($clientData['public_key'] ?? '');
        if ($dbClientPub !== '' && $computedClientPub !== '' && !hash_equals($dbClientPub, $computedClientPub)) {
            $mismatches[] = 'client_public_key_db_mismatch';
        }
        if ($serverPubLive !== '' && $cfgServerPub !== '' && !hash_equals($serverPubLive, $cfgServerPub)) {
            $mismatches[] = 'server_public_key_mismatch';
        }
        if ($serverPskFile !== '' && $cfgPsk !== '' && !hash_equals($serverPskFile, $cfgPsk)) {
            $mismatches[] = 'preshared_key_mismatch';
        }
        if ($peer === null) {
            $mismatches[] = 'peer_not_found_on_server';
        }

        $checks['client_public_key'] = [
            'db' => $dbClientPub,
            'computed_from_private' => $computedClientPub,
            'ok' => ($dbClientPub === '' || $computedClientPub === '') ? null : hash_equals($dbClientPub, $computedClientPub),
        ];
        $checks['server_public_key'] = [
            'config' => $cfgServerPub,
            'live' => $serverPubLive,
            'ok' => ($cfgServerPub === '' || $serverPubLive === '') ? null : hash_equals($cfgServerPub, $serverPubLive),
        ];
        $checks['preshared_key'] = [
            'config' => $includeSecrets ? $cfgPsk : ($cfgPsk !== '' ? (substr($cfgPsk, 0, 6) . '...') : ''),
            'server_file' => $includeSecrets ? $serverPskFile : ($serverPskFile !== '' ? (substr($serverPskFile, 0, 6) . '...') : ''),
            'ok' => ($cfgPsk === '' || $serverPskFile === '') ? null : hash_equals($cfgPsk, $serverPskFile),
        ];

        echo json_encode([
            'success' => empty($mismatches),
            'server_id' => $serverId,
            'protocol_id' => $protocolId > 0 ? $protocolId : null,
            'client' => [
                'id' => (int) ($clientData['id'] ?? 0),
                'name' => $clientData['name'] ?? null,
                'client_ip' => $clientData['client_ip'] ?? null,
                'public_key_db' => $dbClientPub,
                'public_key_computed' => $computedClientPub,
                'address_in_config' => $cfgAddress,
                'endpoint_in_config' => $cfgEndpoint,
                'private_key' => $includeSecrets ? $cfgPrivate : ($cfgPrivate !== '' ? (substr($cfgPrivate, 0, 6) . '...') : ''),
            ],
            'wg' => [
                'server_public_key_live' => $serverPubLive,
                'server_listen_port_live' => $serverPortLive,
                'peer' => $peer,
            ],
            'checks' => $checks,
            'mismatches' => $mismatches,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Diagnose why WG/AWG handshake is not happening
// Collects server-side evidence: wg show, peer dump, docker port mapping, basic firewall/NAT snippets,
// and (if available) a short tcpdump capture on the VPN UDP port.
Router::post('/api/servers/{id}/protocols/diagnose-handshake', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    // High-sensitivity endpoint (firewall rules, tcpdump). Keep it admin-only unless explicitly enabled.
    $debugEnabled = debugRoutesEnabled();
    if (($user['role'] ?? '') !== 'admin' && !$debugEnabled) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $serverId = (int) ($params['id'] ?? 0);
    if ($serverId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid server id']);
        return;
    }

    $raw = file_get_contents('php://input');
    $data = [];
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }
    if (empty($data) && !empty($_POST)) {
        $data = $_POST;
    }
    if (!is_array($data)) {
        $data = [];
    }

    $clientId = isset($data['client_id']) ? (int) $data['client_id'] : 0;
    $duration = isset($data['duration_seconds']) ? (int) $data['duration_seconds'] : 5;
    if ($duration < 1)
        $duration = 1;
    if ($duration > 15)
        $duration = 15;

    $deriveWgPublicKey = function (string $privateKeyB64): array {
        $privateKeyB64 = trim($privateKeyB64);
        if ($privateKeyB64 === '') {
            return ['ok' => false, 'error' => 'empty_private_key'];
        }

        $raw = base64_decode($privateKeyB64, true);
        if ($raw === false || strlen($raw) !== 32) {
            return ['ok' => false, 'error' => 'invalid_private_key_base64_or_length'];
        }

        if (!function_exists('sodium_crypto_scalarmult_base')) {
            return ['ok' => false, 'error' => 'libsodium_not_available'];
        }

        try {
            $pubRaw = sodium_crypto_scalarmult_base($raw);
            return ['ok' => true, 'public_key' => base64_encode($pubRaw)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => 'derive_failed: ' . $e->getMessage()];
        }
    };

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $containerName = (string) ($serverData['container_name'] ?? 'amnezia-awg');
        $vpnPort = (int) ($serverData['vpn_port'] ?? 0);

        // Optionally derive client public key from stored client config
        $clientPub = '';
        $clientPubError = '';
        $clientIp = '';
        if ($clientId > 0) {
            $client = new VpnClient($clientId);
            $clientData = $client->getData();
            if (($clientData['server_id'] ?? null) != $serverId) {
                http_response_code(400);
                echo json_encode(['error' => 'client_id does not belong to server']);
                return;
            }
            if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden']);
                return;
            }

            $clientIp = (string) ($clientData['client_ip'] ?? '');

            $cfg = $client->getConfig();
            $cfgPrivate = '';
            if (preg_match('/^\s*PrivateKey\s*=\s*(.+)\s*$/mi', $cfg, $m)) {
                $cfgPrivate = trim($m[1]);
            }
            if ($cfgPrivate !== '') {
                $derived = $deriveWgPublicKey($cfgPrivate);
                if (!empty($derived['ok'])) {
                    $clientPub = (string) ($derived['public_key'] ?? '');
                } else {
                    $clientPubError = (string) ($derived['error'] ?? 'derive_failed');
                    // Fallback: compute using wg inside container (best-effort)
                    $shComputePub = "set -e; priv=" . escapeshellarg($cfgPrivate) . "; printf '%s' \"$priv\" | wg pubkey";
                    $cmdComputePub = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg($shComputePub);
                    $computed = trim((string) $server->executeCommand($cmdComputePub, true));
                    // Basic validation: wg outputs a 44-char base64 key
                    if (preg_match('/^[A-Za-z0-9+\/]{42}==$/', $computed)) {
                        $clientPub = $computed;
                        $clientPubError = '';
                    } elseif ($computed !== '') {
                        $clientPubError = 'wg_pubkey_failed: ' . $computed;
                    }
                }
            }
        }

        // Gather status
        $cmdHostDate = "date -u '+%Y-%m-%dT%H:%M:%SZ'";
        $hostDate = trim($server->executeCommand($cmdHostDate, true));

        $cmdDockerPs = "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' | head -50";
        $dockerPs = $server->executeCommand($cmdDockerPs, true);

        $cmdInspectPorts = "docker inspect " . escapeshellarg($containerName) . " --format '{{json .NetworkSettings.Ports}}' 2>/dev/null || true";
        $dockerPortsJson = trim($server->executeCommand($cmdInspectPorts, true));

        $cmdWgShow = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 2>/dev/null || true");
        $wgShow = $server->executeCommand($cmdWgShow, true);

        $cmdWgDump = "docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("wg show wg0 dump 2>/dev/null || true");
        $wgDump = $server->executeCommand($cmdWgDump, true);

        $cmdHostSs = ($vpnPort > 0)
            ? ("sh -c " . escapeshellarg("ss -lun | grep -E '(:" . (int) $vpnPort . ")\\b' || true"))
            : "sh -c 'echo no_vpn_port_in_db'";
        $hostUdpListen = $server->executeCommand($cmdHostSs, true);

        $cmdCtnSs = ($vpnPort > 0)
            ? ("docker exec -i " . escapeshellarg($containerName) . " sh -c " . escapeshellarg("ss -lun 2>/dev/null | grep -E '(:" . (int) $vpnPort . ")\\b' || true"))
            : "docker exec -i " . escapeshellarg($containerName) . " sh -c 'echo no_vpn_port_in_db'";
        $containerUdpListen = $server->executeCommand($cmdCtnSs, true);

        // Firewall/NAT snippets (best-effort)
        $cmdUfw = "sh -c " . escapeshellarg("ufw status verbose 2>/dev/null || echo 'no ufw'");
        $ufw = $server->executeCommand($cmdUfw, true);

        $cmdIpt = "sh -c " . escapeshellarg("iptables -S INPUT 2>/dev/null | grep -E 'udp|" . (int) $vpnPort . "' | head -80 || true");
        $iptablesInput = $server->executeCommand($cmdIpt, true);

        $cmdNft = "sh -c " . escapeshellarg("nft list ruleset 2>/dev/null | grep -n '" . (int) $vpnPort . "' | head -60 || true");
        $nftPortLines = $server->executeCommand($cmdNft, true);

        // Probe changes over time (wg dump + nft counters) during the same request.
        $wgShowAfter = '';
        $wgDumpAfter = '';
        $nftPortLinesAfter = '';
        if ($duration > 0) {
            $cmdSleep = "sh -c " . escapeshellarg("sleep " . (int) $duration);
            $server->executeCommand($cmdSleep, true);
            $wgShowAfter = $server->executeCommand($cmdWgShow, true);
            $wgDumpAfter = $server->executeCommand($cmdWgDump, true);
            $nftPortLinesAfter = $server->executeCommand($cmdNft, true);
        }

        // tcpdump capture (optional)
        $tcpdump = '';
        if ($vpnPort > 0) {
            $tcpCmd = "sh -c " . escapeshellarg(
                "command -v tcpdump >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 && timeout " . (int) $duration . " tcpdump -ni any udp port " . (int) $vpnPort . " -vv -c 10 2>/dev/null || echo 'tcpdump_unavailable_or_timeout_missing'"
            );
            $tcpdump = $server->executeCommand($tcpCmd, true);
        }

        // Try to extract peer line if clientPub is known
        $peerLine = '';
        $peerLineAfter = '';
        if ($clientPub !== '' && is_string($wgDump) && trim($wgDump) !== '') {
            $lines = preg_split('/\r?\n/', trim($wgDump));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, 'wg0')) {
                    continue;
                }
                $parts = preg_split('/\s+/', $line);
                if ($parts && isset($parts[0]) && hash_equals($parts[0], $clientPub)) {
                    $peerLine = $line;
                    break;
                }
            }
        }

        if ($clientPub !== '' && is_string($wgDumpAfter) && trim($wgDumpAfter) !== '') {
            $lines = preg_split('/\r?\n/', trim($wgDumpAfter));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, 'wg0')) {
                    continue;
                }
                $parts = preg_split('/\s+/', $line);
                if ($parts && isset($parts[0]) && hash_equals($parts[0], $clientPub)) {
                    $peerLineAfter = $line;
                    break;
                }
            }
        }

        $hints = [];
        if ($vpnPort <= 0) {
            $hints[] = 'vpn_port is missing in DB; endpoint may be wrong';
        }
        if (is_string($tcpdump) && str_contains($tcpdump, 'tcpdump_unavailable_or_timeout_missing')) {
            $hints[] = 'tcpdump/timeout not available on server; use nft counters or install tcpdump for deeper packet visibility';
        }
        if ($clientPub === '' && $clientPubError !== '') {
            $hints[] = 'failed to derive client public key from stored config: ' . $clientPubError;
        }
        if ($clientPub !== '' && $peerLine === '') {
            $hints[] = 'peer not found in wg dump for derived client public key (client might not be applied on server)';
        }

        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'checked_at_utc' => $hostDate,
            'container_name' => $containerName,
            'vpn_port_db' => $vpnPort,
            'client' => [
                'client_id' => $clientId > 0 ? $clientId : null,
                'client_ip' => $clientIp !== '' ? $clientIp : null,
                'client_public_key_derived' => $clientPub !== '' ? $clientPub : null,
                'client_public_key_derive_error' => $clientPubError !== '' ? $clientPubError : null,
                'peer_line_from_dump' => $peerLine !== '' ? $peerLine : null,
                'peer_line_from_dump_after' => $peerLineAfter !== '' ? $peerLineAfter : null,
            ],
            'evidence' => [
                'docker_ps' => $dockerPs,
                'docker_ports_json' => $dockerPortsJson,
                'host_udp_listen' => $hostUdpListen,
                'container_udp_listen' => $containerUdpListen,
                'wg_show' => $wgShow,
                'wg_dump' => $wgDump,
                'wg_show_after' => $wgShowAfter,
                'wg_dump_after' => $wgDumpAfter,
                'ufw' => $ufw,
                'iptables_input_snippet' => $iptablesInput,
                'nft_port_lines' => $nftPortLines,
                'nft_port_lines_after' => $nftPortLinesAfter,
                'tcpdump' => $tcpdump,
            ],
            'hints' => $hints,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Uninstall all protocols from server
Router::post('/api/servers/{id}/protocols/uninstall-all', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT sp.protocol_id, p.slug FROM server_protocols sp JOIN protocols p ON p.id = sp.protocol_id WHERE sp.server_id = ?');
        $stmt->execute([$serverId]);
        $rows = $stmt->fetchAll();

        $removedClients = 0;
        $removedBindings = 0;
        $uninstalled = [];
        $errors = [];

        foreach ($rows as $row) {
            $pid = (int) ($row['protocol_id'] ?? 0);
            $slug = (string) ($row['slug'] ?? '');
            if ($pid <= 0 || $slug === '') {
                continue;
            }

            try {
                $protocol = InstallProtocolManager::getById($pid);
                if (!$protocol) {
                    throw new Exception('Protocol not found');
                }

                InstallProtocolManager::uninstall($server, $protocol, []);

                $stmtDelSp = $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
                $stmtDelSp->execute([$serverId, $pid]);
                $removedBindings += (int) $stmtDelSp->rowCount();

                $stmtDelClients = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
                $stmtDelClients->execute([$serverId, $pid]);
                $removedClients += (int) $stmtDelClients->rowCount();

                $uninstalled[] = ['protocol_id' => $pid, 'slug' => $slug];
            } catch (Exception $e) {
                $errors[] = ['protocol_id' => $pid, 'slug' => $slug, 'error' => $e->getMessage()];
            }
        }

        $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?')->execute(['active', $serverId]);

        echo json_encode([
            'success' => empty($errors),
            'uninstalled' => $uninstalled,
            'errors' => $errors,
            'bindings_removed' => $removedBindings,
            'clients_removed' => $removedClients,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Uninstall protocol on server by slug
Router::post('/api/servers/{id}/protocols/{slug}/uninstall', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $serverId = (int) $params['id'];
    $slug = $params['slug'] ?? '';

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $protocol = InstallProtocolManager::getBySlug($slug);
        if (!$protocol) {
            http_response_code(404);
            echo json_encode(['error' => 'Protocol not found']);
            return;
        }

        $result = InstallProtocolManager::uninstall($server, $protocol);

        // Cleanup bindings + clients (same behavior as UI route)
        $pdo = DB::conn();
        $stmtId = $pdo->prepare('SELECT id FROM protocols WHERE slug = ? LIMIT 1');
        $stmtId->execute([$slug]);
        $pid = (int) $stmtId->fetchColumn();
        $deletedClients = 0;
        $deletedBindings = 0;
        if ($pid) {
            $stmtDelSp = $pdo->prepare('DELETE FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $stmtDelSp->execute([$serverId, $pid]);
            $deletedBindings = $stmtDelSp->rowCount();
            $stmtDelClients = $pdo->prepare('DELETE FROM vpn_clients WHERE server_id = ? AND protocol_id = ?');
            $stmtDelClients->execute([$serverId, $pid]);
            $deletedClients = $stmtDelClients->rowCount();
        }
        $stmtUpdate = $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = NULL WHERE id = ?');
        $stmtUpdate->execute(['active', $serverId]);

        echo json_encode(array_merge($result, [
            'bindings_removed' => $deletedBindings,
            'clients_removed' => $deletedClients
        ]), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Create client
Router::post('/api/clients/create', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $serverId = (int) ($data['server_id'] ?? 0);
    $name = trim($data['name'] ?? '');
    $expiresInDays = isset($data['expires_in_days']) ? (int) $data['expires_in_days'] : null;
    $protocolId = isset($data['protocol_id']) ? (int) $data['protocol_id'] : null;
    $username = isset($data['username']) ? trim((string) $data['username']) : null;
    $login = isset($data['login']) ? trim((string) $data['login']) : null;

    if ($serverId <= 0 || empty($name)) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id and name are required']);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        if (($serverData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        // Validate protocol_id is installed on server (if provided)
        if ($protocolId !== null && $protocolId > 0) {
            $pdo = DB::conn();
            $chk = $pdo->prepare('SELECT 1 FROM server_protocols WHERE server_id = ? AND protocol_id = ?');
            $chk->execute([$serverId, $protocolId]);
            if (!$chk->fetchColumn()) {
                http_response_code(400);
                echo json_encode(['error' => 'protocol_id is not installed on this server']);
                return;
            }
        } else {
            $protocolId = null;
        }

        $clientId = VpnClient::create($serverId, (int) $user['id'], $name, $expiresInDays, $protocolId, $username, $login);

        $client = new VpnClient($clientId);

        // For WireGuard/AWG protocols, immediately regenerate config from live server state
        // (AWG junk params + keys can change after reinstall/recreate).
        // For amnezia-wg-advanced, fail fast if we can't obtain AWG params.
        try {
            $regen = $client->regenerateConfigFromServer(true);
            if (is_array($regen) && empty($regen['success']) && ($regen['error'] ?? '') === 'awg_params_missing') {
                http_response_code(500);
                echo json_encode([
                    'error' => 'Failed to generate AWG-Advanced config: missing server AWG params',
                    'result' => $regen,
                ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                return;
            }
        } catch (Throwable $e) {
            error_log('Failed to regenerate config after create: ' . $e->getMessage());
        }

        $clientData = $client->getData();

        // Return client data with config and QR code
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'expires_at' => $clientData['expires_at'],
                'created_at' => $clientData['created_at'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Force-regenerate client config/QR from current server state (WireGuard/AWG)
Router::post('/api/clients/{id}/regenerate-config', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) ($params['id'] ?? 0);
    if ($clientId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid client id']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (($clientData['user_id'] ?? null) != $user['id'] && ($user['role'] ?? '') !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $client->regenerateConfigFromServer(true);
        $clientData = $client->getData();

        echo json_encode([
            'success' => !empty($result['success']),
            'result' => $result,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ],
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client expiration
Router::post('/api/clients/{id}/set-expiration', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $expiresAt = $data['expires_at'] ?? null; // Y-m-d H:i:s format or null

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        VpnClient::setExpiration($clientId, $expiresAt);

        echo json_encode([
            'success' => true,
            'expires_at' => $expiresAt
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Extend client expiration
Router::post('/api/clients/{id}/extend', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $days = (int) ($data['days'] ?? 30);

    if ($days <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'days must be positive']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        VpnClient::extendExpiration($clientId, $days);

        // Get updated expiration
        $client = new VpnClient($clientId);
        $updated = $client->getData();

        echo json_encode([
            'success' => true,
            'expires_at' => $updated['expires_at'],
            'extended_days' => $days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get expiring clients
Router::get('/api/clients/expiring', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $days = (int) ($_GET['days'] ?? 7);

    try {
        $clients = VpnClient::getExpiringClients($days);

        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function ($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }

        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client traffic limit
Router::post('/api/clients/{id}/set-traffic-limit', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    // limit_bytes can be null (unlimited) or positive integer
    $limitBytes = isset($data['limit_bytes']) ? (int) $data['limit_bytes'] : null;

    if ($limitBytes !== null && $limitBytes < 0) {
        http_response_code(400);
        echo json_encode(['error' => 'limit_bytes must be positive or null for unlimited']);
        return;
    }

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $client->setTrafficLimit($limitBytes);

        echo json_encode([
            'success' => true,
            'limit_bytes' => $limitBytes,
            'limit_gb' => $limitBytes ? round($limitBytes / 1073741824, 2) : null
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Check client traffic limit status
Router::get('/api/clients/{id}/traffic-limit-status', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $clientId = (int) $params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $status = $client->getTrafficLimitStatus();

        echo json_encode([
            'success' => true,
            'status' => $status
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get clients over traffic limit
Router::get('/api/clients/overlimit', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    try {
        $clients = VpnClient::getClientsOverLimit();

        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function ($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }

        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * SETTINGS ROUTES
 */

// Settings page
Router::get('/settings', function () {
    requireAuth();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->index();
});

Router::get('/settings/protocols', function () {
    requireAdmin();
    $params = [];
    if (isset($_GET['id'])) {
        $params[] = 'id=' . urlencode($_GET['id']);
    }
    if (isset($_GET['new'])) {
        $params[] = 'new=1';
    }
    $query = empty($params) ? '' : ('?' . implode('&', $params));
    redirect('/settings' . $query . '#protocols');
});

// Legacy protocol routes removed in favor of ProtocolManagementController and /api/protocols endpoints

// NEW PROTOCOL MANAGEMENT ROUTES
Router::get('/settings/protocols-management', function () {
    requireAdmin();
    redirect('/settings#protocols');
});
Router::get('/settings/protocols/new', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $_GET['new'] = 1;
    $controller->index();
});

Router::get('/settings/protocols/{id}/edit', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $_GET['id'] = $params['id'];
    $controller->index();
});

Router::get('/settings/protocols/{id}/template', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    // This will render the template editor component
    $_GET['id'] = $params['id'];
    $_GET['template'] = 1;
    $controller->index();
});

// POST route to save/update protocol
Router::post('/settings/protocols/save', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->save();
});

// API ROUTES FOR PROTOCOLS
Router::get('/api/protocols', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiGetProtocols();
});

Router::get('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiGetProtocol((int) $params['id']);
});

Router::post('/api/protocols', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiCreateProtocol();
});

Router::put('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiUpdateProtocol((int) $params['id']);
});

Router::delete('/api/protocols/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiDeleteProtocol((int) $params['id']);
});

Router::post('/api/protocols/{id}/test-install', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestInstallProtocol((int) $params['id']);
});

Router::get('/api/protocols/{id}/test-install/stream', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestInstallProtocolStream((int) $params['id']);
});

Router::get('/api/protocols/{id}/test-uninstall/stream', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/ProtocolManagementController.php';
    $controller = new ProtocolManagementController();
    $controller->apiTestUninstallProtocolStream((int) $params['id']);
});

// AI ASSISTANT ROUTES
Router::post('/api/ai/assist', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->assist();
});

Router::get('/api/ai/models', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->getModels();
});

Router::post('/api/ai/test-model', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->testModel();
});

Router::get('/api/protocols/{id}/ai-history', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->getGenerationHistory((int) $params['id']);
});

Router::post('/api/ai/generations/{id}/apply', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->applyGeneration((int) $params['id']);
});

Router::get('/ai/preview/{id}', function ($params) {
    requireAdmin();
    require_once __DIR__ . '/../controllers/AIController.php';
    $controller = new AIController();
    $controller->previewGeneration((int) $params['id']);
});

// Save API key
Router::post('/settings/api-key', function () {
    requireAdmin();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveApiKey();
});

// Change password
Router::post('/settings/change-password', function () {
    requireAuth();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->changePassword();
});

// Update profile
Router::post('/settings/profile', function () {
    requireAuth();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->updateProfile();
});

// Add user
Router::post('/settings/add-user', function () {
    requireAdmin();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->addUser();
});

// Delete user
Router::post('/settings/delete-user/{id}', function ($params) {
    requireAdmin();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->deleteUser($params['id']);
});

// LDAP settings page
Router::get('/settings/ldap', function () {
    requireAdmin();
    redirect('/settings#ldap');
});

// Save LDAP settings
Router::post('/settings/ldap/save', function () {
    requireAdmin();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->saveLdapSettings();
});

// Test LDAP connection
Router::post('/settings/ldap/test', function () {
    requireAdmin();

    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->testLdapConnection();
});

/**
 * LANGUAGE ROUTES
 */

// Change language
Router::post('/language/change', function () {
    $lang = $_POST['language'] ?? '';

    if (Translator::setLanguage($lang)) {
        $_SESSION['success'] = 'Language changed successfully';
    } else {
        $_SESSION['error'] = 'Invalid language';
    }

    $redirect = $_POST['redirect'] ?? '/dashboard';
    redirect($redirect);
});

Router::get('/language/change', function () {
    redirect('/dashboard');
});

// API: Get translation statistics
Router::get('/api/translations/stats', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $stats = Translator::getStatistics();
    echo json_encode(['stats' => $stats]);
});

// API: Auto-translate missing keys
Router::post('/api/translations/auto-translate', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    $targetLang = $data['language'] ?? '';

    if (empty($targetLang)) {
        http_response_code(400);
        echo json_encode(['error' => 'Language is required']);
        return;
    }

    try {
        $stats = Translator::translateMissingKeys($targetLang);
        echo json_encode([
            'success' => true,
            'stats' => $stats
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Export translations
Router::get('/api/translations/export/{lang}', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user)
        return;

    $lang = $params['lang'];

    try {
        $json = Translator::exportToJson($lang);
        header('Content-Disposition: attachment; filename="translations_' . $lang . '.json"');
        echo $json;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// ===== Scenario Management Routes (Admin Only) =====

// List scenarios
Router::get('/admin/scenarios', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->listScenarios();
});

// Create scenario form
Router::get('/admin/scenario/create', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->createScenarioForm();
});

// View scenario
Router::get('/admin/scenario/{id}', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->viewScenario((int) $params['id']);
});

// Edit scenario form
Router::get('/admin/scenario/{id}/edit', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->editScenarioForm((int) $params['id']);
});

// Save scenario (create/update)
Router::post('/admin/scenario', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->saveScenario();
});

// Delete scenario
Router::post('/admin/scenario/{id}/delete', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->deleteScenario((int) $params['id']);
});

// Test scenario
Router::post('/admin/scenario/{id}/test', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->testScenario((int) $params['id']);
});

// Export scenario
Router::get('/admin/scenario/{id}/export', function ($params) {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->exportScenario((int) $params['id']);
});

// Import scenario
Router::post('/admin/scenario/import', function () {
    requireAdmin();
    $controller = new ScenarioController();
    $controller->importScenario();
});

// ===== Logs Management Routes (Admin Only) =====

// List and view logs
Router::get('/admin/logs', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->index();
});

// Download log file
Router::get('/admin/logs/download', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->download();
});

// Delete log file
Router::post('/admin/logs/delete', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->delete();
});

// Clear all logs
Router::post('/admin/logs/clear-all', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->clearAll();
});

// Search logs
Router::post('/admin/logs/search', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->search();
});

// Get log statistics
Router::post('/admin/logs/stats', function () {
    requireAdmin();
    require_once __DIR__ . '/../controllers/LogsController.php';
    $controller = new LogsController();
    $controller->stats();
});

// Dispatch router
Router::dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);
