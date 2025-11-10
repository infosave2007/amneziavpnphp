<?php

class SettingsController {
    private $pdo;
    private $translator;
    
    public function __construct() {
        $this->pdo = DB::conn();
        $this->translator = new Translator();
    }
    
    public function index() {
        $stats = $this->getTranslationStats();
        $users = $this->getAllUsers();
        $apiKey = $this->getApiKey('openrouter');
        
        $data = [
            'translation_stats' => $stats,
            'users' => $users,
            'openrouter_key' => $apiKey
        ];
        
        // Check for session messages
        if (isset($_SESSION['settings_success'])) {
            $data['success'] = $_SESSION['settings_success'];
            unset($_SESSION['settings_success']);
        }
        if (isset($_SESSION['settings_error'])) {
            $data['error'] = $_SESSION['settings_error'];
            unset($_SESSION['settings_error']);
        }
        
        View::render('settings.twig', $data);
    }
    
    public function changePassword() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $user = Auth::user();
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $_SESSION['settings_error'] = 'All fields are required';
            header('Location: /settings#profile');
            exit;
        }
        
        if ($newPassword !== $confirmPassword) {
            $_SESSION['settings_error'] = 'New passwords do not match';
            header('Location: /settings#profile');
            exit;
        }
        
        if (strlen($newPassword) < 6) {
            $_SESSION['settings_error'] = 'Password must be at least 6 characters';
            header('Location: /settings#profile');
            exit;
        }
        
        // Verify current password
        if (!password_verify($currentPassword, $user['password_hash'])) {
            $_SESSION['settings_error'] = 'Current password is incorrect';
            header('Location: /settings#profile');
            exit;
        }
        
        // Update password
        $newHash = password_hash($newPassword, PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->execute([$newHash, $user['id']]);
        
        $_SESSION['settings_success'] = 'Password changed successfully';
        header('Location: /settings#profile');
        exit;
    }
    
    public function addUser() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'user';
        
        if (empty($name) || empty($email) || empty($password)) {
            $_SESSION['settings_error'] = 'All fields are required';
            header('Location: /settings#users');
            exit;
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['settings_error'] = 'Invalid email address';
            header('Location: /settings#users');
            exit;
        }
        
        if (strlen($password) < 6) {
            $_SESSION['settings_error'] = 'Password must be at least 6 characters';
            header('Location: /settings#users');
            exit;
        }
        
        // Check if email already exists
        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $_SESSION['settings_error'] = 'Email already exists';
            header('Location: /settings#users');
            exit;
        }
        
        // Create user
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)");
        $stmt->execute([$name, $email, $passwordHash, $role]);
        
        $_SESSION['settings_success'] = 'User added successfully';
        header('Location: /settings#users');
        exit;
    }
    
    public function deleteUser($userId) {
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($userId == $user['id']) {
            $_SESSION['settings_error'] = 'Cannot delete yourself';
            header('Location: /settings#users');
            exit;
        }
        
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        
        $_SESSION['settings_success'] = 'User deleted successfully';
        header('Location: /settings#users');
        exit;
    }
    
    private function getAllUsers() {
        $stmt = $this->pdo->query("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC");
        return $stmt->fetchAll();
    }
    
    private function getApiKey($service) {
        $stmt = $this->pdo->prepare("SELECT api_key FROM api_keys WHERE service_name = ? AND is_active = 1");
        $stmt->execute([$service]);
        $result = $stmt->fetch();
        return $result ? $result['api_key'] : null;
    }
    
    public function saveApiKey() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings');
            exit;
        }
        
        $service = $_POST['service'] ?? '';
        $apiKey = trim($_POST['api_key'] ?? '');
        $skipTest = isset($_POST['skip_test']); // Allow saving without testing
        
        if (empty($service) || empty($apiKey)) {
            View::render('settings.twig', [
                'error' => $this->translator->translate('settings.error_empty_key'),
                'translation_stats' => $this->getTranslationStats()
            ]);
            return;
        }
        
        // Test the API key (unless skip_test is set)
        if ($service === 'openrouter' && !$skipTest) {
            $testResult = $this->testOpenRouterKey($apiKey);
            if (!$testResult['success']) {
                // If rate limited, suggest saving without test
                $errorMsg = $this->translator->translate('settings.error_key_test') . ': ' . $testResult['error'];
                if (strpos($testResult['error'], '429') !== false || strpos($testResult['error'], 'Rate limit') !== false) {
                    $errorMsg .= ' - You can save without testing by checking "Skip validation"';
                }
                
                View::render('settings.twig', [
                    'error' => $errorMsg,
                    'translation_stats' => $this->getTranslationStats(),
                    'openrouter_key' => ''
                ]);
                return;
            }
        }
        
        // Save the key
        $saved = $this->translator->saveApiKey($service, $apiKey);
        
        if ($saved) {
            $_SESSION['settings_success'] = $this->translator->translate('settings.key_saved');
            header('Location: /settings#api');
            exit;
        } else {
            $_SESSION['settings_error'] = $this->translator->translate('message.error');
            header('Location: /settings#api');
            exit;
        }
    }
    
    private function testOpenRouterKey($apiKey) {
        // Test with a simple request to check API key validity
        $url = 'https://openrouter.ai/api/v1/chat/completions';
        $data = [
            'model' => 'openai/gpt-4o-mini',
            'messages' => [
                ['role' => 'user', 'content' => 'Reply with: OK']
            ],
            'max_tokens' => 5
        ];
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $apiKey,
            'HTTP-Referer: https://amnez.ia',
            'X-Title: Amnezia VPN Panel'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        // Handle cURL errors
        if ($curlError) {
            return [
                'success' => false,
                'error' => 'Network error: ' . $curlError
            ];
        }
        
        // Parse response
        $result = json_decode($response, true);
        
        // Success - got a valid response
        if ($httpCode === 200 && isset($result['choices'][0]['message'])) {
            return ['success' => true];
        }
        
        // Extract error message from various formats
        $errorMsg = 'Unknown error';
        
        if (isset($result['error'])) {
            if (is_string($result['error'])) {
                $errorMsg = $result['error'];
            } elseif (isset($result['error']['message'])) {
                $errorMsg = $result['error']['message'];
            } elseif (isset($result['error']['code'])) {
                $errorMsg = 'Error code: ' . $result['error']['code'];
            }
        }
        
        // Add HTTP code if not 200
        if ($httpCode !== 200) {
            $errorMsg .= ' (HTTP ' . $httpCode . ')';
        }
        
        // Common error messages user-friendly translations
        if (strpos($errorMsg, 'No auth credentials') !== false || $httpCode === 401) {
            $errorMsg = 'Invalid API key or authentication failed';
        } elseif (strpos($errorMsg, 'insufficient_quota') !== false || strpos($errorMsg, 'quota') !== false) {
            $errorMsg = 'API quota exceeded or no credits available';
        } elseif (strpos($errorMsg, 'rate_limit') !== false) {
            $errorMsg = 'Rate limit exceeded, try again later';
        }
        
        return [
            'success' => false,
            'error' => $errorMsg
        ];
    }
    
    private function getTranslationStats() {
        // Get all languages
        $stmt = $this->pdo->query("SELECT * FROM languages ORDER BY code");
        $languages = $stmt->fetchAll();
        
        // Get total translation keys count (distinct category + key_name combinations)
        $stmt = $this->pdo->query("SELECT COUNT(DISTINCT CONCAT(category, '.', key_name)) as count FROM translations WHERE locale = 'en'");
        $totalKeys = $stmt->fetch();
        $totalCount = $totalKeys['count'];
        
        $stats = [];
        foreach ($languages as $lang) {
            $stmt = $this->pdo->prepare(
                "SELECT COUNT(*) as count FROM translations WHERE locale = ? AND translation IS NOT NULL AND translation != ''"
            );
            $stmt->execute([$lang['code']]);
            $translated = $stmt->fetch();
            
            $stats[] = [
                'code' => $lang['code'],
                'name' => $lang['name'],
                'native_name' => $lang['native_name'],
                'total_count' => $totalCount,
                'translated_count' => $translated['count']
            ];
        }
        
        return $stats;
    }
    
    public function ldapSettings() {
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        // Get LDAP configuration
        $stmt = $this->pdo->query("SELECT * FROM ldap_configs WHERE id = 1");
        $config = $stmt->fetch() ?: [];
        
        // Get group mappings
        $stmt = $this->pdo->query("SELECT * FROM ldap_group_mappings ORDER BY ldap_group");
        $mappings = $stmt->fetchAll();
        
        $data = [
            'config' => $config,
            'mappings' => $mappings
        ];
        
        // Check for session messages
        if (isset($_SESSION['settings_success'])) {
            $data['success'] = $_SESSION['settings_success'];
            unset($_SESSION['settings_success']);
        }
        if (isset($_SESSION['settings_error'])) {
            $data['error'] = $_SESSION['settings_error'];
            unset($_SESSION['settings_error']);
        }
        
        View::render('settings/ldap.twig', $data);
    }
    
    public function saveLdapSettings() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /settings/ldap');
            exit;
        }
        
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Forbidden']);
            return;
        }
        
        $enabled = isset($_POST['enabled']) ? 1 : 0;
        $host = trim($_POST['host'] ?? '');
        $port = intval($_POST['port'] ?? 389);
        $useTls = isset($_POST['use_tls']) ? 1 : 0;
        $baseDn = trim($_POST['base_dn'] ?? '');
        $bindDn = trim($_POST['bind_dn'] ?? '');
        $bindPassword = $_POST['bind_password'] ?? '';
        $userSearchFilter = trim($_POST['user_search_filter'] ?? '(uid=%s)');
        $groupSearchFilter = trim($_POST['group_search_filter'] ?? '(memberUid=%s)');
        $syncInterval = intval($_POST['sync_interval'] ?? 30);
        
        if (empty($host) || empty($baseDn) || empty($bindDn)) {
            $_SESSION['settings_error'] = 'Host, Base DN, and Bind DN are required';
            header('Location: /settings/ldap');
            exit;
        }
        
        // Update or insert configuration
        $stmt = $this->pdo->prepare("
            INSERT INTO ldap_configs 
            (id, enabled, host, port, use_tls, base_dn, bind_dn, bind_password, user_search_filter, group_search_filter, sync_interval)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            enabled = VALUES(enabled),
            host = VALUES(host),
            port = VALUES(port),
            use_tls = VALUES(use_tls),
            base_dn = VALUES(base_dn),
            bind_dn = VALUES(bind_dn),
            bind_password = VALUES(bind_password),
            user_search_filter = VALUES(user_search_filter),
            group_search_filter = VALUES(group_search_filter),
            sync_interval = VALUES(sync_interval)
        ");
        
        $stmt->execute([
            $enabled,
            $host,
            $port,
            $useTls,
            $baseDn,
            $bindDn,
            $bindPassword,
            $userSearchFilter,
            $groupSearchFilter,
            $syncInterval
        ]);
        
        $_SESSION['settings_success'] = 'LDAP settings saved successfully';
        header('Location: /settings/ldap');
        exit;
    }
    
    public function testLdapConnection() {
        header('Content-Type: application/json');
        
        $user = Auth::user();
        if ($user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Forbidden']);
            return;
        }
        
        try {
            $ldap = new LdapSync();
            
            if (!$ldap->isEnabled()) {
                echo json_encode([
                    'success' => false,
                    'message' => 'LDAP is not enabled. Please save configuration first.'
                ]);
                return;
            }
            
            $result = $ldap->testConnection();
            echo json_encode($result);
            
        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error: ' . $e->getMessage()
            ]);
        }
    }
}
