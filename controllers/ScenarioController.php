<?php

/**
 * ScenarioController
 * Manages protocol installation scenarios (CRUD operations)
 * Allows administrators to view, create, edit, and delete VPN protocol deployment scenarios
 */
class ScenarioController {

    /**
     * List all protocol scenarios
     * GET /admin/scenarios
     */
    public function listScenarios() {
        requireAdmin();
        
        $scenarios = InstallProtocolManager::getAll();
        
        View::render('settings/scenarios.twig', [
            'scenarios' => $scenarios,
            'section' => 'scenarios'
        ]);
    }

    /**
     * View single scenario details
     * GET /admin/scenario/:id
     */
    public function viewScenario($id) {
        requireAdmin();
        
        $scenario = InstallProtocolManager::getById((int)$id);
        if (!$scenario) {
            http_response_code(404);
            View::render('404.twig');
            return;
        }
        
        $definition = $scenario['definition'] ?? [];
        
        View::render('settings/scenario_view.twig', [
            'scenario' => $scenario,
            'definition' => $definition,
            'section' => 'scenarios'
        ]);
    }

    /**
     * Show form to create new scenario
     * GET /admin/scenario/create
     */
    public function createScenarioForm() {
        requireAdmin();
        
        $templateDefinition = [
            'engine' => 'shell',
            'metadata' => [
                'container_name' => 'custom-container',
                'config_path' => '/opt/amnezia/custom'
            ],
            'scripts' => [
                'detect' => 'echo \'{"status":"absent","message":"Custom protocol not found"}\'',
                'install' => 'echo \'{"success":true,"message":"Custom protocol installed"}\'',
                'restore' => 'echo \'{"success":true,"message":"Custom protocol restored"}\''
            ]
        ];
        
        View::render('settings/scenario_form.twig', [
            'scenario' => null,
            'templateDefinition' => json_encode($templateDefinition, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'section' => 'scenarios'
        ]);
    }

    /**
     * Show form to edit existing scenario
     * GET /admin/scenario/:id/edit
     */
    public function editScenarioForm($id) {
        requireAdmin();
        
        $scenario = InstallProtocolManager::getById((int)$id);
        if (!$scenario) {
            http_response_code(404);
            View::render('404.twig');
            return;
        }
        
        $definitionJson = json_encode($scenario['definition'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        
        View::render('settings/scenario_form.twig', [
            'scenario' => $scenario,
            'templateDefinition' => $definitionJson,
            'section' => 'scenarios'
        ]);
    }

    /**
     * Save scenario (create or update)
     * POST /admin/scenario
     */
    public function saveScenario() {
        requireAdmin();
        
        $data = $_POST;
        
        // Validate required fields
        if (empty($data['slug']) || empty($data['name'])) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Slug and name are required'
            ]);
            return;
        }
        
        // Parse definition JSON
        if (!empty($data['definition'])) {
            if (is_string($data['definition'])) {
                $definition = json_decode($data['definition'], true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    header('Content-Type: application/json');
                    http_response_code(400);
                    echo json_encode([
                        'success' => false,
                        'message' => 'Invalid JSON in definition: ' . json_last_error_msg()
                    ]);
                    return;
                }
            } else {
                $definition = $data['definition'];
            }
        } else {
            $definition = [];
        }
        
        // Validate definition structure
        if (empty($definition['engine'])) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Definition must have "engine" field'
            ]);
            return;
        }
        
        $saveData = [
            'slug' => $data['slug'],
            'name' => $data['name'],
            'description' => $data['description'] ?? null,
            'definition' => $definition,
            'is_active' => isset($data['is_active']) ? (int)$data['is_active'] : 1
        ];
        
        if (!empty($data['id'])) {
            $saveData['id'] = (int)$data['id'];
        }
        
        try {
            $id = InstallProtocolManager::save($saveData);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'id' => $id,
                'message' => 'Scenario saved successfully',
                'redirect' => '/admin/scenarios'
            ]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'Error saving scenario: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Delete scenario
     * DELETE /admin/scenario/:id or POST /admin/scenario/:id/delete
     */
    public function deleteScenario($id) {
        requireAdmin();
        
        $id = (int)$id;
        
        // Prevent deletion of default scenario
        $scenario = InstallProtocolManager::getById($id);
        if (!$scenario) {
            header('Content-Type: application/json');
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'message' => 'Scenario not found'
            ]);
            return;
        }
        
        if ($scenario['slug'] === InstallProtocolManager::getDefaultSlug()) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Cannot delete default scenario'
            ]);
            return;
        }
        
        try {
            InstallProtocolManager::delete($id);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'message' => 'Scenario deleted successfully',
                'redirect' => '/admin/scenarios'
            ]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'Error deleting scenario: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Test scenario script (detection)
     * POST /admin/scenario/:id/test
     */
    public function testScenario($id) {
        requireAdmin();
        
        $scenario = InstallProtocolManager::getById((int)$id);
        if (!$scenario) {
            header('Content-Type: application/json');
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'message' => 'Scenario not found'
            ]);
            return;
        }
        
        $serverId = (int)($_POST['server_id'] ?? 0);
        if (!$serverId) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Server ID required'
            ]);
            return;
        }
        
        $server = new VpnServer($serverId);
        if (!$server->getData()) {
            header('Content-Type: application/json');
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'message' => 'Server not found'
            ]);
            return;
        }
        
        try {
            // Test SSH connection first
            if (!$server->testConnection()) {
                throw new Exception('SSH connection to server failed');
            }
            
            // Run detection script
            $result = InstallProtocolManager::runDetection($server, $scenario);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'result' => $result
            ]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'Error testing scenario: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Export scenario as JSON
     * GET /admin/scenario/:id/export
     */
    public function exportScenario($id) {
        requireAdmin();
        
        $scenario = InstallProtocolManager::getById((int)$id);
        if (!$scenario) {
            http_response_code(404);
            return;
        }
        
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="scenario-' . $scenario['slug'] . '-' . date('Y-m-d') . '.json"');
        
        // Remove database IDs from export
        unset($scenario['id']);
        
        echo json_encode($scenario, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Import scenario from JSON
     * POST /admin/scenario/import
     */
    public function importScenario() {
        requireAdmin();
        
        $file = $_FILES['file'] ?? null;
        if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'No file provided'
            ]);
            return;
        }
        
        $contents = file_get_contents($file['tmp_name']);
        $scenario = json_decode($contents, true);
        
        if (!is_array($scenario)) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Invalid JSON file'
            ]);
            return;
        }
        
        try {
            // Remove ID so it creates a new entry
            unset($scenario['id']);
            
            // Ensure required fields exist
            if (empty($scenario['slug']) || empty($scenario['name'])) {
                throw new Exception('Imported scenario must have slug and name');
            }
            
            $id = InstallProtocolManager::save($scenario);
            
            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'id' => $id,
                'message' => 'Scenario imported successfully',
                'redirect' => '/admin/scenarios'
            ]);
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'Error importing scenario: ' . $e->getMessage()
            ]);
        }
    }
}
