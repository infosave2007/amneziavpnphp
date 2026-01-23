<?php

class AIController
{

    private $openRouterService;

    public function __construct()
    {
        $this->openRouterService = new OpenRouterService();
    }

    /**
     * AI Assistant endpoint for generating installation scripts
     */
    public function assist(): void
    {
        requireAdmin();

        try {
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }

            $prompt = trim($input['prompt'] ?? '');
            $model = trim($input['model'] ?? 'openai/gpt-3.5-turbo');
            $protocolType = trim($input['protocol_type'] ?? '');
            $protocolId = isset($input['protocol_id']) ? (int) $input['protocol_id'] : null;
            $target = trim($input['target'] ?? 'install'); // install, uninstall, template

            if (empty($prompt)) {
                throw new Exception('Prompt is required');
            }

            // Generate enhanced prompt based on protocol type and target
            $enhancedPrompt = $this->enhancePrompt($prompt, $protocolType, $target);

            // Call OpenRouter API
            $response = $this->openRouterService->generateScript($enhancedPrompt, $model);

            // Save AI generation to database
            $generationId = $this->saveAIGeneration([
                'protocol_id' => $protocolId,
                'model_used' => $model,
                'prompt' => "[$target] " . $prompt,
                'generated_script' => $response['script'] ?? '',
                'suggestions' => json_encode($response['suggestions'] ?? []),
                'ubuntu_compatible' => $response['ubuntu_compatible'] ?? null,
                'created_at' => date('Y-m-d H:i:s')
            ]);

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => [
                    'script' => $response['script'] ?? '',
                    'suggestions' => $response['suggestions'] ?? [],
                    'ubuntu_compatible' => $response['ubuntu_compatible'] ?? false,
                    'estimated_time' => $response['estimated_time'] ?? '5 minutes',
                    'model_used' => $model,
                    'generation_id' => $generationId,
                    'target' => $target
                ]
            ]);

        } catch (Exception $e) {
            error_log("Error in AIController::assist: " . $e->getMessage());
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Get available AI models
     */
    public function getModels(): void
    {
        requireAdmin();

        try {
            $models = $this->openRouterService->getAvailableModels();

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $models
            ]);

        } catch (Exception $e) {
            error_log("Error in AIController::getModels: " . $e->getMessage());
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    public function testModel(): void
    {
        requireAdmin();
        header('Content-Type: application/json');

        try {
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }

            $model = trim($input['model'] ?? '');
            if ($model === '') {
                throw new Exception('Model id is required');
            }

            $result = $this->openRouterService->testModelAvailability($model);

            echo json_encode([
                'success' => $result['success'] ?? false,
                'message' => $result['message'] ?? null,
                'http_code' => $result['http_code'] ?? null
            ]);

        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Get AI generation history for a protocol
     */
    public function getGenerationHistory(int $protocolId): void
    {
        requireAdmin();

        try {
            $generations = $this->getAIGenerationsByProtocol($protocolId);

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'data' => $generations
            ]);

        } catch (Exception $e) {
            error_log("Error in AIController::getGenerationHistory: " . $e->getMessage());
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Apply AI-generated script to protocol
     */
    public function applyGeneration(int $generationId): void
    {
        requireAdmin();

        try {
            $generation = $this->getAIGeneration($generationId);
            if (!$generation) {
                throw new Exception('AI generation not found');
            }

            if (!$generation['protocol_id']) {
                throw new Exception('This generation is not associated with any protocol');
            }

            // Determine target from prompt
            $target = 'install';
            if (preg_match('/^\[(uninstall|template)\]/', $generation['prompt'], $matches)) {
                $target = $matches[1];
            }

            // Update protocol with generated script
            $pdo = DB::conn();

            if ($target === 'uninstall') {
                $stmt = $pdo->prepare('
                    UPDATE protocols 
                    SET uninstall_script = ?, updated_at = ?
                    WHERE id = ?
                ');
                $stmt->execute([
                    $generation['generated_script'],
                    date('Y-m-d H:i:s'),
                    $generation['protocol_id']
                ]);
            } elseif ($target === 'template') {
                $stmt = $pdo->prepare('
                    UPDATE protocols 
                    SET output_template = ?, updated_at = ?
                    WHERE id = ?
                ');
                $stmt->execute([
                    $generation['generated_script'],
                    date('Y-m-d H:i:s'),
                    $generation['protocol_id']
                ]);
            } else {
                $stmt = $pdo->prepare('
                    UPDATE protocols 
                    SET install_script = ?, ubuntu_compatible = ?, updated_at = ?
                    WHERE id = ?
                ');
                $stmt->execute([
                    $generation['generated_script'],
                    $generation['ubuntu_compatible'],
                    date('Y-m-d H:i:s'),
                    $generation['protocol_id']
                ]);
            }

            header('Content-Type: application/json');
            echo json_encode([
                'success' => true,
                'message' => 'AI-generated script applied to protocol successfully'
            ]);

        } catch (Exception $e) {
            error_log("Error in AIController::applyGeneration: " . $e->getMessage());
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Preview AI-generated script with syntax highlighting
     */
    public function previewGeneration(int $generationId): void
    {
        requireAdmin();

        try {
            $generation = $this->getAIGeneration($generationId);
            if (!$generation) {
                throw new Exception('AI generation not found');
            }

            View::render('ai/preview_generation.twig', [
                'generation' => $generation,
                'script' => $generation['generated_script'],
                'suggestions' => json_decode($generation['suggestions'], true) ?? []
            ]);

        } catch (Exception $e) {
            $_SESSION['protocol_error'] = $e->getMessage();
            redirect('/settings/protocols');
        }
    }

    /**
     * Enhance user prompt with context and requirements
     */
    private function enhancePrompt(string $prompt, string $protocolType, string $target = 'install'): string
    {
        $context = "";

        if ($target === 'uninstall') {
            $context = "Create a bash uninstallation script for a VPN protocol. ";
        } elseif ($target === 'template') {
            $context = "Create a WireGuard-compatible client config template. ";
        } else {
            $context = "Create a bash installation script for a VPN protocol. ";
        }

        if ($protocolType) {
            $context .= "This is for a $protocolType protocol. ";
        }

        $context .= "Requirements:\n";

        if ($target === 'template') {
            $context .= "- Use Mustache-style placeholders like {{private_key}}, {{client_ip}}, {{server_host}}, {{server_port}}\n";
            $context .= "- The template should be valid configuration format (e.g. .conf for WireGuard)\n";
        } elseif ($target === 'uninstall') {
            $context .= "- The script should be compatible with Ubuntu 22.04 and 24.04\n";
            $context .= "- Remove all docker containers, images, and networks created by the installation\n";
            $context .= "- Remove configuration files and directories\n";
            $context .= "- Clean up firewall rules if necessary\n";
        } else {
            $context .= "- The script should be compatible with Ubuntu 22.04 and 24.04\n";
            $context .= "- Use Docker containers where possible for isolation\n";
            $context .= "- Generate necessary keys and certificates automatically\n";
            $context .= "- Configure appropriate firewall rules\n";
            $context .= "- Provide clear output about installation progress\n";
            $context .= "- Handle errors gracefully\n";
            $context .= "- Include configuration validation\n";
        }

        $context .= "\nUser requirements: $prompt\n";
        $context .= "\nReturn the response in this JSON format:\n";
        $context .= "{\n";
        if ($target === 'template') {
            $context .= '  "script": "[Interface]\\nPrivateKey = {{private_key}}...",' . "\n";
        } else {
            $context .= '  "script": "#!/bin/bash\\n# Complete script",' . "\n";
        }
        $context .= '  "suggestions": ["suggestion 1", "suggestion 2"],' . "\n";
        $context .= '  "ubuntu_compatible": true,' . "\n";
        $context .= '  "estimated_time": "5 minutes"' . "\n";
        $context .= "}\n";

        return $context;
    }

    /**
     * Database methods
     */

    private function saveAIGeneration(array $data): int
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            INSERT INTO ai_generations (protocol_id, model_used, prompt, generated_script, suggestions, ubuntu_compatible, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $data['protocol_id'],
            $data['model_used'],
            $data['prompt'],
            $data['generated_script'],
            $data['suggestions'],
            $data['ubuntu_compatible'],
            $data['created_at']
        ]);

        return (int) $pdo->lastInsertId();
    }

    private function getAIGeneration(int $id): ?array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT ag.*, p.name as protocol_name, p.slug as protocol_slug
            FROM ai_generations ag
            LEFT JOIN protocols p ON ag.protocol_id = p.id
            WHERE ag.id = ?
        ');
        $stmt->execute([$id]);
        $generation = $stmt->fetch(PDO::FETCH_ASSOC);

        return $generation ?: null;
    }

    private function getAIGenerationsByProtocol(int $protocolId): array
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT ag.*, p.name as protocol_name
            FROM ai_generations ag
            LEFT JOIN protocols p ON ag.protocol_id = p.id
            WHERE ag.protocol_id = ?
            ORDER BY ag.created_at DESC
            LIMIT 50
        ');
        $stmt->execute([$protocolId]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}