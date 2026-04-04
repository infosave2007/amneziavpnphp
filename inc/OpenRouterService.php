<?php

class OpenRouterService {
    
    private $apiKey;
    private $apiUrl = 'https://openrouter.ai/api/v1';
    private $timeout = 60; // 60 seconds timeout for AI generation
    
    public function __construct() {
        $this->apiKey = $_ENV['OPENROUTER_API_KEY'] ?? null;
        if (!$this->apiKey) {
            throw new Exception('OpenRouter API key not configured');
        }
    }
    
    /**
     * Generate installation script using OpenRouter API
     */
    public function generateScript(string $prompt, string $model = 'openai/gpt-3.5-turbo'): array {
        try {
            $messages = [
                [
                    'role' => 'system',
                    'content' => 'You are a helpful assistant that creates bash installation scripts for VPN protocols. Always respond with valid JSON containing the script, suggestions, ubuntu compatibility, and estimated installation time.'
                ],
                [
                    'role' => 'user',
                    'content' => $prompt
                ]
            ];
            
            $response = $this->makeAPICall('/chat/completions', [
                'model' => $model,
                'messages' => $messages,
                'temperature' => 0.3, // Lower temperature for more consistent results
                'max_tokens' => 4000, // Sufficient for detailed scripts
                'response_format' => ['type' => 'json_object']
            ]);
            
            if (!isset($response['choices'][0]['message']['content'])) {
                throw new Exception('Invalid response from OpenRouter API');
            }
            
            $content = $response['choices'][0]['message']['content'];
            $parsed = json_decode($content, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                // If JSON parsing fails, try to extract script from plain text
                return $this->parsePlainTextResponse($content);
            }
            
            return $this->validateAndEnhanceResponse($parsed);
            
        } catch (Exception $e) {
            error_log("Error in OpenRouterService::generateScript: " . $e->getMessage());
            throw new Exception('Failed to generate script: ' . $e->getMessage());
        }
    }
    
    /**
     * Get available AI models from OpenRouter
     */
    public function getAvailableModels(): array {
        try {
            $response = $this->makeAPICall('/models', [], 'GET');
            
            if (!isset($response['data'])) {
                throw new Exception('Invalid response from OpenRouter API');
            }
            
            // Filter models suitable for code generation
            $codeModels = array_filter($response['data'], function($model) {
                $codeModelIds = [
                    'openai/gpt-3.5-turbo',
                    'openai/gpt-4',
                    'openai/gpt-4-turbo',
                    'anthropic/claude-3-haiku',
                    'anthropic/claude-3-sonnet',
                    'anthropic/claude-3-opus',
                    'google/gemini-pro',
                    'meta-llama/llama-2-70b-chat',
                    'meta-llama/llama-3-70b-instruct'
                ];
                
                return in_array($model['id'], $codeModelIds) && $model['top_provider'] === true;
            });
            
            return array_values(array_map(function($model) {
                return [
                    'id' => $model['id'],
                    'name' => $model['name'] ?? $model['id'],
                    'description' => $model['description'] ?? '',
                    'pricing' => $model['pricing'] ?? null
                ];
            }, $codeModels));
            
        } catch (Exception $e) {
            error_log("Error in OpenRouterService::getAvailableModels: " . $e->getMessage());
            // Return default models if API call fails
            return $this->getDefaultModels();
        }
    }
    
    /**
     * Make API call to OpenRouter
     */
    private function makeAPICall(string $endpoint, array $data = [], string $method = 'POST'): array {
        $ch = curl_init();
        
        $url = $this->apiUrl . $endpoint;
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $this->apiKey,
                'Content-Type: application/json',
                'HTTP-Referer: ' . ($_ENV['APP_URL'] ?? 'https://localhost'),
                'X-Title: Amnezia VPN Panel'
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception('CURL error: ' . $error);
        }
        
        if ($httpCode >= 400) {
            $errorData = json_decode($response, true);
            $errorMessage = $errorData['error']['message'] ?? "HTTP $httpCode error";
            throw new Exception($errorMessage);
        }
        
        $decoded = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid JSON response from OpenRouter API');
        }
        
        return $decoded;
    }
    
    /**
     * Parse plain text response when JSON parsing fails
     */
    private function parsePlainTextResponse(string $content): array {
        // Try to extract bash script from plain text
        if (preg_match('/```bash\n(.*?)\n```/s', $content, $matches)) {
            $script = trim($matches[1]);
        } elseif (preg_match('/```(.*?)```/s', $content, $matches)) {
            $script = trim($matches[1]);
        } else {
            // If no code blocks found, treat the entire content as script
            $script = trim($content);
        }
        
        // Add bash shebang if not present
        if (!str_starts_with($script, '#!')) {
            $script = "#!/bin/bash\n\n" . $script;
        }
        
        return [
            'script' => $script,
            'suggestions' => [
                'Check the script for syntax errors',
                'Test the script in a safe environment',
                'Review security implications'
            ],
            'ubuntu_compatible' => true,
            'estimated_time' => '5 minutes'
        ];
    }
    
    /**
     * Validate and enhance AI response
     */
    private function validateAndEnhanceResponse(array $response): array {
        $defaults = [
            'script' => '#!/bin/bash\n# Default installation script\necho "Installation script placeholder"',
            'suggestions' => [],
            'ubuntu_compatible' => true,
            'estimated_time' => '5 minutes'
        ];
        
        // Ensure all required fields are present
        foreach ($defaults as $key => $defaultValue) {
            if (!isset($response[$key])) {
                $response[$key] = $defaultValue;
            }
        }
        
        // Validate script format
        if (!str_starts_with(trim($response['script']), '#!')) {
            $response['script'] = "#!/bin/bash\n\n" . $response['script'];
        }
        
        // Ensure suggestions is an array
        if (!is_array($response['suggestions'])) {
            $response['suggestions'] = [];
        }
        
        // Add default suggestions if none provided
        if (empty($response['suggestions'])) {
            $response['suggestions'] = [
                'Review the generated script for security implications',
                'Test the script in a development environment first',
                'Ensure all dependencies are available on your system',
                'Backup your system before running the script'
            ];
        }
        
        // Validate ubuntu_compatible is boolean
        if (!is_bool($response['ubuntu_compatible'])) {
            $response['ubuntu_compatible'] = true;
        }
        
        return $response;
    }
    
    /**
     * Get default models when API is unavailable
     */
    private function getDefaultModels(): array {
        return [
            [
                'id' => 'openai/gpt-3.5-turbo',
                'name' => 'GPT-3.5 Turbo',
                'description' => 'Fast and cost-effective model for general purpose tasks',
                'pricing' => ['prompt' => '0.001', 'completion' => '0.002']
            ],
            [
                'id' => 'openai/gpt-4',
                'name' => 'GPT-4',
                'description' => 'Most capable model for complex tasks',
                'pricing' => ['prompt' => '0.03', 'completion' => '0.06']
            ],
            [
                'id' => 'anthropic/claude-3-haiku',
                'name' => 'Claude 3 Haiku',
                'description' => 'Fast and cost-effective model from Anthropic',
                'pricing' => ['prompt' => '0.00025', 'completion' => '0.00125']
            ],
            [
                'id' => 'anthropic/claude-3-sonnet',
                'name' => 'Claude 3 Sonnet',
                'description' => 'Balanced performance and cost from Anthropic',
                'pricing' => ['prompt' => '0.003', 'completion' => '0.015']
            ]
        ];
    }

    public function testModelAvailability(string $modelId): array {
        if (!$this->apiKey) {
            return [
                'success' => false,
                'http_code' => 401,
                'message' => 'OpenRouter API key not configured'
            ];
        }

        $payload = [
            'model' => $modelId,
            'messages' => [
                ['role' => 'user', 'content' => 'Reply with: OK']
            ],
            'max_tokens' => 5,
            'temperature' => 0
        ];

        $ch = curl_init($this->apiUrl . '/chat/completions');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->apiKey,
            'HTTP-Referer: https://amnez.ia',
            'X-Title: Amnezia VPN Panel'
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return [
                'success' => false,
                'http_code' => null,
                'message' => 'Network error: ' . $curlError
            ];
        }

        $json = json_decode($response, true);
        $ok = $httpCode === 200 && isset($json['choices'][0]['message']['content']);
        return [
            'success' => $ok,
            'http_code' => $httpCode,
            'message' => $ok ? 'Model is available' : ($json['error']['message'] ?? 'Model test failed')
        ];
    }
}