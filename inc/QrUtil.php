<?php
use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;
use Endroid\QrCode\Writer\SvgWriter;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\Label\Label;
use Endroid\QrCode\Label\LabelAlignment;
use Endroid\QrCode\Encoding\Encoding;

class QrUtil
{
    public static function pngBase64(string $text, int $size = 300, int $margin = 1, string $label = 'Amnezia QR (old)'): string
    {
        // Try to load Composer autoload if not yet loaded
        if (!class_exists(QrCode::class)) {
            $autoload = __DIR__ . '/vendor/autoload.php';
            if (file_exists($autoload)) {
                require_once $autoload;
            }
        }
        // Prefer Composer library; PNG when GD is available, otherwise SVG fallback
        if (class_exists(QrCode::class)) {
            $qrCode = QrCode::create($text)
                ->setSize($size)
                ->setMargin($margin)
                ->setErrorCorrectionLevel(ErrorCorrectionLevel::Medium)
                ->setEncoding(new Encoding('UTF-8'));

            if (class_exists(PngWriter::class) && extension_loaded('gd')) {
                // Avoid labels in PNG to sidestep GD freetype dependency
                $writer = new PngWriter();
                $result = $writer->write($qrCode);
                return 'data:image/png;base64,' . base64_encode($result->getString());
            }
            if (class_exists(SvgWriter::class)) {
                $writer = new SvgWriter();
                $result = $writer->write($qrCode, null, Label::create($label)->setAlignment(LabelAlignment::Center));
                return 'data:image/svg+xml;base64,' . base64_encode($result->getString());
            }
        }
        // Fallback to phpqrcode.php if available
        $libPath = __DIR__ . '/phpqrcode.php';
        if (file_exists($libPath)) {
            require_once $libPath;
            ob_start();
            // Avoid direct constant references to satisfy linter
            $args = [$text];
            if (function_exists('constant') && defined('QR_ECLEVEL_M')) {
                $args = [$text, null, constant('QR_ECLEVEL_M'), $size / 40, $margin];
            }
            call_user_func_array(['QRcode', 'png'], $args);
            $png = ob_get_clean();
            return 'data:image/png;base64,' . base64_encode($png);
        }
        throw new RuntimeException('QR library not available');
    }

    private static function urlsafe_b64_encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function encodeOldPayloadFromJson(string $jsonText): string
    {
        $json = self::normalizeJson($jsonText);
        // Amnezia format: 12-byte header [version, compressed_len, uncompressed_len] + zlib compressed data
        // Version 0x07C00100 is required for compatibility with Amnezia apps
        $compressed = gzcompress($json, 9);
        if ($compressed === false) {
            throw new RuntimeException('gzcompress failed');
        }
        $uncompressedLen = strlen($json);
        $compressedLen = strlen($compressed) + 4; // +4 for the uncompressed length field
        $version = 0x07C00100; // Amnezia magic version number
        $header = pack('N3', $version, $compressedLen, $uncompressedLen);
        return self::urlsafe_b64_encode($header . $compressed);
    }

    public static function encodeOldPayloadFromConf(string $confText): string
    {
        $payload = self::buildOldEnvelopeFromConf($confText);
        return self::encodeOldPayloadFromJson(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }

    private static function resolveServerDescription(?string $endpointHost): string
    {
        $desc = (string) ($endpointHost ?? '');
        try {
            $cfgPath = __DIR__ . '/config.php';
            $dbPath = __DIR__ . '/Database.php';
            if (file_exists($cfgPath) && file_exists($dbPath)) {
                $config = require $cfgPath;
                require_once $dbPath;
                $pdo = (new Database($config['db']))->pdo();
                $stmt = $pdo->prepare('SELECT name FROM servers WHERE host=? LIMIT 1');
                $stmt->execute([$endpointHost]);
                $row = $stmt->fetch();
                if ($row && !empty($row['name'])) {
                    $desc = $row['name'];
                }
            }
        } catch (\Throwable $e) {
            // fallback to host
        }
        return $desc;
    }

    public static function parseWireGuardConfig(string $conf): array
    {
        $endpointHost = null;
        $endpointPort = null;
        $mtu = null;
        $dns = [];
        $keepAlive = null;
        $privKey = null;
        $pubKeyServer = null;
        $psk = null;
        $address = null;
        $allowedIps = [];
        foreach (explode("\n", $conf) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (stripos($line, 'Endpoint') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                if (preg_match('/^\[?([^\]]+)\]?:([0-9]{2,5})$/', $v, $m)) {
                    $endpointHost = $m[1];
                    $endpointPort = (int) $m[2];
                }
            } elseif (stripos($line, 'MTU') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $mtu = (int) $v;
            } elseif (stripos($line, 'DNS') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $dns = array_map('trim', preg_split('/[,\s]+/', $v));
            } elseif (stripos($line, 'PrivateKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $privKey = $v;
            } elseif (stripos($line, 'PublicKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $pubKeyServer = $v;
            } elseif (stripos($line, 'PresharedKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $psk = $v;
            } elseif (stripos($line, 'Address') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $address = $v;
            } elseif (stripos($line, 'AllowedIPs') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $allowedIps = array_map('trim', preg_split('/[,\s]+/', $v));
            } elseif (stripos($line, 'PersistentKeepalive') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $keepAlive = (int) $v;
            }
        }

        if (!$endpointPort) {
            $endpointPort = 51820;
        }
        if (!$mtu) {
            $mtu = 1280;
        }
        if (!$keepAlive) {
            $keepAlive = 25;
        }
        $dns1 = $dns[0] ?? '1.1.1.1';
        $dns2 = $dns[1] ?? '1.0.0.1';

        // Derive client public key if sodium available
        $clientPubKey = '';
        if ($privKey && function_exists('sodium_crypto_scalarmult_base')) {
            $bin = base64_decode($privKey, true);
            if ($bin !== false && strlen($bin) === 32) {
                $pub = sodium_crypto_scalarmult_base($bin);
                $clientPubKey = base64_encode($pub);
            }
        }

        // Collect obfuscation params from conf if present
        $params = [
            'H1' => null,
            'H2' => null,
            'H3' => null,
            'H4' => null,
            'Jc' => null,
            'Jmin' => null,
            'Jmax' => null,
            'S1' => null,
            'S2' => null,
        ];
        foreach (explode("\n", $conf) as $line) {
            $line = trim($line);
            foreach (array_keys($params) as $k) {
                if (stripos($line, $k) === 0 && strpos($line, '=') !== false) {
                    [, $v] = array_map('trim', explode('=', $line, 2));
                    $params[$k] = $v;
                }
            }
        }

        // Build last_config JSON object (stringified, pretty-printed)
        $lastConfigObj = [
            'H1' => (string) ($params['H1'] ?? ''),
            'H2' => (string) ($params['H2'] ?? ''),
            'H3' => (string) ($params['H3'] ?? ''),
            'H4' => (string) ($params['H4'] ?? ''),
            'Jc' => (string) ($params['Jc'] ?? ''),
            'Jmax' => (string) ($params['Jmax'] ?? ''),
            'Jmin' => (string) ($params['Jmin'] ?? ''),
            'S1' => (string) ($params['S1'] ?? ''),
            'S2' => (string) ($params['S2'] ?? ''),
            'allowed_ips' => $allowedIps ?: ['0.0.0.0/0', '::/0'],
            'clientId' => $clientPubKey ?: '',
            'client_ip' => preg_replace('/\/(\d{1,2})$/', '', (string) ($address ?? '')),
            'client_priv_key' => (string) ($privKey ?? ''),
            'client_pub_key' => $clientPubKey ?: '',
            'config' => $conf,
            'hostName' => (string) ($endpointHost ?? ''),
            'mtu' => (string) $mtu,
            'persistent_keep_alive' => (string) $keepAlive,
            'port' => $endpointPort,
            'psk_key' => (string) ($psk ?? ''),
            'server_pub_key' => (string) ($pubKeyServer ?? ''),
        ];

        $serverDesc = self::resolveServerDescription($endpointHost);

        $vars = [
            'last_config_json' => json_encode($lastConfigObj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
            'port' => (string) $endpointPort,
            'description' => $serverDesc,
            'dns1' => $dns1,
            'dns2' => $dns2,
            'hostName' => $endpointHost,
            'client_pub_key' => $clientPubKey,
            'client_priv_key' => $privKey,
            'client_ip' => preg_replace('/\/(\d{1,2})$/', '', (string) ($address ?? '')),
            'psk_key' => $psk,
            'server_pub_key' => $pubKeyServer,
            'mtu' => $mtu,
            'persistent_keep_alive' => $keepAlive,
            'config' => $conf,
        ];

        // Add params to vars
        foreach ($params as $k => $v) {
            $vars[$k] = (string) ($v ?? '');
        }

        return $vars;
    }

    private static function buildOldEnvelopeFromConf(string $conf): array
    {
        $endpointHost = null;
        $endpointPort = null;
        $mtu = null;
        $dns = [];
        $keepAlive = null;
        $privKey = null;
        $pubKeyServer = null;
        $psk = null;
        $address = null;
        $allowedIps = [];
        foreach (explode("\n", $conf) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (stripos($line, 'Endpoint') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                if (preg_match('/^\[?([^\]]+)\]?:([0-9]{2,5})$/', $v, $m)) {
                    $endpointHost = $m[1];
                    $endpointPort = (int) $m[2];
                }
            } elseif (stripos($line, 'MTU') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $mtu = (int) $v;
            } elseif (stripos($line, 'DNS') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $dns = array_map('trim', preg_split('/[,\s]+/', $v));
            } elseif (stripos($line, 'PrivateKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $privKey = $v;
            } elseif (stripos($line, 'PublicKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $pubKeyServer = $v;
            } elseif (stripos($line, 'PresharedKey') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $psk = $v;
            } elseif (stripos($line, 'Address') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $address = $v;
            } elseif (stripos($line, 'AllowedIPs') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $allowedIps = array_map('trim', preg_split('/[,\s]+/', $v));
            } elseif (stripos($line, 'PersistentKeepalive') === 0 && strpos($line, '=') !== false) {
                [, $v] = array_map('trim', explode('=', $line, 2));
                $keepAlive = (int) $v;
            }
        }

        if (!$endpointPort) {
            $endpointPort = 51820;
        }
        if (!$mtu) {
            $mtu = 1280;
        }
        if (!$keepAlive) {
            $keepAlive = 25;
        }
        $dns1 = $dns[0] ?? '1.1.1.1';
        $dns2 = $dns[1] ?? '1.0.0.1';

        // Derive client public key if sodium available
        $clientPubKey = '';
        if ($privKey && function_exists('sodium_crypto_scalarmult_base')) {
            $bin = base64_decode($privKey, true);
            if ($bin !== false && strlen($bin) === 32) {
                $pub = sodium_crypto_scalarmult_base($bin);
                $clientPubKey = base64_encode($pub);
            }
        }

        // Collect obfuscation params from conf if present
        $params = [
            'H1' => null,
            'H2' => null,
            'H3' => null,
            'H4' => null,
            'Jc' => null,
            'Jmin' => null,
            'Jmax' => null,
            'S1' => null,
            'S2' => null,
        ];
        foreach (explode("\n", $conf) as $line) {
            $line = trim($line);
            foreach (array_keys($params) as $k) {
                if (stripos($line, $k) === 0 && strpos($line, '=') !== false) {
                    [, $v] = array_map('trim', explode('=', $line, 2));
                    $params[$k] = $v;
                }
            }
        }

        // Build last_config JSON object (stringified, pretty-printed)
        $lastConfigObj = [
            'H1' => (string) ($params['H1'] ?? ''),
            'H2' => (string) ($params['H2'] ?? ''),
            'H3' => (string) ($params['H3'] ?? ''),
            'H4' => (string) ($params['H4'] ?? ''),
            'Jc' => (string) ($params['Jc'] ?? ''),
            'Jmax' => (string) ($params['Jmax'] ?? ''),
            'Jmin' => (string) ($params['Jmin'] ?? ''),
            'S1' => (string) ($params['S1'] ?? ''),
            'S2' => (string) ($params['S2'] ?? ''),
            'allowed_ips' => $allowedIps ?: ['0.0.0.0/0', '::/0'],
            'clientId' => $clientPubKey ?: '',
            'client_ip' => preg_replace('/\/(\d{1,2})$/', '', (string) ($address ?? '')),
            'client_priv_key' => (string) ($privKey ?? ''),
            'client_pub_key' => $clientPubKey ?: '',
            'config' => $conf,
            'hostName' => (string) ($endpointHost ?? ''),
            'mtu' => (string) $mtu,
            'persistent_keep_alive' => (string) $keepAlive,
            'port' => $endpointPort,
            'psk_key' => (string) ($psk ?? ''),
            'server_pub_key' => (string) ($pubKeyServer ?? ''),
        ];

        $serverDesc = self::resolveServerDescription($endpointHost);

        // Envelope with keys ordered like variant 1: containers first
        $envelope = [
            'containers' => [
                [
                    // awg first, then container (as in the working QR)
                    'awg' => [
                        'H1' => (string) ($params['H1'] ?? ''),
                        'H2' => (string) ($params['H2'] ?? ''),
                        'H3' => (string) ($params['H3'] ?? ''),
                        'H4' => (string) ($params['H4'] ?? ''),
                        'Jc' => (string) ($params['Jc'] ?? ''),
                        'Jmax' => (string) ($params['Jmax'] ?? ''),
                        'Jmin' => (string) ($params['Jmin'] ?? ''),
                        'S1' => (string) ($params['S1'] ?? ''),
                        'S2' => (string) ($params['S2'] ?? ''),
                        'last_config' => json_encode($lastConfigObj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
                        'port' => (string) $endpointPort,
                        'transport_proto' => 'udp',
                    ],
                    'container' => 'amnezia-awg',
                ],
            ],
            'defaultContainer' => 'amnezia-awg',
            'description' => $serverDesc,
            'dns1' => $dns1,
            'dns2' => $dns2,
            'hostName' => $endpointHost,
        ];
        return $envelope;
    }

    private static function normalizeJson(string $text): string
    {
        $decoded = json_decode($text, true);
        if (!is_array($decoded))
            throw new InvalidArgumentException('Invalid JSON');
        return json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    }

    public static function encodeXrayPayload(string $host, int $port, string $clientId, string $description = '', ?array $reality = null): string
    {
        $desc = $description !== '' ? $description : self::resolveServerDescription($host);
        $clientCfg = [
            'log' => ['loglevel' => 'error'],
            'inbounds' => [
                [
                    'listen' => '127.0.0.1',
                    'port' => 10808,
                    'protocol' => 'socks',
                    'settings' => ['udp' => true]
                ]
            ],
            'outbounds' => [
                [
                    'protocol' => 'vless',
                    'settings' => [
                        'vnext' => [
                            [
                                'address' => $host,
                                'port' => $port,
                                'users' => [
                                    [
                                        'id' => $clientId,
                                        'flow' => ($reality && isset($reality['publicKey']) && $reality['publicKey'] !== '') ? 'xtls-rprx-vision' : null,
                                        'encryption' => 'none'
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'streamSettings' => [
                        'network' => 'tcp',
                        'security' => ($reality && isset($reality['publicKey']) && $reality['publicKey'] !== '') ? 'reality' : 'none',
                        'realitySettings' => ($reality && isset($reality['publicKey']) && $reality['publicKey'] !== '') ? [
                            'fingerprint' => 'chrome',
                            'serverName' => (string) ($reality['serverName'] ?? $host),
                            'publicKey' => (string) $reality['publicKey'],
                            'shortId' => (string) ($reality['shortId'] ?? ''),
                            'spiderX' => ''
                        ] : null
                    ]
                ]
            ]
        ];

        $envelope = [
            'containers' => [
                [
                    'container' => 'amnezia-xray',
                    'xray' => [
                        // X-Ray config must be wrapped in a "config" field inside the last_config JSON
                        'last_config' => json_encode(['config' => json_encode($clientCfg, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                        'port' => (string) $port,
                        'transport_proto' => 'tcp'
                    ]
                ]
            ],
            'defaultContainer' => 'amnezia-xray',
            'description' => $desc,
            'dns1' => '1.1.1.1',
            'dns2' => '1.0.0.1',
            'hostName' => $host,
        ];

        return self::encodeOldPayloadFromJson(json_encode($envelope, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
}