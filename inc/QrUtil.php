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
        $compressed = gzcompress($json, 9);
        if ($compressed === false) {
            throw new RuntimeException('gzcompress failed');
        }
        $uncompressedLen = strlen($json);
        $compressedLen = strlen($compressed) + 4; // +4 for the uncompressed length field
        $version = 0x07C00100; // Amnezia magic version number for compressed format
        $header = pack('N3', $version, $compressedLen, $uncompressedLen);
        return self::urlsafe_b64_encode($header . $compressed);
    }

    public static function encodeOldPayloadFromConf(string $confText, string $protocolSlug = ''): string
    {
        // For AWG2, use simple format: header + plain config text (like real Amnezia app)
        // For other protocols, use the old JSON+compression format for backward compatibility
        if ($protocolSlug === 'awg2') {
            return self::encodeSimpleConf($confText);
        }
        
        // Old format for backward compatibility with regular AWG
        $payload = self::buildOldEnvelopeFromConf($confText, $protocolSlug);
        return self::encodeOldPayloadFromJson(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }

    /**
     * Generate QR code payload in vpn:// URL format for AWG2
     * Returns vpn://<base64url(header + compressed config)>
     */
    public static function encodeVpnUrlPayload(string $confText, string $protocolSlug = ''): string
    {
        if ($protocolSlug === 'awg2') {
            return self::encodeVpnUrlConf($confText);
        }
        
        // For other protocols, use old format with vpn:// prefix
        $payload = self::buildOldEnvelopeFromConf($confText, $protocolSlug);
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        return 'vpn://' . self::encodeOldPayloadFromJson($jsonPayload);
    }

    /**
     * Encode config in simple format used by real Amnezia app for AWG2:
     * Header (8 bytes): version (4) + length (4) + config text
     * No compression, no JSON wrapper
     */
    public static function encodeSimpleConf(string $confText): string
    {
        $version = 0x07C00200; // Amnezia magic version number (updated for newer app compatibility)
        $length = strlen($confText);
        
        $header = pack('N2', $version, $length);
        return self::urlsafe_b64_encode($header . $confText);
    }

    /**
     * Encode config in vpn:// URL format used by newer Amnezia app
     * Format: vpn://<base64url(uint32 BE uncompressed_len + zlib compressed JSON)>
     *
     * Structure:
     * - 4 bytes: uint32 BE — length of JSON after decompression
     * - N bytes: zlib-compressed JSON (level 9, magic 0x78 0xDA)
     * - Entire block encoded in Base64url without padding
     */
    public static function encodeVpnUrlConf(string $confText, string $protocolSlug = ''): string
    {
        // Build JSON envelope like the real Amnezia app
        $envelope = self::buildOldEnvelopeFromConf($confText, $protocolSlug);
        $jsonBytes = json_encode($envelope, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if ($jsonBytes === false) {
            throw new RuntimeException('json_encode failed');
        }
        
        $jsonBytes = (string) $jsonBytes;
        $uncompressedLength = strlen($jsonBytes);
        
        // Compress with zlib level 9 (produces 0x78 0xDA header)
        $compressed = gzcompress($jsonBytes, 9);
        if ($compressed === false) {
            throw new RuntimeException('gzcompress failed');
        }
        
        // Header: uint32 BE with uncompressed length
        $header = pack('N', $uncompressedLength);
        
        // Payload: header + compressed data
        $payload = $header . $compressed;
        
        // Base64url encode without padding
        return self::urlsafe_b64_encode($payload);
    }

    /**
     * Encode config in old compressed format (for second QR code)
     * Uses JSON envelope with gzip compression
     * Header: version (4) + compressedLen+4 (4) + uncompressedLen (4) + compressed data
     */
    public static function encodeCompressedConf(string $confText, string $protocolSlug = ''): string
    {
        $payload = self::buildOldEnvelopeFromConf($confText, $protocolSlug);
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        return self::encodeOldPayloadFromJson($jsonPayload);
    }

    /**
     * Encode config in Amnezia app format for vpn:// URL
     * Format: 3-byte length (big-endian) + zlib compressed JSON data
     * This matches the real Amnezia app vpn:// URL format
     */
    public static function encodeAmneziaVpnUrl(string $confText, string $protocolSlug = ''): string
    {
        // Build JSON envelope like the real Amnezia app
        $payload = self::buildOldEnvelopeFromConf($confText, $protocolSlug);
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        
        // Compress the JSON
        $compressed = gzcompress($jsonPayload, 9);
        if ($compressed === false) {
            throw new RuntimeException('gzcompress failed');
        }
        $length = strlen($compressed);
        // 3-byte length in big-endian
        $lengthBytes = pack('N', $length);
        $header = substr($lengthBytes, 1); // Take last 3 bytes
        return self::urlsafe_b64_encode($header . $compressed);
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
            'I1' => null,
            'I2' => null,
            'I3' => null,
            'I4' => null,
            'I5' => null,
            'Jc' => null,
            'Jmin' => null,
            'Jmax' => null,
            'S1' => null,
            'S2' => null,
            'S3' => null,
            'S4' => null,
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
            'I1' => (string) ($params['I1'] ?? ''),
            'I2' => (string) ($params['I2'] ?? ''),
            'I3' => (string) ($params['I3'] ?? ''),
            'I4' => (string) ($params['I4'] ?? ''),
            'I5' => (string) ($params['I5'] ?? ''),
            'Jc' => (string) ($params['Jc'] ?? ''),
            'Jmax' => (string) ($params['Jmax'] ?? ''),
            'Jmin' => (string) ($params['Jmin'] ?? ''),
            'S1' => (string) ($params['S1'] ?? ''),
            'S2' => (string) ($params['S2'] ?? ''),
            'S3' => (string) ($params['S3'] ?? ''),
            'S4' => (string) ($params['S4'] ?? ''),
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

    private static function buildOldEnvelopeFromConf(string $conf, string $protocolSlug = ''): array
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
            'I1' => null,
            'I2' => null,
            'I3' => null,
            'I4' => null,
            'I5' => null,
            'Jc' => null,
            'Jmin' => null,
            'Jmax' => null,
            'S1' => null,
            'S2' => null,
            'S3' => null,
            'S4' => null,
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
            'I1' => (string) ($params['I1'] ?? ''),
            'I2' => (string) ($params['I2'] ?? ''),
            'I3' => (string) ($params['I3'] ?? ''),
            'I4' => (string) ($params['I4'] ?? ''),
            'I5' => (string) ($params['I5'] ?? ''),
            'Jc' => (string) ($params['Jc'] ?? ''),
            'Jmax' => (string) ($params['Jmax'] ?? ''),
            'Jmin' => (string) ($params['Jmin'] ?? ''),
            'S1' => (string) ($params['S1'] ?? ''),
            'S2' => (string) ($params['S2'] ?? ''),
            'S3' => (string) ($params['S3'] ?? ''),
            'S4' => (string) ($params['S4'] ?? ''),
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
                    ] + ($protocolSlug === 'awg2' ? [
                        'I1' => (string) ($params['I1'] ?? ''),
                        'I2' => (string) ($params['I2'] ?? ''),
                        'I3' => (string) ($params['I3'] ?? ''),
                        'I4' => (string) ($params['I4'] ?? ''),
                        'I5' => (string) ($params['I5'] ?? ''),
                        'S3' => (string) ($params['S3'] ?? ''),
                        'S4' => (string) ($params['S4'] ?? ''),
                    ] : []),
                    'container' => $protocolSlug === 'awg2' ? 'amnezia-awg2' : 'amnezia-awg',
                ],
            ],
            'defaultContainer' => $protocolSlug === 'awg2' ? 'amnezia-awg2' : 'amnezia-awg',
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

    public static function encodeXrayPayload(string $host, int $port, string $clientId, string $description = '', ?array $reality = null, string $rawConfig = '', string $flow = ''): string
    {
        $desc = $description !== '' ? $description : self::resolveServerDescription($host);

        // Construct full Client XRay config (Amnezia native format expects this structure)
        $outbound = [
            'protocol' => 'vless',
            'settings' => [
                'vnext' => [
                    [
                        'address' => $host,
                        'port' => $port,
                        'users' => [
                            [
                                'id' => $clientId,
                                'encryption' => 'none'
                            ]
                        ]
                    ]
                ]
            ],
            'streamSettings' => [
                'network' => 'tcp',
                'security' => ($reality ? 'reality' : 'none')
            ]
        ];

        if ($flow !== '') {
            $outbound['settings']['vnext'][0]['users'][0]['flow'] = $flow;
        }

        if ($reality) {
            $outbound['streamSettings']['realitySettings'] = [
                'fingerprint' => $reality['fingerprint'] ?? 'chrome',
                'serverName' => $reality['serverName'] ?? '',
                'publicKey' => $reality['publicKey'] ?? '',
                'shortId' => $reality['shortId'] ?? '',
                'spiderX' => ''
            ];
        }

        $fullConfig = [
            'log' => ['loglevel' => 'warning'],
            'inbounds' => [
                [
                    'listen' => '127.0.0.1',
                    'port' => 10808,
                    'protocol' => 'socks',
                    'settings' => ['udp' => true]
                ]
            ],
            'outbounds' => [$outbound]
        ];

        $envelope = [
            'containers' => [
                [
                    'xray' => [
                        // No isThirdPartyConfig flag - treats as native container
                        'last_config' => json_encode($fullConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
                        'port' => (string) $port,
                        'transport_proto' => 'tcp'
                    ],
                    'container' => 'amnezia-xray'
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