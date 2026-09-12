<?php
require_once __DIR__ . '/../inc/QrUtil.php';

$checks = 0;
$check = static function (bool $condition, string $message) use (&$checks): void {
    $checks++;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }
};
$decode = static function (string $value): string {
    $padding = (4 - strlen($value) % 4) % 4;
    $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', $padding), true);
    if ($decoded === false) {
        throw new RuntimeException('FAIL: invalid base64url');
    }
    return $decoded;
};

$config = "[Interface]\nAddress = 10.8.31.2/32\nPrivateKey = fixture-private\n" .
    "I1 = <r 2><b 0x11111111><b 0x22222222>\n" .
    implode('', array_map(static fn(int $i): string => "# qr-fixture-$i " . hash('sha256', "qr-fixture-$i") . "\n", range(1, 48))) .
    "\n[Peer]\nPublicKey = fixture-public\nEndpoint = vpn.example:36172\nAllowedIPs = 0.0.0.0/0, ::/0\n";

$check(QrUtil::encodeSimpleConf($config) === $config, 'simple AWG payload is plain config text');
$check(QrUtil::encodeOldPayloadFromConf($config, 'awg31') === $config, 'AWG31 camera path is plain config');

$chunks = QrUtil::encodeVpnQrChunks($config, 'awg31');
$check(count($chunks) >= 2, 'large native connection uses multiple QR parts');
$compressed = '';
foreach ($chunks as $expectedId => $encoded) {
    $frame = $decode($encoded);
    $header = unpack('nmagic/Ccount/Cid/Nlength', substr($frame, 0, 8));
    $body = substr($frame, 8);
    $check($header['magic'] === 0x07C0, "part $expectedId has Amnezia magic");
    $check($header['count'] === count($chunks), "part $expectedId declares complete count");
    $check($header['id'] === $expectedId, "part $expectedId has scan-order id");
    $check($header['length'] === strlen($body), "part $expectedId QByteArray length matches");
    $check(strlen($body) <= 850, "part $expectedId respects upstream chunk limit");
    $check(!str_starts_with($frame, 'vpn://'), "part $expectedId is camera framing, not text URL");
    $compressed .= $body;
}

$vpnPayload = $decode(QrUtil::encodeVpnUrlConf($config, 'awg31'));
$check(hash_equals($vpnPayload, $compressed), 'multipart frames reconstruct copyable URL payload bytes');
$uncompressedLength = unpack('Nlength', substr($compressed, 0, 4))['length'];
$json = gzuncompress(substr($compressed, 4));
$check($json !== false && strlen($json) === $uncompressedLength, 'reconstructed payload follows qCompress format');
$envelope = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
$check(($envelope['containers'][0]['container'] ?? null) === 'amnezia-awg', 'native envelope container preserved');
$check(($envelope['containers'][0]['awg']['protocol_version'] ?? null) === '3.1', 'native envelope protocol preserved');
$lastConfig = json_decode($envelope['containers'][0]['awg']['last_config'], true, 512, JSON_THROW_ON_ERROR);
$check(($lastConfig['config'] ?? null) === $config, 'native envelope preserves exact config and AWG DSL');

printf("PASS qr_import_contract assertions=%d parts=%d simple=plain multipart=qdatastream copy_url=qcompress\n", $checks, count($chunks));
