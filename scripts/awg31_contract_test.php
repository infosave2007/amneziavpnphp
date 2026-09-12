<?php
require_once __DIR__ . '/../inc/Awg31Parameters.php';
require_once __DIR__ . '/../inc/QrUtil.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/BackupLibrary.php';

$checks = 0;
$assert = static function (bool $ok, string $message) use (&$checks): void {
    $checks++;
    if (!$ok) {
        throw new RuntimeException('FAIL: ' . $message);
    }
};

$defaults = Awg31Parameters::defaults();
$assert($defaults['Jc'] >= 4 && $defaults['Jc'] <= 6, 'Jc upstream range');
$assert($defaults['Jmin'] === 10 && $defaults['Jmax'] === 50, 'junk defaults');
foreach (['S1', 'S2', 'S3', 'S4'] as $field) $assert($defaults[$field] === 12, "$field default");
foreach (['H1' => 1, 'H2' => 2, 'H3' => 3, 'H4' => 4] as $field => $value) $assert($defaults[$field] === $value, "$field default");
$assert(strlen($defaults['HeaderProtectionKey']) === 44 && strlen(base64_decode($defaults['HeaderProtectionKey'], true)) === 32, 'header key format');
$assert(!array_key_exists('ContentPaddingAddition', $defaults), 'padding addition absent by default');

$normalized = Awg31Parameters::normalize(array_merge($defaults, [
    'ContentPaddingAddition' => '0-0', 'RandomTrailers' => true, 'DisableCookies' => 'OFF',
]));
$assert($normalized['RandomTrailers'] === 'on' && $normalized['DisableCookies'] === 'off', 'boolean normalization');
foreach (['0', '0-0', '65535', '1-65535'] as $range) {
    $sample = $defaults; $sample['RekeyTimeout'] = $range;
    Awg31Parameters::validate($sample); $checks++;
}
foreach (['-1', '65536', '8-3', '1-65536', 'x'] as $range) {
    $sample = $defaults; $sample['RekeyTimeout'] = $range;
    try { Awg31Parameters::validate($sample); throw new RuntimeException('accepted bad range'); }
    catch (InvalidArgumentException $e) { $checks++; }
}
$badS = $defaults; $badS['S4'] = 11;
try { Awg31Parameters::validate($badS); throw new RuntimeException('accepted S4<12'); }
catch (InvalidArgumentException $e) { $checks++; }
$badLine = $defaults; $badLine['I2'] = "bad\nline";
try { Awg31Parameters::normalize($badLine); throw new RuntimeException('accepted newline'); }
catch (InvalidArgumentException $e) { $checks++; }
$badEffective = array_merge(Awg31Parameters::defaults(), ['S1' => 1]);
try { Awg31Parameters::normalize($badEffective); throw new RuntimeException('accepted effective S1<12'); }
catch (InvalidArgumentException $e) { $checks++; }
$headerOnlyEffective = array_merge(Awg31Parameters::defaults(), ['HeaderProtectionKey' => base64_encode(str_repeat('z', 32))]);
$assert(Awg31Parameters::normalize($headerOnlyEffective)['S1'] === '12', 'header-only override uses effective defaults');
$emptyHeaderEffective = Awg31Parameters::normalize(array_merge(Awg31Parameters::defaults(), ['HeaderProtectionKey' => '', 'S1' => 1]));
$assert($emptyHeaderEffective['HeaderProtectionKey'] === '' && $emptyHeaderEffective['S1'] === '1', 'generic normalizer preserves import absence; install boundary rejects this effective pair');

$portsMatch = static fn(int $endpoint, int $live, ?int $published): bool => $endpoint === $live && $endpoint === $published;
$assert(!$portsMatch(36172, 36172, 32262), 'docker publish mismatch is a diagnostic failure');
$assert($portsMatch(36172, 36172, 36172), 'consistent endpoint/live/published ports pass');

$conf = "[Interface]\nAddress = 10.8.31.2/32\nDNS = 1.1.1.1\nPrivateKey = " . base64_encode(str_repeat('a', 32)) . "\n" . Awg31Parameters::renderInterface($normalized) . "\n\n[Peer]\nPublicKey = " . base64_encode(str_repeat('b', 32)) . "\nPresharedKey = " . base64_encode(str_repeat('c', 32)) . "\nEndpoint = vpn.example:44321\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25-35\n";
$parsed = Awg31Parameters::parseInterface($conf);
foreach ($normalized as $field => $value) {
    if ($value !== '') $assert((string) $parsed[$field] === (string) $value, "$field interface roundtrip");
}

$payload = QrUtil::encodeVpnUrlConf($conf, 'awg31');
$raw = base64_decode(strtr($payload, '-_', '+/') . str_repeat('=', (4 - strlen($payload) % 4) % 4), true);
$length = unpack('N', substr($raw, 0, 4))[1];
$json = gzuncompress(substr($raw, 4));
$assert(strlen($json) === $length, 'qCompress length');
$envelope = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
$entry = $envelope['containers'][0];
$assert($entry['container'] === 'amnezia-awg' && $envelope['defaultContainer'] === 'amnezia-awg', 'upstream container marker');
$assert($entry['awg']['protocol_version'] === '3.1', 'protocol version marker');
$last = json_decode($entry['awg']['last_config'], true, 512, JSON_THROW_ON_ERROR);
$assert($last['persistent_keep_alive'] === '25-35', 'keepalive range preserved');
foreach (Awg31Parameters::fields() as $field) {
    if (array_key_exists($field, $normalized) && $normalized[$field] !== '') $assert((string) $entry['awg'][$field] === (string) $normalized[$field], "$field envelope roundtrip");
}
$built = VpnClient::buildClientConfig(
    base64_encode(str_repeat('a', 32)), '10.8.31.2', base64_encode(str_repeat('b', 32)),
    base64_encode(str_repeat('c', 32)), 'vpn.example', 44321, $normalized, 'awg31'
);
foreach ($normalized as $field => $value) {
    if ($value !== '') $assert(str_contains($built, $field . ' = ' . $value), "$field maintained builder");
}
$withoutOptional = $normalized;
unset($withoutOptional['ContentPaddingAddition']);
$withoutOptional['I2'] = '';
$builtWithoutOptional = VpnClient::buildClientConfig(
    base64_encode(str_repeat('a', 32)), '10.8.31.3', base64_encode(str_repeat('b', 32)),
    base64_encode(str_repeat('c', 32)), 'vpn.example', 44321, $withoutOptional, 'awg31'
);
$assert(!str_contains($builtWithoutOptional, 'ContentPaddingAddition ='), 'omitted padding stays omitted');
$assert(!preg_match('/^I2\s*=/m', $builtWithoutOptional), 'empty I2 stays omitted');
$assert(QrUtil::encodeOldPayloadFromConf($built, 'awg31') === $built, 'AWG camera QR uses plain config');
$cameraParts = QrUtil::encodeVpnQrChunks($built, 'awg31');
$cameraFrame = base64_decode(strtr($cameraParts[0], '-_', '+/') . str_repeat('=', (4 - strlen($cameraParts[0]) % 4) % 4), true);
$cameraHeader = unpack('nmagic/Ccount/Cid/Nlength', substr($cameraFrame, 0, 8));
$assert($cameraHeader['magic'] === 0x07C0 && $cameraHeader['count'] === count($cameraParts) && $cameraHeader['id'] === 0, 'native QR QDataStream framing');
$assert($cameraHeader['length'] === strlen(substr($cameraFrame, 8)), 'native QR QByteArray length');
$assert(str_starts_with(QrUtil::encodeVpnUrlPayload($built, 'awg31'), 'vpn://'), 'vpn payload has scheme');

$nativeBase = [
    'hostName' => '192.0.2.10', 'port' => 22, 'userName' => 'root', 'password' => 'fixture',
    'containers' => [['container' => 'amnezia-awg', 'awg' => array_merge($normalized, [
        'port' => 44321, 'subnet_address' => '10.8.31.0',
        'last_config' => json_encode(['client_ip' => '10.8.31.2', 'config' => $built]),
    ])]],
];
$parseNative = static function (array $entry): array {
    $path = tempnam(sys_get_temp_dir(), 'awg31-fixture-');
    file_put_contents($path, json_encode(['Servers/serversList' => json_encode([$entry])]));
    try { return BackupParser::parse($path); } finally { @unlink($path); }
};
$v3Entry = $nativeBase;
$v3Entry['containers'][0]['awg']['protocol_version'] = '3.1';
$v3Parsed = $parseNative($v3Entry);
$assert($v3Parsed['servers'][0]['install_protocol'] === 'awg31', 'native v3 identity');
$assert($v3Parsed['servers'][0]['container_name'] === 'amnezia-awg', 'native runtime marker preserved');
$assert($v3Parsed['servers'][0]['server_protocols'][0]['slug'] === 'awg31', 'native binding slug');
$legacyEntry = $nativeBase;
$legacyParsed = $parseNative($legacyEntry);
$assert($legacyParsed['servers'][0]['install_protocol'] === 'amnezia-wg-advanced', 'legacy identity');
$badEntry = $v3Entry;
$badEntry['containers'][0]['container'] = 'amnezia-awg2';
try { $parseNative($badEntry); throw new RuntimeException('accepted contradictory marker'); }
catch (Exception $e) { $assert(str_contains($e->getMessage(), 'Contradictory'), 'contradictory marker rejected'); }

$migration = file_get_contents(__DIR__ . '/../migrations/071_add_awg31_protocol.sql');
$assert(str_contains($migration, 'b5928efb6ca19f0153958460c3d141f04abc5c2e'), 'engine pin');
$assert(str_contains($migration, 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'), 'tools pin');
$assert(str_contains($migration, 'ARG AWGTOOLS_COMMIT=$TOOLS_COMMIT'), 'tools checkout injected by immutable sha');
$assert(str_contains($migration, 'amneziawg-go -f awg0'), 'userspace engine supervised in foreground');
$assert(!preg_match('/UPDATE\s+vpn_servers/i', $migration), 'migration leaves server rows untouched');
$assert(str_contains($migration, '/opt/amnezia/awg31:/opt/amnezia/awg:rw') || str_contains($migration, '$ROOT:/opt/amnezia/awg:rw'), 'mount contract');

$awg2 = file_get_contents(__DIR__ . '/../migrations/064_complete_awg2_original_params.sql');
$assert(hash_equals('5a2f29fc2f55168f25384171770be48f65aabc0c647a4dfcfe77040a1fb1f4b0', hash('sha256', $awg2)), 'AWG2 migration byte identity');

printf("PASS awg31_contract checks=%d\n", $checks);
