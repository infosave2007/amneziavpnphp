<?php
$priv = getenv('WG_PRIV_B64') ?: '';
$priv = trim($priv);
$raw = base64_decode($priv, true);
if ($raw === false) {
    fwrite(STDERR, "invalid_base64\n");
    exit(2);
}
echo "raw_len=" . strlen($raw) . "\n";
if (strlen($raw) !== 32) {
    fwrite(STDERR, "invalid_length\n");
    exit(3);
}
if (!function_exists('sodium_crypto_scalarmult_base')) {
    fwrite(STDERR, "libsodium_missing\n");
    exit(4);
}
$pub = sodium_crypto_scalarmult_base($raw);
echo "pub=" . base64_encode($pub) . "\n";
