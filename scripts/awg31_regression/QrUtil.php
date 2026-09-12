<?php

/**
 * Test adapter for VpnClient::generateQRCode(). This fixture exercises the
 * regeneration method through its database update while leaving QR encoding
 * outside the assigned evidence boundary.
 */
final class QrUtil
{
    public static function encodeOldPayloadFromConf(string $config, string $protocolSlug = ''): string
    {
        return 'mock-old-payload:' . $protocolSlug . ':' . hash('sha256', $config);
    }

    public static function pngBase64(string $payload): string
    {
        return 'data:image/png;base64,' . base64_encode($payload);
    }
}
