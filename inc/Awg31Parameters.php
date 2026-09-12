<?php

final class Awg31Parameters
{
    private const SPECIAL_JUNK_1 = '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>';
    private const FIELDS = [
        'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
        'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5',
        'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
        'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
        'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies',
    ];

    public static function fields(): array
    {
        return self::FIELDS;
    }

    public static function defaults(): array
    {
        return [
            'Jc' => random_int(4, 6), 'Jmin' => 10, 'Jmax' => 50,
            'S1' => 12, 'S2' => 12, 'S3' => 12, 'S4' => 12,
            'H1' => 1, 'H2' => 2, 'H3' => 3, 'H4' => 4,
            'I1' => self::SPECIAL_JUNK_1, 'I2' => '', 'I3' => '', 'I4' => '', 'I5' => '',
            'HeaderProtectionKey' => base64_encode(random_bytes(32)),
            'RekeyAfterTime' => '100-120', 'RekeyTimeout' => '3-7',
            'RejectAfterTime' => '150-180', 'KeepaliveTimeout' => '5-15',
            'MaxHandshakeAttempts' => '15-20', 'RandomTrailers' => 'on',
            'DisableCookies' => 'on',
        ];
    }

    public static function normalize(array $input): array
    {
        $byLower = [];
        foreach (self::FIELDS as $field) {
            $byLower[strtolower($field)] = $field;
        }
        $out = [];
        foreach ($input as $key => $value) {
            $canonical = $byLower[strtolower((string) $key)] ?? null;
            if ($canonical === null) {
                throw new InvalidArgumentException('Unknown AWG 3.1 setting: ' . (string) $key);
            }
            if (is_bool($value)) {
                $value = $value ? 'on' : 'off';
            } elseif (is_int($value) || is_float($value)) {
                $value = (string) $value;
            } elseif (!is_string($value)) {
                throw new InvalidArgumentException($canonical . ' must be scalar');
            }
            $value = trim($value);
            if (in_array($canonical, ['RandomTrailers', 'DisableCookies'], true)) {
                $lower = strtolower($value);
                $map = ['1' => 'on', 'true' => 'on', 'yes' => 'on', 'on' => 'on', '0' => 'off', 'false' => 'off', 'no' => 'off', 'off' => 'off'];
                if (!isset($map[$lower])) {
                    throw new InvalidArgumentException($canonical . ' must be on or off');
                }
                $value = $map[$lower];
            }
            $out[$canonical] = $value;
        }
        self::validate($out);
        return $out;
    }

    public static function validate(array $settings): void
    {
        $normalizedKeys = self::normalizeKeysOnly($settings);
        foreach (['ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts'] as $field) {
            if (!array_key_exists($field, $normalizedKeys) || $normalizedKeys[$field] === '') {
                continue;
            }
            $value = (string) $normalizedKeys[$field];
            if (!preg_match('/^(\d{1,5})(?:-(\d{1,5}))?$/', $value, $m)) {
                throw new InvalidArgumentException($field . ' must be uint16 or low-high');
            }
            $low = (int) $m[1];
            $high = isset($m[2]) ? (int) $m[2] : $low;
            if ($low > 65535 || $high > 65535 || $low > $high) {
                throw new InvalidArgumentException($field . ' range is invalid');
            }
        }
        if (isset($normalizedKeys['HeaderProtectionKey']) && $normalizedKeys['HeaderProtectionKey'] !== '') {
            $raw = base64_decode((string) $normalizedKeys['HeaderProtectionKey'], true);
            if ($raw === false || strlen($raw) !== 32 || strlen((string) $normalizedKeys['HeaderProtectionKey']) !== 44) {
                throw new InvalidArgumentException('HeaderProtectionKey must be a 32-byte base64 key');
            }
            foreach (['S1', 'S2', 'S3', 'S4'] as $field) {
                if (!array_key_exists($field, $normalizedKeys) || !ctype_digit((string) $normalizedKeys[$field]) || (int) $normalizedKeys[$field] < 12) {
                    throw new InvalidArgumentException($field . ' must be at least 12 when HeaderProtectionKey is set');
                }
            }
        }
    }

    public static function parseInterface(string $config): array
    {
        $wanted = array_fill_keys(array_map('strtolower', self::FIELDS), true);
        $out = [];
        $inInterface = false;
        foreach (preg_split('/\r?\n/', $config) as $line) {
            $line = trim($line);
            if (preg_match('/^\[(.+)]$/', $line, $m)) {
                $inInterface = strcasecmp($m[1], 'Interface') === 0;
                continue;
            }
            if (!$inInterface || strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $line, 2));
            if (isset($wanted[strtolower($key)])) {
                foreach (self::FIELDS as $field) {
                    if (strcasecmp($field, $key) === 0) {
                        $out[$field] = $value;
                        break;
                    }
                }
            }
        }
        return self::normalize($out);
    }

    public static function renderInterface(array $settings): string
    {
        $normalized = self::normalize($settings);
        $lines = [];
        foreach (self::FIELDS as $field) {
            if (array_key_exists($field, $normalized) && $normalized[$field] !== '') {
                $lines[] = $field . ' = ' . $normalized[$field];
            }
        }
        return implode("\n", $lines);
    }

    public static function normalizeKeysOnly(array $settings): array
    {
        $out = [];
        foreach ($settings as $key => $value) {
            if (is_string($value) && preg_match('/[\r\n]/', $value)) {
                throw new InvalidArgumentException((string) $key . ' must be a single line');
            }
            foreach (self::FIELDS as $field) {
                if (strcasecmp($field, (string) $key) === 0) {
                    $out[$field] = $value;
                    break;
                }
            }
        }
        return $out;
    }
}
