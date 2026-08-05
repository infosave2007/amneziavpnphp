<?php

/**
 * Panel version, and an optional check for a newer released version.
 *
 * The version is read from the VERSION file rather than from git, because
 * deployments are commonly a copied tree with no repository present.
 */
class Version
{
    private const REPO = 'infosave2007/amneziavpnphp';
    private const CACHE_TTL = 86400;

    private static ?string $current = null;
    private static bool $latestResolved = false;
    private static ?string $latest = null;

    /**
     * Installed version, or null if the VERSION file is missing or unreadable.
     */
    public static function current(): ?string
    {
        if (self::$current !== null) {
            return self::$current;
        }

        $file = __DIR__ . '/../VERSION';
        if (!is_readable($file)) {
            return null;
        }

        $value = trim((string) file_get_contents($file));

        return self::$current = ($value === '' ? null : $value);
    }

    /**
     * Whether checking github for a newer version is enabled. Off unless the
     * operator opts in, so a panel never contacts an external host by default.
     */
    public static function updateCheckEnabled(): bool
    {
        $val = strtolower((string) (Config::get('UPDATE_CHECK', '') ?: ''));

        return in_array($val, ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * Latest released version, or null if unknown. Cached on disk; network
     * failures are silent so that a page render never depends on github.
     */
    public static function latest(): ?string
    {
        if (self::$latestResolved) {
            return self::$latest;
        }

        self::$latestResolved = true;

        if (!self::updateCheckEnabled()) {
            return self::$latest = null;
        }

        $cacheFile = sys_get_temp_dir() . '/amnezia_panel_latest_version';

        if (is_readable($cacheFile) && (time() - (int) filemtime($cacheFile)) < self::CACHE_TTL) {
            $cached = trim((string) file_get_contents($cacheFile));
            return self::$latest = ($cached === '' ? null : $cached);
        }

        $latest = self::fetchLatestTag();

        // Cache negative results too, so an unreachable github is not retried
        // on every request.
        @file_put_contents($cacheFile, (string) $latest);

        return self::$latest = $latest;
    }

    /**
     * True when a released version is newer than the installed one.
     */
    public static function updateAvailable(): bool
    {
        $current = self::current();
        $latest = self::latest();

        if ($current === null || $latest === null) {
            return false;
        }

        return version_compare(self::normalize($latest), self::normalize($current), '>');
    }

    private static function fetchLatestTag(): ?string
    {
        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init('https://api.github.com/repos/' . self::REPO . '/tags?per_page=100');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT => 4,
            CURLOPT_USERAGENT => 'amnezia-web-panel',
            CURLOPT_HTTPHEADER => ['Accept: application/vnd.github+json'],
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200 || !is_string($body)) {
            return null;
        }

        $tags = json_decode($body, true);
        if (!is_array($tags)) {
            return null;
        }

        $newest = null;
        foreach ($tags as $tag) {
            $name = $tag['name'] ?? null;
            if (!is_string($name) || !preg_match('/^v?\d+(\.\d+)*$/', $name)) {
                continue;
            }
            if ($newest === null || version_compare(self::normalize($name), self::normalize($newest), '>')) {
                $newest = $name;
            }
        }

        return $newest;
    }

    private static function normalize(string $version): string
    {
        return ltrim(trim($version), 'vV');
    }
}
