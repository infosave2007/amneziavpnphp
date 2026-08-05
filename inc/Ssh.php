<?php

/**
 * Safe construction of SSH command lines.
 *
 * Server host/username/port are supplied by whoever created the server record
 * and are stored verbatim, so every value that reaches a shell must be
 * validated and escaped here rather than interpolated into a format string.
 */
class Ssh
{
    /**
     * Validate a hostname or IP address.
     *
     * @throws InvalidArgumentException
     */
    public static function host(string $host): string
    {
        $host = trim($host);

        if ($host === '' || strlen($host) > 253) {
            throw new InvalidArgumentException('Invalid server host');
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }

        // Dot-separated DNS labels; each label starts and ends alphanumeric.
        // Underscore is tolerated because some internal zones use it, and it is
        // not meaningful to the shell.
        $label = '[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?';
        if (preg_match('/^' . $label . '(?:\.' . $label . ')*\.?$/', $host)) {
            return $host;
        }

        throw new InvalidArgumentException('Invalid server host: must be an IP address or hostname');
    }

    /**
     * Validate a remote login name. A leading dash is rejected because ssh
     * would parse the resulting argument as an option rather than a target.
     *
     * @throws InvalidArgumentException
     */
    public static function user(string $username): string
    {
        $username = trim($username);

        if ($username === '' || strlen($username) > 32) {
            throw new InvalidArgumentException('Invalid SSH username');
        }

        if (!preg_match('/^[A-Za-z0-9_][A-Za-z0-9._-]*$/', $username)) {
            throw new InvalidArgumentException('Invalid SSH username: allowed characters are letters, digits, dot, underscore and hyphen');
        }

        return $username;
    }

    /**
     * Validate a TCP port.
     *
     * @param mixed $port
     * @throws InvalidArgumentException
     */
    public static function port($port): int
    {
        $port = (int) $port;

        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException('Invalid SSH port');
        }

        return $port;
    }

    /**
     * Build the shell-ready `user@host` argument for an ssh invocation.
     * The return value is already escaped — insert it with a bare %s.
     *
     * @throws InvalidArgumentException
     */
    public static function target(string $username, string $host): string
    {
        return escapeshellarg(self::user($username) . '@' . self::host($host));
    }

    /**
     * Quote a value for the *remote* shell, i.e. for text that is embedded in a
     * command string which is itself escaped once more before being sent.
     */
    public static function remoteArg(string $value): string
    {
        return "'" . str_replace("'", "'\\''", $value) . "'";
    }

    /**
     * Prefix a remote command with a non-interactive sudo that reads the
     * password from stdin.
     */
    public static function sudo(string $command, string $password): string
    {
        return "printf '%s\\n' " . self::remoteArg($password) . " | sudo -S -p '' " . $command;
    }
}
