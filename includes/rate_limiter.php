<?php

declare(strict_types=1);

/*
 Rate Limiter
 Database-backed rate limiting for authentication endpoints.
*/

/*
  Get client IP address.

  Do not trust X-Forwarded-For directly because it can be spoofed.
 */
function getClientIp(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return '0.0.0.0';
    }

    return $ip;
}

/*
  Check whether an IP/email has exceeded the allowed attempts.

  This function uses login_attempts as the source of truth.
 */
function isLoginRateLimited(
    mysqli $conn,
    ?string $email,
    string $ipAddress,
    int $maxAttempts = 5,
    int $windowSeconds = 900
): bool {

    if ($maxAttempts < 1 || $windowSeconds < 1) {
        throw new InvalidArgumentException(
            'Invalid rate limit configuration.'
        );
    }

    $since = date('Y-m-d H:i:s', time() - $windowSeconds);

    if ($email === null || $email === '') {

        $sql = '
            SELECT COUNT(*)
            FROM login_attempts
            WHERE success = 0
              AND created_at >= ?
              AND ip_address = ?
        ';

        $stmt = $conn->prepare($sql);

        if ($stmt === false) {
            return true; // fail-closed
        }

        $stmt->bind_param('ss', $since, $ipAddress);

    } else {

        $sql = '
            SELECT COUNT(*)
            FROM login_attempts
            WHERE success = 0
              AND created_at >= ?
              AND (
                  ip_address = ?
                  OR email = ?
              )
        ';

        $stmt = $conn->prepare($sql);

        if ($stmt === false) {
            return true; // fail-closed
        }

        $stmt->bind_param('sss', $since, $ipAddress, $email);
    }

    if (!$stmt->execute()) {
        $stmt->close();
        return true;
    }

    $stmt->bind_result($failedAttempts);

    $found = $stmt->fetch();
    $stmt->close();

    if (!$found) {
        return false;
    }

    return (int) $failedAttempts >= $maxAttempts;
}

/*
 Record a login attempt.
 */
function recordLoginAttempt(
    mysqli $conn,
    ?string $email,
    string $ipAddress,
    bool $success,
    ?int $userId = null,
    ?string $reason = null
): void {

    $successValue = $success ? 1 : 0;

    if ($email === null || $email === '') {
        $email = null;
    }

    if ($reason !== null && strlen($reason) > 100) {
        $reason = substr($reason, 0, 100);
    }

    if (strlen($ipAddress) > 45) {
        $ipAddress = substr($ipAddress, 0, 45);
    }

    try {

        if ($userId === null) {

            $stmt = $conn->prepare(
                'INSERT INTO login_attempts
                 (email, ip_address, user_id, success, reason)
                 VALUES (?, ?, NULL, ?, ?)'
            );

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param(
                'ssis',
                $email,
                $ipAddress,
                $successValue,
                $reason
            );

        } else {

            $stmt = $conn->prepare(
                'INSERT INTO login_attempts
                 (email, ip_address, user_id, success, reason)
                 VALUES (?, ?, ?, ?, ?)'
            );

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param(
                'ssiis',
                $email,
                $ipAddress,
                $userId,
                $successValue,
                $reason
            );
        }

        $stmt->execute();
        $stmt->close();

    } catch (Throwable $e) {

        error_log('[LOGIN_ATTEMPT] ' . $e->getMessage());
    }
}