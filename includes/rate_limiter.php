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

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
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
    $since = date(
        'Y-m-d H:i:s',
        time() - $windowSeconds
    );

    /*
      Count failed attempts from both:
     - the supplied email
     - the client IP
     
      Prepared statements prevent SQL injection.
     */
    $sql = '
        SELECT COUNT(*)
        FROM login_attempts
        WHERE success = 0
          AND created_at >= ?
          AND (
              ip_address = ?
              OR (email IS NOT NULL AND email = ?)
          )
    ';

    $stmt = $conn->prepare($sql);

    if ($stmt === false) {
        // Fail closed for authentication protection.
        return true;
    }

    $stmt->bind_param(
        'sss',
        $since,
        $ipAddress,
        $email
    );

    $stmt->execute();

    $stmt->bind_result($failedAttempts);
    $stmt->fetch();

    $stmt->close();

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

    $stmt->execute();
    $stmt->close();
}