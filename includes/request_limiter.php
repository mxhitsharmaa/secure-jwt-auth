<?php

declare(strict_types=1);

/* Global Request Rate Limiter */

/* Create rate-limit key */

function getRequestRateKey(
    string $scope,
    string $identifier,
    string $endpoint
): string {
    return hash(
        'sha256',
        $scope . '|' . $identifier . '|' . $endpoint
    );
}

/* Get current endpoint (path only, no query string) */

function getCurrentEndpoint(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';

    $path = parse_url($uri, PHP_URL_PATH);

    if (!is_string($path) || $path === '') {
        return '/';
    }

    return substr($path, 0, 255);
}

/* Send rate limit response */

function sendRateLimitResponse(int $retryAfter): never
{
    $retryAfter = max(1, $retryAfter);

    header('Retry-After: ' . $retryAfter);

    errorResponse(
        'Too many requests. Please try again later.',
        429,
        ['retry_after' => $retryAfter]
    );
}

/* Check request rate limit (atomic) */

function checkRequestRateLimit(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $endpoint,
    int $maxRequests = 60,
    int $windowSeconds = 60
): void {

    if ($maxRequests < 1 || $windowSeconds < 1) {
        throw new InvalidArgumentException(
            'Invalid rate limit configuration.'
        );
    }

    $currentTime = time();

    $windowStartTimestamp =
        intdiv($currentTime, $windowSeconds) * $windowSeconds;

    $windowEndTimestamp =
        $windowStartTimestamp + $windowSeconds;

    $windowStart = date('Y-m-d H:i:s', $windowStartTimestamp);
    $expiresAt   = date('Y-m-d H:i:s', $windowEndTimestamp);

    $rateKey = getRequestRateKey($scope, $identifier, $endpoint);

    /*
      Atomic increment + read using LAST_INSERT_ID trick.

      INSERT ... ON DUPLICATE KEY UPDATE
        request_count = LAST_INSERT_ID(request_count + 1)

      makes $conn->insert_id return the NEW count.
    */

    $sql = '
        INSERT INTO rate_limits
        (
            rate_key,
            window_start,
            request_count,
            expires_at
        )
        VALUES (?, ?, LAST_INSERT_ID(1), ?)

        ON DUPLICATE KEY UPDATE
            request_count = LAST_INSERT_ID(request_count + 1),
            expires_at    = VALUES(expires_at)
    ';

    $stmt = $conn->prepare($sql);

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to initialize rate limiter.'
        );
    }

    $stmt->bind_param(
        'sss',
        $rateKey,
        $windowStart,
        $expiresAt
    );

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException(
            'Unable to process rate limit.'
        );
    }

    $stmt->close();

    /* Atomic count read */

    $requestCount = (int) $conn->insert_id;

    if ($requestCount < 1) {
        throw new RuntimeException(
            'Rate limit counter is invalid.'
        );
    }

    if ($requestCount > $maxRequests) {

        $retryAfter = max(1, $windowEndTimestamp - time());

        sendRateLimitResponse($retryAfter);
    }
}

/* Apply global IP rate limit */

function applyGlobalRateLimit(mysqli $conn): void
{
    $ipAddress = getClientIp();
    $endpoint  = getCurrentEndpoint();

    checkRequestRateLimit(
        $conn,
        'ip',
        $ipAddress,
        $endpoint,
        60,
        60
    );
}

/* Apply authenticated user rate limit */

function applyUserRateLimit(
    mysqli $conn,
    int $userId,
    string $endpoint,
    int $maxRequests = 120,
    int $windowSeconds = 60
): void {

    if ($userId < 1) {
        throw new InvalidArgumentException(
            'Invalid user ID.'
        );
    }

    checkRequestRateLimit(
        $conn,
        'user',
        (string) $userId,
        $endpoint,
        $maxRequests,
        $windowSeconds
    );
}

/* Create request lock key */

function getRequestLockKey(
    string $scope,
    string $identifier,
    string $operation
): string {
    return hash(
        'sha256',
        $scope . '|' . $identifier . '|' . $operation
    );
}

/* Acquire request lock (atomic) */

function acquireRequestLock(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $operation,
    int $lockSeconds = 10
): void {

    if ($lockSeconds < 1 || $lockSeconds > 300) {
        throw new InvalidArgumentException(
            'Invalid request lock duration.'
        );
    }

    $lockKey = getRequestLockKey($scope, $identifier, $operation);

    $expiresAt = date('Y-m-d H:i:s', time() + $lockSeconds);

    /*
      Atomic replace: delete expired THEN insert.

      Use INSERT ... ON DUPLICATE KEY UPDATE for atomicity.
      If lock exists and is NOT expired, the update fails the WHERE clause.
    */

    $stmt = $conn->prepare(
        'INSERT INTO request_locks
         (lock_key, expires_at)
         VALUES (?, ?)

         ON DUPLICATE KEY UPDATE
             expires_at = IF(
                 expires_at <= NOW(),
                 VALUES(expires_at),
                 expires_at
             )'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare request lock.'
        );
    }

    $stmt->bind_param('ss', $lockKey, $expiresAt);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException(
            'Unable to acquire request lock.'
        );
    }

    $affected = $stmt->affected_rows;
    $stmt->close();

    /*
      affected_rows == 1 → inserted (fresh lock)
      affected_rows == 2 → updated (expired, replaced) — OK
      affected_rows == 0 → duplicate found, still valid → lock held
    */

    if ($affected === 0) {
        sendRateLimitResponse(1);
    }
}

/* Release request lock */

function releaseRequestLock(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $operation
): void {

    $lockKey = getRequestLockKey($scope, $identifier, $operation);

    $stmt = $conn->prepare(
        'DELETE FROM request_locks WHERE lock_key = ?'
    );

    if ($stmt === false) {
        return;
    }

    $stmt->bind_param('s', $lockKey);
    $stmt->execute();
    $stmt->close();
}