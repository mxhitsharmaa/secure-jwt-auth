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

/* Get current endpoint */

function getCurrentEndpoint(): string
{
    $uri =
        $_SERVER['REQUEST_URI'] ?? '/';

    $path =
        parse_url(
            $uri,
            PHP_URL_PATH
        );

    if (
        !is_string($path) ||
        $path === ''
    ) {
        return '/';
    }

    return substr(
        $path,
        0,
        255
    );
}

/* Send rate limit response */

function sendRateLimitResponse(
    int $retryAfter
): never {
    $retryAfter =
        max(1, $retryAfter);

    header(
        'Retry-After: ' .
        $retryAfter
    );

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    header(
        'Cache-Control: no-store'
    );

    http_response_code(429);

    echo json_encode(
        [
            'success' => false,
            'message' =>
                'Too many requests. Please try again later.',
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

/* Check request rate limit */

function checkRequestRateLimit(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $endpoint,
    int $maxRequests = 60,
    int $windowSeconds = 60
): void {

    if (
        $maxRequests < 1 ||
        $windowSeconds < 1
    ) {
        throw new InvalidArgumentException(
            'Invalid rate limit configuration.'
        );
    }

    $currentTime =
        time();

    $windowStartTimestamp =
        intdiv(
            $currentTime,
            $windowSeconds
        ) * $windowSeconds;

    $windowEndTimestamp =
        $windowStartTimestamp +
        $windowSeconds;

    $windowStart =
        date(
            'Y-m-d H:i:s',
            $windowStartTimestamp
        );

    $expiresAt =
        date(
            'Y-m-d H:i:s',
            $windowEndTimestamp
        );

    $rateKey =
        getRequestRateKey(
            $scope,
            $identifier,
            $endpoint
        );

    /* Atomic Counter */

    $sql = '
        INSERT INTO rate_limits
        (
            rate_key,
            window_start,
            request_count,
            expires_at
        )
        VALUES (?, ?, 1, ?)

        ON DUPLICATE KEY UPDATE
            request_count =
                request_count + 1,
            expires_at =
                VALUES(expires_at)
    ';

    $stmt =
        $conn->prepare($sql);

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

    /* Read Counter */

    $stmt =
        $conn->prepare(
            'SELECT request_count
             FROM rate_limits
             WHERE rate_key = ?
               AND window_start = ?
             LIMIT 1'
        );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to read rate limit.'
        );
    }

    $stmt->bind_param(
        'ss',
        $rateKey,
        $windowStart
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to read rate limit.'
        );
    }

    $stmt->bind_result(
        $requestCount
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    if (!$found) {
        throw new RuntimeException(
            'Rate limit record not found.'
        );
    }

    /* Limit Exceeded */

    if (
        (int) $requestCount >
        $maxRequests
    ) {

        $retryAfter =
            max(
                1,
                $windowEndTimestamp -
                time()
            );

        sendRateLimitResponse(
            $retryAfter
        );
    }
}

/* Apply global IP rate limit */

function applyGlobalRateLimit(
    mysqli $conn
): void {

    $ipAddress =
        getClientIp();

    $endpoint =
        getCurrentEndpoint();

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
        $scope . '|' .
        $identifier . '|' .
        $operation
    );
}

/* Acquire request lock */

function acquireRequestLock(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $operation,
    int $lockSeconds = 10
): void {

    if (
        $lockSeconds < 1 ||
        $lockSeconds > 300
    ) {
        throw new InvalidArgumentException(
            'Invalid request lock duration.'
        );
    }

    $lockKey =
        getRequestLockKey(
            $scope,
            $identifier,
            $operation
        );

    $expiresAt =
        date(
            'Y-m-d H:i:s',
            time() + $lockSeconds
        );

    /* Remove expired lock */

    $stmt =
        $conn->prepare(
            'DELETE FROM request_locks
             WHERE lock_key = ?
               AND expires_at <= NOW()'
        );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare expired lock cleanup.'
        );
    }

    $stmt->bind_param(
        's',
        $lockKey
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to clean expired request lock.'
        );
    }

    $stmt->close();

    /* Create lock */

    $stmt =
        $conn->prepare(
            'INSERT INTO request_locks
            (
                lock_key,
                expires_at
            )
            VALUES (?, ?)'
        );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare request lock.'
        );
    }

    $stmt->bind_param(
        'ss',
        $lockKey,
        $expiresAt
    );

    if ($stmt->execute()) {
        $stmt->close();

        return;
    }

    $errorCode =
        $stmt->errno;

    $stmt->close();

    /* Lock already exists */

    if ($errorCode === 1062) {
        sendRateLimitResponse(1);
    }

    throw new RuntimeException(
        'Unable to acquire request lock.'
    );
}

/* Release request lock */

function releaseRequestLock(
    mysqli $conn,
    string $scope,
    string $identifier,
    string $operation
): void {

    $lockKey =
        getRequestLockKey(
            $scope,
            $identifier,
            $operation
        );

    $stmt =
        $conn->prepare(
            'DELETE FROM request_locks
             WHERE lock_key = ?'
        );

    if ($stmt === false) {
        return;
    }

    $stmt->bind_param(
        's',
        $lockKey
    );

    $stmt->execute();
    $stmt->close();
}