<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../middleware/auth.php';
require_once __DIR__ . '/../middleware/refresh_token.php';

/* Security */

applyApiSecurity();
requireSecureConnection();

/* Request Method */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {
    header('Allow: POST');

    errorResponse(
        'HTTP method not allowed.',
        405
    );
}

/* Authenticate */

$tokenData =
    authenticateRequest();

$userId =
    (int) $tokenData->user->id;

/* Request Lock */

acquireRequestLock(
    $conn,
    'user',
    (string) $userId,
    'logout-all',
    10
);

/* Transaction */

$conn->begin_transaction();

try {

    /* Lock User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            token_version,
            status,
            email_verified_at
         FROM users
         WHERE id = ?
         LIMIT 1
         FOR UPDATE'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare user lock.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to lock user account.'
        );
    }

    $stmt->bind_result(
        $lockedUserId,
        $currentTokenVersion,
        $status,
        $emailVerifiedAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    if (!$found) {
        throw new RuntimeException(
            'User account not found.'
        );
    }

    /* Verify User */

    if (
        (int) $lockedUserId !==
        $userId
    ) {
        throw new RuntimeException(
            'User account verification failed.'
        );
    }

    /* Verify Token Version */

    if (
        (int) $currentTokenVersion < 1
    ) {
        throw new RuntimeException(
            'Invalid token version.'
        );
    }

    /* Account Status */

    if (
        $status !== 'active'
    ) {
        $conn->rollback();

        errorResponse(
            'Account is not active.',
            403
        );
    }

    if (
        $emailVerifiedAt === null
    ) {
        $conn->rollback();

        errorResponse(
            'Email address is not verified.',
            403
        );
    }

    /* Revoke All Refresh Sessions */

    revokeAllUserRefreshTokens(
        $conn,
        $userId
    );

    /* Increment Token Version */

    $stmt = $conn->prepare(
        'UPDATE users
         SET token_version =
             token_version + 1
         WHERE id = ?
           AND token_version = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare token version update.'
        );
    }

    $currentTokenVersion =
        (int) $currentTokenVersion;

    $stmt->bind_param(
        'ii',
        $userId,
        $currentTokenVersion
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate access tokens.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate access tokens.'
        );
    }

    $stmt->close();

    /* Commit */

    $conn->commit();

} catch (Throwable) {

    try {
        $conn->rollback();
    } catch (Throwable) {
    }

    securityLog(
        'logout_all_error',
        $userId
    );

    errorResponse(
        'Unable to complete logout.',
        500
    );
}

/* Audit Log */

securityLog(
    'logout_all_success',
    $userId
);

/* Response */

successResponse(
    'Logged out from all devices successfully.'
);