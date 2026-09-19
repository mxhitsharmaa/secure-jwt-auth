<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
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

/* Request Body */

try {

    $input =
        getJsonInput();

    validateAllowedFields(
        $input,
        [
            'token',
            'new_password',
        ]
    );

    $token =
        validateRequiredString(
            $input['token'] ?? '',
            'Reset token',
            64,
            128
        );

    $newPassword =
        validatePassword(
            $input['new_password'] ?? '',
            8,
            72
        );

} catch (InvalidArgumentException $e) {

    errorResponse(
        $e->getMessage(),
        422
    );
}

/* Reset Token Hash */

$tokenHash =
    hash(
        'sha256',
        $token
    );

/* Request Rate Limit */

$ipAddress =
    getClientIp();

checkRequestRateLimit(
    $conn,
    'password-reset-confirm-ip',
    $ipAddress,
    '/api/auth/reset-password',
    10,
    900
);

checkRequestRateLimit(
    $conn,
    'password-reset-confirm-token',
    $tokenHash,
    '/api/auth/reset-password',
    3,
    900
);

/* Find Token Owner */

$stmt = $conn->prepare(
    'SELECT
        user_id
     FROM password_resets
     WHERE token_hash = ?
     LIMIT 1'
);

if ($stmt === false) {
    errorResponse(
        'Unable to process password reset.',
        500
    );
}

$stmt->bind_param(
    's',
    $tokenHash
);

if (!$stmt->execute()) {

    $stmt->close();

    errorResponse(
        'Unable to process password reset.',
        500
    );
}

$stmt->bind_result(
    $tokenUserId
);

$tokenFound =
    $stmt->fetch();

$stmt->close();

/* Invalid Token */

if (
    !$tokenFound ||
    (int) $tokenUserId < 1
) {
    errorResponse(
        'Invalid or expired password reset token.',
        400
    );
}

$userId =
    (int) $tokenUserId;

/* Request Lock */

acquireRequestLock(
    $conn,
    'user',
    (string) $userId,
    'password-reset',
    10
);

/* Transaction */

$conn->begin_transaction();

try {

    /* Lock Reset Token */

    $stmt = $conn->prepare(
        'SELECT
            id,
            user_id,
            token_hash,
            expires_at,
            used_at
         FROM password_resets
         WHERE token_hash = ?
         LIMIT 1
         FOR UPDATE'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare reset token lookup.'
        );
    }

    $stmt->bind_param(
        's',
        $tokenHash
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to verify reset token.'
        );
    }

    $stmt->bind_result(
        $resetId,
        $resetUserId,
        $storedTokenHash,
        $expiresAt,
        $usedAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    /* Token Validation */

    if (
        !$found ||
        (int) $resetUserId !== $userId ||
        !is_string($storedTokenHash) ||
        !hash_equals(
            $storedTokenHash,
            $tokenHash
        ) ||
        $usedAt !== null
    ) {

        $conn->rollback();

        errorResponse(
            'Invalid or expired password reset token.',
            400
        );
    }

    /* Token Expiry */

    $expiryTimestamp =
        strtotime($expiresAt);

    if (
        $expiryTimestamp === false ||
        $expiryTimestamp <= time()
    ) {

        $conn->rollback();

        errorResponse(
            'Invalid or expired password reset token.',
            400
        );
    }

    /* Lock User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            password,
            status,
            token_version,
            email_verified_at
         FROM users
         WHERE id = ?
         LIMIT 1
         FOR UPDATE'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare user lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve user account.'
        );
    }

    $stmt->bind_result(
        $dbUserId,
        $currentPasswordHash,
        $status,
        $currentTokenVersion,
        $emailVerifiedAt
    );

    $userFound =
        $stmt->fetch();

    $stmt->close();

    if (!$userFound) {
        throw new RuntimeException(
            'User account not found.'
        );
    }

    /* Verify User */

    if (
        (int) $dbUserId !==
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
        $status !== 'active' ||
        $emailVerifiedAt === null
    ) {

        $conn->rollback();

        errorResponse(
            'Account is not eligible for password reset.',
            403
        );
    }

    /* Prevent Same Password */

    if (
        password_verify(
            $newPassword,
            $currentPasswordHash
        )
    ) {

        $conn->rollback();

        errorResponse(
            'New password must be different from the previous password.',
            422
        );
    }

    /* Hash New Password */

    $newPasswordHash =
        password_hash(
            $newPassword,
            $securityConfig['password']['algorithm']
        );

    if (
        !is_string($newPasswordHash) ||
        $newPasswordHash === ''
    ) {
        throw new RuntimeException(
            'Unable to secure new password.'
        );
    }

    /* Update Password */

    $stmt = $conn->prepare(
        'UPDATE users
         SET
            password = ?,
            token_version =
                token_version + 1
         WHERE id = ?
           AND token_version = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare password update.'
        );
    }

    $currentTokenVersion =
        (int) $currentTokenVersion;

    $stmt->bind_param(
        'sii',
        $newPasswordHash,
        $userId,
        $currentTokenVersion
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to update password.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate previous authentication sessions.'
        );
    }

    $stmt->close();

    /* Revoke All Refresh Sessions */

    revokeAllUserRefreshTokens(
        $conn,
        $userId
    );

    /* Consume Reset Token */

    $stmt = $conn->prepare(
        'UPDATE password_resets
         SET used_at = NOW()
         WHERE id = ?
           AND user_id = ?
           AND used_at IS NULL
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare reset token update.'
        );
    }

    $stmt->bind_param(
        'ii',
        $resetId,
        $userId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to consume reset token.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {

        $stmt->close();

        throw new RuntimeException(
            'Reset token could not be consumed.'
        );
    }

    $stmt->close();

    /* Invalidate Other Reset Tokens */

    $stmt = $conn->prepare(
        'UPDATE password_resets
         SET used_at = NOW()
         WHERE user_id = ?
           AND id <> ?
           AND used_at IS NULL'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to invalidate old reset tokens.'
        );
    }

    $stmt->bind_param(
        'ii',
        $userId,
        $resetId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate old reset tokens.'
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
        'password_reset_error',
        $userId
    );

    errorResponse(
        'Unable to reset password.',
        500
    );
}

/* Audit Log */

securityLog(
    'password_reset_completed',
    $userId
);

/* Response */

successResponse(
    'Password reset successfully. Please log in again.'
);