<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
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
    'change-password',
    10
);

/* Request Body */

try {

    $input =
        getJsonInput();

    validateAllowedFields(
        $input,
        [
            'current_password',
            'new_password',
        ]
    );

    $currentPassword =
        validatePassword(
            $input['current_password'] ?? '',
            8,
            72
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

/* Password Difference */

if (
    hash_equals(
        $currentPassword,
        $newPassword
    )
) {
    errorResponse(
        'New password must be different from the current password.',
        422
    );
}

/* Transaction */

$conn->begin_transaction();

try {

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
            'Unable to prepare account lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve account.'
        );
    }

    $stmt->bind_result(
        $dbUserId,
        $passwordHash,
        $status,
        $currentTokenVersion,
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

    /* Verify Current Password */

    if (
        !password_verify(
            $currentPassword,
            $passwordHash
        )
    ) {

        $conn->rollback();

        securityLog(
            'change_password_failed',
            $userId
        );

        errorResponse(
            'Current password is incorrect.',
            401
        );
    }

    /* Password Hash */

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

    /* Commit */

    $conn->commit();

} catch (Throwable) {

    try {
        $conn->rollback();
    } catch (Throwable) {
    }

    securityLog(
        'change_password_error',
        $userId
    );

    errorResponse(
        'Unable to change password.',
        500
    );
}

/* Audit Log */

securityLog(
    'password_changed',
    $userId
);

/* Response */

successResponse(
    'Password changed successfully. Please log in again.'
);