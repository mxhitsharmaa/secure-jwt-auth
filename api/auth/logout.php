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

/* Authenticate Access Token */

$tokenData =
    authenticateRequest();

$userId =
    (int) $tokenData->user->id;

/* Request Data */

try {

    $input =
        getJsonInput();

    validateAllowedFields(
        $input,
        [
            'refresh_token',
        ]
    );

    $refreshToken =
        validateRequiredString(
            $input['refresh_token'] ?? null,
            'Refresh token',
            1,
            4096
        );

} catch (InvalidArgumentException $e) {

    errorResponse(
        $e->getMessage(),
        422
    );
}

/* Refresh Token Hash */

$refreshTokenHash =
    hash(
        'sha256',
        $refreshToken
    );

/* Request Lock */

acquireRequestLock(
    $conn,
    'refresh',
    $refreshTokenHash,
    'logout',
    10
);

/* Transaction */

$conn->begin_transaction();

try {

    /* Find Refresh Session */

    $tokenRecord =
        findRefreshToken(
            $conn,
            $refreshToken,
            true
        );

    /* Token Not Found */

    if (
        $tokenRecord === null
    ) {
        $conn->rollback();

        errorResponse(
            'Invalid refresh token.',
            401
        );
    }

    /* Verify User */

    if (
        (int) $tokenRecord['user_id'] !==
        $userId
    ) {
        $conn->rollback();

        errorResponse(
            'Invalid refresh token.',
            401
        );
    }

    /* Reuse Detection */

    if (
        isRefreshTokenReuseDetected(
            $tokenRecord
        )
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $tokenRecord['family_id'],
            true
        );

        $conn->commit();

        securityLog(
            'logout_refresh_token_reuse',
            $userId,
            [
                'family_id' =>
                    hash(
                        'sha256',
                        $tokenRecord['family_id']
                    ),
            ]
        );

        errorResponse(
            'Refresh token reuse detected. Please authenticate again.',
            401
        );
    }

    /* Already Revoked */

    if (
        isRefreshTokenRevoked(
            $tokenRecord
        )
    ) {
        $conn->rollback();

        successResponse(
            'Logout successful.'
        );
    }

    /* Revoke Current Session */

    revokeRefreshToken(
        $conn,
        (int) $tokenRecord['id']
    );

    /* Commit */

    $conn->commit();

} catch (Throwable) {

    try {
        $conn->rollback();
    } catch (Throwable) {
    }

    securityLog(
        'logout_error',
        $userId
    );

    errorResponse(
        'Unable to complete logout.',
        500
    );
}

/* Audit Log */

securityLog(
    'logout_success',
    $userId
);

/* Response */

successResponse(
    'Logout successful.'
);