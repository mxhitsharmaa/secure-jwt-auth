<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../middleware/jwt.php';
require_once __DIR__ . '/../middleware/refresh_token.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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

/* Client IP */

$ipAddress =
    getClientIp();

/* Refresh Rate Limit */

checkRequestRateLimit(
    $conn,
    'refresh',
    $ipAddress,
    '/api/auth/refresh',
    10,
    60
);

/* Decode Refresh JWT */

try {

    $decoded =
        JWT::decode(
            $refreshToken,
            new Key(
                $jwtConfig['secret'],
                $jwtConfig['algorithm']
            )
        );

} catch (Throwable) {

    errorResponse(
        'Invalid or expired refresh token.',
        401
    );
}

/* Required Claims */

if (
    !isset(
        $decoded->iss,
        $decoded->aud,
        $decoded->iat,
        $decoded->nbf,
        $decoded->exp,
        $decoded->jti,
        $decoded->sub,
        $decoded->type,
        $decoded->token_version,
        $decoded->family_id
    )
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

/* Issuer */

if (
    !is_string($decoded->iss) ||
    !hash_equals(
        $jwtConfig['issuer'],
        $decoded->iss
    )
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

/* Audience */

$audienceValid =
    false;

if (
    is_string($decoded->aud)
) {

    $audienceValid =
        hash_equals(
            $jwtConfig['audience'],
            $decoded->aud
        );

} elseif (
    is_array($decoded->aud)
) {

    foreach (
        $decoded->aud
        as $audience
    ) {

        if (
            is_string($audience) &&
            hash_equals(
                $jwtConfig['audience'],
                $audience
            )
        ) {
            $audienceValid = true;

            break;
        }
    }
}

if (!$audienceValid) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

/* Numeric Claims */

foreach (
    [
        'iat',
        'nbf',
        'exp',
        'token_version',
    ]
    as $claim
) {

    if (
        !is_numeric(
            $decoded->{$claim}
        )
    ) {
        errorResponse(
            'Invalid refresh token.',
            401
        );
    }
}

/* Time Validation */

$now =
    time();

$clockSkew =
    max(
        0,
        (int) (
            $securityConfig['jwt']['clock_skew']
            ?? 30
        )
    );

$issuedAt =
    (int) $decoded->iat;

$notBefore =
    (int) $decoded->nbf;

$expiresAt =
    (int) $decoded->exp;

if (
    $expiresAt <=
    ($now - $clockSkew)
) {
    errorResponse(
        'Refresh token has expired.',
        401
    );
}

if (
    $issuedAt >
    ($now + $clockSkew)
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

if (
    $notBefore >
    ($now + $clockSkew)
) {
    errorResponse(
        'Refresh token is not active yet.',
        401
    );
}

if (
    $expiresAt <=
    $issuedAt
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

/* Token Type */

if (
    !is_string($decoded->type) ||
    $decoded->type !== 'refresh'
) {
    errorResponse(
        'Refresh token required.',
        401
    );
}

/* User ID */

if (
    !is_string($decoded->sub) ||
    !ctype_digit($decoded->sub) ||
    (int) $decoded->sub < 1
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

$userId =
    (int) $decoded->sub;

/* Token Version */

$tokenVersion =
    (int) $decoded->token_version;

if (
    $tokenVersion < 1
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

/* JTI */

if (
    !is_string($decoded->jti) ||
    !preg_match(
        '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
        $decoded->jti
    )
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

$refreshJti =
    $decoded->jti;

/* Family ID */

if (
    !is_string($decoded->family_id) ||
    !preg_match(
        '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
        $decoded->family_id
    )
) {
    errorResponse(
        'Invalid refresh token.',
        401
    );
}

$familyId =
    $decoded->family_id;

/* Request Lock */

acquireRequestLock(
    $conn,
    'user',
    (string) $userId,
    'refresh:' . $refreshJti,
    10
);

/* Transaction */

$conn->begin_transaction();

try {

    /* Lock Refresh Session */

    $tokenData =
        findRefreshToken(
            $conn,
            $refreshToken,
            true
        );

    if (
        $tokenData === null
    ) {
        $conn->rollback();

        errorResponse(
            'Invalid refresh token.',
            401
        );
    }

    /* Verify Stored JTI */

    if (
        !hash_equals(
            $tokenData['jti'],
            $refreshJti
        )
    ) {
        $conn->rollback();

        errorResponse(
            'Invalid refresh token.',
            401
        );
    }

    /* Verify Stored Family */

    if (
        !hash_equals(
            $tokenData['family_id'],
            $familyId
        )
    ) {
        $conn->rollback();

        errorResponse(
            'Invalid refresh token.',
            401
        );
    }

    /* Verify User */

    if (
        (int) $tokenData['user_id'] !==
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
        isRefreshTokenRevoked(
            $tokenData
        ) ||
        isRefreshTokenReuseDetected(
            $tokenData
        )
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $familyId,
            true
        );

        $conn->commit();

        securityLog(
            'refresh_token_reuse_detected',
            $userId,
            [
                'family_id' =>
                    hash(
                        'sha256',
                        $familyId
                    ),
            ]
        );

        errorResponse(
            'Refresh token reuse detected. Please authenticate again.',
            401
        );
    }

    /* Database Expiration */

    if (
        isRefreshTokenExpired(
            $tokenData
        )
    ) {

        revokeRefreshToken(
            $conn,
            (int) $tokenData['id']
        );

        $conn->commit();

        errorResponse(
            'Refresh token has expired.',
            401
        );
    }

    /* JWT and Database Expiration */

    $databaseExpiresAt =
        strtotime(
            $tokenData['expires_at']
        );

    if (
        $databaseExpiresAt === false ||
        abs(
            $databaseExpiresAt -
            $expiresAt
        ) > 1
    ) {

        revokeRefreshToken(
            $conn,
            (int) $tokenData['id']
        );

        $conn->commit();

        errorResponse(
            'Invalid refresh token session.',
            401
        );
    }

    /* User Lock */

    $stmt =
        $conn->prepare(
            'SELECT
                id,
                name,
                email,
                role,
                status,
                token_version,
                email_verified_at
             FROM users
             WHERE id = ?
             LIMIT 1
             FOR UPDATE'
        );

    if (
        $stmt === false
    ) {
        throw new RuntimeException(
            'Unable to lock user account.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (
        !$stmt->execute()
    ) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to verify user account.'
        );
    }

    $result =
        $stmt->get_result();

    $user =
        $result->fetch_assoc();

    $stmt->close();

    if (
        $user === null
    ) {

        $conn->rollback();

        errorResponse(
            'Account is no longer available.',
            401
        );
    }

    /* Token Version */

    if (
        (int) $user['token_version'] !==
        $tokenVersion
    ) {

        revokeRefreshToken(
            $conn,
            (int) $tokenData['id']
        );

        $conn->commit();

        errorResponse(
            'Refresh token has been revoked.',
            401
        );
    }

    /* Account Status */

    if (
        $user['status'] === 'blocked'
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $familyId
        );

        $conn->commit();

        errorResponse(
            'Account is blocked.',
            403
        );
    }

    if (
        $user['status'] === 'suspended'
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $familyId
        );

        $conn->commit();

        errorResponse(
            'Account is suspended.',
            403
        );
    }

    if (
        $user['status'] !== 'active'
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $familyId
        );

        $conn->commit();

        errorResponse(
            'Account is not active.',
            403
        );
    }

    /* Email Verification */

    if (
        $user['email_verified_at'] === null
    ) {

        revokeRefreshTokenFamily(
            $conn,
            $familyId
        );

        $conn->commit();

        errorResponse(
            'Email verification is required.',
            403
        );
    }

    /* Create New Token IDs */

    $newJti =
        generateUuidV4();

    $newFamilyId =
        $familyId;

    /* Create New Access Token */

    $newAccessToken =
        createAccessToken(
            $userId
        );

    /* Create New Refresh Token */

    $newRefreshToken =
        createRefreshToken(
            $userId,
            $newJti,
            $newFamilyId
        );

    /* Store New Refresh Token */

    $newRefreshExpiresAt =
        time() +
        $jwtConfig['refresh_ttl'];

    $newRefreshTokenId =
        storeRefreshToken(
            $conn,
            $userId,
            $newRefreshToken,
            $newJti,
            $newFamilyId,
            $newRefreshExpiresAt,
            (int) $tokenData['id']
        );

    /* Revoke Previous Token */

    revokeRefreshToken(
        $conn,
        (int) $tokenData['id'],
        $newRefreshTokenId
    );

    /* Update Last Used */

    $oldTokenId =
        (int) $tokenData['id'];

    $stmt =
        $conn->prepare(
            'UPDATE refresh_tokens
             SET last_used_at = NOW()
             WHERE id = ?
             LIMIT 1'
        );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to update refresh token usage.'
        );
    }

    $stmt->bind_param(
        'i',
        $oldTokenId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to update refresh token usage.'
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
        'refresh_token_error',
        $userId
    );

    errorResponse(
        'Unable to refresh authentication session.',
        500
    );
}

/* Security Log */

securityLog(
    'refresh_token_rotated',
    $userId
);

/* Response */

successResponse(
    'Token refreshed successfully.',
    [
        'token_type' =>
            'Bearer',

        'access_token' =>
            $newAccessToken,

        'expires_in' =>
            $jwtConfig['access_ttl'],

        'refresh_token' =>
            $newRefreshToken,

        'refresh_expires_in' =>
            $jwtConfig['refresh_ttl'],
    ]
);