<?php

require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/rate_limiter.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/jwt.php';
require_once __DIR__ . '/../middleware/refresh_token.php';
require_once __DIR__ . '/otp_service.php';

try {

    /* Security */

    applyApiSecurity();
    requireSecureConnection();

    /* Method */

    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    ) {
        header('Allow: POST');

        errorResponse(
            'HTTP method not allowed.',
            405
        );
    }

    /* JSON Input */

    $input =
        getJsonInput();

    /* Allowed Fields */

    validateAllowedFields(
        $input,
        [
            'email',
            'otp',
        ]
    );

    /* Validate Email */

    $email =
        validateEmail(
            $input['email'] ?? null
        );

    /* Validate OTP */

    $otp =
        validateOtp(
            $input['otp'] ?? null
        );

    /* Client IP */

    $ipAddress =
        getClientIp();

    /* OTP Security Purpose */

    $otpSecurityPurpose =
        'login_otp';

    /* Request Rate Limits */

    $emailRateKey =
        hash(
            'sha256',
            $email
        );

    checkRequestRateLimit(
        $conn,
        'login_otp_ip',
        $ipAddress,
        '/api/otp/verify-login.php',
        10,
        900
    );

    checkRequestRateLimit(
        $conn,
        'login_otp_email',
        $emailRateKey,
        '/api/otp/verify-login.php',
        5,
        900
    );

    /* OTP Security Block */

    $otpBlock =
        checkOtpBlock(
            $conn,
            $email,
            $ipAddress,
            $otpSecurityPurpose
        );

    if ($otpBlock['blocked']) {

        securityLog(
            'login_otp_blocked',
            null,
            [
                'email' =>
                    $emailRateKey,

                'retry_after' =>
                    $otpBlock['retry_after'],
            ]
        );

        errorResponse(
            'Too many OTP attempts. No OTP will be sent for the next 15 minutes.',
            429,
            [
                'retry_after' =>
                    $otpBlock['retry_after'],
            ]
        );
    }

    /* Find User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            name,
            email,
            role,
            status,
            token_version,
            email_verified_at
         FROM users
         WHERE email = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare user lookup.'
        );
    }

    $stmt->bind_param(
        's',
        $email
    );

    if (!$stmt->execute()) {

        $stmt->close();

        throw new RuntimeException(
            'Unable to verify login.'
        );
    }

    $stmt->bind_result(
        $userId,
        $userName,
        $userEmail,
        $userRole,
        $userStatus,
        $userTokenVersion,
        $userEmailVerifiedAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    /* User Not Found */

    if (!$found) {

        securityLog(
            'login_otp_invalid_request',
            null,
            [
                'email' =>
                    $emailRateKey,
            ]
        );

        errorResponse(
            'Invalid verification request.',
            401
        );
    }

    $userId =
        (int) $userId;

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'login-otp',
        10
    );

    $accessToken = null;
    $refreshToken = null;
    $refreshJti = null;
    $familyId = null;

    try {

        /* Transaction */

        $conn->begin_transaction();

        /* Lock User */

        $stmt = $conn->prepare(
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

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to lock user account.'
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
            $lockedName,
            $lockedEmail,
            $lockedRole,
            $lockedStatus,
            $lockedTokenVersion,
            $lockedEmailVerifiedAt
        );

        $userFound =
            $stmt->fetch();

        $stmt->close();

        /* Validate User */

        if (
            !$userFound ||
            (int) $lockedUserId !== $userId
        ) {
            throw new RuntimeException(
                'Invalid verification request.'
            );
        }

        /* Token Version */

        if (
            (int) $lockedTokenVersion < 1
        ) {
            throw new RuntimeException(
                'Invalid token version.'
            );
        }

        /* Account Status */

        if (
            $lockedStatus === 'blocked'
        ) {
            throw new RuntimeException(
                'Account is blocked.'
            );
        }

        if (
            $lockedStatus === 'suspended'
        ) {
            throw new RuntimeException(
                'Account is suspended.'
            );
        }

        if (
            $lockedStatus !== 'active'
        ) {
            throw new RuntimeException(
                'Account is not active.'
            );
        }

        /* Email Verification */

        if (
            $lockedEmailVerifiedAt === null
        ) {
            throw new RuntimeException(
                'Email verification is required.'
            );
        }

        /* Recheck OTP Security Block */

        $otpBlock =
            checkOtpBlock(
                $conn,
                $lockedEmail,
                $ipAddress,
                $otpSecurityPurpose
            );

        if ($otpBlock['blocked']) {

            throw new RuntimeException(
                'OTP verification is temporarily blocked.'
            );
        }

        /* Lock Latest OTP */

        $purpose =
            'login';

        $stmt = $conn->prepare(
            'SELECT
                id,
                otp_hash,
                attempts,
                max_attempts,
                expires_at,
                consumed_at
             FROM otp_codes
             WHERE user_id = ?
               AND purpose = ?
             ORDER BY id DESC
             LIMIT 1
             FOR UPDATE'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to prepare OTP lookup.'
            );
        }

        $stmt->bind_param(
            'is',
            $userId,
            $purpose
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to retrieve OTP.'
            );
        }

        $stmt->bind_result(
            $otpId,
            $storedOtpHash,
            $otpAttempts,
            $otpMaxAttempts,
            $expiresAt,
            $consumedAt
        );

        $otpFound =
            $stmt->fetch();

        $stmt->close();

        /* OTP Missing */

        if (!$otpFound) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* OTP Consumed */

        if ($consumedAt !== null) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* OTP Expiration */

        $expiresTimestamp =
            strtotime(
                $expiresAt
            );

        if (
            $expiresTimestamp === false ||
            $expiresTimestamp <= time()
        ) {

            throw new RuntimeException(
                'Verification code has expired.'
            );
        }

        /* OTP Hash */

        $otpHash =
            hash(
                'sha256',
                $otp
            );

        /* Constant Time Comparison */

        $valid =
            is_string($storedOtpHash) &&
            hash_equals(
                $storedOtpHash,
                $otpHash
            );

        /* Update OTP Attempts */

        $otpId =
            (int) $otpId;

        $stmt = $conn->prepare(
            'UPDATE otp_codes
             SET attempts = attempts + 1
             WHERE id = ?
               AND consumed_at IS NULL
             LIMIT 1'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to update OTP attempts.'
            );
        }

        $stmt->bind_param(
            'i',
            $otpId
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to update OTP attempts.'
            );
        }

        if (
            $stmt->affected_rows !== 1
        ) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to update OTP attempts.'
            );
        }

        $stmt->close();

        /* Invalid OTP */

        if (!$valid) {

            $attempt =
                recordOtpAttempt(
                    $conn,
                    $lockedEmail,
                    $ipAddress,
                    $otpSecurityPurpose
                );

            if (
                !$conn->commit()
            ) {
                throw new RuntimeException(
                    'Unable to save OTP attempt.'
                );
            }

            securityLog(
                'login_otp_failed',
                $userId,
                [
                    'reason' =>
                        'invalid_otp',

                    'attempts' =>
                        $attempt['attempts'],

                    'remaining' =>
                        $attempt['remaining'],
                ]
            );

            releaseRequestLock(
                $conn,
                'user',
                (string) $userId,
                'login-otp'
            );

            if (
                $attempt['blocked']
            ) {

                errorResponse(
                    'Too many OTP attempts. No OTP will be sent for the next 15 minutes.',
                    429,
                    [
                        'retry_after' =>
                            $attempt['retry_after'],
                    ]
                );
            }

            errorResponse(
                'Invalid verification code.',
                401,
                [
                    'attempts_remaining' =>
                        $attempt['remaining'],
                ]
            );
        }

        /* Consume OTP */

        $stmt = $conn->prepare(
            'UPDATE otp_codes
             SET consumed_at = NOW()
             WHERE id = ?
               AND user_id = ?
               AND consumed_at IS NULL
             LIMIT 1'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to consume OTP.'
            );
        }

        $stmt->bind_param(
            'ii',
            $otpId,
            $userId
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to consume OTP.'
            );
        }

        if (
            $stmt->affected_rows !== 1
        ) {

            $stmt->close();

            throw new RuntimeException(
                'OTP could not be consumed.'
            );
        }

        $stmt->close();

        /* Reset OTP Security */

        resetOtpSecurityState(
            $conn,
            $lockedEmail,
            $ipAddress,
            $otpSecurityPurpose
        );

        /* Generate Refresh Identifiers */

        $refreshJti =
            generateUuidV4();

        $familyId =
            generateUuidV4();

        /* Access Token */

        $accessToken =
            createAccessToken(
                $userId
            );

        /* Refresh Token */

        $refreshToken =
            createRefreshToken(
                $userId,
                $refreshJti,
                $familyId
            );

        /* Refresh Expiration */

        global $jwtConfig;

        $refreshExpiresAt =
            time() +
            (int) $jwtConfig['refresh_ttl'];

        /* Store Refresh Session */

        $refreshTokenId =
            storeRefreshToken(
                $conn,
                $userId,
                $refreshToken,
                $refreshJti,
                $familyId,
                $refreshExpiresAt
            );

        if (
            $refreshTokenId < 1
        ) {
            throw new RuntimeException(
                'Unable to create refresh session.'
            );
        }

        /* Update Last Login */

        $stmt = $conn->prepare(
            'UPDATE users
             SET last_login_at = NOW()
             WHERE id = ?
               AND status = "active"
               AND email_verified_at IS NOT NULL
             LIMIT 1'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to update login time.'
            );
        }

        $stmt->bind_param(
            'i',
            $userId
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to update login time.'
            );
        }

        if (
            $stmt->affected_rows !== 1
        ) {

            $stmt->close();

            throw new RuntimeException(
                'Login account state changed unexpectedly.'
            );
        }

        $stmt->close();

        /* Commit */

        if (
            !$conn->commit()
        ) {
            throw new RuntimeException(
                'Unable to complete login.'
            );
        }

    } catch (
        Throwable $e
    ) {

        try {
            $conn->rollback();
        } catch (Throwable) {
        }

        releaseRequestLock(
            $conn,
            'user',
            (string) $userId,
            'login-otp'
        );

        if (
            $e->getMessage() ===
            'OTP verification is temporarily blocked.'
        ) {

            $currentBlock =
                checkOtpBlock(
                    $conn,
                    $email,
                    $ipAddress,
                    $otpSecurityPurpose
                );

            if (
                $currentBlock['blocked']
            ) {

                errorResponse(
                    'Too many OTP attempts. No OTP will be sent for the next 15 minutes.',
                    429,
                    [
                        'retry_after' =>
                            $currentBlock['retry_after'],
                    ]
                );
            }
        }

        if (
            in_array(
                $e->getMessage(),
                [
                    'Invalid verification request.',
                    'Account is blocked.',
                    'Account is suspended.',
                    'Account is not active.',
                    'Email verification is required.',
                    'Invalid or expired verification code.',
                    'Verification code has expired.',
                ],
                true
            )
        ) {

            errorResponse(
                $e->getMessage(),
                401
            );
        }

        securityLog(
            'login_otp_verification_error',
            $userId
        );

        error_log(
            '[VERIFY_LOGIN_OTP] ' .
            $e->getMessage()
        );

        errorResponse(
            'Unable to complete login.',
            500
        );
    }

    /* Audit */

    securityLog(
        'login_success',
        $userId
    );

    /* Release Lock */

    releaseRequestLock(
        $conn,
        'user',
        (string) $userId,
        'login-otp'
    );

    /* Response */

    successResponse(
        'Login successful.',
        [
            'token_type' =>
                'Bearer',

            'access_token' =>
                $accessToken,

            'expires_in' =>
                (int) $jwtConfig['access_ttl'],

            'refresh_token' =>
                $refreshToken,

            'refresh_expires_in' =>
                (int) $jwtConfig['refresh_ttl'],

            'user' => [
                'id' =>
                    $userId,

                'name' =>
                    $lockedName,

                'email' =>
                    $lockedEmail,

                'role' =>
                    $lockedRole,

                'status' =>
                    $lockedStatus,
            ],
        ]
    );

} catch (
    InvalidArgumentException $e
) {

    errorResponse(
        $e->getMessage(),
        422
    );

} catch (
    Throwable $e
) {

    error_log(
        '[VERIFY_LOGIN_OTP] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to verify login.',
        500
    );
}