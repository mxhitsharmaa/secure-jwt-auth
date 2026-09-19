<?php

require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
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

    /* JSON input */

    $input = getJsonInput();

    /* Allowed fields */

    validateAllowedFields(
        $input,
        [
            'email',
            'otp',
        ]
    );

    /* Validate email */

    $email = validateEmail(
        $input['email'] ?? null
    );

    /* Validate OTP */

    $otp = validateOtp(
        $input['otp'] ?? null
    );

    /* Client IP */

    $ipAddress = getClientIp();

    /* Rate limits */

    $emailRateKey = hash(
        'sha256',
        $email
    );

    checkRequestRateLimit(
        $conn,
        'password_reset_verify_email',
        $emailRateKey,
        '/api/otp/verify-password-reset.php',
        5,
        900
    );

    checkRequestRateLimit(
        $conn,
        'password_reset_verify_ip',
        $ipAddress,
        '/api/otp/verify-password-reset.php',
        20,
        900
    );

    /* Generic response */

    $genericMessage =
        'Invalid or expired verification code.';

    /* Find user */

    $stmt = $conn->prepare(
        'SELECT
            id,
            status,
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
            'Unable to verify password reset request.'
        );
    }

    $stmt->bind_result(
        $userId,
        $userStatus,
        $emailVerifiedAt
    );

    $found = $stmt->fetch();

    $stmt->close();

    /* Account protection */

    if (
        !$found ||
        $userStatus !== 'active' ||
        $emailVerifiedAt === null
    ) {
        errorResponse(
            $genericMessage,
            401
        );
    }

    $userId = (int) $userId;

    /* Request lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'verify-password-reset',
        10
    );

    $resetToken = null;

    try {

        /* Transaction */

        $conn->begin_transaction();

        /* Lock user */

        $stmt = $conn->prepare(
            'SELECT
                id,
                status,
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
            $lockedUserStatus,
            $lockedEmailVerifiedAt
        );

        $foundLockedUser = $stmt->fetch();

        $stmt->close();

        /* Recheck account */

        if (
            !$foundLockedUser ||
            (int) $lockedUserId !== $userId ||
            $lockedUserStatus !== 'active' ||
            $lockedEmailVerifiedAt === null
        ) {
            $conn->rollback();

            errorResponse(
                $genericMessage,
                401
            );
        }

        /* OTP purpose */

        $purpose = 'password_reset';

        /* Lock latest OTP */

        $stmt = $conn->prepare(
            'SELECT
                id,
                otp_hash,
                expires_at,
                attempts,
                max_attempts,
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
            $otpExpiresAt,
            $otpAttempts,
            $otpMaxAttempts,
            $otpConsumedAt
        );

        $foundOtp = $stmt->fetch();

        $stmt->close();

        /* OTP existence */

        if (!$foundOtp) {
            $conn->rollback();

            errorResponse(
                $genericMessage,
                401
            );
        }

        /* OTP consumed */

        if ($otpConsumedAt !== null) {
            $conn->rollback();

            errorResponse(
                $genericMessage,
                401
            );
        }

        /* Maximum attempts */

        $configuredMaxAttempts =
            (int) (
                $securityConfig['otp']['max_attempts']
                ?? 5
            );

        $storedMaxAttempts =
            (int) $otpMaxAttempts;

        if (
            $configuredMaxAttempts < 1 ||
            $storedMaxAttempts < 1
        ) {
            throw new RuntimeException(
                'Invalid OTP configuration.'
            );
        }

        $maxAttempts = min(
            $configuredMaxAttempts,
            $storedMaxAttempts
        );

        if (
            (int) $otpAttempts >=
            $maxAttempts
        ) {
            $conn->rollback();

            securityLog(
                'password_reset_otp_attempt_limit',
                $userId
            );

            errorResponse(
                'Too many verification attempts. Please request a new code.',
                429
            );
        }

        /* OTP expiry */

        $expiresTimestamp = strtotime(
            $otpExpiresAt
        );

        if (
            $expiresTimestamp === false ||
            $expiresTimestamp <= time()
        ) {
            $conn->rollback();

            errorResponse(
                'Verification code has expired.',
                401
            );
        }

        /* Hash OTP */

        $otpHash = hash(
            'sha256',
            $otp
        );

        /* Constant-time comparison */

        $valid =
            is_string($storedOtpHash) &&
            hash_equals(
                $storedOtpHash,
                $otpHash
            );

        $otpId = (int) $otpId;

        /* Increase attempts */

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

        if ($stmt->affected_rows !== 1) {
            $stmt->close();

            throw new RuntimeException(
                'Unable to update OTP attempts.'
            );
        }

        $stmt->close();

        /* Invalid OTP */

        if (!$valid) {

            if (!$conn->commit()) {
                throw new RuntimeException(
                    'Unable to save OTP attempt.'
                );
            }

            securityLog(
                'password_reset_otp_failed',
                $userId,
                [
                    'reason' => 'invalid_otp',
                ]
            );

            releaseRequestLock(
                $conn,
                'user',
                (string) $userId,
                'verify-password-reset'
            );

            errorResponse(
                $genericMessage,
                401
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

        if ($stmt->affected_rows !== 1) {
            $stmt->close();

            throw new RuntimeException(
                'OTP could not be consumed.'
            );
        }

        $stmt->close();

        /* Invalidate previous reset tokens */

        $stmt = $conn->prepare(
            'UPDATE password_resets
             SET used_at = NOW()
             WHERE user_id = ?
               AND used_at IS NULL'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to invalidate previous reset tokens.'
            );
        }

        $stmt->bind_param(
            'i',
            $userId
        );

        if (!$stmt->execute()) {
            $stmt->close();

            throw new RuntimeException(
                'Unable to invalidate previous reset tokens.'
            );
        }

        $stmt->close();

        /* Generate reset token */

        $resetToken = bin2hex(
            random_bytes(32)
        );

        $resetTokenHash = hash(
            'sha256',
            $resetToken
        );

        $resetTokenExpiry = date(
            'Y-m-d H:i:s',
            time() + 900
        );

        /* Store reset token hash */

        $stmt = $conn->prepare(
            'INSERT INTO password_resets
            (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (?, ?, ?)'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to prepare reset token.'
            );
        }

        $stmt->bind_param(
            'iss',
            $userId,
            $resetTokenHash,
            $resetTokenExpiry
        );

        if (!$stmt->execute()) {
            $stmt->close();

            throw new RuntimeException(
                'Unable to create reset token.'
            );
        }

        $stmt->close();

        /* Commit */

        if (!$conn->commit()) {
            throw new RuntimeException(
                'Unable to complete password reset verification.'
            );
        }

    } catch (Throwable $e) {

        try {
            $conn->rollback();
        } catch (Throwable) {
        }

        releaseRequestLock(
            $conn,
            'user',
            (string) $userId,
            'verify-password-reset'
        );

        throw $e;
    }

    /* Audit */

    securityLog(
        'password_reset_otp_verified',
        $userId
    );

    /* Release lock */

    releaseRequestLock(
        $conn,
        'user',
        (string) $userId,
        'verify-password-reset'
    );

    /* Response */

    successResponse(
        'Verification code verified successfully.',
        [
            'reset_token' => $resetToken,
            'expires_in' => 900,
        ]
    );

} catch (InvalidArgumentException $e) {

    errorResponse(
        $e->getMessage(),
        422
    );

} catch (Throwable $e) {

    error_log(
        '[VERIFY_PASSWORD_RESET] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to verify password reset code.',
        500
    );
}