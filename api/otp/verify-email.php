<?php

require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/rate_limiter.php';
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
            'Method not allowed.',
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

    /* Security Purpose */

    $securityPurpose =
        'email_verification';

    /* Request Rate Limits */

    checkRequestRateLimit(
        $conn,
        'email_verification_email',
        hash(
            'sha256',
            $email
        ),
        '/api/otp/verify-email.php',
        10,
        900
    );

    checkRequestRateLimit(
        $conn,
        'email_verification_ip',
        $ipAddress,
        '/api/otp/verify-email.php',
        20,
        900
    );

    /* OTP Security Block */

    $otpBlock =
        checkOtpBlock(
            $conn,
            $email,
            $ipAddress,
            $securityPurpose
        );

    if ($otpBlock['blocked']) {

        securityLog(
            'email_verification_blocked',
            null,
            [
                'email' =>
                    hash(
                        'sha256',
                        $email
                    ),
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
            'Unable to verify email.'
        );
    }

    $stmt->bind_result(
        $userId,
        $userName,
        $userEmail,
        $userStatus,
        $emailVerifiedAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    /* User Not Found */

    if (!$found) {

        errorResponse(
            'Invalid or expired verification code.',
            401
        );
    }

    $userId =
        (int) $userId;

    /* Already Verified */

    if (
        $emailVerifiedAt !== null
    ) {

        successResponse(
            'Email address is already verified.'
        );
    }

    /* Pending Account */

    if (
        $userStatus !== 'pending'
    ) {

        errorResponse(
            'Invalid or expired verification code.',
            401
        );
    }

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'verify-email',
        10
    );

    try {

        /* Transaction */

        $conn->begin_transaction();

        /* Lock User */

        $stmt = $conn->prepare(
            'SELECT
                id,
                name,
                email,
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
                'Unable to verify user account.'
            );
        }

        $stmt->bind_result(
            $lockedUserId,
            $lockedName,
            $lockedEmail,
            $lockedStatus,
            $lockedEmailVerifiedAt
        );

        $foundLockedUser =
            $stmt->fetch();

        $stmt->close();

        /* Validate User */

        if (
            !$foundLockedUser ||
            (int) $lockedUserId !== $userId
        ) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* Already Verified */

        if (
            $lockedEmailVerifiedAt !== null
        ) {

            throw new RuntimeException(
                'Email address is already verified.'
            );
        }

        /* Pending Account */

        if (
            $lockedStatus !== 'pending'
        ) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* Recheck OTP Block */

        $otpBlock =
            checkOtpBlock(
                $conn,
                $lockedEmail,
                $ipAddress,
                $securityPurpose
            );

        if ($otpBlock['blocked']) {

            throw new RuntimeException(
                'OTP verification is temporarily blocked.'
            );
        }

        /* Lock Latest OTP */

        $purpose =
            'email_verification';

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
                'Unable to prepare OTP verification.'
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
                'Unable to verify OTP.'
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

        $foundOtp =
            $stmt->fetch();

        $stmt->close();

        /* OTP Existence */

        if (!$foundOtp) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* OTP Consumed */

        if (
            $otpConsumedAt !== null
        ) {

            throw new RuntimeException(
                'Invalid or expired verification code.'
            );
        }

        /* OTP Expiry */

        $expiresTimestamp =
            strtotime(
                $otpExpiresAt
            );

        if (
            $expiresTimestamp === false ||
            $expiresTimestamp <= time()
        ) {

            throw new RuntimeException(
                'Verification code has expired.'
            );
        }

        /* Hash OTP */

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
                    $securityPurpose
                );

            if (
                !$conn->commit()
            ) {
                throw new RuntimeException(
                    'Unable to save OTP attempt.'
                );
            }

            securityLog(
                'email_verification_failed',
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
                'verify-email'
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
                'Invalid or expired verification code.',
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

        /* Verify Email */

        $stmt = $conn->prepare(
            'UPDATE users
             SET
                email_verified_at = NOW(),
                status = "active",
                updated_at = NOW()
             WHERE id = ?
               AND status = "pending"
               AND email_verified_at IS NULL
             LIMIT 1'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to prepare email verification.'
            );
        }

        $stmt->bind_param(
            'i',
            $userId
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to verify email address.'
            );
        }

        if (
            $stmt->affected_rows !== 1
        ) {

            $stmt->close();

            throw new RuntimeException(
                'Email verification could not be completed.'
            );
        }

        $stmt->close();

        /* Invalidate Other OTPs */

        $stmt = $conn->prepare(
            'UPDATE otp_codes
             SET consumed_at = NOW()
             WHERE user_id = ?
               AND purpose = ?
               AND consumed_at IS NULL'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to invalidate verification codes.'
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
                'Unable to invalidate verification codes.'
            );
        }

        $stmt->close();

        /* Reset OTP Security */

        resetOtpSecurityState(
            $conn,
            $lockedEmail,
            $ipAddress,
            $securityPurpose
        );

        /* Commit */

        if (
            !$conn->commit()
        ) {
            throw new RuntimeException(
                'Unable to complete email verification.'
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
            'verify-email'
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
                    $securityPurpose
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
                    'Invalid or expired verification code.',
                    'Verification code has expired.',
                    'Email address is already verified.',
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
            'email_verification_error',
            $userId
        );

        error_log(
            '[VERIFY_EMAIL] ' .
            $e->getMessage()
        );

        errorResponse(
            'Unable to verify email address.',
            500
        );
    }

    /* Audit */

    securityLog(
        'email_verified',
        $userId
    );

    /* Release Lock */

    releaseRequestLock(
        $conn,
        'user',
        (string) $userId,
        'verify-email'
    );

    /* Response */

    successResponse(
        'Email verified successfully. You can now login.',
        [
            'email_verified' =>
                true,
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
        '[VERIFY_EMAIL] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to verify email address.',
        500
    );
}