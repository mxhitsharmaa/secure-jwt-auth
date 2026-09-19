<?php

require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/otp_service.php';
require_once __DIR__ . '/mail_service.php';

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
        ]
    );

    /* Validate email */

    $email = validateEmail(
        $input['email'] ?? null
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
        'password_reset_resend_email',
        $emailRateKey,
        '/api/otp/resend-password-reset.php',
        3,
        900
    );

    checkRequestRateLimit(
        $conn,
        'password_reset_resend_ip',
        $ipAddress,
        '/api/otp/resend-password-reset.php',
        10,
        900
    );

    /* Generic response */

    $genericMessage =
        'If the email address is registered, a password reset OTP has been sent.';

    /* Find user */

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
            'Unable to process password reset request.'
        );
    }

    $stmt->bind_result(
        $userId,
        $userName,
        $userEmail,
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
        successResponse(
            $genericMessage
        );
    }

    $userId = (int) $userId;

    /* Request lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'resend-password-reset',
        10
    );

    $otp = null;
    $otpId = null;

    try {

        /* Transaction */

        $conn->begin_transaction();

        /* Lock user */

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
                'Unable to lock user account.'
            );
        }

        $stmt->bind_result(
            $lockedUserId,
            $lockedUserName,
            $lockedUserEmail,
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

            successResponse(
                $genericMessage
            );
        }

        /* OTP purpose */

        $purpose = 'password_reset';

        /* Check latest OTP */

        $stmt = $conn->prepare(
            'SELECT
                id,
                created_at,
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
                'Unable to check OTP cooldown.'
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
                'Unable to check OTP cooldown.'
            );
        }

        $stmt->bind_result(
            $latestOtpId,
            $latestOtpCreatedAt,
            $latestOtpExpiresAt,
            $latestOtpConsumedAt
        );

        $hasLatestOtp = $stmt->fetch();

        $stmt->close();

        /* Resend cooldown */

        if ($hasLatestOtp) {

            $cooldown =
                (int) (
                    $securityConfig['otp']['resend_cooldown']
                    ?? 60
                );

            $createdAt =
                strtotime(
                    $latestOtpCreatedAt
                );

            if ($createdAt === false) {
                throw new RuntimeException(
                    'Invalid OTP creation time.'
                );
            }

            $elapsed =
                time() - $createdAt;

            if ($elapsed < $cooldown) {

                $retryAfter =
                    max(
                        1,
                        $cooldown - $elapsed
                    );

                $conn->rollback();

                header(
                    'Retry-After: ' .
                    $retryAfter
                );

                errorResponse(
                    'Please wait before requesting another OTP.',
                    429,
                    [
                        'retry_after' =>
                            $retryAfter,
                    ]
                );
            }
        }

        /* Create new OTP */

        $otp = createOtp(
            $conn,
            $userId,
            $purpose
        );

        /* Get new OTP ID */

        $stmt = $conn->prepare(
            'SELECT
                id
             FROM otp_codes
             WHERE user_id = ?
               AND purpose = ?
             ORDER BY id DESC
             LIMIT 1'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to retrieve OTP identifier.'
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
                'Unable to retrieve OTP identifier.'
            );
        }

        $stmt->bind_result(
            $newOtpId
        );

        $foundOtp = $stmt->fetch();

        $stmt->close();

        if (!$foundOtp) {
            throw new RuntimeException(
                'Unable to retrieve OTP identifier.'
            );
        }

        $otpId = (int) $newOtpId;

        /* Commit */

        if (!$conn->commit()) {
            throw new RuntimeException(
                'Unable to complete OTP request.'
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
            'resend-password-reset'
        );

        throw $e;
    }

    /* Send OTP email */

    try {

        sendOtpEmail(
            $lockedUserEmail,
            $lockedUserName,
            $otp,
            'password_reset'
        );

    } catch (Throwable $e) {

        /* Invalidate failed OTP */

        if ($otpId !== null) {

            $stmt = $conn->prepare(
                'UPDATE otp_codes
                 SET consumed_at = NOW()
                 WHERE id = ?
                   AND consumed_at IS NULL'
            );

            if ($stmt !== false) {

                $stmt->bind_param(
                    'i',
                    $otpId
                );

                $stmt->execute();
                $stmt->close();
            }
        }

        securityLog(
            'password_reset_otp_resend_mail_failed',
            $userId
        );

        releaseRequestLock(
            $conn,
            'user',
            (string) $userId,
            'resend-password-reset'
        );

        errorResponse(
            'Unable to send password reset OTP.',
            500
        );
    }

    /* Audit */

    securityLog(
        'password_reset_otp_resent',
        $userId
    );

    /* Release lock */

    releaseRequestLock(
        $conn,
        'user',
        (string) $userId,
        'resend-password-reset'
    );

    /* Response */

    successResponse(
        $genericMessage,
        [
            'otp_required' => true,
            'expires_in' =>
                (int) (
                    $securityConfig['otp']['expiry']
                    ?? 300
                ),
            'resend_after' =>
                (int) (
                    $securityConfig['otp']['resend_cooldown']
                    ?? 60
                ),
        ]
    );

} catch (InvalidArgumentException $e) {

    errorResponse(
        $e->getMessage(),
        422
    );

} catch (Throwable $e) {

    error_log(
        '[RESEND_PASSWORD_RESET] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to process password reset request.',
        500
    );
}