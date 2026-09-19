<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
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

    /* JSON Input */

    $input = getJsonInput();

    /* Allowed Fields */

    validateAllowedFields(
        $input,
        [
            'email',
        ]
    );

    /* Validate Email */

    $email = validateEmail(
        $input['email'] ?? null
    );

    /* Client IP */

    $ipAddress = getClientIp();

    /* Purpose */

    $purpose = 'email_verification';

    /* Generic Response */

    $genericMessage =
        'If the account requires verification, a verification code has been sent.';

    /* Basic Request Rate Limit */

    checkRequestRateLimit(
        $conn,
        'email_verification_ip',
        $ipAddress,
        '/api/otp/resend-email.php',
        20,
        900
    );

    checkRequestRateLimit(
        $conn,
        'email_verification_email',
        hash(
            'sha256',
            $email
        ),
        '/api/otp/resend-email.php',
        10,
        900
    );

    /* OTP Security Check */

    $otpSecurity = checkOtpResendAllowed(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    if (
        !$otpSecurity['allowed']
    ) {

        $retryAfter = max(
            1,
            (int) $otpSecurity['retry_after']
        );

        header(
            'Retry-After: ' .
            $retryAfter
        );

        /* 15 Minute Block */

        if (
            $otpSecurity['reason'] === 'blocked' ||
            $otpSecurity['reason'] === 'resend_limit'
        ) {

            securityLog(
                'email_verification_otp_blocked',
                null,
                [
                    'email' =>
                        hash(
                            'sha256',
                            $email
                        ),
                    'retry_after' =>
                        $retryAfter,
                ]
            );

            errorResponse(
                'OTP limit reached. No new OTP will be sent for 15 minutes.',
                429,
                [
                    'otp_blocked' => true,
                    'retry_after' => $retryAfter,
                ]
            );
        }

        /* 60 Second Cooldown */

        errorResponse(
            'Please wait before requesting another OTP.',
            429,
            [
                'otp_blocked' => false,
                'retry_after' => $retryAfter,
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
            'Unable to process verification request.'
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

    /* Generic User Response */

    if (!$found) {

        successResponse(
            $genericMessage
        );
    }

    $userId = (int) $userId;

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

        successResponse(
            $genericMessage
        );
    }

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'resend-verification',
        10
    );

    $otp = null;
    $otpId = null;

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
                'Unable to lock user account.'
            );
        }

        $stmt->bind_result(
            $lockedUserId,
            $lockedName,
            $lockedEmail,
            $lockedStatus,
            $lockedEmailVerifiedAt
        );

        $lockedUserFound = $stmt->fetch();

        $stmt->close();

        /* Recheck User */

        if (
            !$lockedUserFound ||
            (int) $lockedUserId !== $userId
        ) {

            $conn->rollback();

            successResponse(
                $genericMessage
            );
        }

        /* Recheck Verification */

        if (
            $lockedEmailVerifiedAt !== null
        ) {

            $conn->rollback();

            successResponse(
                'Email address is already verified.'
            );
        }

        /* Recheck Status */

        if (
            $lockedStatus !== 'pending'
        ) {

            $conn->rollback();

            successResponse(
                $genericMessage
            );
        }

        /* Recheck OTP Security */

        $otpSecurity = checkOtpResendAllowed(
            $conn,
            $email,
            $ipAddress,
            $purpose
        );

        if (
            !$otpSecurity['allowed']
        ) {

            $retryAfter = max(
                1,
                (int) $otpSecurity['retry_after']
            );

            $conn->rollback();

            header(
                'Retry-After: ' .
                $retryAfter
            );

            if (
                $otpSecurity['reason'] === 'blocked' ||
                $otpSecurity['reason'] === 'resend_limit'
            ) {

                errorResponse(
                    'OTP limit reached. No new OTP will be sent for 15 minutes.',
                    429,
                    [
                        'otp_blocked' => true,
                        'retry_after' => $retryAfter,
                    ]
                );
            }

            errorResponse(
                'Please wait before requesting another OTP.',
                429,
                [
                    'otp_blocked' => false,
                    'retry_after' => $retryAfter,
                ]
            );
        }

        /* Create OTP */

        $otp = createOtp(
            $conn,
            $userId,
            $purpose
        );

        /* Get OTP ID */

        $stmt = $conn->prepare(
            'SELECT id
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

        $otpFound = $stmt->fetch();

        $stmt->close();

        if (!$otpFound) {
            throw new RuntimeException(
                'Unable to retrieve OTP identifier.'
            );
        }

        $otpId = (int) $newOtpId;

        /* Commit */

        if (!$conn->commit()) {
            throw new RuntimeException(
                'Unable to create verification code.'
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
            'resend-verification'
        );

        throw $e;
    }

    /* Send OTP Email */

    try {

        sendOtpEmail(
            $lockedEmail,
            $lockedName,
            $otp
        );

    } catch (Throwable $e) {

        /* Invalidate Failed OTP */

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
            'email_verification_otp_mail_failed',
            $userId
        );

        releaseRequestLock(
            $conn,
            'user',
            (string) $userId,
            'resend-verification'
        );

        errorResponse(
            'Unable to send verification code. Please try again later.',
            500
        );
    }

    /* Record OTP Sent */

    recordOtpSent(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    /* Get Current OTP Security State */

    $currentState = getOtpSecurityState(
        $conn,
        $email,
        $ipAddress,
        $purpose,
        false
    );

    $sendCount = (int) (
        $currentState['resend_count'] ?? 0
    );

    $limits = getOtpSecurityLimits();

    /* Audit */

    securityLog(
        'email_verification_otp_resent',
        $userId,
        [
            'otp_send_number' =>
                $sendCount,
            'max_otp_sends' =>
                $limits['max_resends'],
        ]
    );

    /* Release Lock */

    releaseRequestLock(
        $conn,
        'user',
        (string) $userId,
        'resend-verification'
    );

    /* Response */

    successResponse(
        $genericMessage,
        [
            'otp_required' =>
                true,

            'expires_in' =>
                300,

            'resend_after' =>
                $limits['resend_cooldown'],

            'otp_send_number' =>
                $sendCount,

            'max_otp_sends' =>
                $limits['max_resends'],

            'remaining_otp_sends' =>
                max(
                    0,
                    $limits['max_resends'] -
                    $sendCount
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
        '[RESEND_EMAIL] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to process email verification request.',
        500
    );
}