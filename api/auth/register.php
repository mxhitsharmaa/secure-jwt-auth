<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../otp/otp_service.php';
require_once __DIR__ . '/../otp/mail_service.php';

try {

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

$input = getJsonInput();

/* Required Fields */

if (
    !array_key_exists('name', $input) ||
    !array_key_exists('email', $input) ||
    !array_key_exists('password', $input)
) {
    throw new InvalidArgumentException(
        'Name, email and password are required.'
    );
}

/* Validate Name */

$name = validateName(
    $input['name']
);

/* Validate Email */

$email = validateEmail(
    $input['email']
);

/* Validate Password */

$password = validatePassword(
    $input['password'],
    $securityConfig['password']['min_length'],
    $securityConfig['password']['max_length']
);
    /* Client IP */

    $ipAddress = getClientIp();

    /* Email Rate Limit */

    $emailRateKey = hash(
        'sha256',
        $email
    );

    checkRequestRateLimit(
        $conn,
        'registration_ip',
        $ipAddress,
        '/api/auth/register.php',
        10,
        900
    );

    checkRequestRateLimit(
        $conn,
        'registration_email',
        $emailRateKey,
        '/api/auth/register.php',
        3,
        900
    );

    /* OTP Security */

    $otpSecurity = checkOtpResendAllowed(
        $conn,
        $email,
        $ipAddress,
        'email_verification'
    );

    if (!$otpSecurity['allowed']) {

        $retryAfter = max(
            1,
            (int) $otpSecurity['retry_after']
        );

        header(
            'Retry-After: ' .
            $retryAfter
        );

        if (
            $otpSecurity['reason'] === 'blocked' ||
            $otpSecurity['reason'] === 'resend_limit'
        ) {

            securityLog(
                'registration_otp_blocked',
                null,
                [
                    'email' => $emailRateKey,
                    'retry_after' => $retryAfter,
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

        errorResponse(
            'Please wait before requesting another OTP.',
            429,
            [
                'otp_blocked' => false,
                'retry_after' => $retryAfter,
            ]
        );
    }

    /* Find Existing User */

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
            'Unable to process registration.'
        );
    }

    $stmt->bind_result(
        $existingUserId,
        $existingStatus,
        $existingVerifiedAt
    );

    $userExists = $stmt->fetch();

    $stmt->close();

    /* Existing Account */

    if ($userExists) {

        securityLog(
            'registration_existing_email',
            null,
            [
                'email' => $emailRateKey,
            ]
        );

        successResponse(
            'If this email can be registered, verification instructions will be sent.',
            [],
            202
        );
    }

    /* Password Hash */

    $passwordHash = password_hash(
        $password,
        $securityConfig['password']['algorithm']
    );

    if (
        !is_string($passwordHash) ||
        $passwordHash === ''
    ) {
        throw new RuntimeException(
            'Unable to create password hash.'
        );
    }

    /* Registration Lock */

    $registrationLockKey = hash(
        'sha256',
        $email
    );

    acquireRequestLock(
        $conn,
        'registration',
        $registrationLockKey,
        'create-account',
        10
    );

    $userId = null;
    $otp = null;

    try {

        /* Transaction */

        $conn->begin_transaction();

        /* Lock Email */

        $stmt = $conn->prepare(
            'SELECT
                id,
                status,
                email_verified_at
             FROM users
             WHERE email = ?
             LIMIT 1
             FOR UPDATE'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to prepare registration check.'
            );
        }

        $stmt->bind_param(
            's',
            $email
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to verify registration request.'
            );
        }

        $stmt->bind_result(
            $lockedExistingUserId,
            $lockedExistingStatus,
            $lockedExistingVerifiedAt
        );

        $existingAfterLock = $stmt->fetch();

        $stmt->close();

        /* Concurrent Registration */

        if ($existingAfterLock) {

            $conn->rollback();

            releaseRequestLock(
                $conn,
                'registration',
                $registrationLockKey,
                'create-account'
            );

            successResponse(
                'If this email can be registered, verification instructions will be sent.',
                [],
                202
            );
        }

        /* Create User */

        $stmt = $conn->prepare(
            'INSERT INTO users
            (
                name,
                email,
                password,
                role,
                status,
                token_version,
                email_verified_at
            )
            VALUES
            (?, ?, ?, ?, ?, 1, NULL)'
        );

        if ($stmt === false) {
            throw new RuntimeException(
                'Unable to prepare user creation.'
            );
        }

        $role = 'user';
        $status = 'pending';

        $stmt->bind_param(
            'sssss',
            $name,
            $email,
            $passwordHash,
            $role,
            $status
        );

        if (!$stmt->execute()) {

            $stmt->close();

            throw new RuntimeException(
                'Unable to create account.'
            );
        }

        $userId = (int) $conn->insert_id;

        $stmt->close();

        if ($userId < 1) {
            throw new RuntimeException(
                'Unable to create account.'
            );
        }

        /* Create Verification OTP */

        $otp = createOtp(
            $conn,
            $userId,
            'email_verification'
        );

        /* Commit */

        if (!$conn->commit()) {
            throw new RuntimeException(
                'Unable to complete registration.'
            );
        }

    } catch (Throwable $e) {

        try {
            $conn->rollback();
        } catch (Throwable) {
        }

        releaseRequestLock(
            $conn,
            'registration',
            $registrationLockKey,
            'create-account'
        );

        securityLog(
            'registration_failed',
            null,
            [
                'reason' =>
                    'registration_transaction_failed',
            ]
        );

        throw $e;
    }

    /* Send Verification Email */

    try {

        sendOtpEmail(
            $email,
            $name,
            $otp
        );

    } catch (Throwable $e) {

        /* Invalidate OTP */

        $stmt = $conn->prepare(
            'UPDATE otp_codes
             SET consumed_at = NOW()
             WHERE user_id = ?
               AND purpose = ?
               AND consumed_at IS NULL'
        );

        if ($stmt !== false) {

            $purpose = 'email_verification';

            $stmt->bind_param(
                'is',
                $userId,
                $purpose
            );

            $stmt->execute();

            $stmt->close();
        }

        securityLog(
            'registration_email_failed',
            $userId,
            [
                'email' => $emailRateKey,
            ]
        );

        releaseRequestLock(
            $conn,
            'registration',
            $registrationLockKey,
            'create-account'
        );

        errorResponse(
            'Registration could not be completed. Please try again later.',
            500
        );
    }

    /* Record OTP Sent */

    recordOtpSent(
        $conn,
        $email,
        $ipAddress,
        'email_verification'
    );

    /* Audit */

    securityLog(
        'registration_created',
        $userId
    );

    securityLog(
        'registration_otp_sent',
        $userId,
        [
            'email' => $emailRateKey,
        ]
    );

    /* Release Lock */

    releaseRequestLock(
        $conn,
        'registration',
        $registrationLockKey,
        'create-account'
    );

    /* Response */

    successResponse(
        'Registration successful. Please verify your email.',
        [
            'otp_required' => true,

            'expires_in' =>
                (int) $securityConfig['otp']['expiry'],

            'resend_after' =>
                (int) getOtpSecurityLimits()['resend_cooldown'],

            'max_otp_sends' =>
                (int) getOtpSecurityLimits()['max_resends'],
        ],
        201
    );

} catch (InvalidArgumentException $e) {

    errorResponse(
        $e->getMessage(),
        422
    );

}catch (Throwable $e) {

    error_log(
        '[REGISTER] ' .
        $e->getMessage()
    );

    if (
        ($appConfig['environment'] ?? 'local')
        === 'local'
    ) {
        errorResponse(
            'Registration error: ' .
            $e->getMessage(),
            500
        );
    }

    errorResponse(
        'Unable to process registration.',
        500
    );

}