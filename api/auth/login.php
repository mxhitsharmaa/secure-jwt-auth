<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/rate_limiter.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../otp/otp_service.php';

use PHPMailer\PHPMailer\PHPMailer;

/* -------------------------------------------------
   Security
------------------------------------------------- */

applyApiSecurity();
requireSecureConnection();

/* -------------------------------------------------
   Request Method
------------------------------------------------- */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    errorResponse('HTTP method not allowed.', 405);
}

/* -------------------------------------------------
   Request Data
------------------------------------------------- */

try {

    $input = getJsonInput();

    validateAllowedFields(
        $input,
        ['email', 'password']
    );

    $email = validateEmail($input['email'] ?? null);

    $password = validateLoginPassword(
        $input['password'] ?? null,
        72
    );

} catch (InvalidArgumentException $e) {
    errorResponse($e->getMessage(), 422);
}

/* -------------------------------------------------
   Client IP
------------------------------------------------- */

$ipAddress = getClientIp();

/* -------------------------------------------------
   Rate Limits (defense-in-depth)
------------------------------------------------- */

$emailRateKey = hash('sha256', $email);

checkRequestRateLimit(
    $conn,
    'login_ip',
    $ipAddress,
    '/api/auth/login.php',
    30,
    900
);

checkRequestRateLimit(
    $conn,
    'login_email',
    $emailRateKey,
    '/api/auth/login.php',
    15,
    900
);

/* -------------------------------------------------
   Password Security Purpose
------------------------------------------------- */

$passwordPurpose = 'login_password';

/* -------------------------------------------------
   Check Password Block (otp_security)
------------------------------------------------- */

$passwordBlock = checkOtpBlock(
    $conn,
    $email,
    $ipAddress,
    $passwordPurpose
);

if ($passwordBlock['blocked']) {

    securityLog('login_password_blocked', null, [
        'email'       => $emailRateKey,
        'retry_after' => $passwordBlock['retry_after'],
    ]);

    errorResponse(
        'Too many failed login attempts. Try again later.',
        429,
        ['retry_after' => $passwordBlock['retry_after']]
    );
}

/* -------------------------------------------------
   Find User (with locked_until)
------------------------------------------------- */

$stmt = $conn->prepare(
    'SELECT
        id,
        name,
        email,
        password,
        role,
        status,
        token_version,
        email_verified_at,
        locked_until
     FROM users
     WHERE email = ?
     LIMIT 1'
);

if ($stmt === false) {
    errorResponse('Unable to process login.', 500);
}

$stmt->bind_param('s', $email);

if (!$stmt->execute()) {
    $stmt->close();
    errorResponse('Unable to process login.', 500);
}

$result = $stmt->get_result();
$user   = $result->fetch_assoc();
$stmt->close();

/* -------------------------------------------------
   Dummy Hash (prevents timing-based user enumeration)
------------------------------------------------- */

$dummyHash = '$2y$12$usesomesillystringforsalt0000000000000000000000000000';

$storedHash = ($user !== null)
    ? $user['password']
    : $dummyHash;

$passwordOk = password_verify($password, $storedHash);

/* -------------------------------------------------
   Account Locked Check (BEFORE any response)
------------------------------------------------- */

$accountLocked = false;
$lockRetryAfter = 0;

if ($user !== null && $user['locked_until'] !== null) {

    $lockedUntilTs = strtotime($user['locked_until']);

    if ($lockedUntilTs !== false && $lockedUntilTs > time()) {
        $accountLocked   = true;
        $lockRetryAfter  = $lockedUntilTs - time();
    }
}

if ($accountLocked) {

    securityLog(
        'login_locked',
        (int) $user['id'],
        ['retry_after' => $lockRetryAfter]
    );

    header('Retry-After: ' . $lockRetryAfter);

    errorResponse(
        'Account temporarily locked. Try again later.',
        423,
        ['retry_after' => $lockRetryAfter]
    );
}

/* -------------------------------------------------
   Invalid Credentials
------------------------------------------------- */

if ($user === null || !$passwordOk) {

    $attempt = recordOtpAttempt(
        $conn,
        $email,
        $ipAddress,
        $passwordPurpose
    );

    recordLoginAttempt(
        $conn,
        $email,
        $ipAddress,
        false,
        ($user !== null) ? (int) $user['id'] : null,
        'invalid_credentials'
    );

    securityLog(
        'login_failed',
        ($user !== null) ? (int) $user['id'] : null,
        [
            'reason'    => 'invalid_credentials',
            'attempts'  => $attempt['attempts'],
            'remaining' => $attempt['remaining'],
        ]
    );

    /* -------------------------------------------------
       Hard Lock via users.locked_until
    ------------------------------------------------- */

    if ($user !== null) {

        $userId = (int) $user['id'];

        $maxFailures    = (int) ($securityConfig['login']['max_failed_attempts'] ?? 5);
        $failureWindow  = (int) ($securityConfig['login']['failure_window']    ?? 900);
        $lockSeconds    = (int) ($securityConfig['login']['lockout_duration']  ?? 900);

        $stmt = $conn->prepare(
            'SELECT COUNT(*) AS c
             FROM login_attempts
             WHERE user_id = ?
               AND success = 0
               AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)'
        );

        if ($stmt !== false) {

            $stmt->bind_param('ii', $userId, $failureWindow);

            if ($stmt->execute()) {

                $res = $stmt->get_result();
                $row = $res->fetch_assoc();
                $recentFailures = (int) ($row['c'] ?? 0);

                if ($recentFailures >= $maxFailures) {

                    $stmt2 = $conn->prepare(
                        'UPDATE users
                         SET locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND)
                         WHERE id = ?
                         LIMIT 1'
                    );

                    if ($stmt2 !== false) {

                        $stmt2->bind_param('ii', $lockSeconds, $userId);

                        if ($stmt2->execute()) {

                            securityLog(
                                'account_locked',
                                $userId,
                                [
                                    'recent_failures' => $recentFailures,
                                    'lock_seconds'    => $lockSeconds,
                                ]
                            );
                        }

                        $stmt2->close();
                    }
                }
            }

            $stmt->close();
        }
    }

    if ($attempt['blocked']) {

        errorResponse(
            'Too many failed login attempts. Try again later.',
            429,
            ['retry_after' => $attempt['retry_after']]
        );
    }

    errorResponse(
        'Invalid email or password.',
        401,
        ['attempts_remaining' => $attempt['remaining']]
    );
}

/* -------------------------------------------------
   User ID
------------------------------------------------- */

$userId = (int) $user['id'];

/* -------------------------------------------------
   Account Status Checks (before request lock)
------------------------------------------------- */

$status = $user['status'];

if ($status === 'blocked') {

    recordLoginAttempt(
        $conn, $email, $ipAddress, false, $userId, 'account_blocked'
    );

    errorResponse('Account is blocked.', 403);
}

if ($status === 'suspended') {

    recordLoginAttempt(
        $conn, $email, $ipAddress, false, $userId, 'account_suspended'
    );

    errorResponse('Account is suspended.', 403);
}

if ($user['email_verified_at'] === null) {

    recordLoginAttempt(
        $conn, $email, $ipAddress, false, $userId, 'email_not_verified'
    );

    errorResponse('Email verification is required.', 403);
}

if ($status !== 'active') {

    recordLoginAttempt(
        $conn, $email, $ipAddress, false, $userId, 'account_not_active'
    );

    errorResponse('Account is not active.', 403);
}

/* -------------------------------------------------
   Request Lock (before rehash + OTP)
------------------------------------------------- */

acquireRequestLock(
    $conn,
    'user',
    (string) $userId,
    'login',
    10
);

/* -------------------------------------------------
   Check Login OTP Block
------------------------------------------------- */

$otpBlock = checkOtpBlock(
    $conn,
    $email,
    $ipAddress,
    'login_otp'
);

if ($otpBlock['blocked']) {

    releaseRequestLock(
        $conn, 'user', (string) $userId, 'login'
    );

    securityLog('login_otp_blocked', $userId, [
        'retry_after' => $otpBlock['retry_after'],
    ]);

    errorResponse(
        'Too many OTP attempts. Try again later.',
        429,
        ['retry_after' => $otpBlock['retry_after']]
    );
}

/* -------------------------------------------------
   Password Rehash
------------------------------------------------- */

if (
    password_needs_rehash(
        $user['password'],
        $securityConfig['password']['algorithm']
    )
) {

    $newPasswordHash = password_hash(
        $password,
        $securityConfig['password']['algorithm']
    );

    if (!is_string($newPasswordHash) || $newPasswordHash === '') {

        releaseRequestLock(
            $conn, 'user', (string) $userId, 'login'
        );

        errorResponse('Unable to process login.', 500);
    }

    $stmt = $conn->prepare(
        'UPDATE users SET password = ? WHERE id = ? LIMIT 1'
    );

    if ($stmt === false) {

        releaseRequestLock(
            $conn, 'user', (string) $userId, 'login'
        );

        errorResponse('Unable to process login.', 500);
    }

    $stmt->bind_param('si', $newPasswordHash, $userId);

    if (!$stmt->execute()) {

        $stmt->close();

        releaseRequestLock(
            $conn, 'user', (string) $userId, 'login'
        );

        errorResponse('Unable to process login.', 500);
    }

    $stmt->close();
}

/* -------------------------------------------------
   OTP Configuration
------------------------------------------------- */

$otpExpiry = (int) ($securityConfig['otp']['expiry'] ?? 300);

if ($otpExpiry < 1) {

    releaseRequestLock(
        $conn, 'user', (string) $userId, 'login'
    );

    errorResponse('Invalid OTP configuration.', 500);
}

/* -------------------------------------------------
   Generate Login OTP
------------------------------------------------- */

try {

    $otp = createOtp($conn, $userId, 'login');

} catch (Throwable) {

    releaseRequestLock(
        $conn, 'user', (string) $userId, 'login'
    );

    securityLog('login_otp_creation_error', $userId);

    errorResponse('Unable to process login.', 500);
}

/* -------------------------------------------------
   Record OTP Sent
------------------------------------------------- */

try {

    recordOtpSent(
        $conn,
        $email,
        $ipAddress,
        'login_otp'
    );

} catch (Throwable) {

    releaseRequestLock(
        $conn, 'user', (string) $userId, 'login'
    );

    securityLog('login_otp_security_update_error', $userId);

    errorResponse('Unable to process login.', 500);
}

/* -------------------------------------------------
   Send Login OTP
------------------------------------------------- */

try {

    require_once __DIR__ . '/../../vendor/autoload.php';

    $mailConfig = require __DIR__ . '/../../config/mail.php';

    if (
        $mailConfig['host'] === '' ||
        $mailConfig['username'] === '' ||
        $mailConfig['password'] === '' ||
        $mailConfig['from_address'] === ''
    ) {
        throw new RuntimeException(
            'Mail configuration is incomplete.'
        );
    }

    $mail = new PHPMailer(true);

    $mail->isSMTP();
    $mail->Host       = $mailConfig['host'];
    $mail->SMTPAuth   = true;
    $mail->Username   = $mailConfig['username'];
    $mail->Password   = $mailConfig['password'];
    $mail->Port       = $mailConfig['port'];

    if (strtolower($mailConfig['encryption']) === 'tls') {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    } elseif (strtolower($mailConfig['encryption']) === 'ssl') {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    }

    $mail->setFrom(
        $mailConfig['from_address'],
        $mailConfig['from_name']
    );

    $mail->addAddress($email, $user['name']);
    $mail->isHTML(true);
    $mail->Subject = 'Your login verification code';

    $mail->Body =
        '<p>Hello ' .
        htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8') .
        ',</p>' .
        '<p>Your login verification code is:</p>' .
        '<h2>' .
        htmlspecialchars($otp, ENT_QUOTES, 'UTF-8') .
        '</h2>' .
        '<p>This code will expire in ' .
        (int) ($otpExpiry / 60) .
        ' minutes.</p>' .
        '<p>If you did not attempt to log in, secure your account immediately.</p>';

    $mail->AltBody =
        'Your login verification code is: ' .
        $otp .
        '. This code expires in ' .
        (int) ($otpExpiry / 60) .
        ' minutes.';

    $mail->send();

} catch (Throwable) {

    releaseRequestLock(
        $conn, 'user', (string) $userId, 'login'
    );

    securityLog('login_otp_email_failed', $userId);

    errorResponse(
        'Unable to send verification code. Please try again later.',
        500
    );
}

/* -------------------------------------------------
   Record Login Challenge
------------------------------------------------- */

recordLoginAttempt(
    $conn,
    $email,
    $ipAddress,
    true,
    $userId,
    'password_verified_otp_required'
);

securityLog('login_otp_sent', $userId);

/* -------------------------------------------------
   Release Lock
------------------------------------------------- */

releaseRequestLock(
    $conn, 'user', (string) $userId, 'login'
);

/* -------------------------------------------------
   Response
------------------------------------------------- */

successResponse(
    'Password verified. A verification code has been sent to your email.',
    [
        'otp_expires_in'       => $otpExpiry,
        'otp_attempts_allowed' => 6,
    ],
    202
);