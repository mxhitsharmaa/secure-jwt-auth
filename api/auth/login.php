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
            'email',
            'password',
        ]
    );

    $email =
        validateEmail(
            $input['email'] ?? null
        );

$password =
    validateLoginPassword(
        $input['password'] ?? null,
        72
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

/* Password Security Purpose */

$passwordPurpose =
    'login_password';

/* Check Password Block */

$passwordBlock =
    checkOtpBlock(
        $conn,
        $email,
        $ipAddress,
        $passwordPurpose
    );

if ($passwordBlock['blocked']) {

    securityLog(
        'login_password_blocked',
        null,
        [
            'email' =>
                hash(
                    'sha256',
                    $email
                ),
            'retry_after' =>
                $passwordBlock['retry_after'],
        ]
    );

    errorResponse(
        'Too many failed login attempts. No OTP will be sent for the next 15 minutes.',
        429,
        [
            'retry_after' =>
                $passwordBlock['retry_after'],
        ]
    );
}

/* Find User */

$stmt = $conn->prepare(
    'SELECT
        id,
        name,
        email,
        password,
        role,
        status,
        token_version,
        email_verified_at
     FROM users
     WHERE email = ?
     LIMIT 1'
);

if ($stmt === false) {
    errorResponse(
        'Unable to process login.',
        500
    );
}

$stmt->bind_param(
    's',
    $email
);

if (!$stmt->execute()) {

    $stmt->close();

    errorResponse(
        'Unable to process login.',
        500
    );
}

$result =
    $stmt->get_result();

$user =
    $result->fetch_assoc();

$stmt->close();

/* Invalid Credentials */

if (
    $user === null ||
    !password_verify(
        $password,
        $user['password']
    )
) {

    $attempt =
        recordOtpAttempt(
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
        $user !== null
            ? (int) $user['id']
            : null,
        'invalid_credentials'
    );

    securityLog(
        'login_failed',
        $user !== null
            ? (int) $user['id']
            : null,
        [
            'reason' =>
                'invalid_credentials',
            'attempts' =>
                $attempt['attempts'],
            'remaining' =>
                $attempt['remaining'],
        ]
    );

    if ($attempt['blocked']) {

        errorResponse(
            'Too many failed login attempts. No OTP will be sent for the next 15 minutes.',
            429,
            [
                'retry_after' =>
                    $attempt['retry_after'],
            ]
        );
    }

    errorResponse(
        'Invalid email or password.',
        401,
        [
            'attempts_remaining' =>
                $attempt['remaining'],
        ]
    );
}

/* User ID */

$userId =
    (int) $user['id'];

/* Request Lock */

acquireRequestLock(
    $conn,
    'user',
    (string) $userId,
    'login',
    10
);

/* Account Status */

$status =
    $user['status'];

if ($status === 'blocked') {

    recordLoginAttempt(
        $conn,
        $email,
        $ipAddress,
        false,
        $userId,
        'account_blocked'
    );

    errorResponse(
        'Account is blocked.',
        403
    );
}

if ($status === 'suspended') {

    recordLoginAttempt(
        $conn,
        $email,
        $ipAddress,
        false,
        $userId,
        'account_suspended'
    );

    errorResponse(
        'Account is suspended.',
        403
    );
}

/* Email Verification */

if (
    $user['email_verified_at'] === null
) {

    recordLoginAttempt(
        $conn,
        $email,
        $ipAddress,
        false,
        $userId,
        'email_not_verified'
    );

    errorResponse(
        'Email verification is required.',
        403
    );
}

/* Account Status */

if (
    $status !== 'active'
) {

    recordLoginAttempt(
        $conn,
        $email,
        $ipAddress,
        false,
        $userId,
        'account_not_active'
    );

    errorResponse(
        'Account is not active.',
        403
    );
}

/* Check Login OTP Block */

$otpBlock =
    checkOtpBlock(
        $conn,
        $email,
        $ipAddress,
        'login_otp'
    );

if ($otpBlock['blocked']) {

    securityLog(
        'login_otp_blocked',
        $userId,
        [
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

/* Password Rehash */

if (
    password_needs_rehash(
        $user['password'],
        $securityConfig['password']['algorithm']
    )
) {

    $newPasswordHash =
        password_hash(
            $password,
            $securityConfig['password']['algorithm']
        );

    if (
        !is_string($newPasswordHash) ||
        $newPasswordHash === ''
    ) {
        errorResponse(
            'Unable to process login.',
            500
        );
    }

    $stmt = $conn->prepare(
        'UPDATE users
         SET password = ?
         WHERE id = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        errorResponse(
            'Unable to process login.',
            500
        );
    }

    $stmt->bind_param(
        'si',
        $newPasswordHash,
        $userId
    );

    if (!$stmt->execute()) {

        $stmt->close();

        errorResponse(
            'Unable to process login.',
            500
        );
    }

    $stmt->close();
}

/* OTP Configuration */

$otpExpiry =
    (int) (
        $securityConfig['otp']['expiry']
        ?? 300
    );

if ($otpExpiry < 1) {
    errorResponse(
        'Invalid OTP configuration.',
        500
    );
}

/* Generate Login OTP */

try {

    $otp =
        createOtp(
            $conn,
            $userId,
            'login'
        );

} catch (Throwable) {

    securityLog(
        'login_otp_creation_error',
        $userId
    );

    errorResponse(
        'Unable to process login.',
        500
    );
}

/* Record OTP Sent */

try {

    recordOtpSent(
        $conn,
        $email,
        $ipAddress,
        'login_otp'
    );

} catch (Throwable) {

    securityLog(
        'login_otp_security_update_error',
        $userId
    );

    errorResponse(
        'Unable to process login.',
        500
    );
}

/* Send Login OTP */

try {

    require_once __DIR__ .
        '/../../vendor/autoload.php';

    $mailConfig =
        require __DIR__ .
        '/../../config/mail.php';

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

    $mail =
        new PHPMailer(
            true
        );

    $mail->isSMTP();

    $mail->Host =
        $mailConfig['host'];

    $mail->SMTPAuth =
        true;

    $mail->Username =
        $mailConfig['username'];

    $mail->Password =
        $mailConfig['password'];

    $mail->Port =
        $mailConfig['port'];

    if (
        strtolower(
            $mailConfig['encryption']
        ) === 'tls'
    ) {

        $mail->SMTPSecure =
            PHPMailer::ENCRYPTION_STARTTLS;

    } elseif (
        strtolower(
            $mailConfig['encryption']
        ) === 'ssl'
    ) {

        $mail->SMTPSecure =
            PHPMailer::ENCRYPTION_SMTPS;
    }

    $mail->setFrom(
        $mailConfig['from_address'],
        $mailConfig['from_name']
    );

    $mail->addAddress(
        $email,
        $user['name']
    );

    $mail->isHTML(true);

    $mail->Subject =
        'Your login verification code';

    $mail->Body =
        '<p>Hello ' .
        htmlspecialchars(
            $user['name'],
            ENT_QUOTES,
            'UTF-8'
        ) .
        ',</p>' .

        '<p>Your login verification code is:</p>' .

        '<h2>' .
        htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        ) .
        '</h2>' .

        '<p>This code will expire in ' .
        (int) (
            $otpExpiry / 60
        ) .
        ' minutes.</p>' .

        '<p>If you did not attempt to log in, secure your account immediately.</p>';

    $mail->AltBody =
        'Your login verification code is: ' .
        $otp .
        '. This code expires in ' .
        (int) (
            $otpExpiry / 60
        ) .
        ' minutes.';

    $mail->send();

} catch (Throwable) {

    securityLog(
        'login_otp_email_failed',
        $userId
    );

    errorResponse(
        'Unable to send verification code. Please try again later.',
        500
    );
}

/* Record Login Challenge */

recordLoginAttempt(
    $conn,
    $email,
    $ipAddress,
    true,
    $userId,
    'password_verified_otp_required'
);

securityLog(
    'login_otp_sent',
    $userId
);

/* Response */

successResponse(
    'Password verified. A verification code has been sent to your email.',
    [
        'otp_expires_in' =>
            $otpExpiry,
        'otp_attempts_allowed' =>
            6,
    ],
    202
);