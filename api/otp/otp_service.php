<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';

function getOtpSecurityLimits(): array
{
    global $securityConfig;

    return [
        'max_attempts'    => (int) ($securityConfig['otp']['max_attempts']    ?? 6),
        'max_resends'     => (int) ($securityConfig['otp']['max_resends']     ?? 6),
        'resend_cooldown' => (int) ($securityConfig['otp']['resend_cooldown'] ?? 60),
        'block_duration'  => (int) ($securityConfig['otp']['block_duration']  ?? 900),
    ];
}

function normalizeOtpPurpose(string $purpose): string
{
    $allowedPurposes = [
        'login',
        'email_verification',
        'password_reset',
        'login_password',
        'login_otp',
    ];

    if (!in_array($purpose, $allowedPurposes, true)) {
        throw new InvalidArgumentException('Invalid OTP purpose.');
    }

    return $purpose;
}

function generateOtp(): string
{
    return str_pad(
        (string) random_int(0, 999999),
        6,
        '0',
        STR_PAD_LEFT
    );
}

function hashOtp(string $otp): string
{
    global $jwtConfig;

    $secret = $jwtConfig['secret'] ?? '';

    if ($secret === '') {
        throw new RuntimeException(
            'OTP hashing secret is not configured.'
        );
    }

    return hash_hmac('sha256', $otp, $secret);
}

function getOtpSecurityState(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose,
    bool $create = true
): array {

    $purpose = normalizeOtpPurpose($purpose);

    $stmt = $conn->prepare(
        'SELECT
            id,
            email,
            ip_address,
            purpose,
            attempt_count,
            resend_count,
            last_otp_sent_at,
            blocked_until
         FROM otp_security
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to read OTP security state.');
    }

    $stmt->bind_param('sss', $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to read OTP security state.');
    }

    $result = $stmt->get_result();
    $state  = $result->fetch_assoc();
    $stmt->close();

    if ($state !== null) {
        return $state;
    }

    if (!$create) {
        return [
            'id'               => null,
            'email'            => $email,
            'ip_address'       => $ipAddress,
            'purpose'          => $purpose,
            'attempt_count'    => 0,
            'resend_count'     => 0,
            'last_otp_sent_at' => null,
            'blocked_until'    => null,
        ];
    }

    $stmt = $conn->prepare(
        'INSERT INTO otp_security
         (email, ip_address, purpose, attempt_count,
          resend_count, last_otp_sent_at, blocked_until)
         VALUES (?, ?, ?, 0, 0, NULL, NULL)'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to create OTP security state.');
    }

    $stmt->bind_param('sss', $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to create OTP security state.');
    }

    $stmt->close();

    return [
        'id'               => (int) $conn->insert_id,
        'email'            => $email,
        'ip_address'       => $ipAddress,
        'purpose'          => $purpose,
        'attempt_count'    => 0,
        'resend_count'     => 0,
        'last_otp_sent_at' => null,
        'blocked_until'    => null,
    ];
}

function checkOtpBlock(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {

    $state  = getOtpSecurityState($conn, $email, $ipAddress, $purpose);
    $limits = getOtpSecurityLimits();

    $retryAfter = 0;
    $blocked    = false;

    if (!empty($state['blocked_until'])) {

        $blockedTimestamp = strtotime($state['blocked_until']);

        if ($blockedTimestamp !== false && $blockedTimestamp > time()) {
            $blocked    = true;
            $retryAfter = $blockedTimestamp - time();
        }
    }

    $attempts = (int) ($state['attempt_count'] ?? 0);

    return [
        'blocked'     => $blocked,
        'retry_after' => max(0, $retryAfter),
        'attempts'    => $attempts,
        'remaining'   => max(0, $limits['max_attempts'] - $attempts),
    ];
}

function checkOtpResendAllowed(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {

    $state  = getOtpSecurityState($conn, $email, $ipAddress, $purpose);
    $limits = getOtpSecurityLimits();

    if (!empty($state['blocked_until'])) {

        $blockedTimestamp = strtotime($state['blocked_until']);

        if ($blockedTimestamp !== false && $blockedTimestamp > time()) {
            return [
                'allowed'     => false,
                'reason'      => 'blocked',
                'retry_after' => $blockedTimestamp - time(),
            ];
        }
    }

    $resendCount = (int) ($state['resend_count'] ?? 0);

    if ($resendCount >= $limits['max_resends']) {
        return [
            'allowed'     => false,
            'reason'      => 'resend_limit',
            'retry_after' => $limits['block_duration'],
        ];
    }

    if (!empty($state['last_otp_sent_at'])) {

        $lastSentTimestamp = strtotime($state['last_otp_sent_at']);

        if ($lastSentTimestamp !== false) {

            $elapsed = time() - $lastSentTimestamp;

            if ($elapsed < $limits['resend_cooldown']) {
                return [
                    'allowed'     => false,
                    'reason'      => 'cooldown',
                    'retry_after' => $limits['resend_cooldown'] - $elapsed,
                ];
            }
        }
    }

    return [
        'allowed'     => true,
        'reason'      => null,
        'retry_after' => 0,
    ];
}

function recordOtpSent(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {

    $purpose = normalizeOtpPurpose($purpose);

    getOtpSecurityState($conn, $email, $ipAddress, $purpose);

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET resend_count = resend_count + 1,
             last_otp_sent_at = NOW()
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to record OTP send.');
    }

    $stmt->bind_param('sss', $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to record OTP send.');
    }

    $stmt->close();
}

function recordOtpAttempt(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {

    $purpose = normalizeOtpPurpose($purpose);

    getOtpSecurityState($conn, $email, $ipAddress, $purpose);

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET attempt_count = attempt_count + 1
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to record OTP attempt.');
    }

    $stmt->bind_param('sss', $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to record OTP attempt.');
    }

    $stmt->close();

    $state  = getOtpSecurityState($conn, $email, $ipAddress, $purpose, false);
    $limits = getOtpSecurityLimits();

    $attempts    = (int) ($state['attempt_count'] ?? 0);
    $maxAttempts = $limits['max_attempts'];

    $blocked    = false;
    $retryAfter = 0;

    if ($attempts >= $maxAttempts) {

        $blocked = true;

        blockOtpSecurity($conn, $email, $ipAddress, $purpose);

        $retryAfter = $limits['block_duration'];
    }

    return [
        'attempts'    => $attempts,
        'remaining'   => max(0, $maxAttempts - $attempts),
        'blocked'     => $blocked,
        'retry_after' => $retryAfter,
    ];
}

function blockOtpSecurity(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {

    $purpose = normalizeOtpPurpose($purpose);

    getOtpSecurityState($conn, $email, $ipAddress, $purpose);

    $blockDuration = getOtpSecurityLimits()['block_duration'];

    $blockedUntil = date('Y-m-d H:i:s', time() + $blockDuration);

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET blocked_until = ?
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to block OTP security.');
    }

    $stmt->bind_param('ssss', $blockedUntil, $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to block OTP security.');
    }

    $stmt->close();
}

function resetOtpSecurityState(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {

    $purpose = normalizeOtpPurpose($purpose);

    getOtpSecurityState($conn, $email, $ipAddress, $purpose);

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET attempt_count = 0,
             blocked_until = NULL
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to reset OTP security.');
    }

    $stmt->bind_param('sss', $email, $ipAddress, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to reset OTP security.');
    }

    $stmt->close();
}

function createOtp(
    mysqli $conn,
    int $userId,
    string $purpose
): string {

    $purpose = normalizeOtpPurpose($purpose);

    if (!in_array(
        $purpose,
        ['login', 'email_verification', 'password_reset'],
        true
    )) {
        throw new InvalidArgumentException('Invalid OTP creation purpose.');
    }

    if ($userId < 1) {
        throw new InvalidArgumentException('Invalid user ID.');
    }

    global $securityConfig;

    $otpExpiry = (int) ($securityConfig['otp']['expiry'] ?? 300);

    if ($otpExpiry < 1) {
        throw new RuntimeException('Invalid OTP expiry configuration.');
    }

    $stmt = $conn->prepare(
        'UPDATE otp_codes
         SET consumed_at = NOW()
         WHERE user_id = ?
           AND purpose = ?
           AND consumed_at IS NULL'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to invalidate previous OTP.');
    }

    $stmt->bind_param('is', $userId, $purpose);

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to invalidate previous OTP.');
    }

    $stmt->close();

    $otp     = generateOtp();
    $otpHash = hashOtp($otp);

    $expiresAt = date('Y-m-d H:i:s', time() + $otpExpiry);

    $maxAttempts = (int) (getOtpSecurityLimits()['max_attempts']);

    $stmt = $conn->prepare(
        'INSERT INTO otp_codes
         (user_id, purpose, otp_hash, expires_at,
          attempts, max_attempts, consumed_at)
         VALUES (?, ?, ?, ?, 0, ?, NULL)'
    );

    if ($stmt === false) {
        throw new RuntimeException('Unable to create OTP.');
    }

    $stmt->bind_param(
        'isssi',
        $userId,
        $purpose,
        $otpHash,
        $expiresAt,
        $maxAttempts
    );

    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Unable to create OTP.');
    }

    $stmt->close();

    return $otp;
}