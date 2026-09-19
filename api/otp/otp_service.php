<?php

require_once __DIR__ . '/../../config/bootstrap.php';

/* OTP Security Limits */

function getOtpSecurityLimits(): array
{
    return [
        'max_attempts' => 6,
        'max_resends' => 6,
        'resend_cooldown' => 60,
        'block_duration' => 900,
    ];
}

/* Normalize Purpose */

function normalizeOtpPurpose(
    string $purpose
): string {
    $allowedPurposes = [
        'login',
        'email_verification',
        'password_reset',
        'login_password',
        'login_otp',
    ];

    if (!in_array($purpose, $allowedPurposes, true)) {
        throw new InvalidArgumentException(
            'Invalid OTP purpose.'
        );
    }

    return $purpose;
}

/* Generate OTP */

function generateOtp(): string
{
    return str_pad(
        (string) random_int(0, 999999),
        6,
        '0',
        STR_PAD_LEFT
    );
}

/* Hash OTP */

function hashOtp(
    string $otp
): string {
    return hash(
        'sha256',
        $otp
    );
}

/* Get Security State */

function getOtpSecurityState(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose,
    bool $create = true
): array {
    $purpose =
        normalizeOtpPurpose($purpose);

    $stmt = $conn->prepare(
        'SELECT
            id,
            email,
            ip_address,
            purpose,
            failed_attempts,
            resend_count,
            last_sent_at,
            blocked_until
         FROM otp_security
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to read OTP security state.'
        );
    }

    $stmt->bind_param(
        'sss',
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to read OTP security state.'
        );
    }

    $result =
        $stmt->get_result();

    $state =
        $result->fetch_assoc();

    $stmt->close();

    if ($state !== null) {
        return $state;
    }

    if (!$create) {
        return [
            'id' => null,
            'email' => $email,
            'ip_address' => $ipAddress,
            'purpose' => $purpose,
            'failed_attempts' => 0,
            'resend_count' => 0,
            'last_sent_at' => null,
            'blocked_until' => null,
        ];
    }

    $stmt = $conn->prepare(
        'INSERT INTO otp_security
        (
            email,
            ip_address,
            purpose,
            failed_attempts,
            resend_count,
            last_sent_at,
            blocked_until
        )
        VALUES
        (?, ?, ?, 0, 0, NULL, NULL)'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to create OTP security state.'
        );
    }

    $stmt->bind_param(
        'sss',
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to create OTP security state.'
        );
    }

    $stmt->close();

    return [
        'id' => $conn->insert_id,
        'email' => $email,
        'ip_address' => $ipAddress,
        'purpose' => $purpose,
        'failed_attempts' => 0,
        'resend_count' => 0,
        'last_sent_at' => null,
        'blocked_until' => null,
    ];
}

/* Check OTP Block */

function checkOtpBlock(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {
    $state =
        getOtpSecurityState(
            $conn,
            $email,
            $ipAddress,
            $purpose
        );

    $retryAfter = 0;
    $blocked = false;

    if (
        !empty($state['blocked_until'])
    ) {
        $blockedTimestamp =
            strtotime(
                $state['blocked_until']
            );

        if (
            $blockedTimestamp !== false &&
            $blockedTimestamp > time()
        ) {
            $blocked = true;

            $retryAfter =
                $blockedTimestamp - time();
        }
    }

    return [
        'blocked' => $blocked,
        'retry_after' => max(
            0,
            $retryAfter
        ),
        'attempts' => (int) (
            $state['failed_attempts'] ?? 0
        ),
        'remaining' => max(
            0,
            getOtpSecurityLimits()['max_attempts']
            - (int) (
                $state['failed_attempts'] ?? 0
            )
        ),
    ];
}

/* Check OTP Resend */

function checkOtpResendAllowed(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {
    $state =
        getOtpSecurityState(
            $conn,
            $email,
            $ipAddress,
            $purpose
        );

    $limits =
        getOtpSecurityLimits();

    /* Block Check */

    if (
        !empty($state['blocked_until'])
    ) {
        $blockedTimestamp =
            strtotime(
                $state['blocked_until']
            );

        if (
            $blockedTimestamp !== false &&
            $blockedTimestamp > time()
        ) {
            return [
                'allowed' => false,
                'reason' => 'blocked',
                'retry_after' =>
                    $blockedTimestamp - time(),
            ];
        }
    }

    /* Resend Limit */

    $resendCount =
        (int) (
            $state['resend_count'] ?? 0
        );

    if (
        $resendCount >=
        (int) $limits['max_resends']
    ) {
        return [
            'allowed' => false,
            'reason' => 'resend_limit',
            'retry_after' =>
                (int) $limits['block_duration'],
        ];
    }

    /* Cooldown */

    if (
        !empty($state['last_sent_at'])
    ) {
        $lastSentTimestamp =
            strtotime(
                $state['last_sent_at']
            );

        if (
            $lastSentTimestamp !== false
        ) {
            $elapsed =
                time() - $lastSentTimestamp;

            $cooldown =
                (int) $limits['resend_cooldown'];

            if ($elapsed < $cooldown) {
                return [
                    'allowed' => false,
                    'reason' => 'cooldown',
                    'retry_after' =>
                        $cooldown - $elapsed,
                ];
            }
        }
    }

    return [
        'allowed' => true,
        'reason' => null,
        'retry_after' => 0,
    ];
}

/* Record OTP Sent */

function recordOtpSent(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {
    $purpose =
        normalizeOtpPurpose($purpose);

    getOtpSecurityState(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET resend_count = resend_count + 1,
             last_sent_at = NOW()
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to record OTP send.'
        );
    }

    $stmt->bind_param(
        'sss',
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to record OTP send.'
        );
    }

    $stmt->close();
}

/* Record OTP Attempt */

function recordOtpAttempt(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): array {
    $purpose =
        normalizeOtpPurpose($purpose);

    getOtpSecurityState(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET failed_attempts = failed_attempts + 1
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to record OTP attempt.'
        );
    }

    $stmt->bind_param(
        'sss',
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to record OTP attempt.'
        );
    }

    $stmt->close();

    $state =
        getOtpSecurityState(
            $conn,
            $email,
            $ipAddress,
            $purpose,
            false
        );

    $limits =
        getOtpSecurityLimits();

    $attempts =
        (int) (
            $state['failed_attempts'] ?? 0
        );

    $maxAttempts =
        (int) $limits['max_attempts'];

    $blocked = false;
    $retryAfter = 0;

    if ($attempts >= $maxAttempts) {
        $blocked = true;

        blockOtpSecurity(
            $conn,
            $email,
            $ipAddress,
            $purpose
        );

        $retryAfter =
            (int) $limits['block_duration'];
    }

    return [
        'attempts' => $attempts,
        'remaining' => max(
            0,
            $maxAttempts - $attempts
        ),
        'blocked' => $blocked,
        'retry_after' => $retryAfter,
    ];
}

/* Block OTP Security */

function blockOtpSecurity(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {
    $purpose =
        normalizeOtpPurpose($purpose);

    getOtpSecurityState(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    $blockDuration =
        (int) getOtpSecurityLimits()[
            'block_duration'
        ];

    $blockedUntil =
        date(
            'Y-m-d H:i:s',
            time() + $blockDuration
        );

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET blocked_until = ?
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to block OTP security.'
        );
    }

    $stmt->bind_param(
        'ssss',
        $blockedUntil,
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to block OTP security.'
        );
    }

    $stmt->close();
}

/* Reset OTP Security */

function resetOtpSecurityState(
    mysqli $conn,
    string $email,
    string $ipAddress,
    string $purpose
): void {
    $purpose =
        normalizeOtpPurpose($purpose);

    getOtpSecurityState(
        $conn,
        $email,
        $ipAddress,
        $purpose
    );

    $stmt = $conn->prepare(
        'UPDATE otp_security
         SET failed_attempts = 0,
             blocked_until = NULL
         WHERE email = ?
           AND ip_address = ?
           AND purpose = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to reset OTP security.'
        );
    }

    $stmt->bind_param(
        'sss',
        $email,
        $ipAddress,
        $purpose
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to reset OTP security.'
        );
    }

    $stmt->close();
}

/* Create OTP */

function createOtp(
    mysqli $conn,
    int $userId,
    string $purpose
): string {
    $purpose =
        normalizeOtpPurpose($purpose);

    if (
        !in_array(
            $purpose,
            [
                'login',
                'email_verification',
                'password_reset',
            ],
            true
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid OTP creation purpose.'
        );
    }

    global $securityConfig;

    $otpExpiry =
        (int) (
            $securityConfig['otp']['expiry']
            ?? 300
        );

    $maxAttempts =
        (int) (
            getOtpSecurityLimits()['max_attempts']
        );

    if ($otpExpiry < 1) {
        throw new RuntimeException(
            'Invalid OTP expiry configuration.'
        );
    }

    /* Invalidate Previous OTPs */

    $stmt = $conn->prepare(
        'UPDATE otp_codes
         SET consumed_at = NOW()
         WHERE user_id = ?
           AND purpose = ?
           AND consumed_at IS NULL'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to invalidate previous OTP.'
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
            'Unable to invalidate previous OTP.'
        );
    }

    $stmt->close();

    /* Generate OTP */

    $otp =
        generateOtp();

    $otpHash =
        hashOtp($otp);

    $expiresAt =
        date(
            'Y-m-d H:i:s',
            time() + $otpExpiry
        );

    /* Store OTP */

    $stmt = $conn->prepare(
        'INSERT INTO otp_codes
        (
            user_id,
            purpose,
            otp_hash,
            expires_at,
            attempts,
            max_attempts,
            consumed_at
        )
        VALUES
        (?, ?, ?, ?, 0, ?, NULL)'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to create OTP.'
        );
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

        throw new RuntimeException(
            'Unable to create OTP.'
        );
    }

    $stmt->close();

    return $otp;
}