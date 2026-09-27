<?php

declare(strict_types=1);

/* Security Configuration */

return [

    /* Password */

    'password' => [
        'min_length' => 8,
        'max_length' => 72,
        'algorithm'  => PASSWORD_DEFAULT,
    ],

    /* OTP */

    'otp' => [
        'length'           => 6,
        'expiry'           => (int) ($_ENV['OTP_EXPIRY']          ?? 300),
        'max_attempts'     => (int) ($_ENV['OTP_MAX_ATTEMPTS']    ?? 6),
        'max_resends'      => (int) ($_ENV['OTP_MAX_RESENDS']     ?? 6),
        'resend_cooldown'  => (int) ($_ENV['OTP_RESEND_COOLDOWN'] ?? 60),
        'block_duration'   => (int) ($_ENV['OTP_BLOCK_DURATION']  ?? 900),
    ],

    /* Login Lockout */

    'login' => [
        'max_failed_attempts' => 5,
        'failure_window'      => 90,    // production: 900
        'lockout_duration'    => 90,    // production: 900
    ],

    /* Login Rate Limiting (IP/email throttle) */

    'rate_limit' => [
        'max_attempts'   => 5,
        'window_seconds' => 90,         // production: 900

        'global_ip' => [
            'max'    => 600,            // production: 60
            'window' => 60,
        ],
    ],

    /* JWT Security */

    'jwt' => [
        'clock_skew'         => 30,
        'require_issuer'     => true,
        'require_audience'   => true,
        'require_expiration' => true,
        'require_jti'        => true,
    ],

    /* HTTP Security Headers */

    'headers' => [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options'        => 'DENY',
        'Referrer-Policy'        => 'no-referrer',
        'Permissions-Policy'     => 'geolocation=(), microphone=(), camera=()',
        'Cache-Control'          => 'no-store',
        'Pragma'                 => 'no-cache',
    ],

];