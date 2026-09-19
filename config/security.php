<?php

declare(strict_types=1);

/* Security Configuration
*/

return [

    /*
      Password
    */

    'password' => [
        'min_length' => 8,
        'max_length' => 72,
        'algorithm' => PASSWORD_DEFAULT,
    ],

    /*
     OTP
    */

    'otp' => [
        'length' => 6,
        'expiry' => (int) ($_ENV['OTP_EXPIRY'] ?? 300),
        'max_attempts' => (int) ($_ENV['OTP_MAX_ATTEMPTS'] ?? 5),
        'resend_cooldown' => (int) ($_ENV['OTP_RESEND_COOLDOWN'] ?? 60),
    ],

    /*
    Login Rate Limiting
    */

    'rate_limit' => [
        'max_attempts' => 5,
        'window_seconds' => 900,
    ],

    /*
     JWT Security
    */

    'jwt' => [
        'clock_skew' => 30,
        'require_issuer' => true,
        'require_audience' => true,
        'require_expiration' => true,
        'require_jti' => true,
    ],

    /*
     HTTP Security Headers
    */

    'headers' => [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'no-referrer',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ],

];