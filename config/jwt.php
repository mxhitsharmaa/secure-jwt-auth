<?php

declare(strict_types=1);

$secret = $_ENV['JWT_SECRET'] ?? '';

if ($secret === '') {
    throw new RuntimeException('JWT_SECRET is not configured.');
}

if (strlen($secret) < 64) {
    throw new RuntimeException(
        'JWT_SECRET must be at least 64 characters long.'
    );
}

/* Reject weak secrets (all same char, common patterns) */

if (preg_match('/^(.)\1+$/', $secret)) {
    throw new RuntimeException(
        'JWT_SECRET must not consist of a single repeated character.'
    );
}

$algorithm = $_ENV['JWT_ALGORITHM'] ?? 'HS256';

if (!in_array($algorithm, ['HS256', 'HS384', 'HS512'], true)) {
    throw new RuntimeException(
        'Unsupported JWT algorithm: ' . $algorithm
    );
}

return [
    'issuer'  => $_ENV['JWT_ISSUER']   ?? 'secure-jwt-auth',
    'audience' => $_ENV['JWT_AUDIENCE'] ?? 'secure-jwt-users',

    'access_ttl'  => (int) ($_ENV['JWT_ACCESS_TTL']  ?? 900),      // 15 min
    'refresh_ttl' => (int) ($_ENV['JWT_REFRESH_TTL'] ?? 2592000),  // 30 days

    'algorithm' => $algorithm,
    'secret'    => $secret,
];