<?php

declare(strict_types=1);

$secret = $_ENV['JWT_SECRET'] ?? '';

if ($secret === '') {
    throw new RuntimeException(
        'JWT_SECRET is not configured.'
    );
}

if (strlen($secret) < 64) {
    throw new RuntimeException(
        'JWT_SECRET must be at least 64 characters long.'
    );
}

return [
    'issuer' => $_ENV['JWT_ISSUER'] ?? 'secure-jwt-auth',

    'audience' => $_ENV['JWT_AUDIENCE'] ?? 'secure-jwt-users',

    'access_ttl' => (int) ($_ENV['JWT_ACCESS_TTL'] ?? 900),

    'refresh_ttl' => (int) ($_ENV['JWT_REFRESH_TTL'] ?? 2592000),

    'algorithm' => 'HS256',

    'secret' => $secret,
];