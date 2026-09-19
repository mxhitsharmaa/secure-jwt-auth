<?php

declare(strict_types=1);

use Firebase\JWT\JWT;

/* Generate UUID v4 */

function generateUuidV4(): string
{
    $data = random_bytes(16);

    $data[6] = chr(
        (ord($data[6]) & 0x0f) | 0x40
    );

    $data[8] = chr(
        (ord($data[8]) & 0x3f) | 0x80
    );

    return vsprintf(
        '%s%s-%s-%s-%s-%s%s%s',
        str_split(
            bin2hex($data),
            4
        )
    );
}

/* Get user token version */

function getUserTokenVersion(
    mysqli $conn,
    int $userId
): int {
    $stmt = $conn->prepare(
        'SELECT token_version
         FROM users
         WHERE id = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare token version lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve token version.'
        );
    }

    $stmt->bind_result($tokenVersion);

    $found = $stmt->fetch();

    $stmt->close();

    if (!$found) {
        throw new RuntimeException(
            'User account not found.'
        );
    }

    return (int) $tokenVersion;
}

/* Create JWT */

function createJwtToken(
    int $userId,
    string $type,
    int $ttl,
    ?string $jti = null,
    ?string $familyId = null
): string {
    global $jwtConfig;
    global $conn;

    $now = time();

    $jti ??= generateUuidV4();

    $tokenVersion = getUserTokenVersion(
        $conn,
        $userId
    );

    $payload = [
        'iss' => $jwtConfig['issuer'],
        'aud' => $jwtConfig['audience'],
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + $ttl,
        'jti' => $jti,
        'sub' => (string) $userId,
        'type' => $type,
        'token_version' => $tokenVersion,
    ];

    if ($familyId !== null) {
        $payload['family_id'] = $familyId;
    }

    return JWT::encode(
        $payload,
        $jwtConfig['secret'],
        $jwtConfig['algorithm']
    );
}

/* Create access token */

function createAccessToken(
    int $userId
): string {
    global $jwtConfig;

    return createJwtToken(
        $userId,
        'access',
        $jwtConfig['access_ttl']
    );
}

/* Create refresh token */

function createRefreshToken(
    int $userId,
    string $jti,
    string $familyId
): string {
    global $jwtConfig;

    return createJwtToken(
        $userId,
        'refresh',
        $jwtConfig['refresh_ttl'],
        $jti,
        $familyId
    );
}