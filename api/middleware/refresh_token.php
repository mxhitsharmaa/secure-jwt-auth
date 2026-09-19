<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';

/* Hash refresh token */

function hashRefreshToken(
    string $token
): string {
    if ($token === '') {
        throw new InvalidArgumentException(
            'Refresh token is required.'
        );
    }

    return hash(
        'sha256',
        $token
    );
}

/* Store refresh token */

function storeRefreshToken(
    mysqli $conn,
    int $userId,
    string $token,
    string $jti,
    string $familyId,
    int $expiresAt,
    ?int $parentId = null
): int {

    if ($userId < 1) {
        throw new InvalidArgumentException(
            'Invalid user ID.'
        );
    }

    if (
        !preg_match(
            '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
            $jti
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid refresh token JTI.'
        );
    }

    if (
        !preg_match(
            '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
            $familyId
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid refresh token family ID.'
        );
    }

    if ($expiresAt <= time()) {
        throw new InvalidArgumentException(
            'Refresh token expiration is invalid.'
        );
    }

    $tokenHash =
        hashRefreshToken($token);

    $ipAddress =
        $_SERVER['REMOTE_ADDR'] ?? null;

    if (
        $ipAddress !== null &&
        !filter_var(
            $ipAddress,
            FILTER_VALIDATE_IP
        )
    ) {
        $ipAddress = null;
    }

    $userAgent =
        $_SERVER['HTTP_USER_AGENT'] ?? null;

    if ($userAgent !== null) {
        $userAgent =
            substr(
                $userAgent,
                0,
                500
            );
    }

    $expiresAtDate =
        date(
            'Y-m-d H:i:s',
            $expiresAt
        );

    $stmt = $conn->prepare(
        'INSERT INTO refresh_tokens
        (
            user_id,
            token_hash,
            jti,
            family_id,
            parent_id,
            expires_at,
            ip_address,
            user_agent
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare refresh token statement.'
        );
    }

    $stmt->bind_param(
        'isssisss',
        $userId,
        $tokenHash,
        $jti,
        $familyId,
        $parentId,
        $expiresAtDate,
        $ipAddress,
        $userAgent
    );

    if (!$stmt->execute()) {
        $errorCode =
            $stmt->errno;

        $stmt->close();

        if ($errorCode === 1062) {
            throw new RuntimeException(
                'Refresh token identifier already exists.'
            );
        }

        throw new RuntimeException(
            'Unable to store refresh token.'
        );
    }

    $insertedId =
        (int) $conn->insert_id;

    $stmt->close();

    return $insertedId;
}

/* Find refresh token */

function findRefreshToken(
    mysqli $conn,
    string $token,
    bool $forUpdate = false
): ?array {

    $tokenHash =
        hashRefreshToken($token);

    $sql = '
        SELECT
            id,
            user_id,
            token_hash,
            jti,
            family_id,
            parent_id,
            expires_at,
            revoked_at,
            replaced_by_id,
            reuse_detected_at,
            ip_address,
            user_agent,
            created_at,
            last_used_at
        FROM refresh_tokens
        WHERE token_hash = ?
        LIMIT 1
    ';

    if ($forUpdate) {
        $sql .= ' FOR UPDATE';
    }

    $stmt =
        $conn->prepare($sql);

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare refresh token lookup.'
        );
    }

    $stmt->bind_param(
        's',
        $tokenHash
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to lookup refresh token.'
        );
    }

    $result =
        $stmt->get_result();

    $tokenData =
        $result->fetch_assoc();

    $stmt->close();

    return $tokenData ?: null;
}

/* Revoke refresh token */

function revokeRefreshToken(
    mysqli $conn,
    int $tokenId,
    ?int $replacedById = null
): void {

    if ($tokenId < 1) {
        throw new InvalidArgumentException(
            'Invalid refresh token ID.'
        );
    }

    if (
        $replacedById !== null &&
        $replacedById < 1
    ) {
        throw new InvalidArgumentException(
            'Invalid replacement token ID.'
        );
    }

    $stmt = $conn->prepare(
        'UPDATE refresh_tokens
         SET revoked_at = COALESCE(
                 revoked_at,
                 NOW()
             ),
             replaced_by_id = COALESCE(
                 ?,
                 replaced_by_id
             )
         WHERE id = ?
           AND revoked_at IS NULL
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare token revocation.'
        );
    }

    $stmt->bind_param(
        'ii',
        $replacedById,
        $tokenId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to revoke refresh token.'
        );
    }

    $stmt->close();
}

/* Revoke complete token family */

function revokeRefreshTokenFamily(
    mysqli $conn,
    string $familyId,
    bool $reuseDetected = false
): void {

    if (
        !preg_match(
            '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
            $familyId
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid refresh token family ID.'
        );
    }

    if ($reuseDetected) {

        $stmt = $conn->prepare(
            'UPDATE refresh_tokens
             SET revoked_at = COALESCE(
                     revoked_at,
                     NOW()
                 ),
                 reuse_detected_at = COALESCE(
                     reuse_detected_at,
                     NOW()
                 )
             WHERE family_id = ?'
        );

    } else {

        $stmt = $conn->prepare(
            'UPDATE refresh_tokens
             SET revoked_at = COALESCE(
                     revoked_at,
                     NOW()
                 )
             WHERE family_id = ?'
        );
    }

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare token family revocation.'
        );
    }

    $stmt->bind_param(
        's',
        $familyId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to revoke refresh token family.'
        );
    }

    $stmt->close();
}

/* Detect refresh token reuse */

function detectRefreshTokenReuse(
    mysqli $conn,
    array $tokenData
): bool {

    if (
        !isset(
            $tokenData['revoked_at'],
            $tokenData['reuse_detected_at'],
            $tokenData['family_id']
        )
    ) {
        throw new RuntimeException(
            'Invalid refresh token session data.'
        );
    }

    if (
        $tokenData['revoked_at'] === null &&
        $tokenData['reuse_detected_at'] === null
    ) {
        return false;
    }

    revokeRefreshTokenFamily(
        $conn,
        $tokenData['family_id'],
        true
    );

    return true;
}

/* Check refresh token expiration */

function isRefreshTokenExpired(
    array $tokenData
): bool {

    if (
        !isset(
            $tokenData['expires_at']
        )
    ) {
        return true;
    }

    $expiresAt =
        strtotime(
            $tokenData['expires_at']
        );

    if ($expiresAt === false) {
        return true;
    }

    return $expiresAt <= time();
}

/* Check refresh token revoked */

function isRefreshTokenRevoked(
    array $tokenData
): bool {
    return
        isset($tokenData['revoked_at']) &&
        $tokenData['revoked_at'] !== null;
}

/* Check reuse detection */

function isRefreshTokenReuseDetected(
    array $tokenData
): bool {
    return
        isset(
            $tokenData['reuse_detected_at']
        ) &&
        $tokenData['reuse_detected_at'] !== null;
}

/* Revoke all user refresh tokens */

function revokeAllUserRefreshTokens(
    mysqli $conn,
    int $userId
): void {

    if ($userId < 1) {
        throw new InvalidArgumentException(
            'Invalid user ID.'
        );
    }

    $stmt = $conn->prepare(
        'UPDATE refresh_tokens
         SET revoked_at = COALESCE(
                 revoked_at,
                 NOW()
             )
         WHERE user_id = ?
           AND revoked_at IS NULL'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare all-session revocation.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to revoke all refresh sessions.'
        );
    }

    $stmt->close();
}