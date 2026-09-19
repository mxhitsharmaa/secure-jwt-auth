<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/request_limiter.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/* Authenticate request */

function authenticateRequest(): object
{
    global $jwtConfig;
    global $securityConfig;
    global $conn;

    /* Authorization header */

    $authorization =
        $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if ($authorization === '') {
        errorResponse(
            'Authentication required.',
            401
        );
    }

    /* Bearer token */

    if (
        !preg_match(
            '/^Bearer\s+([A-Za-z0-9\-_\.]+)$/',
            $authorization,
            $matches
        )
    ) {
        errorResponse(
            'Invalid authorization header.',
            401
        );
    }

    $token = $matches[1];

    if ($token === '') {
        errorResponse(
            'Access token is required.',
            401
        );
    }

    /* Decode JWT */

    try {
        $decoded = JWT::decode(
            $token,
            new Key(
                $jwtConfig['secret'],
                $jwtConfig['algorithm']
            )
        );
    } catch (Throwable) {
        errorResponse(
            'Invalid or expired access token.',
            401
        );
    }

    /* Clock skew */

    $clockSkew =
        (int) (
            $securityConfig['jwt']['clock_skew']
            ?? 30
        );

    if ($clockSkew < 0) {
        $clockSkew = 0;
    }

    $currentTime = time();

    /* Required claims */

    if (
        !isset(
            $decoded->iss,
            $decoded->aud,
            $decoded->exp,
            $decoded->iat,
            $decoded->nbf,
            $decoded->jti,
            $decoded->sub,
            $decoded->type,
            $decoded->token_version
        )
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* Issuer */

    if (
        !is_string($decoded->iss) ||
        !hash_equals(
            $jwtConfig['issuer'],
            $decoded->iss
        )
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* Audience */

    $audienceValid = false;

    if (is_string($decoded->aud)) {

        $audienceValid =
            hash_equals(
                $jwtConfig['audience'],
                $decoded->aud
            );

    } elseif (is_array($decoded->aud)) {

        foreach ($decoded->aud as $audience) {

            if (
                is_string($audience) &&
                hash_equals(
                    $jwtConfig['audience'],
                    $audience
                )
            ) {
                $audienceValid = true;

                break;
            }
        }
    }

    if (!$audienceValid) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* Expiration */

    if (!is_numeric($decoded->exp)) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    $expiration =
        (int) $decoded->exp;

    if (
        $expiration <=
        ($currentTime - $clockSkew)
    ) {
        errorResponse(
            'Access token has expired.',
            401
        );
    }

    /* Issued at */

    if (!is_numeric($decoded->iat)) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    $issuedAt =
        (int) $decoded->iat;

    if (
        $issuedAt >
        ($currentTime + $clockSkew)
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* Not before */

    if (!is_numeric($decoded->nbf)) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    $notBefore =
        (int) $decoded->nbf;

    if (
        $notBefore >
        ($currentTime + $clockSkew)
    ) {
        errorResponse(
            'Access token is not active yet.',
            401
        );
    }

    /* Token lifetime sanity */

    if ($expiration <= $issuedAt) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* Token type */

    if (
        !is_string($decoded->type) ||
        $decoded->type !== 'access'
    ) {
        errorResponse(
            'Access token required.',
            401
        );
    }

    /* Token version */

    if (
        !is_numeric(
            $decoded->token_version
        )
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    $tokenVersion =
        (int) $decoded->token_version;

    if ($tokenVersion < 1) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* User ID */

    if (
        !is_string($decoded->sub) ||
        !ctype_digit($decoded->sub) ||
        (int) $decoded->sub < 1
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    $userId =
        (int) $decoded->sub;

    /* JTI */

    if (
        !is_string($decoded->jti) ||
        !preg_match(
            '/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i',
            $decoded->jti
        )
    ) {
        errorResponse(
            'Invalid access token.',
            401
        );
    }

    /* User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            name,
            email,
            role,
            status,
            token_version,
            email_verified_at
         FROM users
         WHERE id = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        errorResponse(
            'Unable to verify account.',
            500
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        errorResponse(
            'Unable to verify account.',
            500
        );
    }

    $result =
        $stmt->get_result();

    $user =
        $result->fetch_assoc();

    $stmt->close();

    /* User no longer exists */

    if ($user === null) {
        errorResponse(
            'Account is no longer available.',
            401
        );
    }

    /* Token version */

    if (
        (int) $user['token_version'] !==
        $tokenVersion
    ) {
        errorResponse(
            'Access token has been revoked.',
            401
        );
    }

    /* Blocked account */

    if (
        $user['status'] === 'blocked'
    ) {
        errorResponse(
            'Account is blocked.',
            403
        );
    }

    /* Suspended account */

    if (
        $user['status'] === 'suspended'
    ) {
        errorResponse(
            'Account is suspended.',
            403
        );
    }

    /* Active account */

    if (
        $user['status'] !== 'active'
    ) {
        errorResponse(
            'Account is not active.',
            403
        );
    }

    /* Email verification */

    if (
        $user['email_verified_at'] === null
    ) {
        errorResponse(
            'Email verification is required.',
            403
        );
    }

    /* User Rate Limit */

    applyUserRateLimit(
        $conn,
        $userId,
        getCurrentEndpoint(),
        120,
        60
    );

    /* Attach user */

    $decoded->user = [
        'id' =>
            (int) $user['id'],

        'name' =>
            $user['name'],

        'email' =>
            $user['email'],

        'role' =>
            $user['role'],

        'status' =>
            $user['status'],

        'token_version' =>
            (int) $user['token_version'],
    ];

    return $decoded;
}