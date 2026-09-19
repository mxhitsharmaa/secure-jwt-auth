<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/rate_limiter.php';
require_once __DIR__ . '/../../includes/request_limiter.php';

/* Apply API Security */

function applyApiSecurity(): void
{
    global $securityConfig;
    global $conn;

    /* Allowed HTTP Methods */

    $allowedMethods = [
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS',
    ];

    $method =
        $_SERVER['REQUEST_METHOD'] ?? '';

    if (
        !in_array(
            $method,
            $allowedMethods,
            true
        )
    ) {
        header(
            'Allow: GET, POST, PUT, PATCH, DELETE, OPTIONS'
        );

        errorResponse(
            'HTTP method not allowed.',
            405
        );
    }

    /* Security Headers */

    foreach (
        $securityConfig['headers']
        as $header => $value
    ) {
        header(
            "{$header}: {$value}"
        );
    }

    /* Request Body Size */

    $contentLength =
        $_SERVER['CONTENT_LENGTH'] ?? null;

    if (
        $contentLength !== null &&
        ctype_digit(
            (string) $contentLength
        ) &&
        (int) $contentLength >
        1024 * 1024
    ) {
        errorResponse(
            'Request body is too large.',
            413
        );
    }

    /* JSON Content-Type */

    if (
        in_array(
            $method,
            [
                'POST',
                'PUT',
                'PATCH',
            ],
            true
        )
    ) {
        $contentType =
            $_SERVER['CONTENT_TYPE'] ?? '';

        if (
            stripos(
                $contentType,
                'application/json'
            ) === false
        ) {
            errorResponse(
                'Content-Type must be application/json.',
                415
            );
        }
    }

    /* Global Rate Limit */

    if (
        $method !== 'OPTIONS'
    ) {
        applyGlobalRateLimit(
            $conn
        );
    }
}

/* Require HTTPS */

function requireSecureConnection(): void
{
    global $appConfig;

    /* Local Development */

    if (
        $appConfig['environment'] ===
        'local'
    ) {
        return;
    }

    /* HTTPS Detection */

    $https =
        $_SERVER['HTTPS'] ?? '';

    if (
        $https === '' ||
        strtolower($https) === 'off'
    ) {
        errorResponse(
            'HTTPS connection required.',
            403
        );
    }
}