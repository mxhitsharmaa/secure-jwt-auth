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
        'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS',
    ];

    $method = $_SERVER['REQUEST_METHOD'] ?? '';

    if (!in_array($method, $allowedMethods, true)) {

        header('Allow: GET, POST, PUT, PATCH, DELETE, OPTIONS');

        errorResponse('HTTP method not allowed.', 405);
    }

    /* Security Headers */

    foreach (
        $securityConfig['headers']
        as $header => $value
    ) {
        header("{$header}: {$value}");
    }

    /* Request Body Size */

    $contentLength = $_SERVER['CONTENT_LENGTH'] ?? null;

    if (
        $contentLength !== null &&
        ctype_digit((string) $contentLength) &&
        (int) $contentLength > 1024 * 1024
    ) {
        errorResponse('Request body is too large.', 413);
    }

    /* JSON Content-Type */

    if (
        in_array(
            $method,
            ['POST', 'PUT', 'PATCH'],
            true
        )
    ) {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

        if (
            stripos($contentType, 'application/json') === false
        ) {
            errorResponse(
                'Content-Type must be application/json.',
                415
            );
        }
    }

    /* Global Rate Limit */

    if ($method !== 'OPTIONS') {
        applyGlobalRateLimit($conn);
    }
}

/* Require HTTPS */

function requireSecureConnection(): void
{
    global $appConfig;

    /* Local Development */

    if (
        ($appConfig['environment'] ?? 'local') === 'local'
    ) {
        return;
    }

    /* HTTPS Detection — direct + reverse proxy */

    $https = $_SERVER['HTTPS'] ?? '';

    $isHttps =
        ($https !== '' && strtolower($https) !== 'off');

    /* Reverse proxy support (only trust if configured) */

    if (!$isHttps) {

        $trustedProxies = $_ENV['TRUSTED_PROXIES'] ?? '';

        $trustedProxies = array_filter(
            array_map('trim', explode(',', $trustedProxies))
        );

        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';

        if (
            $remoteAddr !== '' &&
            in_array($remoteAddr, $trustedProxies, true)
        ) {

            $forwardedProto =
                $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';

            if (strtolower($forwardedProto) === 'https') {
                $isHttps = true;
            }
        }
    }

    if (!$isHttps) {
        errorResponse('HTTPS connection required.', 403);
    }
}