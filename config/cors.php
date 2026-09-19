<?php

declare(strict_types=1);

/* Allowed origins */

$allowedOrigins = array_values(
    array_filter(
        array_map(
            'trim',
            explode(
                ',',
                $_ENV['CORS_ALLOWED_ORIGINS'] ?? ''
            )
        )
    )
);

/* Request origin */

$requestOrigin =
    $_SERVER['HTTP_ORIGIN'] ?? '';

/* Validate origin */

if ($requestOrigin !== '') {

    if (
        !in_array(
            $requestOrigin,
            $allowedOrigins,
            true
        )
    ) {
        http_response_code(403);

        header(
            'Content-Type: application/json; charset=utf-8'
        );

        echo json_encode(
            [
                'success' => false,
                'message' =>
                    'Origin is not allowed.',
            ],
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES
        );

        exit;
    }

    /* CORS headers */

    header(
        'Access-Control-Allow-Origin: ' .
        $requestOrigin
    );

    header(
        'Access-Control-Allow-Credentials: true'
    );

    header(
        'Access-Control-Allow-Headers: ' .
        'Content-Type, Authorization, X-Requested-With'
    );

    header(
        'Access-Control-Allow-Methods: ' .
        'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    );

    header(
        'Access-Control-Max-Age: 600'
    );

    header(
        'Vary: Origin'
    );
}

/* Security headers */

header(
    'X-Content-Type-Options: nosniff'
);

header(
    'X-Frame-Options: DENY'
);

header(
    'Referrer-Policy: no-referrer'
);

header(
    'Permissions-Policy: ' .
    'geolocation=(), microphone=(), camera=()'
);

header(
    'Cache-Control: no-store'
);

header(
    'Pragma: no-cache'
);

/* Production HSTS */

if (
    ($_ENV['APP_ENV'] ?? 'local') ===
    'production'
) {
    header(
        'Strict-Transport-Security: ' .
        'max-age=31536000; includeSubDomains'
    );
}

/* Preflight */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') ===
    'OPTIONS'
) {
    http_response_code(204);
    exit;
}