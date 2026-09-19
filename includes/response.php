<?php

declare(strict_types=1);

/*
 API Response Helper
*/

function sendJsonResponse(
    bool $success,
    string $message,
    array $data = [],
    int $statusCode = 200
): never {
    http_response_code($statusCode);

    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');

    $response = [
        'success' => $success,
        'message' => $message,
    ];

    if ($data !== []) {
        $response['data'] = $data;
    }

    echo json_encode(
        $response,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_THROW_ON_ERROR
    );

    exit;
}

/*
 Success response
 */
function successResponse(
    string $message = 'Success.',
    array $data = [],
    int $statusCode = 200
): never {
    sendJsonResponse(
        true,
        $message,
        $data,
        $statusCode
    );
}

/*
 Error response
 */
function errorResponse(
    string $message = 'An error occurred.',
    int $statusCode = 400,
    array $data = []
): never {
    sendJsonResponse(
        false,
        $message,
        $data,
        $statusCode
    );
}