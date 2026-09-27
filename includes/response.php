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

    /* Add Retry-After for 429 if provided in data */
    if (
        $statusCode === 429 &&
        isset($data['retry_after']) &&
        is_numeric($data['retry_after'])
    ) {
        header('Retry-After: ' . max(1, (int) $data['retry_after']));
    }

    /* Add WWW-Authenticate for 401 if Bearer expected */
    if ($statusCode === 401) {
        header('WWW-Authenticate: Bearer');
    }

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

function successResponse(
    string $message = 'Success.',
    array $data = [],
    int $statusCode = 200
): never {
    sendJsonResponse(true, $message, $data, $statusCode);
}

function errorResponse(
    string $message = 'An error occurred.',
    int $statusCode = 400,
    array $data = []
): never {
    sendJsonResponse(false, $message, $data, $statusCode);
}