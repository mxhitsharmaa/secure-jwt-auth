<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../middleware/auth.php';

try {

    /* Security */

    applyApiSecurity();

    requireSecureConnection();

    /* Method */

    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
    ) {
        header(
            'Allow: GET, OPTIONS'
        );

        errorResponse(
            'HTTP method not allowed.',
            405
        );
    }

    /* Authentication */

    $tokenData = authenticateRequest();

    if (
        !isset(
            $tokenData->user['id']
        )
    ) {
        errorResponse(
            'Authorization information is missing.',
            401
        );
    }

    $userId =
        (int) $tokenData->user['id'];

    if ($userId < 1) {
        errorResponse(
            'Invalid user identity.',
            401
        );
    }

    /* Fresh User Data */

    $stmt = $conn->prepare(
        'SELECT
            id,
            name,
            email,
            role,
            status,
            email_verified_at,
            created_at,
            updated_at
         FROM users
         WHERE id = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare profile lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve profile.'
        );
    }

    $stmt->bind_result(
        $id,
        $name,
        $email,
        $role,
        $status,
        $emailVerifiedAt,
        $createdAt,
        $updatedAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    if (!$found) {
        errorResponse(
            'User account not found.',
            404
        );
    }

    /* Account Status */

    if (
        !in_array(
            $status,
            ['active'],
            true
        )
    ) {
        errorResponse(
            'User account is not active.',
            403
        );
    }

    /* Response */

    successResponse(
        'Profile retrieved successfully.',
        [
            'user' => [
                'id' =>
                    (int) $id,

                'name' =>
                    $name,

                'email' =>
                    $email,

                'role' =>
                    $role,

                'status' =>
                    $status,

                'email_verified' =>
                    $emailVerifiedAt !== null,

                'email_verified_at' =>
                    $emailVerifiedAt,

                'created_at' =>
                    $createdAt,

                'updated_at' =>
                    $updatedAt,
            ],
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[USER_ME] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to retrieve profile.',
        500
    );
}