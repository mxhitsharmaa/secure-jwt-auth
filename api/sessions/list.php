
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

    $tokenData =
        authenticateRequest();

    if (
        !isset($tokenData->sub)
    ) {
        errorResponse(
            'Authorization information is missing.',
            401
        );
    }

    $userId =
        filter_var(
            $tokenData->sub,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

    if ($userId === false) {
        errorResponse(
            'Invalid user identity.',
            401
        );
    }

    $userId =
        (int) $userId;

    /* Current Refresh JTI */

    $currentJti = null;

    if (
        isset($tokenData->jti) &&
        is_string($tokenData->jti) &&
        preg_match(
            '/^[0-9a-fA-F]{8}-' .
            '[0-9a-fA-F]{4}-' .
            '4[0-9a-fA-F]{3}-' .
            '[89abAB][0-9a-fA-F]{3}-' .
            '[0-9a-fA-F]{12}$/',
            $tokenData->jti
        )
    ) {
        $currentJti =
            strtolower(
                $tokenData->jti
            );
    }

    /* Get Active Sessions */

    $stmt = $conn->prepare(
        'SELECT
            id,
            jti,
            ip_address,
            user_agent,
            created_at,
            last_used_at,
            expires_at
         FROM refresh_tokens
         WHERE user_id = ?
           AND revoked_at IS NULL
           AND expires_at > NOW()
         ORDER BY
            last_used_at DESC,
            created_at DESC'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare session lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve active sessions.'
        );
    }

    $stmt->bind_result(
        $sessionId,
        $sessionJti,
        $ipAddress,
        $userAgent,
        $createdAt,
        $lastUsedAt,
        $expiresAt
    );

    $sessions = [];

    while ($stmt->fetch()) {

        $isCurrent = (
            $currentJti !== null &&
            is_string($sessionJti) &&
            hash_equals(
                strtolower($sessionJti),
                $currentJti
            )
        );

        $sessions[] = [
            'id' =>
                (int) $sessionId,

            'ip_address' =>
                $ipAddress,

            'user_agent' =>
                $userAgent,

            'created_at' =>
                $createdAt,

            'last_used_at' =>
                $lastUsedAt,

            'expires_at' =>
                $expiresAt,

            'current' =>
                $isCurrent,
        ];
    }

    $stmt->close();

    /* Response */

    successResponse(
        'Active sessions retrieved successfully.',
        [
            'total' =>
                count($sessions),

            'sessions' =>
                $sessions,
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[SESSIONS_LIST] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to retrieve active sessions.',
        500
    );
}
