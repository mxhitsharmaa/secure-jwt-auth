
<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../middleware/auth.php';
require_once __DIR__ . '/../middleware/refresh_token.php';

$transactionStarted = false;

try {

    /* Security */

    applyApiSecurity();

    requireSecureConnection();

    /* Method */

    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    ) {
        header(
            'Allow: POST, OPTIONS'
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

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'sessions-revoke-all',
        10
    );

    /* Transaction */

    $conn->begin_transaction();

    $transactionStarted = true;

    /* Lock User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            status,
            email_verified_at,
            token_version
         FROM users
         WHERE id = ?
         LIMIT 1
         FOR UPDATE'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare user lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve user account.'
        );
    }

    $stmt->bind_result(
        $lockedId,
        $lockedStatus,
        $lockedEmailVerifiedAt,
        $lockedTokenVersion
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    /* User Check */

    if (!$found) {
        $conn->rollback();
        $transactionStarted = false;

        errorResponse(
            'User account not found.',
            404
        );
    }

    if (
        $lockedStatus !== 'active'
    ) {
        $conn->rollback();
        $transactionStarted = false;

        errorResponse(
            'Account is not active.',
            403
        );
    }

    if (
        $lockedEmailVerifiedAt === null
    ) {
        $conn->rollback();
        $transactionStarted = false;

        errorResponse(
            'Email address is not verified.',
            403
        );
    }

    $lockedTokenVersion =
        (int) $lockedTokenVersion;

    if ($lockedTokenVersion < 1) {
        throw new RuntimeException(
            'Invalid token version.'
        );
    }

    /* Revoke Refresh Sessions */

    $stmt = $conn->prepare(
        'UPDATE refresh_tokens
         SET revoked_at = NOW()
         WHERE user_id = ?
           AND revoked_at IS NULL'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare session revocation.'
        );
    }

    $stmt->bind_param(
        'i',
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to revoke sessions.'
        );
    }

    $revokedSessions =
        $stmt->affected_rows;

    $stmt->close();

    /* Increment Token Version */

    $newTokenVersion =
        $lockedTokenVersion + 1;

    $stmt = $conn->prepare(
        'UPDATE users
         SET token_version = ?,
             updated_at = NOW()
         WHERE id = ?
           AND token_version = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare token version update.'
        );
    }

    $stmt->bind_param(
        'iii',
        $newTokenVersion,
        $userId,
        $lockedTokenVersion
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate access tokens.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to invalidate access tokens.'
        );
    }

    $stmt->close();

    /* Commit */

    $conn->commit();

    $transactionStarted = false;

    /* Audit */

    securityLog(
        'all_sessions_revoked',
        $userId,
        [
            'revoked_sessions' =>
                $revokedSessions,
        ]
    );

    /* Response */

    successResponse(
        'All sessions have been revoked successfully.',
        [
            'sessions_revoked' =>
                $revokedSessions,
        ]
    );

} catch (Throwable $e) {

    if ($transactionStarted) {
        $conn->rollback();
    }

    error_log(
        '[REVOKE_ALL_SESSIONS] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to revoke all sessions.',
        500
    );
}