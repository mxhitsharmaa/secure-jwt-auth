
<?php

require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
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

    /* JSON Input */

    $input =
        getJsonInput();

    /* Strict Fields */

    validateAllowedFields(
        $input,
        [
            'session_id',
        ]
    );

    /* Validate Session ID */

    $sessionId =
        validateId(
            $input['session_id'] ?? null
        );

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'session',
        (string) $sessionId,
        'revoke',
        10
    );

    /* Transaction */

    $conn->begin_transaction();

    $transactionStarted = true;

    /* Lock Session */

    $stmt = $conn->prepare(
        'SELECT
            id,
            user_id,
            revoked_at,
            expires_at
         FROM refresh_tokens
         WHERE id = ?
         LIMIT 1
         FOR UPDATE'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare session lookup.'
        );
    }

    $stmt->bind_param(
        'i',
        $sessionId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to retrieve session.'
        );
    }

    $stmt->bind_result(
        $lockedSessionId,
        $lockedUserId,
        $lockedRevokedAt,
        $lockedExpiresAt
    );

    $found =
        $stmt->fetch();

    $stmt->close();

    /* Session Check */

    if (!$found) {
        $conn->rollback();
        $transactionStarted = false;

        errorResponse(
            'Session not found.',
            404
        );
    }

    /* Ownership Check */

    if (
        (int) $lockedUserId !==
        $userId
    ) {
        $conn->rollback();
        $transactionStarted = false;

        errorResponse(
            'Session not found.',
            404
        );
    }

    /* Already Revoked */

    if (
        $lockedRevokedAt !== null
    ) {
        $conn->commit();
        $transactionStarted = false;

        successResponse(
            'Session has already been revoked.',
            [
                'session_id' =>
                    (int) $lockedSessionId,

                'revoked' =>
                    true,
            ]
        );
    }

    /* Revoke Session */

    $stmt = $conn->prepare(
        'UPDATE refresh_tokens
         SET revoked_at = NOW()
         WHERE id = ?
           AND user_id = ?
           AND revoked_at IS NULL
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare session revocation.'
        );
    }

    $stmt->bind_param(
        'ii',
        $sessionId,
        $userId
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to revoke session.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {
        $stmt->close();

        throw new RuntimeException(
            'Session revocation was not completed.'
        );
    }

    $stmt->close();

    /* Commit */

    $conn->commit();

    $transactionStarted = false;

    /* Audit */

    securityLog(
        'session_revoked',
        $userId,
        [
            'session_id' =>
                $sessionId,
        ]
    );

    /* Response */

    successResponse(
        'Session revoked successfully.',
        [
            'session_id' =>
                $sessionId,

            'revoked' =>
                true,
        ]
    );

} catch (InvalidArgumentException $e) {

    if ($transactionStarted) {
        $conn->rollback();
    }

    errorResponse(
        $e->getMessage(),
        422
    );

} catch (Throwable $e) {

    if ($transactionStarted) {
        $conn->rollback();
    }

    error_log(
        '[SESSION_REVOKE] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to revoke session.',
        500
    );
}

