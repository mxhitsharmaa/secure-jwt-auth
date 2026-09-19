
<?php


require_once __DIR__ . '/../../config/bootstrap.php';
require_once __DIR__ . '/../../includes/response.php';
require_once __DIR__ . '/../../includes/validation.php';
require_once __DIR__ . '/../../includes/logger.php';
require_once __DIR__ . '/../../includes/request_limiter.php';
require_once __DIR__ . '/../middleware/security.php';
require_once __DIR__ . '/../middleware/auth.php';

$transactionStarted = false;

try {

    /* Security */

    applyApiSecurity();

    requireSecureConnection();

    /* Method */

    if (
        ($_SERVER['REQUEST_METHOD'] ?? '') !== 'PATCH'
    ) {
        header(
            'Allow: PATCH, OPTIONS'
        );

        errorResponse(
            'HTTP method not allowed.',
            405
        );
    }

    /* Authentication */

    $tokenData = authenticateRequest();

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

    $userId = (int) $userId;

    /* JSON Input */

    $input = getJsonInput();

    /* Strict Fields */

    validateAllowedFields(
        $input,
        [
            'name',
        ]
    );

    /* Validate Name */

    $name = validateName(
        $input['name'] ?? null
    );

    /* Request Lock */

    acquireRequestLock(
        $conn,
        'user',
        (string) $userId,
        'update-profile',
        10
    );

    /* Transaction */

    $conn->begin_transaction();

    $transactionStarted = true;

    /* Lock User */

    $stmt = $conn->prepare(
        'SELECT
            id,
            name,
            email,
            role,
            status,
            email_verified_at
         FROM users
         WHERE id = ?
         LIMIT 1
         FOR UPDATE'
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
        $lockedId,
        $lockedName,
        $lockedEmail,
        $lockedRole,
        $lockedStatus,
        $lockedEmailVerifiedAt
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

    /* No Change */

    if (
        hash_equals(
            $lockedName,
            $name
        )
    ) {
        $conn->commit();
        $transactionStarted = false;

        successResponse(
            'Profile is already up to date.',
            [
                'user' => [
                    'id' =>
                        (int) $lockedId,

                    'name' =>
                        $lockedName,

                    'email' =>
                        $lockedEmail,

                    'role' =>
                        $lockedRole,

                    'status' =>
                        $lockedStatus,
                ],
            ]
        );
    }

    /* Update Profile */

    $stmt = $conn->prepare(
        'UPDATE users
         SET name = ?,
             updated_at = NOW()
         WHERE id = ?
           AND status = ?
         LIMIT 1'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Unable to prepare profile update.'
        );
    }

    $activeStatus = 'active';

    $stmt->bind_param(
        'sis',
        $name,
        $userId,
        $activeStatus
    );

    if (!$stmt->execute()) {
        $stmt->close();

        throw new RuntimeException(
            'Unable to update profile.'
        );
    }

    if (
        $stmt->affected_rows !== 1
    ) {
        $stmt->close();

        throw new RuntimeException(
            'Profile update was not completed.'
        );
    }

    $stmt->close();

    /* Audit */

    securityLog(
        'profile_updated',
        $userId,
        [
            'fields' => [
                'name',
            ],
        ]
    );

    /* Commit */

    $conn->commit();

    $transactionStarted = false;

    /* Response */

    successResponse(
        'Profile updated successfully.',
        [
            'user' => [
                'id' =>
                    $userId,

                'name' =>
                    $name,

                'email' =>
                    $lockedEmail,

                'role' =>
                    $lockedRole,

                'status' =>
                    $lockedStatus,
            ],
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
        '[UPDATE_PROFILE] ' .
        $e->getMessage()
    );

    errorResponse(
        'Unable to update profile.',
        500
    );
}
