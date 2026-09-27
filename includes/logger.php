<?php

declare(strict_types=1);

/*
 Security Logger
*/

function securityLog(
    string $event,
    ?int $userId = null,
    array $metadata = []
): void {
    global $conn;

    if (!isset($conn) || !($conn instanceof mysqli)) {
        return;
    }

    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

    if ($userAgent !== null) {
        $userAgent = substr($userAgent, 0, 500);
    }

    if ($ipAddress !== null && strlen($ipAddress) > 45) {
        $ipAddress = substr($ipAddress, 0, 45);
    }

    $metadataJson = null;

    if ($metadata !== []) {
        try {
            $metadataJson = json_encode(
                $metadata,
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES |
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException) {
            $metadataJson = null;
        }
    }

    try {

        if ($userId === null) {

            $stmt = $conn->prepare(
                'INSERT INTO audit_logs
                 (user_id, event, ip_address, user_agent, metadata)
                 VALUES (NULL, ?, ?, ?, ?)'
            );

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param(
                'ssss',
                $event,
                $ipAddress,
                $userAgent,
                $metadataJson
            );

        } else {

            $stmt = $conn->prepare(
                'INSERT INTO audit_logs
                 (user_id, event, ip_address, user_agent, metadata)
                 VALUES (?, ?, ?, ?, ?)'
            );

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param(
                'issss',
                $userId,
                $event,
                $ipAddress,
                $userAgent,
                $metadataJson
            );
        }

        $stmt->execute();
        $stmt->close();

    } catch (Throwable $e) {

        /* Audit logging must not break the request. Log locally. */

        error_log(
            '[AUDIT] ' . $event . ' — ' . $e->getMessage()
        );
    }
}