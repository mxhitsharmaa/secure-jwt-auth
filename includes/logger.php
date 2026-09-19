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

    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

    // Limit user-agent size before storing it.
    if ($userAgent !== null) {
        $userAgent = substr($userAgent, 0, 500);
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

    if (!isset($conn) || !($conn instanceof mysqli)) {
        return;
    }

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

    $stmt->execute();
    $stmt->close();
}