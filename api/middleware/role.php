<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/response.php';

/* Require Role */

function requireRole(
    object $tokenData,
    string|array $allowedRoles
): void {

    if (
        !isset(
            $tokenData->user,
            $tokenData->user->role
        )
    ) {
        errorResponse(
            'Authorization information is missing.',
            403
        );
    }

    $roles = is_array(
        $allowedRoles
    )
        ? $allowedRoles
        : [$allowedRoles];

    $userRole = $tokenData->user->role;

    if (
        !is_string($userRole) ||
        !in_array(
            $userRole,
            $roles,
            true
        )
    ) {
        errorResponse(
            'You are not authorized to access this resource.',
            403
        );
    }
}

/* Require Admin */

function requireAdmin(
    object $tokenData
): void {

    requireRole(
        $tokenData,
        'admin'
    );
}

/* Require User */

function requireUser(
    object $tokenData
): void {

    requireRole(
        $tokenData,
        'user'
    );
}