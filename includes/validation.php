<?php

/* Validate required string */

function validateRequiredString(
    mixed $value,
    string $field,
    int $minLength = 1,
    int $maxLength = 255
): string {
    if (!is_string($value)) {
        throw new InvalidArgumentException(
            "{$field} must be a string."
        );
    }

    $value = trim($value);

    $length = mb_strlen($value);

    if ($length < $minLength) {
        throw new InvalidArgumentException(
            "{$field} is too short."
        );
    }

    if ($length > $maxLength) {
        throw new InvalidArgumentException(
            "{$field} is too long."
        );
    }

    return $value;
}

/* Validate name */

function validateName(
    mixed $name,
    int $minLength = 2,
    int $maxLength = 100
): string {
    if (!is_string($name)) {
        throw new InvalidArgumentException(
            'Name must be a string.'
        );
    }

    $name = trim($name);

    $length = mb_strlen($name);

    if ($length < $minLength) {
        throw new InvalidArgumentException(
            'Name is too short.'
        );
    }

    if ($length > $maxLength) {
        throw new InvalidArgumentException(
            'Name is too long.'
        );
    }

    if (
        !preg_match(
            "/^[\p{L}\p{M}]+(?:[ '\-][\p{L}\p{M}]+)*$/u",
            $name
        )
    ) {
        throw new InvalidArgumentException(
            'Name contains invalid characters.'
        );
    }

    return $name;
}

/* Validate email */

function validateEmail(
    mixed $email
): string {
    if (!is_string($email)) {
        throw new InvalidArgumentException(
            'Email must be a string.'
        );
    }

    $email = trim(
        strtolower($email)
    );

    if (
        $email === '' ||
        strlen($email) > 255 ||
        !filter_var(
            $email,
            FILTER_VALIDATE_EMAIL
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid email address.'
        );
    }

    return $email;
}

/* Validate password */

function validatePassword(
    mixed $password,
    int $minLength = 8,
    int $maxLength = 72
): string {
    if (!is_string($password)) {
        throw new InvalidArgumentException(
            'Password must be a string.'
        );
    }

    $length = strlen($password);

    if ($length < $minLength) {
        throw new InvalidArgumentException(
            "Password must be at least {$minLength} characters."
        );
    }

    if ($length > $maxLength) {
        throw new InvalidArgumentException(
            "Password must not exceed {$maxLength} characters."
        );
    }

    return $password;
}

/* Validate login password */

function validateLoginPassword(
    mixed $password,
    int $maxLength = 72
): string {
    if (!is_string($password)) {
        throw new InvalidArgumentException(
            'Password must be a string.'
        );
    }

    if ($password === '') {
        throw new InvalidArgumentException(
            'Password is required.'
        );
    }

    if (strlen($password) > $maxLength) {
        throw new InvalidArgumentException(
            'Password is too long.'
        );
    }

    return $password;
}

/* Validate positive integer ID */

function validateId(
    mixed $id
): int {
    if (
        filter_var(
            $id,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        ) === false
    ) {
        throw new InvalidArgumentException(
            'Invalid ID.'
        );
    }

    return (int) $id;
}

/* Validate OTP */

function validateOtp(
    mixed $otp,
    int $length = 6
): string {
    if (!is_string($otp)) {
        throw new InvalidArgumentException(
            'OTP must be a string.'
        );
    }

    if (
        strlen($otp) !== $length ||
        !preg_match(
            '/^\d{' . $length . '}$/',
            $otp
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid OTP.'
        );
    }

    return $otp;
}

/* Get JSON request body */

function getJsonInput(): array
{
    $contentType =
        $_SERVER['CONTENT_TYPE'] ?? '';

    if (
        stripos(
            $contentType,
            'application/json'
        ) === false
    ) {
        throw new InvalidArgumentException(
            'Content-Type must be application/json.'
        );
    }

    $rawInput =
        file_get_contents(
            'php://input'
        );

    if (
        $rawInput === false ||
        trim($rawInput) === ''
    ) {
        throw new InvalidArgumentException(
            'Request body is required.'
        );
    }

    try {

        $data = json_decode(
            $rawInput,
            true,
            512,
            JSON_THROW_ON_ERROR
        );

    } catch (JsonException) {

        throw new InvalidArgumentException(
            'Invalid JSON request body.'
        );
    }

    if (!is_array($data)) {
        throw new InvalidArgumentException(
            'JSON body must be an object.'
        );
    }

    return $data;
}

/* Validate allowed fields */

function validateAllowedFields(
    array $input,
    array $allowedFields
): void {
    $unknownFields =
        array_diff(
            array_keys($input),
            $allowedFields
        );

    if ($unknownFields !== []) {
        throw new InvalidArgumentException(
            'Request contains invalid fields.'
        );
    }
}