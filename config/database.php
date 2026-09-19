<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

// Database configuration
$host = $_ENV['DB_HOST'] ?? 'localhost';
$port = $_ENV['DB_PORT'] ?? '3306';
$database = $_ENV['DB_DATABASE'] ?? '';
$username = $_ENV['DB_USERNAME'] ?? '';
$password = $_ENV['DB_PASSWORD'] ?? '';

if ($database === '' || $username === '') {
    throw new RuntimeException('Database configuration is incomplete.');
}

// Create MySQL connection
$conn = new mysqli(
    $host,
    $username,
    $password,
    $database,
    (int) $port
);

// Check connection
if ($conn->connect_errno) {
    throw new RuntimeException(
        'Database connection failed.'
    );
}

// UTF-8 support
$conn->set_charset('utf8mb4');