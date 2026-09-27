<?php

$host = 'localhost';
$port = 3306;
$database = 'auth';
$username = 'root';
$password = '';

mysqli_report(MYSQLI_REPORT_OFF);

$conn = new mysqli(
    $host,
    $username,
    $password,
    $database,
    $port
);

if ($conn->connect_errno) {

    http_response_code(500);

    header('Content-Type: application/json; charset=UTF-8');

    echo json_encode([
        'success' => false,
        'message' => 'Database connection failed.',
        'mysql_error' => $conn->connect_error,
        'mysql_errno' => $conn->connect_errno
    ]);

    exit;
}

$conn->set_charset('utf8mb4');