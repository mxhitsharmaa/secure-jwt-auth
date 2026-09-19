<?php

declare(strict_types=1);

/*
 Secure JWT Auth - Bootstrap
 Loads environment variables and application configuration.
*/

require_once __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;

// Load .env
$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

// Apply CORS policy and handle browser preflight requests before API execution.
require_once __DIR__ . '/cors.php';

// Set timezone
date_default_timezone_set('Asia/Kolkata');

// Prevent PHP from exposing unnecessary information
ini_set('expose_php', '0');

// Load configurations
$appConfig = require __DIR__ . '/app.php';
$jwtConfig = require __DIR__ . '/jwt.php';
$mailConfig = require __DIR__ . '/mail.php';
$securityConfig = require __DIR__ . '/security.php';

// Database connection
require_once __DIR__ . '/database.php';
