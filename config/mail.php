<?php

declare(strict_types=1);

$mailConfig = [
    /*
     SMTP Host
    */
    'host' => $_ENV['SMTP_HOST'] ?? $_ENV['MAIL_HOST'] ?? '',

    /*
     SMTP Port
    */
    'port' => (int) ($_ENV['SMTP_PORT'] ?? $_ENV['MAIL_PORT'] ?? 587),

    /*
     SMTP Username
    */
    'username' => $_ENV['SMTP_USERNAME'] ?? $_ENV['MAIL_USERNAME'] ?? '',

    /*
     SMTP Password
    */
    'password' => $_ENV['SMTP_PASSWORD'] ?? $_ENV['MAIL_PASSWORD'] ?? '',

    /*
     SMTP Encryption
    */
    'encryption' => $_ENV['SMTP_ENCRYPTION'] ?? $_ENV['MAIL_ENCRYPTION'] ?? 'tls',

    /*
     Sender
    */
    'from_address' => $_ENV['MAIL_FROM_ADDRESS'] ?? $_ENV['SMTP_USERNAME'] ?? $_ENV['MAIL_USERNAME'] ?? '',
    'from_name' => $_ENV['MAIL_FROM_NAME'] ?? 'Secure JWT Auth',
];

return $mailConfig;
