<?php

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

header('Content-Type: text/plain; charset=utf-8');

try {
    $mail = new PHPMailer(true);

    $mail->isSMTP();
    $mail->Host = $mailConfig['host'];
    $mail->SMTPAuth = true;
    $mail->Username = $mailConfig['username'];
    $mail->Password = $mailConfig['password'];
    $mail->Port = $mailConfig['port'];

    $mail->SMTPSecure =
        strtolower($mailConfig['encryption']) === 'ssl'
            ? PHPMailer::ENCRYPTION_SMTPS
            : PHPMailer::ENCRYPTION_STARTTLS;

    $mail->setFrom(
        $mailConfig['from_address'],
        $mailConfig['from_name']
    );

    // YAHAN APNI TEST EMAIL DALO
    $mail->addAddress('mohitttt009@gmail.com');

    $mail->isHTML(true);
    $mail->Subject = 'Secure JWT Auth - SMTP Test';
    $mail->Body = '<h2>SMTP is working!</h2><p>This is a test email.</p>';
    $mail->AltBody = 'SMTP is working! This is a test email.';

    $mail->send();

    echo "SUCCESS: Email sent successfully.";
} catch (Throwable $e) {
    http_response_code(500);

    echo "ERROR: " . $e->getMessage();
}