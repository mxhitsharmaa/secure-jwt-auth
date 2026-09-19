<?php

require_once __DIR__ . '/../../config/bootstrap.php';

use PHPMailer\PHPMailer\PHPMailer;

/* Send OTP Email */

function sendOtpEmail(
    string $email,
    string $name,
    string $otp,
    string $purpose = 'email_verification'
): void {

    global $mailConfig;
    global $securityConfig;

    /* Mail Configuration */

    if (
        $mailConfig['host'] === '' ||
        $mailConfig['username'] === '' ||
        $mailConfig['password'] === '' ||
        $mailConfig['from_address'] === ''
    ) {
        throw new RuntimeException(
            'Mail configuration is incomplete.'
        );
    }

    /* Purpose */

    $isPasswordReset =
        $purpose === 'password_reset';

    $safeName =
        htmlspecialchars(
            $name,
            ENT_QUOTES,
            'UTF-8'
        );

    $safeOtp =
        htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        );

    $expiryMinutes =
        max(
            1,
            (int) ceil(
                (int) $securityConfig['otp']['expiry']
                / 60
            )
        );

    /* Mail */

    $mail =
        new PHPMailer(true);

    $mail->isSMTP();

    $mail->Host =
        $mailConfig['host'];

    $mail->SMTPAuth =
        true;

    $mail->Username =
        $mailConfig['username'];

    $mail->Password =
        $mailConfig['password'];

    $mail->Port =
        (int) $mailConfig['port'];

    $mail->CharSet =
        'UTF-8';

    $mail->SMTPSecure =
        strtolower(
            $mailConfig['encryption']
        ) === 'ssl'
            ? PHPMailer::ENCRYPTION_SMTPS
            : PHPMailer::ENCRYPTION_STARTTLS;

    /* Sender */

    $mail->setFrom(
        $mailConfig['from_address'],
        $mailConfig['from_name']
    );

    $mail->addAddress(
        $email,
        $name
    );

    /* Content */

    $mail->isHTML(true);

    $mail->Subject =
        $isPasswordReset
            ? 'Password Reset Code'
            : 'Email Verification Code';

    $action =
        $isPasswordReset
            ? 'password reset'
            : 'email verification';

    /* Professional Email */

    $mail->Body = '
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>' . $mail->Subject . '</title>

</head>

<body
    style="
        margin:0;
        padding:0;
        background:#f4f6f8;
        font-family:Arial,Helvetica,sans-serif;
        color:#1f2937;
    "
>

    <table
        width="100%"
        cellpadding="0"
        cellspacing="0"
        border="0"
        style="
            background:#f4f6f8;
            padding:40px 15px;
        "
    >

        <tr>

            <td align="center">

                <table
                    width="100%"
                    cellpadding="0"
                    cellspacing="0"
                    border="0"
                    style="
                        max-width:560px;
                        background:#ffffff;
                        border-radius:12px;
                        overflow:hidden;
                        border:1px solid #e5e7eb;
                    "
                >

                    <!-- Header -->

                    <tr>

                        <td
                            align="center"
                            style="
                                background:#111827;
                                padding:28px 20px;
                            "
                        >

                            <div
                                style="
                                    font-size:24px;
                                    font-weight:bold;
                                    color:#ffffff;
                                    letter-spacing:0.5px;
                                "
                            >
                                Secure Account
                            </div>

                            <div
                                style="
                                    margin-top:7px;
                                    font-size:13px;
                                    color:#cbd5e1;
                                "
                            >
                                Account Security & Verification
                            </div>

                        </td>

                    </tr>

                    <!-- Content -->

                    <tr>

                        <td
                            style="
                                padding:35px;
                            "
                        >

                            <p
                                style="
                                    margin:0 0 18px;
                                    font-size:16px;
                                    line-height:1.6;
                                    color:#111827;
                                "
                            >
                                Hello
                                <strong>' . $safeName . '</strong>,
                            </p>

                            <p
                                style="
                                    margin:0 0 24px;
                                    font-size:15px;
                                    line-height:1.7;
                                    color:#4b5563;
                                "
                            >
                                We received a request for
                                <strong>' . $action . '</strong>
                                on your account.
                                Please use the verification code below
                                to continue.
                            </p>

                            <!-- OTP Box -->

                            <table
                                width="100%"
                                cellpadding="0"
                                cellspacing="0"
                                border="0"
                            >

                                <tr>

                                    <td
                                        align="center"
                                        style="
                                            background:#f3f4f6;
                                            border:1px solid #e5e7eb;
                                            border-radius:10px;
                                            padding:22px 15px;
                                        "
                                    >

                                        <div
                                            style="
                                                font-size:12px;
                                                font-weight:bold;
                                                color:#6b7280;
                                                text-transform:uppercase;
                                                letter-spacing:1.5px;
                                                margin-bottom:10px;
                                            "
                                        >
                                            Your Verification Code
                                        </div>

                                        <div
                                            style="
                                                font-size:32px;
                                                font-weight:bold;
                                                letter-spacing:8px;
                                                color:#111827;
                                            "
                                        >
                                            ' . $safeOtp . '
                                        </div>

                                    </td>

                                </tr>

                            </table>

                            <!-- Expiry -->

                            <p
                                style="
                                    margin:24px 0 0;
                                    text-align:center;
                                    font-size:13px;
                                    color:#6b7280;
                                    line-height:1.6;
                                "
                            >
                                This code will expire in
                                <strong>
                                    ' . $expiryMinutes . ' minutes
                                </strong>.
                            </p>

                            <!-- Security Notice -->

                            <table
                                width="100%"
                                cellpadding="0"
                                cellspacing="0"
                                border="0"
                                style="
                                    margin-top:28px;
                                "
                            >

                                <tr>

                                    <td
                                        style="
                                            background:#fff7ed;
                                            border-left:4px solid #f59e0b;
                                            padding:14px 16px;
                                            border-radius:5px;
                                        "
                                    >

                                        <div
                                            style="
                                                font-size:13px;
                                                line-height:1.6;
                                                color:#92400e;
                                            "
                                        >

                                            <strong>
                                                Security Notice
                                            </strong>

                                            <br>

                                            Never share this verification
                                            code with anyone.
                                            Our team will never ask you
                                            for your OTP.

                                        </div>

                                    </td>

                                </tr>

                            </table>

                            <p
                                style="
                                    margin:28px 0 0;
                                    font-size:14px;
                                    line-height:1.7;
                                    color:#6b7280;
                                "
                            >
                                If you did not request this code,
                                you can safely ignore this email.
                                No changes will be made to your account.
                            </p>

                            <p
                                style="
                                    margin:25px 0 0;
                                    font-size:14px;
                                    color:#374151;
                                "
                            >
                                Regards,<br>
                                <strong>Security Team</strong>
                            </p>

                        </td>

                    </tr>

                    <!-- Footer -->

                    <tr>

                        <td
                            align="center"
                            style="
                                background:#f9fafb;
                                border-top:1px solid #e5e7eb;
                                padding:20px;
                            "
                        >

                            <div
                                style="
                                    font-size:12px;
                                    color:#9ca3af;
                                    line-height:1.6;
                                "
                            >
                                This is an automated security email.
                                Please do not reply to this message.
                            </div>

                            <div
                                style="
                                    margin-top:8px;
                                    font-size:11px;
                                    color:#d1d5db;
                                "
                            >
                                &copy; ' . date('Y') . '
                                Secure Account System
                            </div>

                        </td>

                    </tr>

                </table>

            </td>

        </tr>

    </table>

</body>

</html>
';

    /* Plain Text Version */

    $mail->AltBody =
        'Hello ' . $name . ",\n\n" .
        'We received a request for ' .
        $action .
        ".\n\n" .
        'Your verification code is: ' .
        $otp .
        "\n\n" .
        'This code will expire in ' .
        $expiryMinutes .
        " minutes.\n\n" .
        'Security notice: Never share this verification code with anyone. ' .
        'Our team will never ask you for your OTP.' .
        "\n\n" .
        'If you did not request this code, you can safely ignore this email.' .
        "\n\n" .
        'Regards,' .
        "\nSecurity Team";

    /* Send */

    $mail->send();
}