USE auth;

CREATE TABLE IF NOT EXISTS otp_security (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,

    purpose ENUM(
        'login',
        'email_verification',
        'password_reset'
    ) NOT NULL,

    attempt_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
    resend_count TINYINT UNSIGNED NOT NULL DEFAULT 0,

    blocked_until DATETIME NULL,

    last_otp_sent_at DATETIME NULL,
    first_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_otp_security_email_ip_purpose (
        email,
        ip_address,
        purpose
    ),

    INDEX idx_otp_security_blocked_until (
        blocked_until
    ),

    INDEX idx_otp_security_email (
        email
    ),

    INDEX idx_otp_security_ip (
        ip_address
    ),

    INDEX idx_otp_security_purpose (
        purpose
    )
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;