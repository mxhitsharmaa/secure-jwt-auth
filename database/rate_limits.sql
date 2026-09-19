CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    rate_key VARCHAR(255) NOT NULL,

    window_start DATETIME NOT NULL,

    request_count INT UNSIGNED NOT NULL DEFAULT 1,

    expires_at DATETIME NOT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_rate_key_window (
        rate_key,
        window_start
    ),

    INDEX idx_rate_limits_expiry (
        expires_at
    )

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;







  DELETE FROM rate_limits
WHERE expires_at < NOW();




SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS cleanup_rate_limits
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM rate_limits
    WHERE expires_at < NOW();