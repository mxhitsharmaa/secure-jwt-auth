CREATE TABLE IF NOT EXISTS request_locks (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    lock_key VARCHAR(255) NOT NULL,

    expires_at DATETIME NOT NULL,

    created_at DATETIME NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_request_lock_key (
        lock_key
    ),

    INDEX idx_request_locks_expiry (
        expires_at
    )

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


/* Cleanup Expired Locks */

DELETE FROM request_locks
WHERE expires_at < NOW();


/* Automatic Cleanup */

SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS cleanup_request_locks
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM request_locks
    WHERE expires_at < NOW();



-- iska kaam
Request
   ↓
Acquire Lock
   ↓
lock_key unique
   ↓
10 sec expiry
   ↓
Duplicate request → 429
   ↓
Lock expires
   ↓
Cleanup event removes it