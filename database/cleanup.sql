
/* OTP Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_otp_codes
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM otp_codes
    WHERE expires_at < NOW()
       OR used_at IS NOT NULL;


/* Email Verification Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_email_verifications
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM email_verifications
    WHERE expires_at < NOW()
       OR verified_at IS NOT NULL;


/* Password Reset Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_password_resets
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM password_resets
    WHERE expires_at < NOW()
       OR used_at IS NOT NULL;


/* Refresh Token Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_refresh_tokens
ON SCHEDULE EVERY 15 MINUTE
DO
    DELETE FROM refresh_tokens
    WHERE expires_at < NOW()
       OR (
            revoked_at IS NOT NULL
            AND revoked_at < DATE_SUB(
                NOW(),
                INTERVAL 30 DAY
            )
       );


/* Login Attempt Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_login_attempts
ON SCHEDULE EVERY 15 MINUTE
DO
    DELETE FROM login_attempts
    WHERE created_at < DATE_SUB(
        NOW(),
        INTERVAL 30 DAY
    );


/* Audit Log Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_audit_logs
ON SCHEDULE EVERY 1 DAY
DO
    DELETE FROM audit_logs
    WHERE created_at < DATE_SUB(
        NOW(),
        INTERVAL 180 DAY
    );


/* Rate Limit Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_rate_limits
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM rate_limits
    WHERE expires_at < NOW();


/* Request Lock Cleanup */

CREATE EVENT IF NOT EXISTS cleanup_request_locks
ON SCHEDULE EVERY 5 MINUTE
DO
    DELETE FROM request_locks
    WHERE expires_at < NOW();