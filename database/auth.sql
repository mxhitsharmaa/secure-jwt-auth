
-- Secure JWT Authentication System
-- Database Schema

CREATE DATABASE IF NOT EXISTS secure_jwt_auth
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE secure_jwt_auth;


-- 1. USERS

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    name VARCHAR(100) NOT NULL,

    email VARCHAR(255) NOT NULL,

    password VARCHAR(255) NOT NULL,

    token_version INT UNSIGNED NOT NULL DEFAULT 1,

    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',

    status ENUM('active', 'blocked', 'suspended', 'pending')
        NOT NULL DEFAULT 'pending',

    email_verified_at DATETIME NULL,

    last_login_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_users_email (email),

    INDEX idx_users_status (status),

    INDEX idx_users_role (role),

    INDEX idx_users_created_at (created_at)

) ENGINE=InnoDB;


-- 2. EMAIL VERIFICATION TOKENS

CREATE TABLE email_verifications (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NOT NULL,

    token_hash CHAR(64) NOT NULL,

    expires_at DATETIME NOT NULL,

    verified_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_email_verification_token (token_hash),

    INDEX idx_email_verification_user (user_id),

    INDEX idx_email_verification_expiry (expires_at),

    CONSTRAINT fk_email_verification_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB;


-- 3. OTP CODES

CREATE TABLE otp_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NOT NULL,

    purpose ENUM(
        'login',
        'email_verification',
        'password_reset',
        'change_email'
    ) NOT NULL,

    otp_hash CHAR(64) NOT NULL,

    expires_at DATETIME NOT NULL,

    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,

    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 5,

    consumed_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_otp_user_purpose (user_id, purpose),

    INDEX idx_otp_expiry (expires_at),

    CONSTRAINT fk_otp_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB;


-- 4. REFRESH TOKENS / SESSIONS

CREATE TABLE refresh_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NOT NULL,

    token_hash CHAR(64) NOT NULL,

    jti CHAR(36) NOT NULL,

    family_id CHAR(36) NOT NULL,

    parent_id BIGINT UNSIGNED NULL,

    expires_at DATETIME NOT NULL,

    revoked_at DATETIME NULL,

    replaced_by_id BIGINT UNSIGNED NULL,

    reuse_detected_at DATETIME NULL,

    ip_address VARCHAR(45) NULL,

    user_agent VARCHAR(500) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_used_at DATETIME NULL,

    PRIMARY KEY (id),

    UNIQUE KEY uq_refresh_token_hash (token_hash),

    UNIQUE KEY uq_refresh_jti (jti),

    INDEX idx_refresh_user (user_id),

    INDEX idx_refresh_family (family_id),

    INDEX idx_refresh_expiry (expires_at),

    INDEX idx_refresh_revoked (revoked_at),

    CONSTRAINT fk_refresh_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_refresh_parent
        FOREIGN KEY (parent_id)
        REFERENCES refresh_tokens(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_refresh_replaced_by
        FOREIGN KEY (replaced_by_id)
        REFERENCES refresh_tokens(id)
        ON DELETE SET NULL

) ENGINE=InnoDB;


-- 5. LOGIN ATTEMPTS

CREATE TABLE login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    email VARCHAR(255) NULL,

    ip_address VARCHAR(45) NOT NULL,

    user_id BIGINT UNSIGNED NULL,

    success TINYINT(1) NOT NULL DEFAULT 0,

    reason VARCHAR(100) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_login_email (email),

    INDEX idx_login_ip (ip_address),

    INDEX idx_login_user (user_id),

    INDEX idx_login_created (created_at),

    CONSTRAINT fk_login_attempt_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL

) ENGINE=InnoDB;


-- 6. PASSWORD RESET TOKENS

CREATE TABLE password_resets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NOT NULL,

    token_hash CHAR(64) NOT NULL,

    expires_at DATETIME NOT NULL,

    used_at DATETIME NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_password_reset_token (token_hash),

    INDEX idx_password_reset_user (user_id),

    INDEX idx_password_reset_expiry (expires_at),

    CONSTRAINT fk_password_reset_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB;


-- 7. AUDIT LOGS

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id BIGINT UNSIGNED NULL,

    event VARCHAR(100) NOT NULL,

    ip_address VARCHAR(45) NULL,

    user_agent VARCHAR(500) NULL,

    metadata JSON NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_audit_user (user_id),

    INDEX idx_audit_event (event),

    INDEX idx_audit_created (created_at),

    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL

) ENGINE=InnoDB;
USE auth;

ALTER TABLE otp_security
MODIFY COLUMN purpose ENUM(
    'login_password',
    'login_otp',
    'email_verification',
    'password_reset'
) NOT NULL;