-- Run once when upgrading an existing database.
-- Each statement is conditional, so it supports either legacy users-table variant.

SET @statement = (
    SELECT IF(
        COUNT(*) > 0,
        'ALTER TABLE users CHANGE COLUMN password_hash password VARCHAR(255) NOT NULL',
        'SELECT 1'
    )
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'password_hash'
);
PREPARE migration_statement FROM @statement;
EXECUTE migration_statement;
DEALLOCATE PREPARE migration_statement;

SET @statement = (
    SELECT IF(
        COUNT(*) = 0,
        'ALTER TABLE users ADD COLUMN token_version INT UNSIGNED NOT NULL DEFAULT 1 AFTER password',
        'SELECT 1'
    )
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'token_version'
);
PREPARE migration_statement FROM @statement;
EXECUTE migration_statement;
DEALLOCATE PREPARE migration_statement;
