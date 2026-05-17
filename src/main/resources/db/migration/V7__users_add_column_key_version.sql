-- V7__users_add_column_key_version

ALTER TABLE users ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;