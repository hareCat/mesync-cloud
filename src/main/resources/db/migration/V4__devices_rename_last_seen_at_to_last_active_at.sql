-- V4__devices_rename_last_seen_at_to_last_active_at.sql

ALTER TABLE devices RENAME COLUMN last_seen_at TO last_active_at;