ALTER TABLE devices
DROP CONSTRAINT IF EXISTS uq_devices_user_id_name;

CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_user_name_active
    ON devices (user_id, name)
    WHERE revoked_at IS NULL;