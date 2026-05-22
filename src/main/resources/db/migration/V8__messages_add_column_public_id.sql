-- V8__messages_add_column_public_id

ALTER TABLE messages ADD COLUMN IF NOT EXISTS public_id UUID;

UPDATE messages SET public_id = gen_random_uuid() WHERE public_id IS NULL;

ALTER TABLE messages ALTER COLUMN public_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_user_id_public_id ON messages(user_id, public_id);