-- V3__rename_keycloak_sub_to_auth_id.sql

ALTER TABLE users RENAME COLUMN keycloak_sub TO auth_id;