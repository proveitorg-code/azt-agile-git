-- Nimbus Agile Board — PostgreSQL schema
-- Run once against a fresh database: psql "$DATABASE_URL" -f schema.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;   -- case-insensitive email column, must exist before it's used below

-- ---------------------------------------------------------------------
-- USERS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT NOT NULL,
  email          CITEXT UNIQUE NOT NULL,          -- case-insensitive email
  password_hash  TEXT NOT NULL,                    -- bcrypt hash, never plaintext
  is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
  is_premium     BOOLEAN NOT NULL DEFAULT FALSE,
  is_guest       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- ENCRYPTED USER PROGRESS (their board / issues data)
-- Encrypted server-side with AES-256-GCM before it ever touches the row.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_progress (
  user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ciphertext     BYTEA NOT NULL,
  iv             BYTEA NOT NULL,
  auth_tag       BYTEA NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- ONE-TIME LINK CODES
-- A user generates a short-lived code representing "add me to your team".
-- A team owner/manager redeems it to add that user as a member.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS link_codes (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code           TEXT UNIQUE NOT NULL,             -- e.g. 8-char alphanumeric
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at     TIMESTAMPTZ NOT NULL,
  used_at        TIMESTAMPTZ,                      -- NULL until redeemed
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- TEAMS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS teams (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT NOT NULL,
  owner_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- TEAM ROLES  (custom, per-team — e.g. Owner, Manager, Member, Viewer)
-- Only the team owner (creator) may create/edit/delete these.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_roles (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,                    -- 'Manager', 'Member', ...
  can_edit       BOOLEAN NOT NULL DEFAULT FALSE,    -- can edit board issues
  can_view       BOOLEAN NOT NULL DEFAULT TRUE,     -- can view board
  can_manage_team BOOLEAN NOT NULL DEFAULT FALSE,   -- can add/remove members, edit roles
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, name)
);

-- ---------------------------------------------------------------------
-- TEAM MEMBERS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_members (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id        UUID NOT NULL REFERENCES team_roles(id) ON DELETE RESTRICT,
  joined_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, user_id)
);

-- ---------------------------------------------------------------------
-- PREMIUM UPGRADE REQUESTS (manual billing — logged when a user clicks
-- "Upgrade to Premium" and is sent to the Google Form. You mark them
-- premium yourself in the admin panel once payment is confirmed.)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS premium_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  fulfilled      BOOLEAN NOT NULL DEFAULT FALSE,
  fulfilled_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_link_codes_user ON link_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_premium_requests_user ON premium_requests(user_id);

