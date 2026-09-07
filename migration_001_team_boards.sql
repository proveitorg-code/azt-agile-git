-- Nimbus — Phase 1 migration: team-shared boards, custom workflows,
-- custom fields, issue status history (for burndown), and team branding.
--
-- Run once against your existing database:
--   psql "<connection string>" -f migration_001_team_boards.sql
--
-- Safe to re-run: every statement uses IF NOT EXISTS.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------
-- TEAM STATUSES — each team's own workflow columns (replaces the fixed
-- To Do / In Progress / Done board for team-owned issues). Seeded with a
-- sensible default set when a team is created (done in application code).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_statuses (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  key          TEXT NOT NULL,             -- stable slug, e.g. 'in_progress'
  label        TEXT NOT NULL,             -- display name, e.g. 'In Progress'
  color        TEXT NOT NULL DEFAULT '6B7280',
  sort_order   INTEGER NOT NULL DEFAULT 0,
  is_done      BOOLEAN NOT NULL DEFAULT FALSE,  -- marks "completed" for burndown math
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, key)
);

-- ---------------------------------------------------------------------
-- TEAM CUSTOM FIELDS — extra fields a team defines on their issues.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_custom_fields (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  field_key    TEXT NOT NULL,             -- stable slug, e.g. 'environment'
  label        TEXT NOT NULL,             -- display name, e.g. 'Environment'
  field_type   TEXT NOT NULL DEFAULT 'text', -- 'text' | 'number' | 'select' | 'date'
  options      JSONB,                     -- for 'select': ["Staging","Prod"]
  sort_order   INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, field_key)
);

-- ---------------------------------------------------------------------
-- TEAM ISSUES — shared board storage for teams. (Individual/guest users
-- keep using the existing encrypted user_progress blob — unchanged.)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_issues (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  key            TEXT NOT NULL,                       -- e.g. 'NIM-14'
  type           TEXT NOT NULL DEFAULT 'Task',         -- Epic/Story/Task/Sub-task/Bug
  title          TEXT NOT NULL,
  description    TEXT,
  status_id      UUID REFERENCES team_statuses(id) ON DELETE SET NULL,
  priority       TEXT NOT NULL DEFAULT 'Medium',
  assignee_id    UUID REFERENCES users(id) ON DELETE SET NULL,  -- must be a real team member
  points         INTEGER,
  parent_id      UUID REFERENCES team_issues(id) ON DELETE SET NULL,
  custom_fields  JSONB NOT NULL DEFAULT '{}'::jsonb,   -- { field_key: value }
  due_date       DATE,
  created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, key)
);

-- ---------------------------------------------------------------------
-- ISSUE STATUS HISTORY — a snapshot logged every time an issue's status
-- or points change. This is what makes a real burndown chart possible
-- (and doubles as the activity feed's data source later).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS issue_status_history (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id     UUID NOT NULL REFERENCES team_issues(id) ON DELETE CASCADE,
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  status_id    UUID REFERENCES team_statuses(id) ON DELETE SET NULL,
  points       INTEGER,                    -- the issue's points at this moment
  changed_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- TEAM BRANDING
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_branding (
  team_id      UUID PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
  accent_color TEXT NOT NULL DEFAULT '5B5FEF',
  logo_url     TEXT,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_team_statuses_team ON team_statuses(team_id);
CREATE INDEX IF NOT EXISTS idx_team_custom_fields_team ON team_custom_fields(team_id);
CREATE INDEX IF NOT EXISTS idx_team_issues_team ON team_issues(team_id);
CREATE INDEX IF NOT EXISTS idx_team_issues_status ON team_issues(status_id);
CREATE INDEX IF NOT EXISTS idx_team_issues_assignee ON team_issues(assignee_id);
CREATE INDEX IF NOT EXISTS idx_issue_history_issue ON issue_status_history(issue_id);
CREATE INDEX IF NOT EXISTS idx_issue_history_team_time ON issue_status_history(team_id, changed_at);
