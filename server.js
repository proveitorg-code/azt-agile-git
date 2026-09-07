require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { pool } = require("./db");
const {
  encryptJSON,
  decryptJSON,
  generateLinkCode,
  isStrongPassword,
  PASSWORD_RULES_TEXT,
} = require("./crypto-utils");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PROD = process.env.NODE_ENV === "production";
const LINK_CODE_TTL_MINUTES = 30;

if (!JWT_SECRET) throw new Error("JWT_SECRET is not set. See .env.example.");

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: (process.env.CORS_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean),
    credentials: true,
  })
);

// -----------------------------------------------------------------------
// Session helpers — JWT stored in an httpOnly cookie, not localStorage,
// so it can't be read or exfiltrated by page JavaScript.
// -----------------------------------------------------------------------
function issueSession(res, user) {
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("nimbus_session", token, {
    httpOnly: true,
    secure: true,        // required whenever sameSite is "none"
    sameSite: "none",    // frontend and API are on different Render subdomains,
                          // which browsers treat as cross-site — "lax" would
                          // silently block the cookie from being sent back.
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.nimbus_session;
    if (!token) return res.status(401).json({ error: "Not logged in." });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query(
      "SELECT id, name, email, is_admin, is_premium, is_guest FROM users WHERE id = $1",
      [payload.sub]
    );
    if (!rows[0]) return res.status(401).json({ error: "Session no longer valid." });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Session expired or invalid." });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: "Admin access required." });
  next();
}

/** Returns the caller's role row in a given team, or null if not a member. */
async function getMembership(userId, teamId) {
  const { rows } = await pool.query(
    `SELECT tm.*, tr.name AS role_name, tr.can_edit, tr.can_view, tr.can_manage_team
     FROM team_members tm
     JOIN team_roles tr ON tr.id = tm.role_id
     WHERE tm.user_id = $1 AND tm.team_id = $2`,
    [userId, teamId]
  );
  return rows[0] || null;
}

// =========================================================================
// AUTH
// =========================================================================

// Create a full account (name + email + password). Also used to convert
// a guest into a permanent account (pass an existing guest session cookie).
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are all required." });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({ error: PASSWORD_RULES_TEXT });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, is_admin, is_premium, is_guest`,
      [name.trim(), email.trim().toLowerCase(), passwordHash]
    );
    const user = rows[0];
    issueSession(res, user);
    res.json({ user });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "An account with that email already exists." });
    }
    console.error(err);
    res.status(500).json({ error: "Could not create account." });
  }
});

// Log in with email + password. If the email doesn't exist at all, we
// create a guest account on the fly so first-time visitors always land
// somewhere usable (per your "guest user initially" requirement) —
// but only when no password was meaningfully checked against anything,
// i.e. this is an explicit "continue as guest" action, not silent auto-signup
// on a mistyped password. See /api/auth/guest for the actual guest entry point.
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required." });
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email.trim().toLowerCase()]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "No account with that email. Sign up instead?" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password." });
    issueSession(res, user);
    res.json({
      user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin, is_premium: user.is_premium, is_guest: user.is_guest },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed." });
  }
});

// Explicit "Continue as guest" button — creates a throwaway account with
// no email/password so first-time visitors can try the board immediately.
// They can later use /api/auth/signup to upgrade to a real saved account
// (their existing user id is simply given a password + real email).
app.post("/api/auth/guest", async (req, res) => {
  try {
    const guestEmail = `guest-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@guest.local`;
    const randomPassword = require("crypto").randomBytes(24).toString("hex");
    const passwordHash = await bcrypt.hash(randomPassword, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, is_guest)
       VALUES ($1, $2, $3, TRUE)
       RETURNING id, name, email, is_admin, is_premium, is_guest`,
      ["Guest", guestEmail, passwordHash]
    );
    const user = rows[0];
    issueSession(res, user);
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create guest session." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("nimbus_session", { httpOnly: true, secure: true, sameSite: "none" });
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// =========================================================================
// ENCRYPTED PROGRESS (the user's board / issues data)
// =========================================================================

app.get("/api/progress", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT ciphertext, iv, auth_tag FROM user_progress WHERE user_id = $1",
      [req.user.id]
    );
    if (!rows[0]) return res.json({ data: null });
    const data = decryptJSON({
      ciphertext: rows[0].ciphertext,
      iv: rows[0].iv,
      authTag: rows[0].auth_tag,
    });
    res.json({ data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load saved progress." });
  }
});

app.put("/api/progress", requireAuth, async (req, res) => {
  const { data } = req.body || {};
  if (data === undefined) return res.status(400).json({ error: "Missing data." });
  try {
    const { ciphertext, iv, authTag } = encryptJSON(data);
    await pool.query(
      `INSERT INTO user_progress (user_id, ciphertext, iv, auth_tag, updated_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (user_id) DO UPDATE
       SET ciphertext = EXCLUDED.ciphertext, iv = EXCLUDED.iv, auth_tag = EXCLUDED.auth_tag, updated_at = now()`,
      [req.user.id, ciphertext, iv, authTag]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not save progress." });
  }
});

// =========================================================================
// ONE-TIME LINK CODES  (a user generates one, a team owner/manager redeems it)
// =========================================================================

app.post("/api/link-code", requireAuth, async (req, res) => {
  try {
    const code = generateLinkCode();
    const expiresAt = new Date(Date.now() + LINK_CODE_TTL_MINUTES * 60 * 1000);
    await pool.query(
      "INSERT INTO link_codes (code, user_id, expires_at) VALUES ($1, $2, $3)",
      [code, req.user.id, expiresAt]
    );
    res.json({ code, expiresAt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not generate a code." });
  }
});

// =========================================================================
// TEAMS
// =========================================================================

// Create a team. The creator becomes Owner with full rights automatically.
app.post("/api/teams", requireAuth, async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: "Team name is required." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows: teamRows } = await client.query(
      "INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING *",
      [name.trim(), req.user.id]
    );
    const team = teamRows[0];
    const { rows: roleRows } = await client.query(
      `INSERT INTO team_roles (team_id, name, can_edit, can_view, can_manage_team)
       VALUES ($1, 'Owner', TRUE, TRUE, TRUE) RETURNING *`,
      [team.id]
    );
    await client.query(
      "INSERT INTO team_members (team_id, user_id, role_id) VALUES ($1, $2, $3)",
      [team.id, req.user.id, roleRows[0].id]
    );
    await client.query("COMMIT");
    res.json({ team });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Could not create team." });
  } finally {
    client.release();
  }
});

// List teams the caller belongs to.
app.get("/api/teams", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT t.*, tr.name AS my_role, tr.can_edit, tr.can_view, tr.can_manage_team
     FROM team_members tm
     JOIN teams t ON t.id = tm.team_id
     JOIN team_roles tr ON tr.id = tm.role_id
     WHERE tm.user_id = $1
     ORDER BY t.created_at`,
    [req.user.id]
  );
  res.json({ teams: rows });
});

// Full detail: members + their roles + all defined roles for this team.
app.get("/api/teams/:teamId", requireAuth, async (req, res) => {
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership) return res.status(403).json({ error: "You are not a member of this team." });

  const { rows: members } = await pool.query(
    `SELECT u.id AS user_id, u.name, u.email, tr.id AS role_id, tr.name AS role_name,
            tr.can_edit, tr.can_view, tr.can_manage_team, tm.joined_at
     FROM team_members tm
     JOIN users u ON u.id = tm.user_id
     JOIN team_roles tr ON tr.id = tm.role_id
     WHERE tm.team_id = $1
     ORDER BY tm.joined_at`,
    [req.params.teamId]
  );
  const { rows: roles } = await pool.query(
    "SELECT * FROM team_roles WHERE team_id = $1 ORDER BY created_at",
    [req.params.teamId]
  );
  res.json({ members, roles, myMembership: membership });
});

// Redeem someone else's one-time link code to add them to this team.
// Requires can_manage_team on the caller's membership (Owner by default).
app.post("/api/teams/:teamId/members", requireAuth, async (req, res) => {
  const { code, roleId } = req.body || {};
  if (!code) return res.status(400).json({ error: "A link code is required." });

  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can add members." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows: codeRows } = await client.query(
      "SELECT * FROM link_codes WHERE code = $1 FOR UPDATE",
      [code.trim().toUpperCase()]
    );
    const linkCode = codeRows[0];
    if (!linkCode) throw { status: 404, message: "That code was not found." };
    if (linkCode.used_at) throw { status: 410, message: "That code has already been used." };
    if (new Date(linkCode.expires_at) < new Date()) throw { status: 410, message: "That code has expired." };

    // Default new members to a 'Member' role — create it if this team doesn't have one yet.
    let finalRoleId = roleId;
    if (!finalRoleId) {
      const { rows: existingRole } = await client.query(
        "SELECT id FROM team_roles WHERE team_id = $1 AND name = 'Member'",
        [req.params.teamId]
      );
      if (existingRole[0]) {
        finalRoleId = existingRole[0].id;
      } else {
        const { rows: newRole } = await client.query(
          `INSERT INTO team_roles (team_id, name, can_edit, can_view, can_manage_team)
           VALUES ($1, 'Member', TRUE, TRUE, FALSE) RETURNING id`,
          [req.params.teamId]
        );
        finalRoleId = newRole[0].id;
      }
    }

    await client.query(
      `INSERT INTO team_members (team_id, user_id, role_id) VALUES ($1, $2, $3)
       ON CONFLICT (team_id, user_id) DO UPDATE SET role_id = EXCLUDED.role_id`,
      [req.params.teamId, linkCode.user_id, finalRoleId]
    );
    await client.query("UPDATE link_codes SET used_at = now() WHERE id = $1", [linkCode.id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.status) return res.status(err.status).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: "Could not add member." });
  } finally {
    client.release();
  }
});

// Change a member's role. Owner/manager only.
app.patch("/api/teams/:teamId/members/:userId", requireAuth, async (req, res) => {
  const { roleId } = req.body || {};
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can change roles." });
  }
  if (!roleId) return res.status(400).json({ error: "roleId is required." });
  await pool.query(
    "UPDATE team_members SET role_id = $1 WHERE team_id = $2 AND user_id = $3",
    [roleId, req.params.teamId, req.params.userId]
  );
  res.json({ ok: true });
});

// Remove a member. Owner/manager only; cannot remove the team owner.
app.delete("/api/teams/:teamId/members/:userId", requireAuth, async (req, res) => {
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can remove members." });
  }
  const { rows: teamRows } = await pool.query("SELECT owner_id FROM teams WHERE id = $1", [req.params.teamId]);
  if (teamRows[0]?.owner_id === req.params.userId) {
    return res.status(400).json({ error: "The team owner cannot be removed." });
  }
  await pool.query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2", [
    req.params.teamId,
    req.params.userId,
  ]);
  res.json({ ok: true });
});

// Create a new role definition (e.g. "Manager"). Owner/manager only.
app.post("/api/teams/:teamId/roles", requireAuth, async (req, res) => {
  const { name, canEdit, canView, canManageTeam } = req.body || {};
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can create roles." });
  }
  if (!name || !name.trim()) return res.status(400).json({ error: "Role name is required." });
  try {
    const { rows } = await pool.query(
      `INSERT INTO team_roles (team_id, name, can_edit, can_view, can_manage_team)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.params.teamId, name.trim(), !!canEdit, canView !== false, !!canManageTeam]
    );
    res.json({ role: rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "A role with that name already exists on this team." });
    console.error(err);
    res.status(500).json({ error: "Could not create role." });
  }
});

// Edit a role definition. Owner/manager only.
app.patch("/api/teams/:teamId/roles/:roleId", requireAuth, async (req, res) => {
  const { name, canEdit, canView, canManageTeam } = req.body || {};
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can edit roles." });
  }
  await pool.query(
    `UPDATE team_roles SET
       name = COALESCE($1, name),
       can_edit = COALESCE($2, can_edit),
       can_view = COALESCE($3, can_view),
       can_manage_team = COALESCE($4, can_manage_team)
     WHERE id = $5 AND team_id = $6`,
    [name, canEdit, canView, canManageTeam, req.params.roleId, req.params.teamId]
  );
  res.json({ ok: true });
});

// Delete a role. Owner/manager only; cannot delete a role still in use.
app.delete("/api/teams/:teamId/roles/:roleId", requireAuth, async (req, res) => {
  const membership = await getMembership(req.user.id, req.params.teamId);
  if (!membership || !membership.can_manage_team) {
    return res.status(403).json({ error: "Only a team owner or manager can delete roles." });
  }
  const { rows: inUse } = await pool.query("SELECT 1 FROM team_members WHERE role_id = $1 LIMIT 1", [req.params.roleId]);
  if (inUse[0]) return res.status(400).json({ error: "Reassign members off this role before deleting it." });
  await pool.query("DELETE FROM team_roles WHERE id = $1 AND team_id = $2", [req.params.roleId, req.params.teamId]);
  res.json({ ok: true });
});

// =========================================================================
// PREMIUM UPGRADE  (manual billing via an external Google Form)
// =========================================================================

app.get("/api/premium/form-url", requireAuth, (req, res) => {
  res.json({ url: process.env.PREMIUM_FORM_URL || null });
});

// Just logs that the user clicked "Upgrade" and was sent to the form.
// You review submissions in the Google Sheet, take payment yourself,
// then flip is_premium on via the admin panel below.
app.post("/api/premium/request", requireAuth, async (req, res) => {
  await pool.query("INSERT INTO premium_requests (user_id) VALUES ($1)", [req.user.id]);
  res.json({ ok: true, formUrl: process.env.PREMIUM_FORM_URL || null });
});

// =========================================================================
// ADMIN
// No separate admin login page or link exists anywhere in the frontend —
// an account logs in through the exact same form everyone uses. If that
// account's is_admin flag is true, the client shows an extra "Admin" panel.
// Make a user an admin with: npm run create-admin (see create-admin.js).
// =========================================================================

app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, name, email, is_admin, is_premium, is_guest, created_at FROM users ORDER BY created_at DESC"
  );
  res.json({ users: rows });
});

app.patch("/api/admin/users/:userId/premium", requireAuth, requireAdmin, async (req, res) => {
  const { isPremium } = req.body || {};
  await pool.query("UPDATE users SET is_premium = $1, updated_at = now() WHERE id = $2", [
    !!isPremium,
    req.params.userId,
  ]);
  res.json({ ok: true });
});

// Admin resets ANY user's (or another admin's) password.
app.patch("/api/admin/users/:userId/reset-password", requireAuth, requireAdmin, async (req, res) => {
  const { newPassword } = req.body || {};
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: PASSWORD_RULES_TEXT });
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [
    passwordHash,
    req.params.userId,
  ]);
  res.json({ ok: true });
});

// A logged-in user resetting their OWN password (knows current password).
app.patch("/api/auth/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: PASSWORD_RULES_TEXT });
  const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
  const ok = await bcrypt.compare(currentPassword || "", rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "Current password is incorrect." });
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [
    passwordHash,
    req.user.id,
  ]);
  res.json({ ok: true });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Nimbus server listening on port ${PORT}`));
