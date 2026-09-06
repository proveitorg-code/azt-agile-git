// Run once, from your own machine or a Render shell, to promote an existing
// account to admin. There is no web UI for this on purpose.
//
// Usage:
//   node create-admin.js someone@example.com
//
require("dotenv").config();
const { pool } = require("./db");

async function main() {
  const email = process.argv[2];
  if (!email) {
    console.error("Usage: node create-admin.js <email>");
    process.exit(1);
  }
  const { rows } = await pool.query(
    "UPDATE users SET is_admin = TRUE WHERE email = $1 RETURNING id, name, email",
    [email.trim().toLowerCase()]
  );
  if (!rows[0]) {
    console.error(`No user found with email ${email}. They must sign up first, then run this again.`);
    process.exit(1);
  }
  console.log(`${rows[0].email} (${rows[0].name}) is now an admin.`);
  await pool.end();
}

main();
