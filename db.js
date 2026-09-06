const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set. Copy .env.example to .env and fill it in.");
}

// Render's managed Postgres requires SSL; disable only for local dev without SSL.
const useSSL = process.env.NODE_ENV === "production" || process.env.DATABASE_URL.includes("render.com");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

module.exports = { pool };
