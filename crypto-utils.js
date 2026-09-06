const crypto = require("crypto");

const KEY_HEX = process.env.ENCRYPTION_KEY;
if (!KEY_HEX || KEY_HEX.length !== 64) {
  throw new Error("ENCRYPTION_KEY must be a 64-character hex string (32 bytes). See .env.example.");
}
const KEY = Buffer.from(KEY_HEX, "hex");

/** Encrypt a JS value (will be JSON.stringify'd) with AES-256-GCM. */
function encryptJSON(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

/** Reverse of encryptJSON — returns the original parsed JS value. */
function decryptJSON({ ciphertext, iv, authTag }) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

/** Short, human-friendly one-time link code, e.g. "K7M3-XQ2P". */
function generateLinkCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I to avoid confusion
  let out = "";
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    out += chars[bytes[i] % chars.length];
    if (i === 3) out += "-";
  }
  return out;
}

/**
 * Strong password standard:
 *  - at least 10 characters
 *  - at least one uppercase, one lowercase, one digit, one symbol
 */
function isStrongPassword(password) {
  if (typeof password !== "string" || password.length < 10) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSymbol;
}

const PASSWORD_RULES_TEXT =
  "Password must be at least 10 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.";

module.exports = { encryptJSON, decryptJSON, generateLinkCode, isStrongPassword, PASSWORD_RULES_TEXT };
