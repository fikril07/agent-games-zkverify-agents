"use strict";
const crypto = require("crypto");

/**
 * HMAC helpers for Agent Games.
 *
 * Platform facts (rules 1.3 + build guide):
 * - Each agent gets a 32-byte secret at registration, shown once.
 * - Incoming requests carry header `x-agent-games-signature`.
 * - Every response must be signed with the same header over the raw body.
 *
 * SPEC-PENDING uncertainties (kept tolerant on verify, explicit on sign):
 * - Secret presentation format at registration (hex vs base64) — parseSecret
 *   accepts hex (with/without 0x), base64, or raw utf8.
 * - Signature encoding — verify accepts hex or base64, with an optional
 *   "sha256=" prefix. We SIGN with lowercase hex HMAC-SHA256 of the raw body,
 *   which is the format the build guide's examples imply.
 */

function parseSecret(value) {
  if (!value) return null;
  const v = String(value).trim();
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v.replace(/^0x/, ""), "hex");
  // base64 for exactly 32 bytes
  if (/^[A-Za-z0-9+/=]{43,44}$/.test(v)) {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  }
  return Buffer.from(v, "utf8");
}

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7).trim();
  const hex = signBody(secret, rawBody);
  if (safeEqual(v.toLowerCase(), hex)) return true;
  const b64 = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");
  if (safeEqual(v, b64)) return true;
  return false;
}

module.exports = { parseSecret, signBody, verifySignature };
