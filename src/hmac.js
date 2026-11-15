"use strict";
const crypto = require("crypto");


/**
 * HMAC helpers for Agent Games.
 *
 * Platform facts (rules 1.3 + build guide):
 * - Each agent gets a 32-byte secret at registration, shown once.
 * - Incoming requests carry header `x-agent-games-signature`.
 * - Every response must be signed with the same header over the raw body.
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
  // VERIFIED 2026-11-15 against a live platform preflight (AGDBG capture):
  // the platform HMACs with the secret TEXT itself (UTF-8) as the key —
  // the 64-char hex string is NOT hex-decoded. The platform's request
  // signature matched HMAC(key = utf8 string) exactly, and its rejection
  // of our responses was because we signed with the hex-decoded bytes.
  return Buffer.from(v, "utf8");
}

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function candidateKeys(secret) {
  // Verification stays tolerant: the canonical UTF-8 string key first,
  // then the hex-decoded-bytes interpretation as a fallback.
  const keys = [secret];
  const asText = secret.toString("utf8");
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(asText)) keys.push(Buffer.from(asText.replace(/^0x/, ""), "hex"));
  return keys;
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
  for (const key of candidateKeys(secret)) {
    const hex = crypto.createHmac("sha256", key).update(rawBody).digest("hex");
    if (safeEqual(v.toLowerCase(), hex)) return true;
    const b64 = crypto.createHmac("sha256", key).update(rawBody).digest("base64");
    if (safeEqual(v, b64)) return true;
  }
  return false;
}

module.exports = { parseSecret, signBody, verifySignature };
