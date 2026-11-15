"use strict";
const { parseSecret, signBody, verifySignature } = require("./hmac");
const { IdempotencyStore } = require("./idempotency");
const { decide } = require("./steal");
const { handleDuel, holdResponse } = require("./duel");
const { judge, judgeDecision } = require("./gatekeeper");

/**
 * Transport-agnostic request processor shared by the Express server and the
 * Vercel function adapters.
 *
 *   processRequest(kind, rawBody, signatureHeader, env)
 *     kind: "steal" | "gatekeeper"
 *     -> { status, body: string, signature: string|null }
 *
 * Pipeline (SPEC.md): verify x-agent-games-signature over the RAW body BEFORE
 * parsing -> 401 on failure. Preflight ({"challenge":"preflight"} or
 * {"type":"preflight"}) is the one documented exception: it is answered
 * {"ok":true} even if the signature check fails, because its purpose is to
 * prove OUR response signing — but it is still always signed.
 * Every response is signed over its raw body with the agent's secret.
 * Responses contain ONLY the fields the spec allows.
 */

const stores = { steal: new IdempotencyStore(), gatekeeper: new IdempotencyStore() };

function secretFor(kind, env) {
  const raw = kind === "steal" ? env.STEAL_SECRET : env.GATEKEEPER_SECRET;
  return parseSecret(raw);
}

function isPreflight(json) {
  return (
    json &&
    (json.challenge === "preflight" ||
      json.type === "preflight" ||
      json.type === "agent-games.preflight.v1")
  );
}

function preflightResponse(json) {
  // Live dashboard save-check (2026-11-15) rejects any preflight response
  // that is not "signed protocol-v1 JSON", for every preflight shape it
  // sends — so protocolVersion is always included.
  return { ok: true, protocolVersion: "v1" };
}

async function processRequest(kind, rawBody, signatureHeader, env = process.env) {
  const secret = secretFor(kind, env);
  if (!secret) return { status: 503, body: JSON.stringify({ error: `${kind} agent not configured` }), signature: null };

  const respond = (status, obj) => {
    const body = JSON.stringify(obj);
    return { status, body, signature: signBody(secret, Buffer.from(body)) };
  };

  let json = null;
  try { json = JSON.parse(rawBody.toString("utf8")); } catch { /* handled below */ }

  const sigOk = verifySignature(secret, rawBody, signatureHeader);
  if (!sigOk) {
    if (json && isPreflight(json)) return respond(200, preflightResponse(json));
    return respond(401, { error: "invalid signature" });
  }
  if (!json || typeof json !== "object") return respond(400, { error: "invalid json" });
  if (isPreflight(json)) return respond(200, preflightResponse(json));

  if (kind === "steal") {
    // Two documented protocol generations, routed by envelope shape:
    // grid (SPEC.md: board/tokens/player_id) vs balance-duel (/build:
    // matchId + state). 
    const isDuel = !!(json.state && json.matchId);
    const key = isDuel
      ? `steal-duel:${json.matchId}:${json.turn}`
      : json.game_id != null && json.turn != null
        ? `steal:${json.game_id}:${json.turn}`
        : null;
    const produce = async () => {
      try {
        return {
          body: Buffer.from(JSON.stringify(isDuel ? await handleDuel(json) : decide(json))),
          contentType: "application/json",
        };
      } catch {
        // Never answer a delivery with a 500: fall back to the safest
        // legal action for the envelope shape (HOLD duel / WAIT grid).
        const fallback = isDuel ? holdResponse(json) : { action: "WAIT" };
        return { body: Buffer.from(JSON.stringify(fallback)), contentType: "application/json" };
      }
    };
    const out = key ? await stores.steal.run(key, produce) : await produce();
    const body = out.body.toString();
    return { status: 200, body, signature: signBody(secret, out.body) };
  }

  // gatekeeper — verdict protocol (SPEC.md: proof_url) vs decision protocol
  // (/build: type agent-games.proof-gatekeeper.v1 with an `input` object).
  const isDecision = !json.proof_url && (json.type === "agent-games.proof-gatekeeper.v1" || !!json.input);
  const key = json.task_id ? `gatekeeper:${json.task_id}` : null;
  const produce = async () => {
    if (isDecision) {
      const out = await judgeDecision(json);
      return { body: Buffer.from(JSON.stringify(out)), contentType: "application/json" };
    }
    const timeoutSec = Math.min(Math.max(Number(json.timeout_seconds) || 60, 5), 300);
    const budgetMs = Math.min(timeoutSec * 1000 * 0.8, 50000); // answer well inside the deadline
    let verdict;
    try {
      verdict = await Promise.race([
        judge(json),
        new Promise((_, reject) => setTimeout(() => reject(new Error("internal deadline")), budgetMs)),
      ]);
    } catch {
      verdict = {
        verdict: "unverifiable",
        confidence: 0.4,
        reason: "verification could not be completed inside the task deadline; answering unverifiable rather than guessing.",
        evidence: [],
      };
    }
    return { body: Buffer.from(JSON.stringify(verdict)), contentType: "application/json" };
  };
  const out = key ? await stores.gatekeeper.run(key, produce) : await produce();
  const body = out.body.toString();
  return { status: 200, body, signature: signBody(secret, out.body) };
}

module.exports = { processRequest };
