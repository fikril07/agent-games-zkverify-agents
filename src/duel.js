"use strict";
const { keccak256 } = require("js-sha3");
const { prove } = require("./prover");

/**
 * Steal the VFY — BALANCE-DUEL protocol, as specified on /build (the starter
 * prompt there says /build is the source of truth; SPEC.md's grid protocol is
 * the other documented generation and is handled in steal.js — core.js picks
 * the mode from the envelope shape).
 *
 * Envelope: { protocolVersion:"v1", eventId:"steal-the-vfy", mode, matchId,
 *   turn, issuedAt, deadlineAt,
 *   state: { selfBalance:"95", opponentBalance:"105",
 *            selfFortifiedUntilTurn:null, opponentFortifiedUntilTurn:null },
 *   strategyCommitment: { hash:"0x..." }, resolverVersion:"v1", nonce }
 *
 * Actions: HOLD (no transfer), FORTIFY (costs 2 VFY, blocks up to 6 VFY of
 * incoming extraction this turn), EXTRACT N (steal up to N, max 10, from the
 * opponent's spendable balance; a fortified opponent reduces the gain by 6).
 * Match: 20 turns, start balance 100 VFY, highest balance wins.
 *
 * Response: { matchId, turn, action:{type, amount?}, policyProof:
 *   { circuitVersion:"v1", proof, public_signals, publicInputsHash },
 *   agentTimestamp, idempotencyKey }
 * action.amount is present ONLY for EXTRACT (schema rejects it otherwise).
 * Per /build ("What you return" + "Common mistakes" #1), policyProof MUST
 * carry the Groth16 proof and public_signals INSIDE it — a hash-only
 * policyProof fails the practice schema validation ("Agent response did
 * not match the VFY protocol schema", live 2026-11-16) and scores the turn
 * as HOLD with no proof in real rounds. publicInputsHash is an optional
 * audit pointer: keccak256 of the 8 ABI-packed 32-byte big-endian fields,
 * in order: [commitment, matchId (UUID as hex), turn, selfBalance,
 * opponentBalance, actionCode (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount
 * (0 for HOLD/FORTIFY), circuitVersion (1)] — verbatim from /build.
 *
 * ROUND-04 BUG (diagnosed 2026-11-17, tools/diag-live-proof.js): the hash
 * MUST be packed from the SAME public inputs the proof attests — above
 * all the commitment field must be the circuit commitment the proof
 * binds (OWN_COMMITMENT, public_signals[1]). Packing the envelope's
 * strategyCommitment.hash instead made the response hash diverge from
 * the proof at exactly public_signals[1] in every LIVE turn (practice
 * envelopes carry no strategyCommitment, so the fallback kept practice
 * consistent — practice passed, all 20 live turns were rejected with
 * "public_signal[1] does not match the task"). The envelope value is the
 * dashboard-registered reference (currently 0x4ebbcd65...ded6, the SHA256
 * publicInputsHash of the genesis proof) — a different number from the
 * Poseidon circuit commitment (0x23d944d5...e9a4); it must never be
 * packed into the per-turn hash.
 */

const { createHash } = require("crypto");

/** The response schema validates idempotencyKey as a UUID (the /build
 *  example shows a UUID-shaped key). A raw "matchId:turn" string is
 *  rejected as a mis-typed field, so derive a deterministic UUID from
 *  the turn identity instead: same turn -> same key (true idempotency),
 *  unique per turn. */
function turnKey(matchId, turn) {
  const h = createHash("sha256").update(`${matchId}:${turn}`).digest("hex");
  const variant = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
const EXTRACT_MAX = 10;
const FORTIFY_BLOCK = 6;

function be32(n) {
  let v = BigInt(n);
  const buf = Buffer.alloc(32);
  for (let i = 31; i >= 0 && v > 0n; i--) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

// Our own circuit commitment (public signal #2 of the registered policy
// proof), used when an envelope arrives without a usable strategyCommitment
// — e.g. practice deliveries, which omit it and previously threw a BigInt
// TypeError -> HTTP 500 (live practice failure, 2026-11-16).
const OWN_COMMITMENT =
  "16214830582135074479649400365420921172603306988248244802062782181847191316900";

// The committed strategy, frozen at registration (see
// tools/policy-commitment.js): commitment = Poseidon(strategyParams, salt).
const STRATEGY_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];
const SALT = 987654321;

function toBig(value, fallback) {
  try {
    if (value === null || value === undefined) return fallback;
    if (typeof value === "bigint") return value;
    if (typeof value === "number") return BigInt(Math.trunc(value));
    const s = String(value).trim();
    if (!s) return fallback;
    return BigInt(s);
  } catch {
    return fallback;
  }
}

function matchIdBig(matchId) {
  // Well-formed UUIDs pack exactly as before (dashes stripped, 32 hex).
  // Anything else is sanitized deterministically instead of throwing.
  const hex = String(matchId || "").replace(/[^0-9a-fA-F]/g, "");
  if (!hex) return 0n;
  const trimmed = hex.length > 32 ? hex.slice(-32) : hex.padStart(32, "0");
  return BigInt("0x" + trimmed);
}

function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const packed = Buffer.concat([
    be32(toBig(commitment, BigInt(OWN_COMMITMENT))),
    be32(matchIdBig(matchId)),
    be32(toBig(turn, 0n)),
    be32(toBig(selfBalance, 0n)),
    be32(toBig(opponentBalance, 0n)),
    be32(ACTION_CODE[action] ?? 0),
    be32(toBig(amount || 0, 0n)),
    be32(1),
  ]);
  return "0x" + keccak256(packed);
}

/**
 * Generate the per-turn Groth16 proof for the vfy-policy circuit. The
 * circuit inputs are the committed strategy (params + salt + commitment)
 * plus this turn's public state, in the exact encoding the offline
 * commitment was generated with (tools/policy-commitment.js). The circuit
 * itself enforces that the action is the committed strategy's action for
 * this state, so a proof can only exist for a strategy-consistent turn.
 */
async function proveTurn({ matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const inputs = {
    commitment: OWN_COMMITMENT,
    circuitVersion: 1,
    matchId: matchIdBig(matchId).toString(),
    turnNumber: Number(toBig(turn, 0n)),
    selfBalance: Number(toBig(selfBalance, 0n)),
    opponentBalance: Number(toBig(opponentBalance, 0n)),
    action: ACTION_CODE[action] ?? 0,
    amount: Number(toBig(amount || 0, 0n)),
    salt: SALT,
    strategyParams: STRATEGY_PARAMS,
  };
  return prove("vfyPolicy", inputs);
}

/**
 * The endpoint's duel policy IS the committed circuit strategy, so the two
 * can never diverge (a turn whose action differs from the committed strategy
 * cannot be proven and is scored as HOLD with no proof):
 *   strategyParams = [10,0,0,0,0,0,0,0]  (see tools/policy-commitment.js)
 *   opponentBalance > 0  -> EXTRACT 10   (the game caps the actual transfer
 *   opponentBalance == 0 -> HOLD          at the opponent's balance)
 * Verified against the circuit as an oracle: with these params, EXTRACT 10
 * is the unique provable action at opponent balances 1..100 (even 1, 3, 5 —
 * the attested amount is params[0] exactly, NOT min(10, balance)), and HOLD
 * is the unique provable action at opponent balance 0. Fortification is not
 * a circuit input, so the committed strategy cannot condition on it;
 * extracting into a fortified opponent still gains max(0, min(10,opp)-6)
 * and costs 0, so it is never worse than holding.
 */
function decideDuel(state, turn) {
  const opp = Number(state.opponentBalance);
  if (opp > 0) return { type: "EXTRACT", amount: EXTRACT_MAX };
  return { type: "HOLD" };
}

function holdResponse(envelope) {
  const state = (envelope && envelope.state) || {};
  const hash = publicInputsHash({
    // Always the circuit commitment the proof binds — never the
    // envelope's strategyCommitment.hash (see header: Round-04 bug).
    commitment: OWN_COMMITMENT,
    matchId: envelope && envelope.matchId,
    turn: envelope && envelope.turn,
    selfBalance: state.selfBalance,
    opponentBalance: state.opponentBalance,
    action: "HOLD",
    amount: 0,
  });
  return {
    matchId: envelope && envelope.matchId,
    turn: envelope && envelope.turn,
    action: { type: "HOLD" },
    policyProof: { circuitVersion: "v1", publicInputsHash: hash },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: turnKey(envelope && envelope.matchId, envelope && envelope.turn),
  };
}

async function handleDuel(envelope) {
  try {
    const state = envelope.state || {};
    const action = decideDuel(state, envelope.turn);
    const hash = publicInputsHash({
      // Always the circuit commitment the proof binds — never the
      // envelope's strategyCommitment.hash (see header: Round-04 bug).
      commitment: OWN_COMMITMENT,
      matchId: envelope.matchId,
      turn: envelope.turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      action: action.type,
      amount: action.amount || 0,
    });
    // The schema-required part: a real per-turn proof + public signals
    // inside policyProof. If proving ever fails, degrade to the hash-only
    // pointer rather than a 500 — the delivery still lands.
    let policyProof = { circuitVersion: "v1", publicInputsHash: hash };
    try {
      const { proof, publicSignals } = await proveTurn({
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance: state.selfBalance,
        opponentBalance: state.opponentBalance,
        action: action.type,
        amount: action.amount || 0,
      });
      policyProof = {
        circuitVersion: "v1",
        proof,
        public_signals: publicSignals,
        publicInputsHash: hash,
      };
    } catch {
      /* keep the hash-only policyProof */
    }
    const actionObj = { type: action.type };
    if (action.type === "EXTRACT") actionObj.amount = action.amount;
    return {
      matchId: envelope.matchId,
      turn: envelope.turn,
      action: actionObj,
      policyProof,
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: turnKey(envelope.matchId, envelope.turn),
    };
  } catch {
    // A malformed envelope must still get a signed 200, never a 500:
    // a HOLD turn scores as a miss at worst, a 500 forfeits the delivery.
    return holdResponse(envelope || {});
  }
}

module.exports = { handleDuel, decideDuel, publicInputsHash, ACTION_CODE, holdResponse, proveTurn, OWN_COMMITMENT };
