"use strict";
const { keccak256 } = require("js-sha3");

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
 *   { circuitVersion:"v1", publicInputsHash }, agentTimestamp, idempotencyKey }
 * action.amount is present ONLY for EXTRACT (schema rejects it otherwise).
 * publicInputsHash = keccak256 of the 8 ABI-packed 32-byte big-endian fields,
 * in order: [commitment, matchId (UUID as hex), turn, selfBalance,
 * opponentBalance, actionCode (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount
 * (0 for HOLD/FORTIFY), circuitVersion (1)] — verbatim from /build.
 */

const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
const EXTRACT_MAX = 10;
const FORTIFY_BLOCK = 6;

function be32(n) {
  let v = BigInt(n);
  const buf = Buffer.alloc(32);
  for (let i = 31; i >= 0 && v > 0n; i--) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const packed = Buffer.concat([
    be32(BigInt(commitment)),
    be32(BigInt("0x" + String(matchId).replace(/-/g, ""))),
    be32(turn),
    be32(selfBalance),
    be32(opponentBalance),
    be32(ACTION_CODE[action]),
    be32(amount || 0),
    be32(1),
  ]);
  return "0x" + keccak256(packed);
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

function handleDuel(envelope) {
  const state = envelope.state || {};
  const action = decideDuel(state, envelope.turn);
  const hash = publicInputsHash({
    commitment: envelope.strategyCommitment && envelope.strategyCommitment.hash,
    matchId: envelope.matchId,
    turn: envelope.turn,
    selfBalance: state.selfBalance,
    opponentBalance: state.opponentBalance,
    action: action.type,
    amount: action.amount || 0,
  });
  const actionObj = { type: action.type };
  if (action.type === "EXTRACT") actionObj.amount = action.amount;
  return {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: actionObj,
    policyProof: { circuitVersion: "v1", publicInputsHash: hash },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: `${envelope.matchId}:${envelope.turn}`,
  };
}

module.exports = { handleDuel, decideDuel, publicInputsHash, ACTION_CODE };
