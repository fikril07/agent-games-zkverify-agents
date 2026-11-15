"use strict";

/**
 * Steal the VFY — per-turn policy (PURE game logic, no I/O, no proof).
 * Per SPEC.md the per-turn response carries NO proof and NO extra fields:
 *   {"action":"MOVE|WAIT|FORTIFY|EXTRACT|STEAL|BLOCK"}
 *   + "direction" ONLY for MOVE
 *   + "amount" ONLY for EXTRACT / STEAL
 *   + "target_agent_id" ONLY for STEAL
 * The policy proof is an OFFLINE, one-time commitment (see
 * tools/policy-commitment.js), not part of this handler.
 *
 * Strategy ("extract-first, steal opportunistically, protect the endgame"):
 *  score = 10*tokens extracted + 5*tokens held at end - 5*stolen from you
 *          + 1*blocks defended
 *  1. Token on my cell and energy >= 2          -> EXTRACT its value.
 *  2. Endgame (turns_remaining <= 2), holding tokens, adjacent opponent who
 *     could steal from me                       -> BLOCK (protect +5/token).
 *  3. Adjacent opponent with balance >= STEAL_MIN_BALANCE and energy >= 3
 *                                               -> STEAL min(balance, CAP).
 *  4. Adjacent threat while I hold tokens and cannot afford STEAL -> BLOCK.
 *  5. Otherwise MOVE toward the nearest token (greedy Manhattan, avoiding
 *     fortified cells and occupied cells when an equal step exists).
 *  6. No tokens and nothing to steal: FORTIFY if an opponent is adjacent and
 *     I hold tokens; else WAIT.
 * Deterministic: all ties break by board order / fixed direction order.
 */

const STEAL_MIN_BALANCE = 5; // don't waste 3 energy on dust
const STEAL_CAP = 25; // per-steal amount cap (platform cap unknown; documented guess)

const DIRS = [
  { name: "UP", dx: 0, dy: -1 },
  { name: "DOWN", dx: 0, dy: 1 },
  { name: "LEFT", dx: -1, dy: 0 },
  { name: "RIGHT", dx: 1, dy: 0 },
];

const manhattan = (a, b) => Math.abs(a.x - b.x) + Math.abs(a.y - b.y);

function decide(state) {
  const board = Array.isArray(state.board) ? state.board : [];
  const me = board.find((a) => a.agent_id === state.player_id);
  if (!me) return { action: "WAIT" };
  const energy = typeof me.energy === "number" ? me.energy : 10;
  const tokens = Array.isArray(state.tokens) ? state.tokens : [];
  const forts = Array.isArray(state.fortifications) ? state.fortifications : [];
  const turnsLeft = typeof state.turns_remaining === "number" ? state.turns_remaining : 99;
  const opponents = board.filter((a) => a.agent_id !== state.player_id);
  const adjacent = opponents.filter((o) => manhattan(me, o) === 1);

  // 1. Extract a token on my cell.
  const here = tokens.filter((t) => t.x === me.x && t.y === me.y);
  if (here.length && energy >= 2) {
    const best = here.reduce((a, b) => (b.value > a.value ? b : a));
    return { action: "EXTRACT", amount: best.value };
  }

  // 2. Endgame protection.
  if (turnsLeft <= 2 && me.balance > 0 && adjacent.length) {
    return { action: "BLOCK" };
  }

  // 3. Opportunistic steal from the richest adjacent opponent.
  if (energy >= 3) {
    const targets = adjacent
      .filter((o) => o.balance >= STEAL_MIN_BALANCE)
      .sort((a, b) => b.balance - a.balance);
    if (targets.length) {
      const t = targets[0];
      return {
        action: "STEAL",
        amount: Math.min(t.balance, STEAL_CAP),
        target_agent_id: t.agent_id,
      };
    }
  }

  // 4. Cheap defence when threatened and holding tokens.
  if (me.balance > 0 && adjacent.some((o) => o.balance >= me.balance)) {
    return { action: "BLOCK" };
  }

  // 5. Move toward the nearest token.
  if (tokens.length && energy >= 1) {
    const fortCells = new Set(
      forts.filter((f) => typeof f.x === "number").map((f) => `${f.x},${f.y}`)
    );
    const occupied = new Set(opponents.map((o) => `${o.x},${o.y}`));
    const nearest = tokens
      .map((t) => ({ t, d: manhattan(me, t) }))
      .sort((a, b) => a.d - b.d)[0].t;
    const steps = DIRS.map((dir) => {
      const cell = { x: me.x + dir.dx, y: me.y + dir.dy };
      return { dir, cell, d: manhattan(cell, nearest) };
    }).sort((a, b) => a.d - b.d);
    const unblocked = steps.filter(
      (s) => !fortCells.has(`${s.cell.x},${s.cell.y}`) && !occupied.has(`${s.cell.x},${s.cell.y}`)
    );
    const pick = (unblocked.length ? unblocked : steps)[0];
    if (pick && pick.d < manhattan(me, nearest)) {
      return { action: "MOVE", direction: pick.dir.name };
    }
  }

  // 6. Stall with protection if an opponent is adjacent and I hold tokens.
  if (adjacent.length && me.balance > 0 && energy >= 1) return { action: "FORTIFY" };
  return { action: "WAIT" };
}

module.exports = { decide, STEAL_MIN_BALANCE, STEAL_CAP };
