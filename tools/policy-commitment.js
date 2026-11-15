"use strict";
/**
 * Offline Steal-the-VFY policy commitment generator.
 *
 * What is PROVEN about the vfy-policy circuit (FNV-hash probing of the wasm
 * + witness-oracle experiments, 2026-11-15):
 *   inputs (17): commitment, circuitVersion, matchId, turnNumber,
 *     selfBalance, opponentBalance, action, amount, salt,
 *     strategyParams[8]
 *   commitment === Poseidon(strategyParams[0..7], salt)  (9-input Poseidon;
 *     a wrong commitment fails at template line 72, the correct one passes)
 *   public signals (9): 8 public inputs + 1 output (snarkjs returns outputs
 *     first, then public inputs in declaration order).
 *
 * Usage:
 *   node tools/policy-commitment.js <inputs.json>
 * where inputs.json = { strategyParams:[8 numbers], salt, matchId,
 *   turnNumber, selfBalance, opponentBalance, action, amount,
 *   circuitVersion } — action/amount/state describe the turn the proof
 *   attests to (for the one-time dashboard commitment, use the genesis
 *   state your strategy commits to, as the dashboard directs).
 *
 * Output: the proof, its public signals, the commitment, and the
 * publicInputsHash computed BOTH ways the docs describe:
 *   - SPEC.md: SHA256 of the 8 public inputs as 32-byte big-endian field
 *     elements concatenated in order;
 *   - /build:  keccak256 of the same ABI-packed fields.
 * The dashboard (Edit agent -> Steal the VFY, circuitVersion "v1") is the
 * arbiter of which one it expects.
 */
const fs = require("fs");
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");
const { prove } = require("../src/prover");

function be32(n) {
  let v = BigInt(n);
  const buf = Buffer.alloc(32);
  for (let i = 31; i >= 0 && v > 0n; i--) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

async function main() {
  const file = process.argv[2];
  if (!file) { console.error("usage: node tools/policy-commitment.js <inputs.json>"); process.exit(2); }
  const spec = JSON.parse(fs.readFileSync(file, "utf8"));
  const { buildPoseidon } = require("circomlibjs");
  const poseidon = await buildPoseidon();
  const commitment = poseidon.F.toObject(
    poseidon([...spec.strategyParams.map(BigInt), BigInt(spec.salt)])
  ).toString();

  const inputs = {
    commitment,
    circuitVersion: spec.circuitVersion ?? 1,
    matchId: spec.matchId,
    turnNumber: spec.turnNumber,
    selfBalance: spec.selfBalance,
    opponentBalance: spec.opponentBalance,
    action: spec.action,
    amount: spec.amount,
    salt: spec.salt,
    strategyParams: spec.strategyParams,
  };
  const t0 = Date.now();
  const { proof, publicSignals } = await prove("vfyPolicy", inputs);
  const ms = Date.now() - t0;

  // The 8 hashed fields in the order /build documents for the per-turn
  // publicInputsHash: [commitment, matchId, turn, selfBalance,
  // opponentBalance, action, amount, circuitVersion]. We hash the INPUT
  // values in that order (unambiguous), and also print the raw publicSignals
  // so the parent can reconcile against whatever the dashboard shows.
  const eight = [
    BigInt(commitment),
    BigInt(spec.matchId),
    BigInt(spec.turnNumber),
    BigInt(spec.selfBalance),
    BigInt(spec.opponentBalance),
    BigInt(spec.action),
    BigInt(spec.amount),
    BigInt(spec.circuitVersion ?? 1),
  ];
  const packed = Buffer.concat(eight.map(be32));
  const shaHash = "0x" + crypto.createHash("sha256").update(packed).digest("hex");
  const keccakHash = "0x" + keccak256(packed);

  console.log(JSON.stringify({
    commitment,
    provingMs: ms,
    publicSignals,
    publicInputsHash_sha256_SPEC: shaHash,
    publicInputsHash_keccak_build: keccakHash,
    proof,
  }, null, 2));
}

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
