import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const commitment = F.toObject(poseidon([10,0,0,0,0,0,0,0,0].map(BigInt))).toString();
async function t(self, opp, action, amount) {
  try { await snarkjs.groth16.fullProve({ strategyParams: [10,0,0,0,0,0,0,0], salt: 0, commitment, matchId: 1, turnNumber: 1, selfBalance: self, opponentBalance: opp, circuitVersion: 1, action, amount }, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey'); return true; } catch { return false; }
}
console.log('(100,5) extract10:', await t(100,5,2,10), '| extract5:', await t(100,5,2,5), '| hold:', await t(100,5,0,0));
console.log('(100,3) extract10:', await t(100,3,2,10), '| extract3:', await t(100,3,2,3));
console.log('(100,1) extract10:', await t(100,1,2,10), '| extract1:', await t(100,1,2,1));
