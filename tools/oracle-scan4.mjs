import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P9 = (params, salt) => F.toObject(poseidon([...params.map(BigInt), BigInt(salt)])).toString();
async function tryProve(inputs) {
  try { await snarkjs.groth16.fullProve(inputs, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey'); return true; }
  catch { return false; }
}
async function dictated(params, self, opp, turn = 1) {
  const commitment = P9(params, 0);
  const found = [];
  for (const action of [0,1,2]) for (const amount of [0,1,5,10]) {
    if (await tryProve({ strategyParams: params, salt: 0, commitment, matchId: 1, turnNumber: turn, selfBalance: self, opponentBalance: opp, circuitVersion: 1, action, amount })) found.push(`a${action}/amt${amount}`);
  }
  return found;
}
console.log('params [10,0..] (100,100):', await dictated([10,0,0,0,0,0,0,0], 100, 100));
console.log('params [10,0..] (100,0):', await dictated([10,0,0,0,0,0,0,0], 100, 0));
console.log('params [10,0..] (0,0):', await dictated([10,0,0,0,0,0,0,0], 0, 0));
console.log('params [10,0..] (50,30):', await dictated([10,0,0,0,0,0,0,0], 50, 30));
console.log('params [10,0..] (100,100) turn 20:', await dictated([10,0,0,0,0,0,0,0], 100, 100, 20));
console.log('params [5,0..] (100,100):', await dictated([5,0,0,0,0,0,0,0], 100, 100));
