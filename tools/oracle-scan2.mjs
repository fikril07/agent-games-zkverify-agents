import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const commitment = F.toObject(poseidon([0,0,0,0,0,0,0,0,0].map(BigInt))).toString();
async function tryProve(inputs) {
  try { const { publicSignals } = await snarkjs.groth16.fullProve(inputs, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey'); return publicSignals; }
  catch { return null; }
}
const base = { strategyParams: [0,0,0,0,0,0,0,0], salt: 0, commitment, matchId: 1, turnNumber: 1, selfBalance: 100, opponentBalance: 100, circuitVersion: 1, action: 0, amount: 0 };
let found = 0;
for (const action of [0,1,2,3,4,5]) for (const amount of [0,1,2,5,10]) {
  const ps = await tryProve({ ...base, action, amount });
  if (ps) { console.log(`PROVED action=${action} amount=${amount} pubSigs=[${ps.join(',')}]`); found++; }
}
console.log('action/amount scan done, found:', found);
for (const turnNumber of [0,2,3,20]) {
  const ps = await tryProve({ ...base, turnNumber });
  console.log('turnNumber', turnNumber, ps ? 'PROVED' : 'failed');
}
for (const matchId of ['123456789012345678901234567890', '999']) {
  const ps = await tryProve({ ...base, matchId });
  console.log('matchId', matchId, ps ? 'PROVED' : 'failed');
}
for (const circuitVersion of [0,2]) {
  const ps = await tryProve({ ...base, circuitVersion });
  console.log('circuitVersion', circuitVersion, ps ? 'PROVED' : 'failed');
}
