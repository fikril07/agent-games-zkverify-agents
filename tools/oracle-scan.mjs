import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P9 = (params, salt) => F.toObject(poseidon([...params.map(BigInt), BigInt(salt)]));
async function tryProve(inputs) {
  const t0 = Date.now();
  try {
    const { publicSignals } = await snarkjs.groth16.fullProve(inputs, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey');
    return { ok: true, ms: Date.now() - t0, publicSignals };
  } catch (e) { return { ok: false, ms: Date.now() - t0, err: String(e.message || e).match(/line: \d+/)?.[0] }; }
}
const params = [0,0,0,0,0,0,0,0], salt = 0;
const commitment = P9(params, salt).toString();
console.log('commitment (all-zero params):', commitment);
for (const [self, opp] of [[100,100],[50,100],[100,10],[10,100],[0,100],[100,0]]) {
  const results = [];
  for (const action of [0,1,2]) {
    for (const amount of action === 2 ? [1,5,10] : [0]) {
      const r = await tryProve({ strategyParams: params, salt, commitment, matchId: 1, turnNumber: 1, selfBalance: self, opponentBalance: opp, circuitVersion: 1, action, amount });
      if (r.ok) results.push(`action=${action} amount=${amount} PROVED (${r.ms}ms) pubSigs=[${r.publicSignals.join(',')}]`);
    }
  }
  console.log(`state self=${self} opp=${opp}:`, results.length ? results.join(' | ') : 'no action proved');
}
