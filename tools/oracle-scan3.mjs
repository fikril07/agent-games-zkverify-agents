import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P9 = (params, salt) => F.toObject(poseidon([...params.map(BigInt), BigInt(salt)])).toString();
async function tryProve(inputs) {
  try { await snarkjs.groth16.fullProve(inputs, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey'); return 'PROVED'; }
  catch (e) { return (String(e.message || e).match(/line: \d+/) || ['?'])[0]; }
}
const params = [1,2,3,4,5,6,7,8], salt = 7;
const good = P9(params, salt);
const base = { strategyParams: params, salt, matchId: 1, turnNumber: 1, selfBalance: 100, opponentBalance: 100, circuitVersion: 1, action: 0, amount: 0 };
console.log('nonzero params + correct poseidon9 commitment:', await tryProve({ ...base, commitment: good }));
console.log('nonzero params + wrong commitment (12345):', await tryProve({ ...base, commitment: '12345' }));
// vary one param at a time with all-zero base
for (let i = 0; i < 8; i++) {
  for (const v of [1, 10, 100]) {
    const p = [0,0,0,0,0,0,0,0]; p[i] = v;
    const c = P9(p, 0);
    let res = null;
    for (const action of [0,1,2]) for (const amount of action === 2 ? [1,5,10] : [0]) {
      const r = await tryProve({ strategyParams: p, salt: 0, commitment: c, matchId: 1, turnNumber: 1, selfBalance: 100, opponentBalance: 100, circuitVersion: 1, action, amount });
      if (r === 'PROVED') { res = `param[${i}]=${v} action=${action} amount=${amount}`; break; }
    }
    console.log(`param[${i}]=${v}:`, res || 'no proof');
    if (res) break;
  }
}
