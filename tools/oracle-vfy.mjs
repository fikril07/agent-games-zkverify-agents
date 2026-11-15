import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P = (arr) => F.toObject(poseidon(arr.map(BigInt)));
const base = { strategyParams: [0,0,0,0,0,0,0,0], salt: 0, matchId: 1, turnNumber: 1, selfBalance: 100, opponentBalance: 100, circuitVersion: 1, action: 0, amount: 0 };
const candidates = {
  'commitment=0': 0n,
  'poseidon(params,salt)': P([...base.strategyParams, 0]),
  'poseidon(salt,params)': P([0, ...base.strategyParams]),
  'poseidon(params)': P(base.strategyParams),
};
for (const [label, commitment] of Object.entries(candidates)) {
  const inputs = { ...base, commitment: commitment.toString() };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, '../artifacts/vfy-policy.wasm', '../artifacts/vfy-policy_final.zkey');
    console.log(label, '-> PROVED. publicSignals:', publicSignals.join(','));
  } catch (e) {
    console.log(label, '-> FAILED:', String(e.message || e).slice(0, 120));
  }
}
