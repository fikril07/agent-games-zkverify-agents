# Agent Games by ZkVerify — autonomous agents for @ithasa3

Two autonomous agents for [Agent Games by ZkVerify](https://agentgames.zkverify.io),
implemented as one small Node.js service:

| Agent | Endpoint | Event |
|---|---|---|
| Steal the VFY agent | `POST /steal/agent` | Steal the VFY (Swiss duels / arena) |
| Proof Gatekeeper agent | `POST /gatekeeper/agent` | Proof Gatekeeper (ZK proof verification tasks) |

Every request and response is authenticated with the per-agent HMAC secret
issued at registration (`x-agent-games-signature` = hex HMAC-SHA256 over the
raw body). Responses are idempotent per task/turn id.

## Proof Gatekeeper agent

The agent receives verification tasks and answers with a verdict
(`valid` / `invalid` / `unverifiable`, a confidence, a reason and evidence)
— or, in decision-task envelopes, an `APPROVE` / `REJECT` decision with a
machine-readable `reason_code`. It never answers `valid` on trust:

1. The task's `vk_hash` must equal the canonical circuit hash published by
   the platform (`GET /api/circuit-info`) — a substituted VK is judged
   `invalid` without touching the proof (fake-VK trap).
2. The proof payload is fetched from `proof_url`; anything unreachable or
   unparseable is `unverifiable` (fail closed, never guessed).
3. The Groth16 (BN254) proof is verified locally with
   [snarkjs](https://github.com/iden3/snarkjs) against the circuit's
   verification key. Only a cryptographic pass can produce `valid`.

For decision tasks, the agent additionally proves its own decision in zero
knowledge with the platform's `gatekeeper` circuit (Groth16 over the 13
public inputs: VK hashes, minimum, balances, blocks, recipients, amounts —
plus the decision), so the platform can check the decision was derived by
the published rule without seeing the agent's internals. Rule order:
VK match → not expired → recipient match → balance ≥ minimum →
amount ≤ max transfer → amount ≤ balance.

## Steal the VFY agent

Two envelope shapes are supported and routed automatically:

* **Arena grid** — the agent plays a documented policy: extract a token on
  its cell, protect a lead in the endgame, steal from the richest adjacent
  opponent when the expected gain beats moving, otherwise move toward the
  nearest token avoiding fortifications and occupied cells, fortifying when
  threatened with nothing better to do.
* **Swiss duel** — the endpoint's policy *is* the committed ZK strategy
  (below), so an answer can never diverge from the strategy proof:
  extract 10 VFY whenever the opponent holds a balance, hold otherwise.
  The response carries the `policyProof.publicInputsHash` recomputed
  exactly as the platform does (keccak256 over the ABI-packed fields:
  commitment, matchId, turn, both balances, action code, amount,
  circuitVersion).

### The committed strategy (zkVerify usage)

Before Round 1 the strategy is committed as a Groth16 proof in the
platform's `vfy-policy` circuit (17 inputs; 9 public signals). The circuit
input schema is undocumented, so it was recovered directly from the
published circuit artifacts (signal names via the wasm symbol hashes) and
by using the circuit as a witness oracle:

* `commitment = Poseidon(strategyParams[0..7], salt)` — 9-input Poseidon;
  a wrong commitment fails the circuit, the correct one passes.
* With `strategyParams = [10,0,0,0,0,0,0,0]` the circuit dictates exactly
  one action per state: `EXTRACT amount = 10` whenever
  `opponentBalance > 0` (the attested amount is the parameter itself, not
  clamped to the balance), and `HOLD` when `opponentBalance == 0`.
  Extracting is free and the game caps the transfer at the opponent's
  balance, so max-extraction is never worse than holding.

Generate / regenerate the commitment artifacts with:

```bash
node tools/policy-commitment.js <inputs.json>   # fullProve + both hash forms
```

## Running

```bash
npm install
STEAL_SECRET=… GATEKEEPER_SECRET=… npm start    # listens on $PORT (3000)
npm test                                        # local integration tests
```

Circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`,
`vfy-policy.wasm`, `vfy-policy_final.zkey`) are **not** committed; the
service downloads them from `agentgames.zkverify.io/circuits` on first use
and caches them, or reads them from `$ARTIFACT_DIR` when set.

## Deployment (Vercel)

`vercel.json` + the `api/` functions deploy the service as two serverless
functions (`sin1` region, 60 s / 30 s duration budgets — proving a
gatekeeper decision takes well under a second locally; verification is
milliseconds). Set `STEAL_SECRET` and `GATEKEEPER_SECRET` in the project
environment, deploy, then put the two function URLs into the Agent Games
dashboard as the agents' endpoints.
