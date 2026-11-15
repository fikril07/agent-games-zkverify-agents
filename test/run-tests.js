"use strict";
/**
 * Local integration tests. Boots the Express app on an ephemeral port with
 * TEST secrets (never real ones) and exercises:
 *  - preflight, both documented variants + /build's .v1 variant (signed and
 *    unsigned), always signed in response;
 *  - HMAC enforcement (bad/missing signature -> 401, signed);
 *  - Steal GRID mode (SPEC.md): EXTRACT on token cell, MOVE toward token,
 *    STEAL adjacent rich opponent, BLOCK endgame, exact response fields
 *    (amount omitted for non-EXTRACT/STEAL, direction only for MOVE,
 *    target_agent_id only for STEAL), idempotent replay byte-identical;
 *  - Steal DUEL mode (/build): EXTRACT with amount, FORTIFY/HOLD without
 *    amount, publicInputsHash recomputed independently and compared;
 *  - Gatekeeper VERDICT mode with a stubbed proof server on localhost:
 *    unreachable proof_url -> unverifiable; fake vk_hash -> invalid;
 *    canonical vk_hash + garbage proof -> invalid;
 *    canonical vk_hash + REAL gatekeeper-circuit proof -> valid
 *    (proof generated in-test with the recovered circuit inputs);
 *  - Gatekeeper DECISION mode: VK substitution -> REJECT/VK_SUBSTITUTION
 *    with a circuit proof attached; clean transfer -> APPROVE with proof
 *    that verifies against the gatekeeper VK.
 */
process.env.STEAL_SECRET = "test-steal-secret-0123456789abcdef";
process.env.GATEKEEPER_SECRET = "test-gatekeeper-secret-0123456789";
process.env.ARTIFACT_DIR = require("path").join(__dirname, "..", "..", "artifacts");

const assert = require("assert");
const crypto = require("crypto");
const http = require("http");
const { keccak256 } = require("js-sha3");

const sign = (secret, body) => crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(body).digest("hex");
let passed = 0;
const ok = (name, cond) => { assert(cond, name); passed++; console.log("  ok -", name); };

async function post(base, path, secret, obj, { sig = true, rawBody = null } = {}) {
  const body = rawBody != null ? rawBody : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sig) headers["x-agent-games-signature"] = sign(secret, body);
  const res = await fetch(base + path, { method: "POST", headers, body });
  const text = await res.text();
  // every response must carry a valid signature over its raw body
  const expected = sign(secret, text);
  assert.strictEqual(res.headers.get("x-agent-games-signature"), expected, `response signature valid for ${path}`);
  return { status: res.status, json: JSON.parse(text), text };
}

async function main() {
  const app = require("../src/app");
  const server = app.listen(0);
  await new Promise((r) => server.on("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const SS = process.env.STEAL_SECRET, GS = process.env.GATEKEEPER_SECRET;

  console.log("== preflight ==");
  for (const [label, payload] of [
    ["challenge variant", { challenge: "preflight" }],
    ["type variant", { type: "preflight" }],
    ["build .v1 variant", { type: "agent-games.preflight.v1", agent_id: "agt_x", nonce: "abc123" }],
  ]) {
    const r = await post(base, "/steal/agent", SS, payload);
    ok(`${label} -> 200 ok`, r.status === 200 && r.json.ok === true);
    if (payload.type === "agent-games.preflight.v1") ok(".v1 preflight carries protocolVersion", r.json.protocolVersion === "v1");
  }
  const unsigned = await post(base, "/gatekeeper/agent", GS, { challenge: "preflight" }, { sig: false });
  ok("unsigned preflight still answered (documented exception)", unsigned.status === 200 && unsigned.json.ok === true);

  console.log("== hmac enforcement ==");
  const bad = await post(base, "/steal/agent", SS, { game_id: "g", turn: 1 }, { rawBody: JSON.stringify({ game_id: "g", turn: 1 }), sig: false });
  ok("missing signature -> 401", bad.status === 401);

  console.log("== steal grid mode ==");
  const grid = (over) => ({
    game_id: "steal-2026-11-15-001", turn: 12, player_id: "agent-1234", mode: "competition",
    board: [
      { agent_id: "agent-1234", x: 0, y: 0, balance: 10, score: 30, energy: 10 },
      { agent_id: "agent-5678", x: 3, y: 3, balance: 10, score: 30, energy: 10 },
    ],
    tokens: [{ token_id: "t-001", x: 1, y: 0, value: 10 }],
    fortifications: [], turns_remaining: 38, opponent_policies: [],
    ...over,
  });
  let r = await post(base, "/steal/agent", SS, grid({ tokens: [{ token_id: "t-0", x: 0, y: 0, value: 7 }] }));
  ok("token on cell -> EXTRACT amount=7, no direction/target", r.json.action === "EXTRACT" && r.json.amount === 7 && !("direction" in r.json) && !("target_agent_id" in r.json));
  r = await post(base, "/steal/agent", SS, grid({ turn: 13 }));
  ok("token adjacent -> MOVE RIGHT toward it, no amount", r.json.action === "MOVE" && r.json.direction === "RIGHT" && !("amount" in r.json));
  const stealState = grid({ turn: 14, tokens: [], board: [
    { agent_id: "agent-1234", x: 0, y: 0, balance: 10, score: 30, energy: 10 },
    { agent_id: "agent-5678", x: 1, y: 0, balance: 20, score: 30, energy: 10 },
  ]});
  r = await post(base, "/steal/agent", SS, stealState);
  ok("adjacent rich opponent -> STEAL with target+amount", r.json.action === "STEAL" && r.json.target_agent_id === "agent-5678" && r.json.amount === 20);
  const replay = await post(base, "/steal/agent", SS, stealState);
  ok("idempotent replay is byte-identical", replay.text === r.text);
  const endgame = grid({ turn: 15, tokens: [], turns_remaining: 1, board: [
    { agent_id: "agent-1234", x: 0, y: 0, balance: 10, score: 30, energy: 10 },
    { agent_id: "agent-5678", x: 1, y: 0, balance: 3, score: 30, energy: 10 },
  ]});
  r = await post(base, "/steal/agent", SS, endgame);
  ok("endgame holding tokens, poor neighbour -> BLOCK, no amount", r.json.action === "BLOCK" && !("amount" in r.json));

  console.log("== steal duel mode ==");
  const duel = (over) => ({
    protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
    matchId: "9f4e1b2a-1111-2222-3333-444455556666", turn: 3, issuedAt: "x", deadlineAt: "y",
    state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: "0x7d91" }, resolverVersion: "v1", nonce: "n1", ...over,
  });
  r = await post(base, "/steal/agent", SS, duel({}));
  ok("duel: unfortified opponent -> EXTRACT 10", r.json.action.type === "EXTRACT" && r.json.action.amount === 10);
  ok("duel: echoes matchId+turn", r.json.matchId === "9f4e1b2a-1111-2222-3333-444455556666" && r.json.turn === 3);
  const be32 = (n) => { let v = BigInt(n); const b = Buffer.alloc(32); for (let i = 31; i >= 0 && v > 0n; i--) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
  const expectHash = "0x" + keccak256(Buffer.concat([
    be32(0x7d91n), be32(BigInt("0x9f4e1b2a111122223333444455556666")), be32(3), be32(95), be32(105), be32(2), be32(10), be32(1),
  ]));
  ok("duel: publicInputsHash matches independent keccak computation", r.json.policyProof.publicInputsHash === expectHash);
  r = await post(base, "/steal/agent", SS, duel({ turn: 4, state: { selfBalance: "95", opponentBalance: "4", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: 9 } }));
  ok("duel: committed strategy extracts 10 even into fortification / above balance", r.json.action.type === "EXTRACT" && r.json.action.amount === 10);
  r = await post(base, "/steal/agent", SS, duel({ turn: 5, state: { selfBalance: "5", opponentBalance: "0", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null } }));
  ok("duel: opponent balance 0 -> HOLD without amount (unique provable action)", r.json.action.type === "HOLD" && !("amount" in r.json.action));

  console.log("== gatekeeper verdict mode (stub proof server) ==");
  const { prove, verifyOwn } = require("../src/prover");
  const CANON = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
  // Build a REAL gatekeeper-circuit proof to serve as a genuine task proof.
  const realProof = await prove("gatekeeper", {
    taskId: "424242", registeredVkHash: "111", proofVkHash: "111", minimum: "1000",
    publicBalance: "1460", expiryBlock: "8430000", currentBlock: "8420000",
    recipient: "0xDe42", conditionRecipient: "0xDe42", amount: "500",
    maxTransfer: "1000", decision: 1, salt: "7",
  });
  const stub = http.createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/real.json") res.end(JSON.stringify({ proof: realProof.proof, publicSignals: realProof.publicSignals }));
    else if (req.url === "/garbage.json") res.end(JSON.stringify({ proof: { pi_a: ["1", "2", "1"], pi_b: [["1", "2"], ["3", "4"], ["1", "0"]], pi_c: ["1", "2", "1"], protocol: "groth16", curve: "bn128" }, publicSignals: realProof.publicSignals }));
    else { res.statusCode = 404; res.end("{}"); }
  });
  await new Promise((r2) => stub.listen(0, r2));
  const stubBase = `http://127.0.0.1:${stub.address().port}`;
  const task = (over) => ({ task_id: "pg-2026-11-15-001", proof_url: `${stubBase}/real.json`, vk_hash: CANON, timeout_seconds: 60, mode: "competition", ...over });

  r = await post(base, "/gatekeeper/agent", GS, task({ task_id: "t-unreach", proof_url: "http://127.0.0.1:1/nope.json" }));
  ok("unreachable proof_url -> unverifiable", r.json.verdict === "unverifiable");
  r = await post(base, "/gatekeeper/agent", GS, task({ task_id: "t-fakevk", vk_hash: "0xdeadbeef" }));
  ok("fake vk_hash -> invalid", r.json.verdict === "invalid");
  r = await post(base, "/gatekeeper/agent", GS, task({ task_id: "t-garbage", proof_url: `${stubBase}/garbage.json` }));
  ok("canonical vk + non-verifying proof -> invalid", r.json.verdict === "invalid");
  r = await post(base, "/gatekeeper/agent", GS, task({ task_id: "t-real" }));
  ok("canonical vk + real proof -> valid with evidence", r.json.verdict === "valid" && Array.isArray(r.json.evidence) && r.json.evidence.length >= 2);
  ok("verdict response has exactly the 4 spec fields", JSON.stringify(Object.keys(r.json).sort()) === JSON.stringify(["confidence", "evidence", "reason", "verdict"]));

  console.log("== gatekeeper decision mode ==");
  const dtask = (over) => ({
    type: "agent-games.proof-gatekeeper.v1", task_id: "gk_8d31_test", mode: "competition",
    issued_at: "x", deadline_at: "y",
    input: {
      registered_vk: "0x7d91", proof_vk: "0x7d91", minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000, recipient: "0xDe42",
      condition_recipient: "0xDe42", amount: "500", max_transfer: "1000", proof_tx: "0xa82c",
    }, ...over,
  });
  r = await post(base, "/gatekeeper/agent", GS, dtask({}));
  ok("clean transfer -> APPROVE", r.json.decision === "APPROVE");
  ok("decision proof attached and verifies vs gatekeeper VK", !!r.json.proof && (await verifyOwn("gatekeeper", r.json.public_signals, r.json.proof)) === true);
  const badVk = dtask({ task_id: "gk_8d31_bad" });
  badVk.input = { ...badVk.input, proof_vk: "0x13aa" };
  r = await post(base, "/gatekeeper/agent", GS, badVk);
  ok("vk substitution -> REJECT VK_SUBSTITUTION with proof", r.json.decision === "REJECT" && r.json.reason_code === "VK_SUBSTITUTION" && !!r.json.proof);

  stub.close();
  server.close();
  console.log(`\nALL TESTS PASSED (${passed} assertions)`);
}

main().catch((e) => { console.error("TEST FAILURE:", e); process.exit(1); });
