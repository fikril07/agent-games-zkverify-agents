"use strict";
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

/**
 * Thin wrapper over snarkjs for the two Agent Games circuits.
 * Artifacts are the platform's own published files:
 *   gatekeeper: gatekeeper.wasm + gatekeeper_final.zkey (13 public signals)
 *   vfyPolicy:  vfy-policy.wasm + vfy-policy_final.zkey (9 public signals)
 * Canonical vk hashes (GET /api/circuit-info, mainnet):
 *   gatekeeper 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *   vfyPolicy  0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *
 * If artifact files are not bundled, they are downloaded once from
 * agentgames.zkverify.io into ARTIFACT_CACHE_DIR (default /tmp) — this keeps
 * serverless bundles small.
 */

const ARTIFACT_BASE = "https://agentgames.zkverify.io/circuits";
const CIRCUITS = {
  gatekeeper: { wasm: "gatekeeper.wasm", zkey: "gatekeeper_final.zkey" },
  vfyPolicy: { wasm: "vfy-policy.wasm", zkey: "vfy-policy_final.zkey" },
};

const cache = new Map(); // name -> { wasm: Buffer, zkey: Buffer, vk: object }

async function loadBuffer(name, file) {
  const localDirs = [];
  if (process.env.ARTIFACT_DIR) localDirs.push(process.env.ARTIFACT_DIR);
  localDirs.push(path.join(__dirname, "..", "artifacts"));       // package-local
  localDirs.push(path.join(__dirname, "..", "..", "artifacts")); // workspace layout
  for (const dir of localDirs) {
    const local = path.join(dir, file);
    if (fs.existsSync(local)) return fs.readFileSync(local);
  }
  const cacheDir = process.env.ARTIFACT_CACHE_DIR || "/tmp/agentgames-artifacts";
  const cached = path.join(cacheDir, file);
  if (fs.existsSync(cached)) return fs.readFileSync(cached);
  const res = await fetch(`${ARTIFACT_BASE}/${file}`);
  if (!res.ok) throw new Error(`artifact download failed ${file}: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(cached, buf);
  return buf;
}

async function loadCircuit(name) {
  if (cache.has(name)) return cache.get(name);
  const files = CIRCUITS[name];
  if (!files) throw new Error(`unknown circuit ${name}`);
  const [wasm, zkey] = await Promise.all([
    loadBuffer(name, files.wasm),
    loadBuffer(name, files.zkey),
  ]);
  const vk = await snarkjs.zKey.exportVerificationKey(zkey);
  const entry = { wasm, zkey, vk };
  cache.set(name, entry);
  return entry;
}

/** Generate a Groth16 proof. Returns { proof, publicSignals }. */
async function prove(name, inputs) {
  const { wasm, zkey } = await loadCircuit(name);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm, zkey);
  return { proof, publicSignals };
}

/** Verify a Groth16 proof against an explicit verification key object. */
async function verifyWithVK(vk, publicSignals, proof) {
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

/** Verify a proof against one of the platform circuits' own VK. */
async function verifyOwn(name, publicSignals, proof) {
  const { vk } = await loadCircuit(name);
  return verifyWithVK(vk, publicSignals, proof);
}

module.exports = { prove, verifyWithVK, verifyOwn, loadCircuit, CIRCUITS };
