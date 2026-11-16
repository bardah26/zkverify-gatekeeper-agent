// Vercel serverless adapter for the Proof Gatekeeper agent.
// Same logic as server.js (gatekeeper-core.js), adapted for Vercel's Node
// runtime: raw body (bodyParser disabled) so the inbound HMAC can be
// verified, signed JSON response, and a 60s task deadline.
//
// LIMITS vs the persistent server:
// - Stateless: the proof_tx seen-set and the response cache live only in the
//   warm instance's memory. A PROOF_REUSED trap is caught only if both tasks
//   hit the same warm instance. (The platform sends 8 tasks/round; Vercel
//   usually routes bursts to the same instance, but this is best-effort.)
// - Cold start: first invocation loads snarkjs + the circuit files (~1-3s),
//   then proving takes ~1s. Well inside the 60s deadline.
// - The circuit files (gatekeeper.wasm, gatekeeper_final.zkey,
//   verification_key.json) must be included in the deployment bundle:
//   they sit at the project root next to package.json. After deploying,
//   verify with a signed test POST that the function answers and the proof
//   verifies; if Vercel's bundler drops the .wasm/.zkey, add them to
//   vercel.json "functions" includeFiles (see README.md).
//
// Env vars in the Vercel project: HMAC_SECRET (the secret returned by
// addAgentAction at registration), KURIER_API_KEY (optional).
"use strict";
const fs = require("fs");
const path = require("path");
const core = require("../gatekeeper-core");

const WASM_PATH = path.join(__dirname, "..", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "..", "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "..", "verification_key.json");
const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));

const HMAC_SECRET = process.env.HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";

// In-memory only (see header note about statelessness).
const seenProofTx = new Set();
const responseCache = {};

async function kurierSubmitBestEffort(proof, publicSignals) {
  if (!KURIER_API_KEY) return;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    await fetch(`https://api.kurier.xyz/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof, publicSignals }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
  } catch (e) { /* non-blocking, ignore */ }
}

async function handleTask(task) {
  const input = task.input || {};
  const taskId = String(task.task_id || "");
  if (taskId && responseCache[taskId]) return responseCache[taskId];
  const proofTx = input.proof_tx ? String(input.proof_tx) : "";
  const reused = proofTx ? seenProofTx.has(proofTx) : false;
  if (proofTx) seenProofTx.add(proofTx);
  const { decision, reason_code } = core.decide({ ...input, _proofReused: reused });
  if (reason_code === "MALFORMED_INPUT") {
    const body = { decision: "REJECT", reason_code, proof_tx: proofTx, proof: null, public_signals: null };
    if (taskId) responseCache[taskId] = body;
    return body;
  }
  const salt = core.randomSalt();
  let proof = null, publicSignals = null;
  let finalDecision = decision === 1 ? "APPROVE" : "REJECT";
  let finalReason = reason_code;
  try {
    const r = await core.proveDecision(core.buildCircuitInput(input, decision, salt, taskId), WASM_PATH, ZKEY_PATH, vk);
    proof = r.proof; publicSignals = r.publicSignals;
  } catch (e) {
    if (reason_code === "PROOF_REUSED") {
      proof = null; publicSignals = null;
    } else {
      const flipped = decision === 1 ? 0 : 1;
      try {
        const r2 = await core.proveDecision(core.buildCircuitInput(input, flipped, salt, taskId), WASM_PATH, ZKEY_PATH, vk);
        proof = r2.proof; publicSignals = r2.publicSignals;
        finalDecision = flipped === 1 ? "APPROVE" : "REJECT";
        finalReason = flipped === 1 ? "CIRCUIT_CORRECTED_APPROVE" : "CIRCUIT_ENFORCED_REJECT";
      } catch (e2) { proof = null; publicSignals = null; }
    }
  }
  if (!proof) { finalDecision = "REJECT"; finalReason = reason_code; }
  const body = { decision: finalDecision, reason_code: finalReason, proof_tx: proofTx, proof, public_signals: publicSignals };
  if (taskId) responseCache[taskId] = body;
  if (proof) kurierSubmitBestEffort(proof, publicSignals);
  return body;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  const secret = HMAC_SECRET;
  const send = (status, obj) => {
    const raw = JSON.stringify(obj);
    if (secret) res.setHeader("x-agent-games-signature", core.hmacHex(secret, raw));
    res.setHeader("Content-Type", "application/json");
    res.status(status).send(raw);
  };
  try {
    if (req.method === "GET") return send(200, { ok: true, protocolVersion: "v1" });
    if (req.method !== "POST") return res.status(405).send("method not allowed");
    const raw = await readRawBody(req);
    if (secret && !core.verifySignature(secret, raw, req.headers["x-agent-games-signature"])) {
      return res.status(401).send(JSON.stringify({ error: "bad signature" }));
    }
    // A validly signed POST that is not a Gatekeeper task is a platform probe
    // (preflight/health): HTTP 200 + signed {"ok":true,"protocolVersion":"v1"},
    // within 10s, body <= 16 KB. A real task always parses and carries
    // type "agent-games.proof-gatekeeper.v1" + input + task_id.
    let task = null;
    let parseOk = true;
    try { task = JSON.parse(raw.toString("utf8")); } catch (e) { parseOk = false; }
    if (!parseOk || !task || task.preflight === true
        || task.type === "preflight" || task.type === "agent-games.preflight.v1") {
      return send(200, { ok: true, protocolVersion: "v1" });
    }
    if (task.type !== "agent-games.proof-gatekeeper.v1") {
      return send(200, { ok: true, protocolVersion: "v1" });
    }
    if (!task.input || !task.task_id) {
      return send(400, { decision: "REJECT", reason_code: "MALFORMED_INPUT", proof_tx: "", proof: null, public_signals: null });
    }
    const deadlineMs = task.deadline_at ? Date.parse(task.deadline_at) : Date.now() + 55000;
    const budgetMs = Math.max(5000, Math.min(55000, deadlineMs - Date.now() - 2000));
    const result = await Promise.race([
      handleTask(task),
      new Promise((resolve) => setTimeout(() => resolve({
        decision: "REJECT", reason_code: "TIMEOUT_FAIL_CLOSED",
        proof_tx: String((task.input || {}).proof_tx || ""), proof: null, public_signals: null,
      }), budgetMs)),
    ]);
    return send(200, result);
  } catch (e) {
    return send(200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: "", proof: null, public_signals: null });
  }
};

module.exports.config = { api: { bodyParser: false } };
