// zkVerify Agent Games — Proof Gatekeeper agent (persistent Node.js server).
// Uses gatekeeper-core.js for the decision rules + Groth16 proving.
// - Verifies inbound HMAC (x-agent-games-signature) over the RAW request body.
// - Decides APPROVE/REJECT from the 7 known Gatekeeper traps, fail-closed.
// - Generates a local Groth16 proof (snarkjs) and returns
//   {decision, reason_code, proof_tx, proof, public_signals}, signed with HMAC.
// - task_id is the idempotency key; task proof_tx values are kept in a seen-set
//   (PROOF_REUSED trap). Responses are cached per task_id on disk.
// - Preflight: GET / or POST {"preflight":true} -> {ok:true, protocolVersion:"v1"} (signed).
// - Kurier on-chain submission is OPTIONAL and non-blocking: only if
//   KURIER_API_KEY is set; never blocks the 60s response deadline.
//
// Config via env: HMAC_SECRET (or file HMAC_SECRET_FILE), PORT (default 8080),
// KURIER_API_KEY (optional), STATE_DIR (default ./state).
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const core = require("./gatekeeper-core");

const PORT = parseInt(process.env.PORT || "8080", 10);
const STATE_DIR = process.env.STATE_DIR || path.join(__dirname, "state");
const WASM_PATH = path.join(__dirname, "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "verification_key.json");

let HMAC_SECRET = process.env.HMAC_SECRET || "";
if (!HMAC_SECRET && process.env.HMAC_SECRET_FILE) {
  try { HMAC_SECRET = fs.readFileSync(process.env.HMAC_SECRET_FILE, "utf8").trim(); } catch (e) { /* no secret file */ }
}
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";

fs.mkdirSync(STATE_DIR, { recursive: true });
const SEEN_FILE = path.join(STATE_DIR, "seen.json");
const CACHE_FILE = path.join(STATE_DIR, "responses.json");
const LOG_FILE = path.join(STATE_DIR, "agent.log");

function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return fallback; }
}
function saveJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}
const seenProofTx = new Set(loadJson(SEEN_FILE, []));
const responseCache = loadJson(CACHE_FILE, {});
function log(msg) {
  const line = new Date().toISOString() + " " + msg + "\n";
  fs.appendFileSync(LOG_FILE, line);
  console.log(line.trim());
}

const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));

// --- Optional, non-blocking Kurier submission of our own proof (best effort) ---
async function kurierSubmitBestEffort(proof, publicSignals) {
  if (!KURIER_API_KEY) return;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(`https://api.kurier.xyz/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof, publicSignals }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    log("kurier submit -> HTTP " + res.status);
  } catch (e) {
    log("kurier submit skipped/failed (non-blocking): " + e.message);
  }
}

// --- Warm-up: one dummy prove at startup so the first real task is fast ---
let warm = false;
async function warmup() {
  const dummy = core.buildCircuitInput({
    registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    minimum: "1000", public_balance: "1460", expiry_block: "8430000", current_block: "8420000",
    recipient: "0xDe42000000000000000000000000000000009f01",
    condition_recipient: "0xDe42000000000000000000000000000000009f01",
    amount: "500", max_transfer: "1000",
  }, 1, "12345", "warmup");
  const t0 = Date.now();
  await core.proveDecision(dummy, WASM_PATH, ZKEY_PATH, vk);
  warm = true;
  log(`warmup prove ${((Date.now() - t0) / 1000).toFixed(1)}s verify=OK`);
}

async function handleTask(task) {
  const started = Date.now();
  const input = task.input || {};
  const taskId = String(task.task_id || "");
  if (taskId && responseCache[taskId]) {
    log(`task ${taskId}: replay cached response`);
    return responseCache[taskId];
  }
  // Proof-reuse check happens against the seen-set BEFORE the decision.
  const proofTx = input.proof_tx ? String(input.proof_tx) : "";
  const reused = proofTx ? seenProofTx.has(proofTx) : false;
  if (proofTx) {
    seenProofTx.add(proofTx);
    saveJson(SEEN_FILE, [...seenProofTx]);
  }
  const { decision, reason_code } = core.decide({ ...input, _proofReused: reused });
  if (reason_code === "MALFORMED_INPUT") {
    const body = { decision: "REJECT", reason_code, proof_tx: proofTx, proof: null, public_signals: null };
    if (taskId) { responseCache[taskId] = body; saveJson(CACHE_FILE, responseCache); }
    log(`task ${taskId}: REJECT/MALFORMED_INPUT proof=NO ${Date.now() - started}ms`);
    return body;
  }
  const salt = core.randomSalt();
  let proof = null;
  let publicSignals = null;
  let finalDecision = decision === 1 ? "APPROVE" : "REJECT";
  let finalReason = reason_code;
  try {
    const r = await core.proveDecision(core.buildCircuitInput(input, decision, salt, taskId), WASM_PATH, ZKEY_PATH, vk);
    proof = r.proof; publicSignals = r.publicSignals;
  } catch (e) {
    // The circuit asserts the decision it computes from the 13 public inputs.
    // A failed prove means our decision disagrees with the circuit.
    // - PROOF_REUSED is the one trap the circuit CANNOT express (no "seen"
    //   input): the circuit wants decision=1 for an otherwise-valid input, so
    //   NO valid proof exists for the correct REJECT. Return REJECT without
    //   proof (the platform excludes PROOF_REUSED tasks from the
    //   proof-reliability bonus).
    // - Any other mismatch: flip the decision once and retry; the circuit is
    //   the ground truth for the 13 public inputs.
    log(`task ${taskId}: prove failed (${e.message.slice(0, 120)}), reason=${reason_code}`);
    if (reason_code === "PROOF_REUSED") {
      proof = null; publicSignals = null;
    } else {
      const flipped = decision === 1 ? 0 : 1;
      try {
        const r2 = await core.proveDecision(core.buildCircuitInput(input, flipped, salt, taskId), WASM_PATH, ZKEY_PATH, vk);
        proof = r2.proof; publicSignals = r2.publicSignals;
        finalDecision = flipped === 1 ? "APPROVE" : "REJECT";
        finalReason = flipped === 1 ? "CIRCUIT_CORRECTED_APPROVE" : "CIRCUIT_ENFORCED_REJECT";
      } catch (e2) {
        log(`task ${taskId}: flipped prove also failed: ${e2.message.slice(0, 120)}`);
        proof = null; publicSignals = null;
      }
    }
  }
  if (!proof) { finalDecision = "REJECT"; finalReason = reason_code; }
  const body = {
    decision: finalDecision,
    reason_code: finalReason,
    proof_tx: proofTx,
    proof,
    public_signals: publicSignals,
  };
  if (taskId) { responseCache[taskId] = body; saveJson(CACHE_FILE, responseCache); }
  log(`task ${taskId}: ${finalDecision}/${finalReason} proof=${proof ? "yes" : "NO"} ${Date.now() - started}ms`);
  if (proof) kurierSubmitBestEffort(proof, publicSignals); // fire-and-forget
  return body;
}

function sendSigned(res, status, obj) {
  const raw = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };
  if (HMAC_SECRET) headers["x-agent-games-signature"] = core.hmacHex(HMAC_SECRET, raw);
  res.writeHead(status, headers);
  res.end(raw);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    try {
      if (req.method === "GET" || req.url === "/preflight") {
        return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      }
      if (req.method !== "POST") { res.writeHead(405); return res.end("method not allowed"); }
      if (HMAC_SECRET && !core.verifySignature(HMAC_SECRET, raw, req.headers["x-agent-games-signature"])) {
        log("HMAC mismatch from " + (req.socket.remoteAddress || "?"));
        res.writeHead(401); return res.end(JSON.stringify({ error: "bad signature" }));
      }
      // A validly signed POST that is not a Gatekeeper task is a platform
      // probe (preflight/health). The preflight POST is signed, must get
      // HTTP 200 + signed {"ok":true,"protocolVersion":"v1"} within 10s,
      // with a body <= 16 KB. A real task always parses and carries
      // type "agent-games.proof-gatekeeper.v1" + input + task_id.
      let task = null;
      let parseOk = true;
      try { task = JSON.parse(raw.toString("utf8")); } catch (e) { parseOk = false; }
      if (!parseOk || !task || task.preflight === true
          || task.type === "preflight" || task.type === "agent-games.preflight.v1") {
        return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      }
      if (task.type !== "agent-games.proof-gatekeeper.v1") {
        return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      }
      if (!task.input || !task.task_id) {
        return sendSigned(res, 400, { decision: "REJECT", reason_code: "MALFORMED_INPUT", proof_tx: "", proof: null, public_signals: null });
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
      sendSigned(res, 200, result);
    } catch (e) {
      log("handler error: " + e.message);
      try { sendSigned(res, 200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: "", proof: null, public_signals: null }); } catch (_) { /* socket gone */ }
    }
  });
});

warmup().then(() => {
  server.listen(PORT, "0.0.0.0", () => log(`gatekeeper agent listening on :${PORT} (warm=${warm}, hmac=${HMAC_SECRET ? "set" : "NOT SET"}, kurier=${KURIER_API_KEY ? "set" : "unset"})`));
}).catch((e) => {
  log("warmup FAILED: " + e.message + " — starting anyway (first task will be slow)");
  server.listen(PORT, "0.0.0.0", () => log(`gatekeeper agent listening on :${PORT} (warm=false)`));
});
