// Local end-to-end test for the Gatekeeper agent.
// Starts server.js on port 18080 with a test HMAC secret, waits for warmup,
// then sends: 1 valid task + 6 trap tasks + 1 reuse + 1 duplicate + 1 tampered
// request + 1 preflight. Verifies decision, reason_code, snarkjs proof validity
// (against verification_key.json) and the response HMAC signature.
"use strict";
const { spawn } = require("child_process");
const crypto = require("crypto");
const http = require("http");
const path = require("path");
const fs = require("fs");

const SECRET = "test-hmac-secret-123";
const PORT = 18080;
const BASE = `http://127.0.0.1:${PORT}`;
const snarkjs = require(path.join(__dirname, "node_modules", "snarkjs"));
const vk = JSON.parse(fs.readFileSync(path.join(__dirname, "verification_key.json"), "utf8"));

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0xa4c1b8ff00000000000000000000000000000000000000000000000000000000";
const RECIP = "0xDe42000000000000000000000000000000009f01";
const OTHER_RECIP = "0x1111111111111111111111111111111111111111";

function baseInput(over) {
  return {
    registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
    expiry_block: "8430000", current_block: "8420000",
    recipient: RECIP, condition_recipient: RECIP,
    amount: "500", max_transfer: "1000", proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000001",
    ...over,
  };
}
function task(id, input) {
  const now = new Date();
  return {
    type: "agent-games.proof-gatekeeper.v1", task_id: id, mode: "competition",
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60000).toISOString(),
    input,
  };
}
function sign(raw) { return crypto.createHmac("sha256", SECRET).update(raw).digest("hex"); }
function post(pathname, obj, { badSig = false, noSig = false } = {}) {
  return new Promise((resolve, reject) => {
    const raw = JSON.stringify(obj);
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(raw) };
    if (!noSig) headers["x-agent-games-signature"] = badSig ? "deadbeef" : sign(raw);
    const req = http.request(BASE + pathname, { method: "POST", headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    req.write(raw); req.end();
  });
}
function get(pathname) {
  return new Promise((resolve, reject) => {
    http.get(BASE + pathname, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    }).on("error", reject);
  });
}
async function waitReady(secs) {
  for (let i = 0; i < secs; i++) {
    try { const r = await get("/"); if (r.status === 200) return true; } catch (e) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

(async () => {
  const server = spawn("node", ["server.js"], {
    cwd: __dirname,
    env: { ...process.env, HMAC_SECRET: SECRET, PORT: String(PORT), STATE_DIR: path.join(__dirname, "state-test") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => process.stdout.write("[server] " + d));
  server.stderr.on("data", (d) => process.stdout.write("[server:err] " + d));
  const ready = await waitReady(400);
  if (!ready) { console.error("SERVER DID NOT BECOME READY"); server.kill("SIGKILL"); process.exit(1); }

  let pass = 0, fail = 0;
  const check = (name, cond, extra = "") => {
    console.log((cond ? "PASS" : "FAIL") + "  " + name + (extra ? "  " + extra : ""));
    cond ? pass++ : fail++;
  };

  // Preflight
  const pf = await get("/");
  check("preflight GET / -> ok v1", pf.status === 200 && JSON.parse(pf.body).ok === true && JSON.parse(pf.body).protocolVersion === "v1");
  check("preflight response is HMAC-signed", !!pf.headers["x-agent-games-signature"] && pf.headers["x-agent-games-signature"] === sign(pf.body));

  async function runTask(name, t, expectDecision, expectReason, expectNoProof = false) {
    const r = await post("/", t);
    let ok = r.status === 200;
    let body = null;
    try { body = JSON.parse(r.body); } catch (e) { ok = false; }
    if (!body) { check(name, false, "status=" + r.status); return null; }
    const decOk = body.decision === expectDecision;
    const reasonOk = body.reason_code === expectReason;
    let proofOk = false, sigOk = false;
    if (expectNoProof) {
      // PROOF_REUSED: the circuit cannot express a reuse-based reject, so no
      // valid proof exists for the correct REJECT. Expect proof=null.
      proofOk = body.proof === null && body.public_signals === null;
    } else if (body.proof && body.public_signals) {
      try { proofOk = await snarkjs.groth16.verify(vk, body.public_signals, body.proof); } catch (e) { proofOk = false; }
    }
    sigOk = r.headers["x-agent-games-signature"] === sign(r.body);
    // public signals must echo the task inputs (only when a proof exists)
    const ps = body.public_signals || [];
    const echoOk = expectNoProof || (ps.length === 13 && ps[3] === String(t.input.minimum) && ps[4] === String(t.input.public_balance)
      && ps[11] === (expectDecision === "APPROVE" ? "1" : "0"));
    check(`${name}: decision=${body.decision} reason=${body.reason_code}`, decOk && reasonOk, `got ${body.decision}/${body.reason_code}`);
    check(`${name}: ${expectNoProof ? "no proof (expected for reuse)" : "proof verifies (snarkjs)"}`, proofOk);
    check(`${name}: response HMAC valid + public signals echo task`, sigOk && echoOk);
    return body;
  }

  const t1 = task("gk_test_1", baseInput({}));
  const b1 = await runTask("VALID -> APPROVE", t1, "APPROVE", "VALID_CONDITION");
  await runTask("THRESHOLD -> REJECT", task("gk_test_2", baseInput({ public_balance: "500", proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000002" })), "REJECT", "THRESHOLD_MISMATCH");
  await runTask("VK_SUBSTITUTION -> REJECT", task("gk_test_3", baseInput({ proof_vk: OTHER_VK, proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000003" })), "REJECT", "VK_SUBSTITUTION");
  await runTask("EXPIRED -> REJECT", task("gk_test_4", baseInput({ expiry_block: "8420000", proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000004" })), "REJECT", "EXPIRED_CONDITION");
  await runTask("RECIPIENT -> REJECT", task("gk_test_5", baseInput({ condition_recipient: OTHER_RECIP, proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000005" })), "REJECT", "RECIPIENT_MISMATCH");
  await runTask("AMOUNT_OVERFLOW -> REJECT", task("gk_test_6", baseInput({ amount: "1500", proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000006" })), "REJECT", "AMOUNT_OVERFLOW");
  // Proof reuse: same proof_tx as the valid task, everything else valid.
  // No valid proof can exist for this REJECT (circuit cannot express reuse),
  // so expect proof=null / public_signals=null.
  await runTask("PROOF_REUSED -> REJECT", task("gk_test_7", baseInput({ proof_tx: "0xabc0000000000000000000000000000000000000000000000000000000000001" })), "REJECT", "PROOF_REUSED", true);
  // Duplicate task_id -> cached identical response.
  const dup = await post("/", t1);
  check("duplicate task_id replays cached APPROVE", dup.status === 200 && JSON.parse(dup.body).decision === "APPROVE"
    && JSON.stringify(JSON.parse(dup.body).proof) === JSON.stringify(b1.proof));
  // Tampered / missing signature -> 401.
  const bad = await post("/", t1, { badSig: true });
  check("tampered signature -> 401", bad.status === 401);
  const nosig = await post("/", t1, { noSig: true });
  check("missing signature -> 401", nosig.status === 401);
  // Malformed task -> REJECT response (signed), not a crash.
  const mal = await post("/", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_bad", input: {} });
  check("malformed input -> signed REJECT", mal.status === 400 || JSON.parse(mal.body).decision === "REJECT");
  // Signed non-task POSTs are platform probes -> preflight response (200).
  const pf2 = await post("/", { type: "preflight" });
  check("signed {type:preflight} POST -> 200 preflight", pf2.status === 200 && JSON.parse(pf2.body).ok === true);
  const pf3 = await post("/", { hello: "probe" });
  check("signed unknown-type POST -> 200 preflight", pf3.status === 200 && JSON.parse(pf3.body).ok === true);
  // Signed unparseable body -> preflight response (a real task always parses).
  const pf4 = await new Promise((resolve, reject) => {
    const raw = "not json at all";
    const req = http.request(BASE + "/", { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(raw), "x-agent-games-signature": sign(raw) } }, (res) => {
      const chunks = []; res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject); req.write(raw); req.end();
  });
  check("signed unparseable body -> 200 preflight", pf4.status === 200 && JSON.parse(pf4.body).ok === true);

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  server.kill("SIGKILL");
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("TEST FATAL", e); process.exit(1); });
