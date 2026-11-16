// Pure Gatekeeper logic shared by the persistent server (server.js) and the
// Vercel serverless adapter (api/index.js). No HTTP, no state — just the
// decision rules, the circuit input encoding, and the snarkjs prove/verify
// helpers. The circuit (GatekeeperEvaluation_79) enforces that the claimed
// decision matches the one computed from the 13 public inputs; it CANNOT
// express PROOF_REUSED (no "seen" input), so a reuse-based REJECT has no
// valid proof by construction.
"use strict";
const crypto = require("crypto");
const snarkjs = require("snarkjs");

const FIELD_P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const modP = (hexOrDec) => {
  const s = String(hexOrDec);
  const v = s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s);
  return v % FIELD_P;
};
const toField = (v) => modP(v).toString();
const addrToField = (addr) => BigInt(String(addr)).toString();
const taskIdToField = (taskId) =>
  (BigInt("0x" + crypto.createHash("sha256").update(String(taskId)).digest("hex")) % FIELD_P).toString();
// NOTE: taskId encoding (sha256(task_id) mod p) is an ASSUMPTION — must be
// validated against a real practice task before trusting the reliability bonus.

// --- Decision logic: the 7 traps, fail-closed. Returns {decision: 0|1, reason_code} ---
function decide(input) {
  const need = ["registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block",
    "current_block", "recipient", "condition_recipient", "amount", "max_transfer", "proof_tx"];
  for (const k of need) {
    if (input[k] === undefined || input[k] === null || input[k] === "") {
      return { decision: 0, reason_code: "MALFORMED_INPUT" };
    }
  }
  if (toField(input.proof_vk) !== toField(input.registered_vk)) {
    return { decision: 0, reason_code: "VK_SUBSTITUTION" };
  }
  if (BigInt(String(input.public_balance)) < BigInt(String(input.minimum))) {
    return { decision: 0, reason_code: "THRESHOLD_MISMATCH" };
  }
  if (BigInt(String(input.expiry_block)) <= BigInt(String(input.current_block))) {
    return { decision: 0, reason_code: "EXPIRED_CONDITION" };
  }
  if (addrToField(input.recipient) !== addrToField(input.condition_recipient)) {
    return { decision: 0, reason_code: "RECIPIENT_MISMATCH" };
  }
  if (BigInt(String(input.amount)) > BigInt(String(input.max_transfer))) {
    return { decision: 0, reason_code: "AMOUNT_OVERFLOW" };
  }
  if (input._proofReused === true) {
    return { decision: 0, reason_code: "PROOF_REUSED" };
  }
  return { decision: 1, reason_code: "VALID_CONDITION" };
}

function buildCircuitInput(input, decision, salt, taskId) {
  return {
    registeredVkHash: toField(input.registered_vk),
    proofVkHash: toField(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: addrToField(input.recipient),
    conditionRecipient: addrToField(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: String(decision),
    taskId: taskIdToField(taskId),
    salt,
  };
}

function randomSalt() {
  return (BigInt("0x" + crypto.randomBytes(31).toString("hex")) % FIELD_P).toString();
}

async function proveDecision(circuitInput, wasmPath, zkeyPath, vk) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasmPath, zkeyPath);
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) throw new Error("local proof verification failed");
  return { proof, publicSignals };
}

// --- HMAC helpers (x-agent-games-signature over the raw body) ---
function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
function verifySignature(secret, rawBody, header) {
  if (!secret || !header) return false;
  const given = String(header).trim();
  for (const c of [hmacHex(secret, rawBody), "sha256=" + hmacHex(secret, rawBody)]) {
    const a = Buffer.from(given);
    const b = Buffer.from(c);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

module.exports = {
  FIELD_P, modP, toField, addrToField, taskIdToField,
  decide, buildCircuitInput, randomSalt, proveDecision,
  hmacHex, verifySignature,
};
