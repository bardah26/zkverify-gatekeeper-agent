# Proof Gatekeeper agent — zkVerify Agent Games

Node.js agent for the **Proof Gatekeeper** track. Verifies the platform's HMAC,
decides APPROVE/REJECT from the 7 known traps (fail-closed), generates a local
Groth16 proof with snarkjs, and returns a signed response — all in ~0.3–0.4 s
per task (warm), well inside the 60 s deadline.

## Files

| File | What it is |
|---|---|
| `server.js` | Persistent HTTP server (port 8080). Disk-persisted seen-set + response cache in `state/`. |
| `api/index.js` | Vercel serverless adapter (same logic; in-memory seen-set only). |
| `gatekeeper-core.js` | Shared logic: 7-trap decision, circuit input encoding, prove/verify, HMAC. |
| `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` | Official Gatekeeper circuit artifacts (see `../circuits/` for the PoC). |
| `test-local.js` | End-to-end test (30 checks). |
| `vercel.json` | Vercel function config (maxDuration 60 s, includeFiles for the circuit). |

## Config (env)

- `HMAC_SECRET` — the secret returned once by `addAgentAction` at registration.
  (Or `HMAC_SECRET_FILE` pointing at a file containing it.)
- `PORT` — default 8080 (persistent server only).
- `KURIER_API_KEY` — optional. If set, the agent's own proof is submitted to
  Kurier (best-effort, non-blocking, 8 s cap). Never blocks the response.
- `STATE_DIR` — default `./state` (persistent server only).

## Run locally

```bash
npm install
HMAC_SECRET=test-secret PORT=8080 node server.js
# test:
node test-local.js   # 30 checks, expect "30 pass, 0 fail"
```

## Deploy (recommended: Vercel Hobby, free, no card)

1. Create a Vercel account (GitHub login, no card) and a project from this
   `agent/` directory (the repo is created later by the parent; the agent dir
   is deployable as-is).
2. Set env var `HMAC_SECRET` in the Vercel project (the secret from agent
   registration). Optional: `KURIER_API_KEY`.
3. Deploy. The endpoint is `https://<project>.vercel.app/api`.
4. Sanity-check from the outside: `GET https://<project>.vercel.app/api`
   must return `{"ok":true,"protocolVersion":"v1"}`.
5. Register the agent in the zkVerify dashboard (Manage Agents) with that URL,
   save the returned HMAC secret into the Vercel env var, run preflight,
   then run a practice task from `/dashboard/practice`.

Caveats: Vercel is stateless, so the `proof_tx` seen-set (PROOF_REUSED trap)
lives only in a warm instance's memory — best-effort. Cold start is ~3 s,
proving ~1 s, so the 10 s preflight window and the 60 s task deadline are
both comfortable. Verify after deploy that the `.wasm`/`.zkey` are in the
bundle (vercel.json `includeFiles` covers this; a signed test POST that
returns a verifying proof confirms it).

## Persistent-server alternative

Any always-on host (Render/Railway/a VPS) can run `server.js`. It keeps the
seen-set and response cache on disk, so PROOF_REUSED detection survives
restarts. Render's free tier sleeps after 15 min idle (~50 s wake-up), which
is risky against the 60 s deadline — prefer Vercel or a host that doesn't sleep.

## Decision rules (fail-closed)

Order: VK_SUBSTITUTION → THRESHOLD_MISMATCH → EXPIRED_CONDITION →
RECIPIENT_MISMATCH → AMOUNT_OVERFLOW → PROOF_REUSED → VALID_CONDITION
(APPROVE). Any missing field, any prove failure, any timeout → REJECT.

Known circuit fact: the circuit (`GatekeeperEvaluation_79`) asserts the
decision it computes from the 13 public inputs, so a wrong decision cannot
be proven. PROOF_REUSED is the one trap the circuit cannot express (no
"seen" input) — for it the agent correctly returns REJECT with
`proof: null, public_signals: null`; the platform excludes PROOF_REUSED
tasks from the proof-reliability bonus.

## Open assumptions (validate in practice mode)

- `taskId` signal = `sha256(task_id string) mod p`. Not yet confirmed by the
  platform; a practice task will show whether the platform accepts our proof
  (if it rejects it, the encoding is wrong).
- The platform verifies our proof + public signals offline against its own
  registered VK; on-chain submission of our own proof is optional (Kurier).
