// SPDX-License-Identifier: GPL-3.0-or-later
// The dispatch applier. ORDER IS THE SECURITY DESIGN:
//   (1) auth FIRST — timing-safe token check before parsing any attacker byte
//   (2) load + decrypt state (missing file → first write)
//   (3) replay guard (nonce in tail → no-op) + rate guard
//   (4) build remote plan (checkin → mint; envelope → gunzip → planFromWire)
//   (5) mergePlans VERBATIM from the app
//   (6) re-encrypt with a fresh IV, rev+1, health tail append
//   (7) log COUNTS ONLY — never names, never payload
// Exit codes: 0 = state written (commit me), 2 = fatal (auth/validation,
// never retried), 3 = no-op (replay — already applied, nothing to commit).
import fs from "node:fs";
import path from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { loadApp } from "./loadapp.mjs";
import { mintCheckin } from "./mint.mjs";
import {
  importStateKey,
  encryptState,
  decryptState,
  serializeStateFile,
  parseStateFile,
  b64urlDecode,
} from "./crypto.mjs";

export const CAPS = {
  payloadChars: 64 * 1024,
  gunzipBytes: 512 * 1024,
  events: 500,
  areas: 200,
  people: 200,
  weeks: 400,
};
export const TAIL_MAX = 50;
// The tail holds TAIL_MAX entries, so ">60 pushes/h" is measured as: tail
// full AND its oldest entry younger than TAIL_MAX minutes (a sustained
// >1 push/min). A household never gets near this; a leaked token does.
const RATE_WINDOW_MS = TAIL_MAX * 60 * 1000;

const RE_PLAN_ID = /^[A-Za-z0-9_-]{1,32}$/;
const RE_PERSON_ID = /^[A-Za-z0-9_-]{1,32}$/;
const RE_NONCE = /^[a-z2-9]{4,32}$/;

function sha256Hex(str) {
  return createHash("sha256").update(str, "utf8").digest("hex");
}

function fatal(reason) {
  return { code: 2, reason, log: [`fatal reason=${reason}`] };
}

function defaultHealth() {
  return { rev: 0, at: "", lastRunId: "", tail: [] };
}

// input: {mode, planId, personId, token, nonce, payload, clientRev}
// deps:  {PZ, key, tokens, siteDir, nowMs, runId}
export async function applyDispatch(input, deps) {
  const { PZ, key, tokens, siteDir, nowMs, runId } = deps;
  const log = [];

  // ---- (0) shape-only guards; no attacker payload parsed yet ----
  const mode = input.mode === "envelope" || input.mode === "checkin" ? input.mode : "";
  if (!mode) return fatal("mode");
  if (!RE_PLAN_ID.test(String(input.planId || ""))) return fatal("planid-shape");
  if (!RE_PERSON_ID.test(String(input.personId || ""))) return fatal("personid-shape");
  if (!RE_NONCE.test(String(input.nonce || ""))) return fatal("nonce-shape");
  const token = String(input.token || "");
  if (token.length < 8 || token.length > 128) return fatal("token-shape");

  // ---- (1) AUTH FIRST, timing-safe ----
  const expected = tokens && typeof tokens === "object" ? tokens[input.personId] : null;
  if (typeof expected !== "string" || expected.length !== 64) return fatal("auth");
  const actual = sha256Hex(token);
  if (!timingSafeEqual(Buffer.from(actual, "utf8"), Buffer.from(expected, "utf8"))) {
    return fatal("auth");
  }
  log.push(`auth=ok person=${input.personId} mode=${mode} clientRev=${Number(input.clientRev) || 0}`);

  // ---- (2) load + decrypt current state ----
  const planPath = path.join(siteDir, "plans", `${input.planId}.json`);
  let basePlan = null;
  let baseRev = 0;
  if (fs.existsSync(planPath)) {
    const file = parseStateFile(fs.readFileSync(planPath, "utf8"));
    if (!file) return fatal("statefile");
    let plainBytes;
    try {
      // AAD binds ciphertext to planId — a swapped file fails right here.
      plainBytes = await decryptState(key, input.planId, file.iv, file.ct);
    } catch (e) {
      return fatal("decrypt");
    }
    let wire;
    try {
      wire = JSON.parse(
        Buffer.from(gunzipSync(plainBytes, { maxOutputLength: CAPS.gunzipBytes })).toString("utf8"),
      );
      basePlan = PZ.share.planFromWire(wire).plan;
    } catch (e) {
      return fatal("state-decode");
    }
    baseRev = file.rev;
  }

  // ---- (3) replay + rate guards ----
  const healthPath = path.join(siteDir, "health.json");
  let health = defaultHealth();
  if (fs.existsSync(healthPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(healthPath, "utf8"));
      if (parsed && Array.isArray(parsed.tail)) health = parsed;
    } catch (e) {
      /* corrupt health: rebuild from scratch, state file is the truth */
    }
  }
  const tail = health.tail.filter((t) => t && typeof t === "object");
  if (tail.some((t) => t.nonce === input.nonce)) {
    return { code: 3, reason: "replay", log: [...log, "replay: nonce already applied"] };
  }
  if (tail.length >= TAIL_MAX) {
    const oldest = Date.parse(tail[tail.length - 1].at || "");
    if (Number.isFinite(oldest) && nowMs - oldest < RATE_WINDOW_MS) return fatal("rate");
  }

  // ---- (4) build the remote plan ----
  let remotePlan;
  let minted = 0;
  if (mode === "checkin") {
    const areaId = String(input.payload || "");
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(areaId)) return fatal("areaid-shape");
    if (!basePlan) return fatal("no-plan");
    const res = mintCheckin(PZ, basePlan, areaId, input.personId, nowMs);
    if (res.error) return fatal(res.error);
    // idempotent no-op still appends the nonce to the tail below — the
    // client's write-confirmation looks for it there.
    remotePlan = {
      v: 1,
      planId: input.planId,
      name: "",
      updatedAt: 0,
      areas: [],
      people: [],
      events: res.event ? [res.event] : [],
      weeks: [],
      seq: {},
    };
    minted = res.event ? 1 : 0;
  } else {
    const payload = String(input.payload || "");
    if (!payload || payload.length > CAPS.payloadChars) return fatal("payload-size");
    let decoded;
    try {
      const gz = b64urlDecode(payload);
      const json = Buffer.from(gunzipSync(gz, { maxOutputLength: CAPS.gunzipBytes })).toString("utf8");
      decoded = PZ.share.planFromWire(JSON.parse(json));
    } catch (e) {
      return fatal("wire");
    }
    remotePlan = decoded.plan;
    if (remotePlan.planId !== input.planId) return fatal("planid-mismatch");
    if (
      remotePlan.events.length > CAPS.events ||
      remotePlan.areas.length > CAPS.areas ||
      remotePlan.people.length > CAPS.people ||
      remotePlan.weeks.length > CAPS.weeks
    ) {
      return fatal("caps");
    }
  }

  // ---- (5) the app's merge, verbatim ----
  let merged;
  try {
    merged = PZ.share.mergePlans(basePlan, remotePlan, nowMs);
  } catch (e) {
    return fatal("merge");
  }
  const counts = merged.summary;
  counts.minted = minted;

  // ---- (6) re-encrypt (fresh IV), rev+1, health tail append ----
  const plan = merged.plan;
  const wireOut = PZ.share.wireFromPlan(plan, plan.events.length, false);
  const plainBytes = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(wireOut), "utf8")));
  const { iv, ct } = await encryptState(key, input.planId, plainBytes);
  const rev = baseRev + 1;
  const atIso = new Date(nowMs).toISOString();
  const stateText = serializeStateFile(rev, atIso, iv, ct);
  const entry = { at: atIso, by: input.personId, nonce: input.nonce, run: runId, rev, counts };
  const healthText = JSON.stringify(
    { rev, at: atIso, lastRunId: runId, tail: [entry, ...tail].slice(0, TAIL_MAX) },
    null,
    1,
  );

  // ---- (7) counts only ----
  log.push(`rev=${rev} counts=${JSON.stringify(counts)}`);
  return { code: 0, reason: "applied", log, writes: { planPath, stateText, healthPath, healthText } };
}

// ---- workflow entry point: everything arrives via env, never argv ----
async function main() {
  const env = process.env;
  const siteDir = env.SITE_DIR || "site";
  const PZ = loadApp(env.PUTZII_DIR || "putzii-app");
  const keyBytes = b64urlDecode(env.DROP_KEY_B64 || "");
  if (keyBytes.length !== 32) {
    console.log("fatal reason=key-config");
    process.exit(2);
  }
  const key = await importStateKey(keyBytes);
  let tokens = null;
  try {
    tokens = JSON.parse(env.DROP_TOKENS_SHA256 || "");
  } catch (e) {
    console.log("fatal reason=tokens-config");
    process.exit(2);
  }
  const result = await applyDispatch(
    {
      mode: env.DROP_MODE,
      planId: env.DROP_PLAN_ID,
      personId: env.DROP_PERSON_ID,
      token: env.DROP_TOKEN,
      nonce: env.DROP_NONCE,
      payload: env.DROP_PAYLOAD,
      clientRev: env.DROP_CLIENT_REV,
    },
    { PZ, key, tokens, siteDir, nowMs: Date.now(), runId: env.GITHUB_RUN_ID || "" },
  );
  for (const line of result.log) console.log(line);
  if (result.code === 0) {
    fs.mkdirSync(path.dirname(result.writes.planPath), { recursive: true });
    fs.writeFileSync(result.writes.planPath, result.writes.stateText);
    fs.writeFileSync(result.writes.healthPath, result.writes.healthText);
  }
  process.exit(result.code);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
