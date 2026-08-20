// SPDX-License-Identifier: GPL-3.0-or-later
// Full runner suite — runs WITHOUT network. Usage:
//   TZ=Europe/Berlin node runner/test.mjs [path-to-putzii-checkout]
// The suite REQUIRES TZ=Europe/Berlin: it asserts the same pin apply.yml
// carries, so removing the pin turns this gate red.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { loadApp } from "./loadapp.mjs";
import { mintCheckin } from "./mint.mjs";
import { applyDispatch, CAPS, TAIL_MAX } from "./apply.mjs";
import {
  importStateKey,
  encryptState,
  decryptState,
  serializeStateFile,
  parseStateFile,
  b64urlEncode,
  b64urlDecode,
} from "./crypto.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appDir = process.argv[2] || process.env.PUTZII_DIR || path.join(here, "..", "..", "putzii");

let passed = 0;
const failures = [];
function check(name, ok, detail) {
  if (ok) passed++;
  else failures.push(`${name}${detail ? ` — ${detail}` : ""}`);
}
async function throws(name, fn) {
  try {
    await fn();
    check(name, false, "did not throw");
  } catch (e) {
    check(name, true);
  }
}

// ---- TZ pin gate ----
check("tz-pinned-env", process.env.TZ === "Europe/Berlin", `TZ=${process.env.TZ}`);
const applyYml = fs.readFileSync(path.join(here, "..", ".github", "workflows", "apply.yml"), "utf8");
check("tz-pinned-workflow", /TZ:\s*Europe\/Berlin/.test(applyYml));
// no-plaintext static gate: `${{ inputs.* }}` may ONLY appear on env-assignment
// lines (DROP_*: …) — never interpolated into run: script bodies.
const inputLines = applyYml.split("\n").filter((l) => l.includes("${{ inputs."));
check(
  "inputs-only-via-env",
  inputLines.length > 0 && inputLines.every((l) => /^\s*DROP_[A-Z_]+:\s*\$\{\{ inputs\./.test(l)),
  inputLines.join(" | "),
);

const PZ = loadApp(appDir);
const H = PZ.helpers;
check("modules-loaded", !!(PZ.helpers && PZ.model && PZ.share));

// TZ divergence semantics under the pin: Sun 22:30 UTC == Mon 00:30 CEST
check("weekkey-berlin", H.isoWeekKey(new Date(Date.UTC(2026, 7, 23, 22, 30))) === "2026-W35");
// DST day numbers advance exactly 1/day across both 2026 boundaries
for (const [label, y, m, days] of [["dst-start", 2026, 2, [27, 28, 29, 30, 31]], ["dst-end", 2026, 9, [23, 24, 25, 26, 27]]]) {
  const nums = days.map((d) => H.dayNumber(new Date(y, m, d, 12)));
  check(`${label}-daynumbers`, nums.every((v, i) => i === 0 || v - nums[i - 1] === 1), nums.join(","));
}

// ---- crypto ----
const keyBytes = new Uint8Array(32).map((_, i) => i * 7 + 1);
const key = await importStateKey(keyBytes);
{
  const plain = new TextEncoder().encode("hello state");
  const { iv, ct } = await encryptState(key, "planA", plain);
  check("crypto-iv-length", iv.length === 12);
  const back = await decryptState(key, "planA", iv, ct);
  check("crypto-roundtrip", new TextDecoder().decode(back) === "hello state");
  const { iv: iv2 } = await encryptState(key, "planA", plain);
  check("crypto-fresh-iv", b64urlEncode(iv) !== b64urlEncode(iv2));
  const tampered = ct.slice();
  tampered[0] ^= 1;
  await throws("crypto-tamper-throws", () => decryptState(key, "planA", iv, tampered));
  await throws("crypto-aad-mismatch-throws", () => decryptState(key, "planB", iv, ct));
  const fileText = serializeStateFile(3, "2026-08-20T12:00:00.000Z", iv, ct);
  const parsed = parseStateFile(fileText);
  check("statefile-roundtrip", parsed && parsed.rev === 3 && b64urlEncode(parsed.ct) === b64urlEncode(ct));
  check("statefile-rejects-junk", parseStateFile("{}") === null && parseStateFile("nope") === null);
}

// ---- fixtures ----
const NOW = Date.UTC(2026, 7, 20, 12, 0);
const mkPlan = () => ({
  v: 1,
  planId: "AbC123xy",
  name: "Testplan",
  updatedAt: 1755600000,
  areas: [
    { id: "kche1", name: "Küche", intervalDays: 7, createdAt: 1755000000, updatedAt: 1755000000, deletedAt: 0 },
    { id: "bad22", name: "Bad", intervalDays: 14, createdAt: 1755000000, updatedAt: 1755100000, deletedAt: 0 },
    { id: "gone9", name: "Alt", intervalDays: 7, createdAt: 1755000000, updatedAt: 1755200000, deletedAt: 1755200000 },
  ],
  people: [
    { id: "sina7", name: "Sina", createdAt: 1755000000, updatedAt: 1755000000, deletedAt: 0 },
    { id: "timo3", name: "Timo", createdAt: 1755000000, updatedAt: 1755000000, deletedAt: 0 },
  ],
  events: [
    { id: "abcde.1", areaId: "kche1", personId: "sina7", ts: Math.floor(Date.UTC(2026, 7, 18, 10, 5) / 60000) * 60000 },
  ],
  weeks: [{ id: "2026-W34", days: { 3: [["kche1", "sina7"]] }, createdAt: 1755000000, updatedAt: 1755000000 }],
  seq: {},
});
const TOKEN = "tok-sina-1234567890ab"; // test vector, not a secret — gitleaks:allow
const tokens = { sina7: createHash("sha256").update(TOKEN, "utf8").digest("hex") };

async function encodeEnvelope(plan) {
  const wire = PZ.share.wireFromPlan(plan, plan.events.length, false);
  return Buffer.from(gzipSync(Buffer.from(JSON.stringify(wire), "utf8"))).toString("base64url");
}

const allLogs = [];
function freshSite() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dropsite-"));
  fs.mkdirSync(path.join(dir, "plans"), { recursive: true });
  return dir;
}
async function run(siteDir, input, nowMs) {
  const res = await applyDispatch(
    { planId: "AbC123xy", personId: "sina7", token: TOKEN, clientRev: "0", ...input },
    { PZ, key, tokens, siteDir, nowMs: nowMs || NOW, runId: "run-test" },
  );
  allLogs.push(...res.log);
  if (res.code === 0) {
    fs.writeFileSync(res.writes.planPath, res.writes.stateText);
    fs.writeFileSync(res.writes.healthPath, res.writes.healthText);
  }
  return res;
}

// ---- mint ----
{
  const plan = mkPlan();
  const r1 = mintCheckin(PZ, plan, "bad22", "timo3", NOW);
  check("mint-id-format", r1.event && r1.event.id === "gtimo3.1", r1.event && r1.event.id);
  check("mint-quantized", r1.event.ts % 60000 === 0 && r1.event.ts === Math.floor(NOW / 60000) * 60000);
  plan.events.push(r1.event);
  const r2 = mintCheckin(PZ, plan, "bad22", "timo3", NOW + 5 * 60000);
  check("mint-idempotent-10min", r2.noop === true);
  const r3 = mintCheckin(PZ, plan, "bad22", "timo3", NOW + 11 * 60000);
  check("mint-seq-increments", r3.event && r3.event.id === "gtimo3.2", r3.event && r3.event.id);
  check("mint-unknown-area", mintCheckin(PZ, plan, "nope", "timo3", NOW).error === "unknown-area");
  check("mint-deleted-area", mintCheckin(PZ, plan, "gone9", "timo3", NOW).error === "unknown-area");
}

// ---- apply pipeline ----
{
  const site = freshSite();
  // auth
  const bad = await run(site, { mode: "checkin", payload: "kche1", nonce: "aaaa2222", token: "wrong-token-123" });
  check("apply-authfail", bad.code === 2 && bad.reason === "auth");
  const unknownPerson = await applyDispatch(
    { mode: "checkin", planId: "AbC123xy", personId: "ghost", token: TOKEN, nonce: "aaaa3333", payload: "kche1" },
    { PZ, key, tokens, siteDir: site, nowMs: NOW, runId: "run-test" },
  );
  check("apply-unknown-person", unknownPerson.code === 2 && unknownPerson.reason === "auth");
  check("apply-authfail-no-state", !fs.existsSync(path.join(site, "plans", "AbC123xy.json")));

  // first write via envelope
  const env1 = await run(site, { mode: "envelope", payload: await encodeEnvelope(mkPlan()), nonce: "bbbb2222" });
  check("apply-first-write", env1.code === 0, env1.reason);
  const stateFile = parseStateFile(fs.readFileSync(path.join(site, "plans", "AbC123xy.json"), "utf8"));
  check("apply-first-rev", stateFile && stateFile.rev === 1);
  const health1 = JSON.parse(fs.readFileSync(path.join(site, "health.json"), "utf8"));
  check("apply-health-tail", health1.rev === 1 && health1.tail.length === 1 && health1.tail[0].nonce === "bbbb2222");

  // state file decrypts back to the same plan (uncapped)
  const back = await decryptState(key, "AbC123xy", stateFile.iv, stateFile.ct);
  const { gunzipSync } = await import("node:zlib");
  const backPlan = PZ.share.planFromWire(JSON.parse(Buffer.from(gunzipSync(back)).toString("utf8"))).plan;
  check("state-roundtrip-counts", backPlan.events.length === 1 && backPlan.areas.length === 3 && backPlan.weeks.length === 1);

  // replay
  const replay = await run(site, { mode: "envelope", payload: await encodeEnvelope(mkPlan()), nonce: "bbbb2222" });
  check("apply-replay-noop", replay.code === 3 && replay.reason === "replay");

  // checkin mints and merges
  const chk = await run(site, { mode: "checkin", payload: "bad22", nonce: "cccc2222" });
  check("apply-checkin", chk.code === 0 && chk.log.some((l) => l.includes('"minted":1')), JSON.stringify(chk.log));
  const state2 = parseStateFile(fs.readFileSync(path.join(site, "plans", "AbC123xy.json"), "utf8"));
  check("apply-rev-bump", state2 && state2.rev === 2);

  // idempotent checkin still confirms the nonce
  const chk2 = await run(site, { mode: "checkin", payload: "bad22", nonce: "dddd2222" }, NOW + 4 * 60000);
  check("apply-checkin-idempotent", chk2.code === 0 && chk2.log.some((l) => l.includes('"minted":0')));
  const health2 = JSON.parse(fs.readFileSync(path.join(site, "health.json"), "utf8"));
  check("apply-idempotent-nonce-in-tail", health2.tail.some((t) => t.nonce === "dddd2222"));

  // unknown area via dispatch
  const badArea = await run(site, { mode: "checkin", payload: "zzzzz", nonce: "eeee2222" });
  check("apply-unknown-area", badArea.code === 2 && badArea.reason === "unknown-area");

  // caps: 501 events
  const fat = mkPlan();
  for (let i = 1; i <= 501; i++) {
    fat.events.push({ id: `flood.${i.toString(36)}`, areaId: "kche1", personId: "sina7", ts: Math.floor((NOW - i * 60000) / 60000) * 60000 });
  }
  const capped = await run(site, { mode: "envelope", payload: await encodeEnvelope(fat), nonce: "ffff2222" });
  check("apply-caps-events", capped.code === 2 && capped.reason === "caps");

  // payload too large
  const big = await run(site, { mode: "envelope", payload: "A".repeat(CAPS.payloadChars + 1), nonce: "gggg2222" });
  check("apply-payload-size", big.code === 2 && big.reason === "payload-size");

  // planId mismatch
  const other = mkPlan();
  other.planId = "Other000";
  const mm = await run(site, { mode: "envelope", payload: await encodeEnvelope(other), nonce: "hhhh2222" });
  check("apply-planid-mismatch", mm.code === 2 && mm.reason === "planid-mismatch");

  // garbage payload
  const junk = await run(site, { mode: "envelope", payload: "not-base64-gzip!!", nonce: "jjjj2222" });
  check("apply-wire-junk", junk.code === 2 && junk.reason === "wire");

  // no-plan checkin
  const site2 = freshSite();
  const noplan = await run(site2, { mode: "checkin", payload: "kche1", nonce: "kkkk2222" });
  check("apply-checkin-no-plan", noplan.code === 2 && noplan.reason === "no-plan");

  // rate guard: full fresh tail
  const site3 = freshSite();
  const freshTail = Array.from({ length: TAIL_MAX }, (_, i) => ({
    at: new Date(NOW - i * 30000).toISOString(),
    by: "sina7",
    nonce: `rate${i.toString(36)}xx`,
    run: "x",
    rev: i + 1,
    counts: {},
  }));
  fs.writeFileSync(path.join(site3, "health.json"), JSON.stringify({ rev: 50, at: "", lastRunId: "", tail: freshTail }));
  const rated = await run(site3, { mode: "envelope", payload: await encodeEnvelope(mkPlan()), nonce: "mmmm2222" });
  check("apply-rate-guard", rated.code === 2 && rated.reason === "rate");

  // state swap across plans fails on AAD
  const siteSwap = freshSite();
  await run(siteSwap, { mode: "envelope", payload: await encodeEnvelope(mkPlan()), nonce: "nnnn2222" });
  const swapTokens = { ...tokens };
  const swapped = await applyDispatch(
    { mode: "checkin", planId: "AbC123xy", personId: "sina7", token: TOKEN, nonce: "pppp2222", payload: "kche1" },
    { PZ, key: await importStateKey(new Uint8Array(32).map((_, i) => i + 99)), tokens: swapTokens, siteDir: siteSwap, nowMs: NOW, runId: "t" },
  );
  check("apply-wrong-key-fatal", swapped.code === 2 && swapped.reason === "decrypt");
}

// ---- no-plaintext-in-log gate (dynamic): names & payload never in logs ----
{
  const banned = ["Küche", "Sina", "Timo", "Testplan", TOKEN];
  const joined = allLogs.join("\n");
  for (const marker of banned) {
    check(`log-clean-${marker.slice(0, 6)}`, !joined.includes(marker));
  }
}

const total = passed + failures.length;
if (failures.length) {
  console.log(JSON.stringify({ ok: false, passed, total, failures }, null, 1));
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, passed, total }));
