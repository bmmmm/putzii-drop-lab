// SPDX-License-Identifier: GPL-3.0-or-later
// Generate crypto parity vectors (Node side) for the Go test suite.
// Usage: node runner/genvectors.mjs <outfile>
// Deterministic: fixed keys/IVs derived via sha256 — vector files are
// regenerated in CI, never hand-edited.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { b64urlEncode } from "./crypto.mjs";

const subtle = crypto.subtle;

function det(label, len) {
  const out = new Uint8Array(len);
  let pos = 0;
  let counter = 0;
  while (pos < len) {
    const block = createHash("sha256").update(`${label}:${counter++}`).digest();
    const take = Math.min(block.length, len - pos);
    out.set(block.subarray(0, take), pos);
    pos += take;
  }
  return out;
}

async function encryptWithIv(keyBytes, planId, iv, plain) {
  const key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const aad = new TextEncoder().encode(planId + "|1");
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plain));
}

const cases = [
  { name: "short", planId: "AbC123xy", plain: new TextEncoder().encode("hello drop") },
  { name: "empty", planId: "AbC123xy", plain: new Uint8Array(0) },
  { name: "other-plan", planId: "Zz9_-Pl0", plain: new TextEncoder().encode("bound to another plan") },
  { name: "gzip-wire", planId: "AbC123xy", plain: new Uint8Array(gzipSync(Buffer.from(JSON.stringify([1, "AbC123xy", "Testplan", 1755600000, 29785167, [["kche1", "Küche", 7, 1755000000, 1755000000, 0]], [["sina7", "Sina", 1755000000, 1755000000, 0]], [["abcde.1", "kche1", "sina7", 0]], 0, []]), "utf8"))) },
  { name: "big", planId: "AbC123xy", plain: det("big-plain", 100 * 1024) },
];

const vectors = [];
for (const c of cases) {
  const key = det(`key:${c.name}`, 32);
  const iv = det(`iv:${c.name}`, 12);
  const ct = await encryptWithIv(key, c.planId, iv, c.plain);
  vectors.push({
    name: c.name,
    planId: c.planId,
    key: b64urlEncode(key),
    iv: b64urlEncode(iv),
    plain: b64urlEncode(c.plain),
    ct: b64urlEncode(ct),
  });
}

fs.mkdirSync(require_dir(process.argv[2]), { recursive: true });
fs.writeFileSync(process.argv[2], JSON.stringify({ v: 1, vectors }, null, 1));
console.log(`wrote ${vectors.length} vectors to ${process.argv[2]}`);

function require_dir(p) {
  return p.split("/").slice(0, -1).join("/") || ".";
}
