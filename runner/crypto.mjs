// SPDX-License-Identifier: GPL-3.0-or-later
// AES-256-GCM state-file crypto. The core (importStateKey/encryptState/
// decryptState) uses ONLY WebCrypto + Uint8Array and is kept line-identical
// with the app's dropcrypto.js — the three-way vector test in CI pins parity.
// AAD binds ciphertext to planId and format version: no plan-swap, no
// downgrade.

const IV_BYTES = 12;
const AAD_SUFFIX = "|1";

function aadFor(planId) {
  return new TextEncoder().encode(planId + AAD_SUFFIX);
}

export async function importStateKey(rawBytes) {
  if (!(rawBytes instanceof Uint8Array) || rawBytes.length !== 32) {
    throw new Error("state key must be 32 bytes");
  }
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// Fresh random IV per write — NEVER reuse an IV under the same key.
export async function encryptState(key, planId, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadFor(planId) },
      key,
      plainBytes,
    ),
  );
  return { iv, ct };
}

// Throws on tamper or AAD mismatch (wrong planId / format downgrade).
export async function decryptState(key, planId, ivBytes, ctBytes) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes, additionalData: aadFor(planId) },
      key,
      ctBytes,
    ),
  );
}

// --- state-file marshalling (Node-side; the app mirrors this in drop.js) ---

export function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function b64urlDecode(str) {
  return new Uint8Array(Buffer.from(String(str || ""), "base64url"));
}

// {v, alg, iv, ct, rev, at} — rev/at deliberately plaintext: freshness checks
// without decrypt; the commit log leaks timing anyway.
export function serializeStateFile(rev, atIso, iv, ct) {
  return JSON.stringify({
    v: 1,
    alg: "A256GCM",
    iv: b64urlEncode(iv),
    ct: b64urlEncode(ct),
    rev,
    at: atIso,
  });
}

export function parseStateFile(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    return null;
  }
  if (!obj || obj.v !== 1 || obj.alg !== "A256GCM") return null;
  if (typeof obj.iv !== "string" || typeof obj.ct !== "string") return null;
  if (!Number.isFinite(obj.rev) || obj.rev < 1) return null;
  return {
    iv: b64urlDecode(obj.iv),
    ct: b64urlDecode(obj.ct),
    rev: obj.rev,
    at: typeof obj.at === "string" ? obj.at : "",
  };
}
