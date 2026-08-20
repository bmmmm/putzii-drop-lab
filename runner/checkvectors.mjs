// SPDX-License-Identifier: GPL-3.0-or-later
// Verify Go-generated vectors decrypt correctly in Node (the Go->Node leg
// of the three-way parity test). Usage: node runner/checkvectors.mjs <file>
import fs from "node:fs";
import { gunzipSync } from "node:zlib";
import { decryptState, b64urlDecode } from "./crypto.mjs";

const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let failures = 0;
for (const v of data.vectors) {
  const key = await crypto.subtle.importKey("raw", b64urlDecode(v.key), { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    const plain = await decryptState(key, v.planId, b64urlDecode(v.iv), b64urlDecode(v.ct));
    const want = b64urlDecode(v.plain);
    const same = plain.length === want.length && plain.every((b, i) => b === want[i]);
    if (!same) {
      console.log(`FAIL ${v.name}: plaintext mismatch`);
      failures++;
      continue;
    }
    if (v.gzip === true) {
      gunzipSync(plain); // must be Node-gunzippable when Go gzipped it
    }
    console.log(`ok ${v.name}`);
  } catch (e) {
    console.log(`FAIL ${v.name}: ${e.message}`);
    failures++;
  }
}
process.exit(failures ? 1 : 0);
