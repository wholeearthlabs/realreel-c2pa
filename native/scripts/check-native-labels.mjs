// Drift guard: the iOS/Android native code HARDCODES the C2PA timestamp
// assertion label (native can't import the TS constant). If the canonical label
// in @realreel/c2pa-trust-core changes without the native literals following,
// the native manifest walk silently stops resolving the capture (a real bug
// once: c2pa.timestamp vs c2pa.time-stamp → GPS redaction no-ops). Pin them here
// so the invariant lives with the native source — consumers need not read these
// literals out of node_modules to guard against drift.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TIMESTAMP_ASSERTION_LABEL } from "@realreel/c2pa-trust-core";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sources = [
  ["iOS", "ios/PhotoAttestModule.swift"],
  ["Android", "android/src/main/java/expo/modules/photoattest/PhotoAttestModule.kt"],
];

let ok = true;
for (const [platform, rel] of sources) {
  if (!readFileSync(join(root, rel), "utf8").includes(`"${TIMESTAMP_ASSERTION_LABEL}"`)) {
    console.error(`✗ ${platform} (${rel}) does not contain the canonical label "${TIMESTAMP_ASSERTION_LABEL}"`);
    ok = false;
  }
}
if (!ok) {
  console.error(`  TIMESTAMP_ASSERTION_LABEL is "${TIMESTAMP_ASSERTION_LABEL}" (from @realreel/c2pa-trust-core) — update the native literal(s) in lockstep.`);
  process.exit(1);
}
console.log(`✓ native timestamp label in lockstep with @realreel/c2pa-trust-core: "${TIMESTAMP_ASSERTION_LABEL}"`);
