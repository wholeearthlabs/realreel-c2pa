// Drift guard: the iOS/Android native code HARDCODES C2PA assertion labels
// (native can't import the TS constants). If a canonical label in
// @realreel/c2pa-trust-core changes without the native literals following,
// the native manifest walk silently stops resolving the capture (a real bug
// once: c2pa.timestamp vs c2pa.time-stamp → GPS redaction no-ops), or the
// signers emit an assertion no reader looks for. Pin them here so the
// invariant lives with the native source — consumers need not read these
// literals out of node_modules to guard against drift.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  TIMESTAMP_ASSERTION_LABEL,
  METADATA_ASSERTION_LABEL,
} from "@realreel/c2pa-trust-core";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sources = [
  ["iOS", "ios/PhotoAttestModule.swift"],
  ["Android", "android/src/main/java/expo/modules/photoattest/PhotoAttestModule.kt"],
];
const labels = [
  ["TIMESTAMP_ASSERTION_LABEL", TIMESTAMP_ASSERTION_LABEL],
  ["METADATA_ASSERTION_LABEL", METADATA_ASSERTION_LABEL],
];

let ok = true;
for (const [platform, rel] of sources) {
  const source = readFileSync(join(root, rel), "utf8");
  for (const [name, label] of labels) {
    if (!source.includes(`"${label}"`)) {
      console.error(`✗ ${platform} (${rel}) does not contain the canonical ${name} "${label}" — update the native literal(s) in lockstep with @realreel/c2pa-trust-core.`);
      ok = false;
    }
  }
}
if (!ok) process.exit(1);
console.log(`✓ native assertion labels in lockstep with @realreel/c2pa-trust-core: ${labels.map(([, l]) => `"${l}"`).join(", ")}`);
