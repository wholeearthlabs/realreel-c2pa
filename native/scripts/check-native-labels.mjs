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

// Second guard, same file: every assertion label the signer authors must be
// in BUILDER_SETTINGS_JSON's `created_assertion_labels`, or c2pa-rs routes it
// to `gathered_assertions` (spec 2.4 §10.2.2 — "not sourced from the claim
// generator") the moment an entry forgets its `"created": true`. The list must
// also be identical on both platforms.
const CREATED_LABELS_RE = /"created_assertion_labels":\[([^\]]*)\]/;
const AUTHORED_LABEL_RE = /"(org\.realreel\.[a-z_]+|c2pa\.metadata)"/g;

let ok = true;
const createdLabelLists = new Map();
for (const [platform, rel] of sources) {
  const source = readFileSync(join(root, rel), "utf8");
  for (const [name, label] of labels) {
    if (!source.includes(`"${label}"`)) {
      console.error(`✗ ${platform} (${rel}) does not contain the canonical ${name} "${label}" — update the native literal(s) in lockstep with @realreel/c2pa-trust-core.`);
      ok = false;
    }
  }
  const createdMatch = source.match(CREATED_LABELS_RE);
  if (!createdMatch) {
    console.error(`✗ ${platform} (${rel}) has no created_assertion_labels in BUILDER_SETTINGS_JSON.`);
    ok = false;
    continue;
  }
  const created = new Set(createdMatch[1].split(",").map((l) => l.trim().replace(/^"|"$/g, "")));
  createdLabelLists.set(platform, [...created].sort().join(","));
  for (const [, label] of source.matchAll(AUTHORED_LABEL_RE)) {
    if (!created.has(label)) {
      console.error(`✗ ${platform} (${rel}) authors "${label}" but BUILDER_SETTINGS_JSON's created_assertion_labels does not list it — c2pa-rs would route it to gathered_assertions.`);
      ok = false;
    }
  }
}
if (new Set(createdLabelLists.values()).size > 1) {
  console.error(`✗ created_assertion_labels differ between platforms: ${[...createdLabelLists].map(([p, l]) => `${p}=[${l}]`).join(" vs ")}`);
  ok = false;
}
if (!ok) process.exit(1);
console.log(`✓ native assertion labels in lockstep with @realreel/c2pa-trust-core: ${labels.map(([, l]) => `"${l}"`).join(", ")}`);
console.log(`✓ every authored assertion label is in created_assertion_labels on both platforms`);
