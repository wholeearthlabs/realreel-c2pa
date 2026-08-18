// Engine probe for the crJSON harness (./crjson.ts): the verifier's OWN
// embedded C2PA engine — the same c2pa-node Reader.fromAsset call verify.ts
// makes — on one asset with one settings document, validation results to
// stdout as JSON. Spawned as a child (under faketime when an instant is
// injected) so it validates at the same instant as c2patool. Only c2pa-node
// and node builtins, so it runs identically from src (tsx) and dist.
//
//   engine-probe <asset-path> <mime-type> <settings-json-path>
//   → {"found":bool,"activeManifest":…,"validationState":…,"validationResults":…}

import { readFileSync } from "node:fs";
import { Reader } from "@contentauth/c2pa-node";

const [assetPath, mimeType, settingsPath] = process.argv.slice(2);
if (!assetPath || !mimeType || !settingsPath) {
  console.error("usage: engine-probe <asset-path> <mime-type> <settings-json-path>");
  process.exit(2);
}

const settings = readFileSync(settingsPath, "utf8");
const buffer = readFileSync(assetPath);

try {
  const reader = await Reader.fromAsset({ buffer, mimeType }, settings);
  if (reader === null) {
    process.stdout.write(JSON.stringify({ found: false }));
  } else {
    const store = reader.json() as unknown as {
      active_manifest?: string | null;
      validation_state?: string;
      validation_results?: unknown;
    };
    process.stdout.write(
      JSON.stringify({
        found: true,
        activeManifest: store.active_manifest ?? null,
        validationState: store.validation_state ?? null,
        validationResults: store.validation_results ?? null,
      }),
    );
  }
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
