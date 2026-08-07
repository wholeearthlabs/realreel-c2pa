// Regenerates src/trust-list/client-trust-anchors.generated.ts from the
// verifier's trust-sources.yaml + the PEM files it references.
//
//   npm run codegen:trust-anchors   (from trust-core/)
//
// The output must byte-equal the CLIENT PROJECTION of the trust pool the
// verifier's loader builds at boot: each included PEM trimmed, joined with
// "\n", `sources:` entries before `tsa_roots:` entries (the loader's
// concatenation order), minus any entry marked `client_bundle: false` —
// those are verifier-private acceptance roots that must not feed the
// generator's conformance-visible recorded ingredient validation. The
// projection is asserted byte-for-byte by
// verifier/__tests__/client-trust-anchors-lockstep.test.ts, so a stale
// generated file fails CI rather than shipping a client pool that
// disagrees with the server's.
//
// Declared-but-missing PEMs are warned and skipped, mirroring the loader
// (which tolerates them at boot) — so "regenerate" always reproduces the
// pool the loader would actually build, including mid-onboarding or
// mid-removal states.
//
// The `yaml` import resolves through the npm-workspace hoist (it's a
// verifier dependency); this script only ever runs inside the monorepo,
// and the published trust-core package itself stays dependency-free.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFIER_DIR = resolve(HERE, "..", "..", "verifier");
const YAML_PATH = resolve(VERIFIER_DIR, "trust-sources.yaml");
const OUT_PATH = resolve(
  HERE,
  "..",
  "src",
  "trust-list",
  "client-trust-anchors.generated.ts",
);

const raw = parseYaml(readFileSync(YAML_PATH, "utf-8"));
const entries = [...(raw?.sources ?? []), ...(raw?.tsa_roots ?? [])];
if (entries.length === 0) {
  throw new Error(`no sources/tsa_roots entries found in ${YAML_PATH}`);
}

const included = [];
const excluded = [];
for (const entry of entries) {
  if (entry.client_bundle === false) {
    excluded.push(entry);
    continue;
  }
  const pemPath = resolve(VERIFIER_DIR, entry.root_cert);
  if (!existsSync(pemPath)) {
    console.warn(
      `warning: skipping '${entry.id}' — root_cert not found at ${pemPath} (the loader skips it too)`,
    );
    continue;
  }
  included.push({ ...entry, pem: readFileSync(pemPath, "utf-8").trim() });
}
if (included.length === 0) {
  throw new Error("client trust-anchor projection is empty — refusing to emit");
}

const bundle = included.map((e) => e.pem).join("\n");

// The bundle is emitted as a template literal so the generated file
// diffs line-by-line like the PEMs themselves.
if (bundle.includes("`") || bundle.includes("${")) {
  throw new Error(
    "PEM bundle contains template-literal metacharacters — switch the emitter to JSON.stringify",
  );
}

const header = `// GENERATED FILE — DO NOT EDIT.
// Regenerate with \`npm run codegen:trust-anchors\` (in trust-core/) after any
// change to verifier/trust-sources.yaml or a PEM it references. Byte-lockstep
// with the verifier's boot-time trust pool (client projection) is asserted by
// verifier/__tests__/client-trust-anchors-lockstep.test.ts.
//
// Included (in order):
${included.map((e) => `//   - verifier/${e.root_cert} (${e.id})`).join("\n")}
// Excluded (client_bundle: false — verifier-private, see the YAML entry):
${excluded.map((e) => `//   - verifier/${e.root_cert} (${e.id})`).join("\n") || "//   (none)"}

/**
 * The client's trust pool — content-source CA roots plus TSA roots — as one
 * concatenated PEM bundle: the pool the Cloud Run verifier loads at boot,
 * minus entries the verifier trusts privately (\`client_bundle: false\`,
 * e.g. the general-purpose TSA roots that anchor RealReel's own timestamps
 * but are not on the C2PA TSA Trust List — the generator must not RECORD
 * trust for those).
 *
 * Pass as \`trustAnchorsPem\` to \`@realreel/photo-attest\`'s Stage-2 /
 * Update-Manifest sign calls (see that option's doc for the recorded
 * ingredient-validation rationale) so sign-time validation and server-side
 * verification agree on every root the client asserts trust for.
 *
 * Local-dev caveat: dev builds sign under the throwaway \`realreel-ca-dev\`
 * hierarchy, deliberately NOT in this published bundle — a dev RealReel
 * parent records untrusted at ingest. Cosmetic and dev-only: the verifier
 * re-validates chains itself and treats recorded ingredient results as
 * advisory.
 */
export const CLIENT_TRUST_ANCHORS_PEM: string = \``;

writeFileSync(OUT_PATH, `${header}${bundle}\`;\n`);
console.log(
  `wrote ${OUT_PATH} (${bundle.length} bytes of PEM; ${included.length} included, ${excluded.length} excluded)`,
);
