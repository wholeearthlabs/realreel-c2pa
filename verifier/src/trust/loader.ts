// Loads trust-sources.yaml + the referenced PEM files at startup.
// Produces a TrustConfig the rest of the verifier consumes:
//   - sources: per-source server-side policy (root_cert path,
//     verification_profile), each enriched with the
//     loaded PEM. Joined with @realreel/c2pa-trust-core's TRUSTED_ISSUERS
//     by `id` for the issuerMatch substring at dispatch time.
//   - trustAnchorsBundle: concatenated PEM string handed to c2pa-node's
//     settings.trust.trust_anchors. This is the actual cryptographic
//     trust gate.
//
// Sources whose root_cert file does not exist on disk are skipped with
// a warning. This lets trust-sources.yaml declare upcoming sources
// (e.g. pixel) before their root PEM is committed.

import { readFile, access } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { parse as parseYaml } from "yaml";
import * as SentrySdk from "@sentry/node";
import { TRUSTED_ISSUERS } from "@realreel/c2pa-trust-core";
import type {
  TrustConfig,
  TrustSource,
  TrustSourceConfig,
  TsaRoot,
  TsaRootConfig,
} from "./types.js";

interface RawConfig {
  sources: TrustSourceConfig[];
  /** Optional. Absent → an empty `tsaRoots` array (sigTst2 validation
   *  degrades to "no TSA trust list", which c2pa-rs treats as untrusted —
   *  the verifier rejects sigTst2-bearing manifests if no TSA roots load). */
  tsa_roots?: TsaRootConfig[];
}

/** Surface area the loader uses from Config. Kept narrow so loader tests
 * can pass plain objects. */
interface LoaderEnv {
  isProduction: boolean;
}

export async function loadTrustConfig(
  yamlPath: string,
  env: LoaderEnv = { isProduction: false },
): Promise<TrustConfig> {
  const absYamlPath = resolve(yamlPath);
  const yamlText = await readFile(absYamlPath, "utf-8");
  const raw = parseYaml(yamlText) as RawConfig;

  if (!raw?.sources || !Array.isArray(raw.sources)) {
    throw new Error(`trust-sources.yaml missing or malformed: ${absYamlPath}`);
  }

  const baseDir = dirname(absYamlPath);
  const sources: TrustSource[] = [];

  for (const cfg of raw.sources) {
    validateSourceConfig(cfg, absYamlPath);

    const certPath = resolve(baseDir, cfg.root_cert);
    try {
      await access(certPath);
    } catch {
      const skipMsg = `trust-sources: skipping '${cfg.id}' — root_cert not found at ${certPath}`;
      console.warn(skipMsg);
      // In production, also flag to Sentry: an accidentally-dropped
      // root.pem silently degrades the verifier to "reject all of that
      // vendor's uploads." Sentry init runs before this is called from
      // server.ts, so captureMessage either ships to Sentry (prod) or
      // no-ops (dev without DSN).
      if (env.isProduction) {
        SentrySdk.captureMessage("trust_source_missing_root_cert", {
          level: "error",
          tags: { source_id: cfg.id },
          extra: { yaml_path: absYamlPath, expected_cert_path: certPath },
        });
      }
      continue;
    }

    const rootCertPem = await readFile(certPath, "utf-8");
    sources.push({ ...cfg, rootCertPem });
  }

  if (sources.length === 0) {
    throw new Error(
      `trust-sources.yaml at ${absYamlPath} produced zero usable sources — refusing to start a verifier with an empty trust list`,
    );
  }

  // Load TSA roots. These pool into the SAME trust_anchors bundle as signer
  // roots — c2pa-rs uses one trust pool for both signing-cert and TSA
  // validation. Missing PEM files are skipped with a warning. Absence of a
  // tsa_roots: section is allowed (degrades to zero TSA roots →
  // sigTst2-bearing manifests fail verify_timestamp_trust, but legacy
  // non-sigTst2 manifests still validate).
  const tsaRoots: TsaRoot[] = [];
  const rawTsaRoots = raw?.tsa_roots ?? [];
  for (const cfg of rawTsaRoots) {
    validateTsaRootConfig(cfg, absYamlPath);
    const certPath = resolve(baseDir, cfg.root_cert);
    try {
      await access(certPath);
    } catch {
      const skipMsg = `trust-sources: skipping TSA root '${cfg.id}' — root_cert not found at ${certPath}`;
      console.warn(skipMsg);
      if (env.isProduction) {
        SentrySdk.captureMessage("tsa_root_missing_pem", {
          level: "error",
          tags: { tsa_id: cfg.id },
          extra: { yaml_path: absYamlPath, expected_cert_path: certPath },
        });
      }
      continue;
    }
    const rootCertPem = await readFile(certPath, "utf-8");
    tsaRoots.push({ ...cfg, rootCertPem });
  }

  if (rawTsaRoots.length > 0 && tsaRoots.length === 0) {
    console.warn(
      `trust-sources.yaml declared TSA roots but none loaded — sigTst2 validation will fail closed`,
    );
  }

  // Zero TSA roots is a silent degradation (sigTst2-bearing manifests
  // treated as untimestamped). We don't throw — dev configs legitimately
  // have no tsa_roots and legacy non-sigTst2 manifests still validate — but
  // in prod we surface it so the misconfiguration is auditable rather than
  // invisible until first upload-time failure.
  if (tsaRoots.length === 0) {
    const msg =
      `trust-sources: loaded ZERO TSA roots — manifests with embedded ` +
      `sigTst2 will validate without timestamp-chain trust (see ` +
      `verify.ts comment for the validation_results surface).`;
    if (env.isProduction) {
      console.warn(msg);
      SentrySdk.captureMessage("trust_loader_zero_tsa_roots", {
        level: "warning",
        extra: { yaml_path: absYamlPath, declared_count: rawTsaRoots.length },
      });
    }
  }

  // Duplicate-id detection across sources + tsa_roots — they share one id
  // namespace, so a duplicate of either kind is a misconfiguration that we
  // fail loud on at load time rather than silently double-bundling a PEM or
  // letting a TSA id shadow a signer id.
  const allIds: Array<{ id: string; kind: "source" | "tsa_root" }> = [
    ...sources.map((s) => ({ id: s.id, kind: "source" as const })),
    ...tsaRoots.map((t) => ({ id: t.id, kind: "tsa_root" as const })),
  ];
  const seen = new Map<string, "source" | "tsa_root">();
  for (const { id, kind } of allIds) {
    const prior = seen.get(id);
    if (prior !== undefined) {
      throw new Error(
        `trust-sources.yaml: duplicate id '${id}' — already declared as ${prior}, conflicts with ${kind}. Ids must be unique across sources and tsa_roots.`,
      );
    }
    seen.set(id, kind);
  }

  // Build the c2pa-node trust_anchors bundle: signer roots + TSA roots
  // concatenated with newlines so the OpenSSL-style parser inside
  // c2pa-rs reads each as a separate certificate. c2pa-rs's TSA
  // validator pulls from the same pool when verify_timestamp_trust is
  // enabled (see verify.ts).
  const trustAnchorsBundle = [
    ...sources.map((s) => s.rootCertPem.trim()),
    ...tsaRoots.map((t) => t.rootCertPem.trim()),
  ].join("\n");

  // Precompute the loaded-id set for identifyTrustSource()'s hot-path
  // check. trustConfig is immutable after this returns, so memoizing
  // here avoids the per-request `new Set(sources.map(...))` allocation.
  // TSA root ids are excluded — they're never returned by
  // identifyTrustSource (which routes content-issuer manifests, not
  // timestamps).
  const loadedIds: ReadonlySet<string> = new Set(sources.map((s) => s.id));

  return { sources, tsaRoots, trustAnchorsBundle, loadedIds };
}

function validateSourceConfig(
  cfg: TrustSourceConfig,
  yamlPath: string,
): void {
  const ctx = `trust-sources.yaml entry (path=${yamlPath})`;
  if (!cfg.id || typeof cfg.id !== "string") {
    throw new Error(`${ctx}: missing or non-string 'id'`);
  }
  // Lockstep: every YAML entry must have a matching TRUSTED_ISSUERS row in
  // @realreel/c2pa-trust-core. Without it, an unknown id would load its PEM
  // into c2pa-node's trust_anchors bundle (chain validation accepts the
  // root) but identifyTrustSource() would always return null for it
  // (manifests fail-closed as UNTRUSTED_ISSUER). Throwing at startup surfaces
  // the misconfiguration instead of failing closed silently.
  const known = TRUSTED_ISSUERS.some((entry) => entry.id === cfg.id);
  if (!known) {
    throw new Error(
      `${ctx}: id '${cfg.id}' has no matching entry in ` +
        `@realreel/c2pa-trust-core TRUSTED_ISSUERS. Add the cross-process ` +
        `metadata (displayName, issuerMatch, rootCommonName) to ` +
        `trust-core/src/trust-list/trusted-issuers.ts ` +
        `before declaring this source here.`,
    );
  }
  if (!cfg.root_cert || typeof cfg.root_cert !== "string") {
    throw new Error(`${ctx} '${cfg.id}': missing or non-string 'root_cert'`);
  }
  if (
    cfg.verification_profile !== "realreel" &&
    cfg.verification_profile !== "wrap_parent_only"
  ) {
    throw new Error(
      `${ctx} '${cfg.id}': unknown verification_profile '${cfg.verification_profile}' (expected 'realreel' or 'wrap_parent_only')`,
    );
  }
}

function validateTsaRootConfig(
  cfg: TsaRootConfig,
  yamlPath: string,
): void {
  // TSA roots intentionally do NOT have the TRUSTED_ISSUERS lockstep
  // check (TSAs don't sign content) and no verification_profile. Just
  // enough validation to catch obvious YAML typos.
  const ctx = `trust-sources.yaml tsa_roots entry (path=${yamlPath})`;
  if (!cfg.id || typeof cfg.id !== "string") {
    throw new Error(`${ctx}: missing or non-string 'id'`);
  }
  if (!cfg.root_cert || typeof cfg.root_cert !== "string") {
    throw new Error(`${ctx} '${cfg.id}': missing or non-string 'root_cert'`);
  }
}
