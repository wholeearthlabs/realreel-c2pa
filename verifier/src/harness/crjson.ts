// C2PA Conformance Program v0.2 validation test harness: (asset, C2PA Trust
// List, TSA Trust List, RFC 3339 instant) → crJSON. Full rationale and usage
// in verifier/README.md "Conformance test harness"; the short form:
//
// c2pa-node exposes neither c2pa-rs's crJSON serializer nor a validation-time
// override, and c2pa-rs reads the system clock (SystemTime::now for
// untimestamped cert validity, Utc::now for `validationTime`). So one run
// spawns TWO children under libfaketime, clock FROZEN at the instant (which
// also makes the output byte-deterministic): c2patool produces the crJSON,
// and the verifier's own engine (c2pa-node, ./engine-probe.ts) validates the
// same asset — both fed the settings document verify.ts builds
// (buildVerifierSettings, with the supplied anchors) — and their validation
// results are compared status-by-status. crJSON's per-manifest
// validationResults are c2pa-rs's ValidationResults re-arranged (active →
// activeManifest, the rest → ingredient deltas), so the comparison is
// complete; a disagreement lands in the run record, never hidden.
//
// Callable first (vitest drives it: __tests__/harness/), CLI second (./cli.ts).

import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildVerifierSettings } from "../verify.js";

// ── Public types ────────────────────────────────────────────────────────────

export interface ValidationStatusEntry {
  code: string;
  url?: string;
  explanation?: string;
}

export interface StatusCodes {
  success: ValidationStatusEntry[];
  informational: ValidationStatusEntry[];
  failure: ValidationStatusEntry[];
}

export interface IngredientDelta {
  ingredientAssertionURI: string;
  validationDeltas: StatusCodes;
}

/** One entry of crJSON `manifests[]` — only the fields the harness reads. */
export interface CrjsonManifest {
  label: string;
  assertions: Record<string, unknown>;
  claim?: Record<string, unknown>;
  "claim.v2"?: Record<string, unknown>;
  signature: Record<string, unknown>;
  validationResults: StatusCodes & { specVersion: string; validationTime: string };
  ingredientDeltas?: IngredientDelta[];
}

export interface CrjsonDocument {
  "@context": unknown;
  manifests: CrjsonManifest[];
  jsonGenerator: { name: string; version: string };
}

export interface CrjsonHarnessInputs {
  /** The asset to validate. c2patool picks its asset handler by extension. */
  assetPath: string;
  /** C2PA Trust List — PEM bundle text (claim-signing anchors). */
  trustListPem: string;
  /** C2PA TSA Trust List — PEM bundle text (time-stamp authority anchors). */
  tsaTrustListPem: string;
  /** The instant to validate at (sub-second part is dropped: libfaketime
   *  freezes to the second), or "wall-clock" for local smoke tests. */
  validationTime: Date | "wall-clock";
}

export interface CrjsonHarnessOptions {
  /** c2patool binary. Default: $C2PATOOL, else "c2patool" on PATH. */
  c2patool?: string;
  /** faketime binary. Default: "faketime" on PATH. */
  faketime?: string;
  /** Run the verifier's own engine and compare (default true). */
  crossCheck?: boolean;
  /** Per-child wall-clock limit (default 120 s); a hung validator becomes a
   *  typed error instead of a hang. */
  timeoutMs?: number;
}

export interface CrjsonRunRecord {
  harness: { name: string; version: string };
  validator: {
    /** `c2patool --version` output. */
    c2patool: string;
    /** c2pa-rs version c2patool embeds, as it reports in jsonGenerator. */
    c2paRs: string | null;
    /** Who produced the crJSON text: c2patool, or the harness (the empty
     *  document, when c2patool reported "No claim found"). */
    crjsonOrigin: "c2patool" | "harness-empty-document";
    /** c2patool's stderr when it said anything. */
    stderr?: string;
  };
  /** The deployed verifier's engine — present when the cross-check ran. */
  engine: { package: string; version: string; c2paRs: string | null } | null;
  inputs: {
    asset: { path: string; sha256: string; mimeType: string | null };
    trustList: { sha256: string; certificates: number };
    tsaTrustList: { sha256: string; certificates: number };
    /** RFC 3339 (second precision) or "wall-clock". */
    validationTime: string;
  };
  engineAgreement: {
    /** false when the comparison did not run: disabled, no MIME type for the
     *  asset (c2pa-node needs one), or the engine failed on the asset. */
    checked: boolean;
    /** false on a status difference OR an engine failure — either means the
     *  crJSON is not attested by the deployed engine. */
    agree: boolean;
    differences: string[];
  };
  engineVerdict: {
    found: boolean;
    activeManifest: string | null;
    validationState: string | null;
  } | null;
}

export interface CrjsonHarnessRun {
  crjson: CrjsonDocument;
  /** The crJSON exactly as the validator emitted it (or the synthesized
   *  empty document — see runCrjsonHarness). Write THIS, not a re-serialization. */
  crjsonText: string;
  record: CrjsonRunRecord;
}

export type CrjsonHarnessErrorKind =
  | "input"
  | "c2patool-missing"
  | "faketime-missing"
  | "validator-failed";

export class CrjsonHarnessError extends Error {
  constructor(
    readonly kind: CrjsonHarnessErrorKind,
    message: string,
    /** Raw stderr / cause where there is one. */
    readonly detail?: string,
  ) {
    super(message);
    this.name = "CrjsonHarnessError";
  }
}

// ── Environment ─────────────────────────────────────────────────────────────

const HARNESS_NAME = "realreel-c2pa verifier crjson-harness";
const require = createRequire(import.meta.url);
const HARNESS_VERSION: string = (
  JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
    version: string;
  }
).version;
const ENGINE_PACKAGE = "@contentauth/c2pa-node";
const ENGINE_VERSION: string = (
  require(`${ENGINE_PACKAGE}/package.json`) as { version: string }
).version;

// c2pa-node does not expose the c2pa-rs it embeds; this table is read off
// c2pa-js's Cargo.lock at each tag. Unknown → null, and the pin test in
// __tests__/harness/crjson-harness.test.ts fails until the entry is added.
const ENGINE_C2PA_RS: Record<string, string> = { "0.8.3": "0.90.5" };

export const HARNESS_IDENTITY = { name: HARNESS_NAME, version: HARNESS_VERSION };
export const ENGINE_IDENTITY = {
  package: ENGINE_PACKAGE,
  version: ENGINE_VERSION,
  c2paRs: ENGINE_C2PA_RS[ENGINE_VERSION] ?? null,
};

export interface HarnessEnvironment {
  /** `c2patool --version` output, or null when the binary can't be run. */
  c2patool: string | null;
  faketime: boolean;
}

/** Which of the two external tools are runnable. Tests skip (or fail, in
 *  CI) on this; the CLI turns it into an actionable message. */
export function probeHarnessEnvironment(
  options: Pick<CrjsonHarnessOptions, "c2patool" | "faketime"> = {},
): HarnessEnvironment {
  const c2patool = spawnSync(resolveC2patool(options), ["--version"], { encoding: "utf8" });
  const faketime = spawnSync(options.faketime ?? "faketime", ["--version"], { encoding: "utf8" });
  return {
    c2patool: c2patool.error || c2patool.status !== 0 ? null : c2patool.stdout.trim(),
    faketime: !faketime.error,
  };
}

function resolveC2patool(options: Pick<CrjsonHarnessOptions, "c2patool">): string {
  return options.c2patool ?? process.env.C2PATOOL ?? "c2patool";
}

// ── Inputs ──────────────────────────────────────────────────────────────────

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** Certificates in a PEM bundle, each block trimmed. Zero is allowed — an
 *  empty list is a legitimate negative test input. */
export function pemCertificates(bundle: string): string[] {
  return bundle.match(PEM_BLOCK) ?? [];
}

/** The settings document both children get: verify.ts's own builder with the
 *  supplied lists as the anchor pool. c2pa-rs keeps ONE pool for claim-signing
 *  and TSA certificates (EKU-discriminated), so the two lists are concatenated
 *  — the same pooling trust/loader.ts does for trust-sources.yaml. */
export function harnessSettings(trustListPem: string, tsaTrustListPem: string): string {
  const anchors = [...pemCertificates(trustListPem), ...pemCertificates(tsaTrustListPem)];
  const settings = buildVerifierSettings({ trustAnchorsBundle: anchors.join("\n") + "\n" });
  if (anchors.length > 0) return settings;
  // Two empty lists = nothing trusted. c2pa-rs refuses to configure from an
  // empty anchor STRING ("COSE error parsing certificate") but treats an
  // absent key as "no anchors" — every signer and TSA untrusted, which is the
  // honest verdict for this input. Same behaviour in both engines.
  const parsed = JSON.parse(settings) as { trust: Record<string, unknown> };
  delete parsed.trust.trust_anchors;
  return JSON.stringify(parsed);
}

// c2patool infers the asset type from the extension; c2pa-node needs it
// spelled out. Every type c2pa-rs's asset handlers serve.
const MIME_BY_EXTENSION: Record<string, string> = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".tif": "image/tiff",
  ".tiff": "image/tiff",
  ".dng": "image/x-adobe-dng",
  ".heic": "image/heic",
  ".heif": "image/heif",
  ".avif": "image/avif",
  ".svg": "image/svg+xml",
  ".mp4": "video/mp4",
  ".m4v": "video/mp4",
  ".mov": "video/quicktime",
  ".m4a": "audio/mp4",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".avi": "video/x-msvideo",
  ".pdf": "application/pdf",
  ".c2pa": "application/c2pa",
};

export function mimeTypeForAsset(assetPath: string): string | null {
  return MIME_BY_EXTENSION[extname(assetPath).toLowerCase()] ?? null;
}

// RFC 3339 date-time with an explicit offset — no local-time fallback, which
// `new Date("2026-08-17T00:00:00")` would silently do. A leap second (:60) is
// clamped to :59 (libfaketime works to the second anyway).
const RFC3339_RE = /^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** Parse the Program's validation time. Throws CrjsonHarnessError("input"). */
export function parseValidationTime(text: string): Date {
  const m = RFC3339_RE.exec(text.trim());
  if (!m) throw new CrjsonHarnessError("input", `validation time is not RFC 3339 with an offset: ${text}`);
  const [, date, hhmm, ss, frac, offset] = m;
  const instant = new Date(`${date}T${hhmm}:${ss === "60" ? "59" : ss}${frac ?? ""}${offset.toUpperCase()}`);
  if (Number.isNaN(instant.getTime())) throw new CrjsonHarnessError("input", `validation time is not a valid instant: ${text}`);
  return instant;
}

/** libfaketime's absolute-time syntax, which FREEZES the clock (the `@`
 *  prefix would start it there and let it run). UTC — the children get TZ=UTC. */
export function toFaketime(instant: Date): string {
  if (Number.isNaN(instant.getTime())) {
    throw new CrjsonHarnessError("input", "validationTime is not a valid instant");
  }
  return instant.toISOString().slice(0, 19).replace("T", " ");
}

function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

// ── Cross-check ─────────────────────────────────────────────────────────────

interface EngineProbeResult {
  found: boolean;
  activeManifest?: string | null;
  validationState?: string | null;
  validationResults?: {
    activeManifest?: Partial<StatusCodes>;
    ingredientDeltas?: IngredientDelta[];
  } | null;
}

const GROUPS = ["success", "informational", "failure"] as const;

// Statuses compare by (code, url). Explanations are prose and free to differ
// between c2pa-rs releases without the verdict changing.
function statusKeys(entries: ValidationStatusEntry[] | undefined): string[] {
  return (entries ?? []).map((e) => `${e.code} @ ${e.url ?? ""}`).sort();
}

function diffGroups(where: string, a: Partial<StatusCodes> | undefined, b: Partial<StatusCodes> | undefined, out: string[]): void {
  for (const g of GROUPS) {
    const ka = statusKeys(a?.[g]);
    const kb = statusKeys(b?.[g]);
    if (ka.join("\n") !== kb.join("\n")) {
      out.push(`${where}.${g}: crJSON [${ka.join(", ")}] vs engine [${kb.join(", ")}]`);
    }
  }
}

/** Every way the crJSON's validation results could disagree with the engine's.
 *  Empty array = agreement. Exported for the harness's own tests. */
export function compareWithEngine(crjson: CrjsonDocument, engine: EngineProbeResult): string[] {
  const out: string[] = [];
  if (!engine.found) {
    if (crjson.manifests.length > 0) {
      out.push(`engine found no manifest store; crJSON has ${crjson.manifests.length} manifest(s)`);
    }
    return out;
  }
  const active = crjson.manifests[0];
  if (!active) {
    out.push(`engine found a manifest store (active ${engine.activeManifest}); crJSON has none`);
    return out;
  }
  if (active.label !== engine.activeManifest) {
    out.push(`active manifest: crJSON ${active.label} vs engine ${engine.activeManifest}`);
  }
  diffGroups("activeManifest", active.validationResults, engine.validationResults?.activeManifest, out);

  // Ingredient deltas: the engine reports one flat list; crJSON hangs each
  // off the manifest that holds the ingredient assertion. Compare them as one
  // multiset of (uri, group, code, url) — no keying, so two deltas with the
  // same URI can't shadow each other — and check the placement separately:
  // an absolute assertion URI names its manifest.
  const deltaKeys = (deltas: IngredientDelta[]): string[] =>
    deltas
      .flatMap((d) => GROUPS.flatMap((g) => statusKeys(d.validationDeltas[g]).map((k) => `${d.ingredientAssertionURI} ${g}: ${k}`)))
      .sort();
  const crjsonDeltas = crjson.manifests.flatMap((m) => m.ingredientDeltas ?? []);
  const a = deltaKeys(crjsonDeltas);
  const b = deltaKeys(engine.validationResults?.ingredientDeltas ?? []);
  if (a.join("\n") !== b.join("\n")) {
    const only = (x: string[], y: string[]) => x.filter((k) => !y.includes(k));
    out.push(`ingredientDeltas: crJSON-only [${only(a, b).join(", ")}] engine-only [${only(b, a).join(", ")}]`);
  }
  for (const m of crjson.manifests) {
    for (const d of m.ingredientDeltas ?? []) {
      const owner = /^self#jumbf=\/c2pa\/([^/]+)\//.exec(d.ingredientAssertionURI)?.[1];
      if (owner && owner !== m.label) out.push(`ingredient delta ${d.ingredientAssertionURI} placed under manifest ${m.label}`);
    }
  }
  return out;
}

// ── Run ─────────────────────────────────────────────────────────────────────

/** Spawn a command, optionally under a frozen faketime clock. */
function spawnAt(
  cmd: string,
  args: string[],
  faketimeAt: string | null,
  faketimeBin: string,
  timeout: number,
): SpawnSyncReturns<string> {
  const opts = {
    encoding: "utf8" as const,
    maxBuffer: 256 * 1024 * 1024,
    timeout,
    env: { ...process.env, TZ: "UTC", FAKETIME_DONT_FAKE_MONOTONIC: "1" },
  };
  return faketimeAt === null
    ? spawnSync(cmd, args, opts)
    : spawnSync(faketimeBin, ["-f", faketimeAt, cmd, ...args], opts);
}

/** What went wrong with a child that spawned but did not succeed. */
function childFailure(run: SpawnSyncReturns<string>, timeout: number): string {
  if (run.error && (run.error as NodeJS.ErrnoException).code === "ETIMEDOUT") return `timed out after ${timeout} ms`;
  if (run.error) return run.error.message;
  return (run.stderr || run.stdout).trim() || `exited ${run.status ?? `by signal ${run.signal}`}`;
}

// The probe runs in the flavour this module runs in: dist/…/crjson.js spawns
// dist/…/engine-probe.js; src/…/crjson.ts (tsx, vitest) spawns the .ts
// sibling through tsx's loader. Either way it is the verifier's own c2pa-node.
function engineProbeCommand(): { cmd: string; args: string[] } {
  const isTs = extname(fileURLToPath(import.meta.url)) === ".ts";
  const probe = fileURLToPath(new URL(isTs ? "./engine-probe.ts" : "./engine-probe.js", import.meta.url));
  const args = isTs ? ["--import", import.meta.resolve("tsx"), probe] : [probe];
  return { cmd: process.execPath, args };
}

const EMPTY_DOCUMENT_CONTEXT = {
  "@vocab": "https://c2pa.org/crjson",
  extras: "https://c2pa.org/crjson/extras",
};

export function runCrjsonHarness(
  inputs: CrjsonHarnessInputs,
  options: CrjsonHarnessOptions = {},
): CrjsonHarnessRun {
  const c2patoolBin = resolveC2patool(options);
  const faketimeBin = options.faketime ?? "faketime";
  const crossCheck = options.crossCheck ?? true;
  const timeout = options.timeoutMs ?? 120_000;

  const faketimeAt = inputs.validationTime === "wall-clock" ? null : toFaketime(inputs.validationTime);
  if (faketimeAt !== null && spawnSync(faketimeBin, ["--version"], { encoding: "utf8" }).error) {
    throw new CrjsonHarnessError(
      "faketime-missing",
      `\`${faketimeBin}\` (libfaketime) is needed to validate at ${faketimeAt} UTC and was not found — brew install libfaketime / apt-get install faketime, or use the harness image (verifier/Dockerfile target crjson-harness).`,
    );
  }

  let assetBytes: Buffer;
  try {
    assetBytes = readFileSync(inputs.assetPath);
  } catch (e) {
    throw new CrjsonHarnessError("input", `cannot read asset ${inputs.assetPath}`, String(e));
  }
  const mimeType = mimeTypeForAsset(inputs.assetPath);
  // A bundle with text but no PEM certificate (DER, PKCS#7, "TRUSTED
  // CERTIFICATE" blocks…) must not silently become "nothing trusted".
  for (const [label, pem] of [["trust list", inputs.trustListPem], ["TSA trust list", inputs.tsaTrustListPem]] as const) {
    if (pem.trim() !== "" && pemCertificates(pem).length === 0) {
      throw new CrjsonHarnessError("input", `${label} contains no PEM "-----BEGIN CERTIFICATE-----" block — the harness accepts PEM bundles only`);
    }
  }
  const settings = harnessSettings(inputs.trustListPem, inputs.tsaTrustListPem);

  const workDir = mkdtempSync(join(tmpdir(), "crjson-harness-"));
  try {
    const settingsPath = join(workDir, "settings.json");
    writeFileSync(settingsPath, settings);

    // 1. c2patool → crJSON. Probed first so a missing binary is reported as
    //    such rather than as faketime's "running specified command failed".
    const versionProbe = spawnSync(c2patoolBin, ["--version"], { encoding: "utf8" });
    if (versionProbe.error || versionProbe.status !== 0) {
      throw new CrjsonHarnessError(
        "c2patool-missing",
        `could not run ${c2patoolBin}: ${versionProbe.error?.message ?? versionProbe.stderr.trim()} — install c2patool (https://github.com/contentauth/c2pa-rs/releases) or set C2PATOOL / --c2patool.`,
      );
    }
    const version = versionProbe.stdout.trim();
    const tool = spawnAt(c2patoolBin, [inputs.assetPath, "--crjson", "--settings", settingsPath], faketimeAt, faketimeBin, timeout);

    let crjsonText: string;
    let crjson: CrjsonDocument;
    let crjsonOrigin: CrjsonRunRecord["validator"]["crjsonOrigin"] = "c2patool";
    if (!tool.error && tool.status === 0) {
      crjsonText = tool.stdout;
      try {
        crjson = JSON.parse(crjsonText) as CrjsonDocument;
      } catch (e) {
        throw new CrjsonHarnessError("validator-failed", "c2patool emitted non-JSON", String(e));
      }
    } else if (!tool.error && /No claim found/i.test(tool.stderr)) {
      // c2patool 0.27.x says this for "no manifest store" — a bare asset OR
      // one whose store is unreadable — and exits 1 instead of emitting an
      // empty document. The crJSON for "no manifests" is fully determined
      // (§3.1), so state it under the harness's own name; the run record
      // says so (crjsonOrigin, stderr) and the engine's own `found` is next
      // to it.
      crjson = { "@context": EMPTY_DOCUMENT_CONTEXT, manifests: [], jsonGenerator: HARNESS_IDENTITY };
      crjsonText = JSON.stringify(crjson, null, 2) + "\n";
      crjsonOrigin = "harness-empty-document";
    } else {
      throw new CrjsonHarnessError("validator-failed", `c2patool failed on ${inputs.assetPath}`, childFailure(tool, timeout));
    }

    // 2. The verifier's own engine, same settings, same instant.
    let engineAgreement: CrjsonRunRecord["engineAgreement"];
    let engineVerdict: CrjsonRunRecord["engineVerdict"] = null;
    if (!crossCheck) {
      engineAgreement = { checked: false, agree: true, differences: ["cross-check disabled"] };
    } else if (mimeType === null) {
      engineAgreement = {
        checked: false,
        agree: true,
        differences: [`no MIME type known for '${extname(inputs.assetPath)}' — c2pa-node needs one; c2patool inferred its own`],
      };
    } else {
      const { cmd, args } = engineProbeCommand();
      const probe = spawnAt(cmd, [...args, inputs.assetPath, mimeType, settingsPath], faketimeAt, faketimeBin, timeout);
      if (probe.error || probe.status !== 0) {
        // The crJSON stands (c2patool produced it); what's lost is the
        // engine's attestation of it — reported, not thrown, so the document
        // for a Program input is never withheld because our engine choked.
        engineAgreement = {
          checked: false,
          agree: false,
          differences: [`engine (${ENGINE_PACKAGE} ${ENGINE_VERSION}) failed on the asset: ${childFailure(probe, timeout)}`],
        };
      } else {
        const result = JSON.parse(probe.stdout) as EngineProbeResult;
        const differences = compareWithEngine(crjson, result);
        engineAgreement = { checked: true, agree: differences.length === 0, differences };
        engineVerdict = {
          found: result.found,
          activeManifest: result.activeManifest ?? null,
          validationState: result.validationState ?? null,
        };
      }
    }

    const record: CrjsonRunRecord = {
      harness: HARNESS_IDENTITY,
      validator: {
        c2patool: version,
        c2paRs: crjson.jsonGenerator.name === "c2pa-rs" ? crjson.jsonGenerator.version : null,
        crjsonOrigin,
        ...(tool.stderr.trim() ? { stderr: tool.stderr.trim() } : {}),
      },
      engine: crossCheck && mimeType !== null ? ENGINE_IDENTITY : null,
      inputs: {
        asset: { path: inputs.assetPath, sha256: sha256(assetBytes), mimeType },
        trustList: { sha256: sha256(inputs.trustListPem), certificates: pemCertificates(inputs.trustListPem).length },
        tsaTrustList: { sha256: sha256(inputs.tsaTrustListPem), certificates: pemCertificates(inputs.tsaTrustListPem).length },
        validationTime: faketimeAt === null ? "wall-clock" : faketimeAt.replace(" ", "T") + "Z",
      },
      engineAgreement,
      engineVerdict,
    };
    return { crjson, crjsonText, record };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}
