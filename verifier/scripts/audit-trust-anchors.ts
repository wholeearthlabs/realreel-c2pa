// Trust-anchor expiry audit.
//
// Reads verifier/trust-sources.yaml, inspects each anchor's root.pem
// via openssl, and reports days-until-expiry against WARN/CRIT
// thresholds. The pure auditAnchors() function is exported so vitest
// can stub openssl + clock; the CLI wrapper at the bottom shells out
// to /usr/bin/openssl for real.
//
// Run:
//   make verify-trust-anchors
//   npx tsx verifier/scripts/audit-trust-anchors.ts
//
// Exit codes:
//   0 — all OK (every anchor > warnDays remaining)
//   1 — at least one WARN, no CRIT
//   2 — at least one CRIT, OR any unreadable / missing PEM, OR any
//       non-self-signed root
//
// Env overrides:
//   VERIFY_TRUST_WARN_DAYS — default 365. Buys ~10 weekly nudges
//     before the WARN→CRIT crossover, which is conservative for the
//     50-year roots we ship today. Tighten if a future intermediate
//     or shorter-lived anchor is added.
//   VERIFY_TRUST_CRIT_DAYS — default 90. Three months matches typical
//     CA renewal lead time + our deploy ritual.
//
// This is an on-demand script, not a scheduled CI job: run it
// (`make verify-trust-anchors`) on a recurring reminder, or wire it into
// your own scheduler. A non-zero exit is the signal to start the
// trust-anchor rotation runbook (see verifier/DEPLOY.md
// "#trust-anchor-rotation").

import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

const execFileAsync = promisify(execFile);

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_WARN_DAYS = 365;
const DEFAULT_CRIT_DAYS = 90;
const MS_PER_DAY = 86_400_000;

export interface TrustSource {
  id: string;
  root_cert: string;
}

export interface CertInfo {
  subjectCn: string;
  notAfter: Date;
}

export type Status = "OK" | "WARN" | "CRIT" | "ERROR";

export interface AuditRow {
  id: string;
  subjectCn: string;
  notAfter: Date | null;
  days: number | null;
  status: Status;
  error?: string;
}

export interface AuditResult {
  rows: AuditRow[];
  exitCode: 0 | 1 | 2;
  warnDays: number;
  critDays: number;
  now: Date;
}

/**
 * Pure audit function. Takes already-parsed sources, threshold knobs,
 * a pinned clock, and an injectable cert reader. Tests stub
 * getCertInfo to avoid spawning openssl and pin `now` for determinism.
 *
 * Returns rows sorted ascending by days-remaining (ERROR rows first,
 * since they need attention regardless of expiry).
 */
export async function auditAnchors(opts: {
  sources: TrustSource[];
  warnDays: number;
  critDays: number;
  now: Date;
  getCertInfo: (src: TrustSource) => Promise<CertInfo>;
}): Promise<AuditResult> {
  const { sources, warnDays, critDays, now, getCertInfo } = opts;
  const rows: AuditRow[] = [];

  for (const src of sources) {
    try {
      const info = await getCertInfo(src);
      const days = Math.floor((info.notAfter.getTime() - now.getTime()) / MS_PER_DAY);
      let status: Status;
      if (days < critDays) status = "CRIT";
      else if (days < warnDays) status = "WARN";
      else status = "OK";
      rows.push({
        id: src.id,
        subjectCn: info.subjectCn,
        notAfter: info.notAfter,
        days,
        status,
      });
    } catch (err) {
      rows.push({
        id: src.id,
        subjectCn: "(unreadable)",
        notAfter: null,
        days: null,
        status: "ERROR",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  rows.sort((a, b) => {
    // ERROR before everything; otherwise ascending by days.
    if (a.status === "ERROR" && b.status !== "ERROR") return -1;
    if (b.status === "ERROR" && a.status !== "ERROR") return 1;
    return (a.days ?? 0) - (b.days ?? 0);
  });

  const hasCritOrError = rows.some((r) => r.status === "CRIT" || r.status === "ERROR");
  const hasWarn = rows.some((r) => r.status === "WARN");
  const exitCode: 0 | 1 | 2 = hasCritOrError ? 2 : hasWarn ? 1 : 0;

  return { rows, exitCode, warnDays, critDays, now };
}

/**
 * Format an AuditResult as a fixed-width table + summary line.
 * Exposed so tests can snapshot rendering separately from audit logic.
 */
export function renderAudit(result: AuditResult): string {
  const { rows, exitCode, warnDays, critDays, now } = result;
  const lines: string[] = [];
  lines.push(`Trust anchor expiry audit (warn at <${warnDays}d, crit at <${critDays}d)`);
  lines.push(`Now: ${now.toISOString()}`);
  lines.push("");

  const idW = Math.max("id".length, ...rows.map((r) => r.id.length));
  const cnW = Math.max("subject CN".length, ...rows.map((r) => r.subjectCn.length));
  const naW = "2050-05-08T22:32:21Z".length;   // ISO without ms

  const fmt = (id: string, cn: string, na: string, days: string, status: string) =>
    `${id.padEnd(idW)}  ${cn.padEnd(cnW)}  ${na.padEnd(naW)}  ${days.padStart(5)}  ${status}`;

  lines.push(fmt("id", "subject CN", "notAfter", "days", "status"));
  lines.push(fmt("-".repeat(idW), "-".repeat(cnW), "-".repeat(naW), "-".repeat(5), "------"));

  for (const r of rows) {
    const na = r.notAfter ? r.notAfter.toISOString().replace(/\.\d+Z$/, "Z") : "(n/a)";
    const days = r.days != null ? String(r.days) : "n/a";
    lines.push(fmt(r.id, r.subjectCn, na, days, r.status));
  }
  lines.push("");

  const critCount = rows.filter((r) => r.status === "CRIT").length;
  const errorCount = rows.filter((r) => r.status === "ERROR").length;
  const warnCount = rows.filter((r) => r.status === "WARN").length;

  if (exitCode === 0) {
    lines.push(`OK: all ${rows.length} trust anchors within validity windows.`);
  } else if (exitCode === 1) {
    const firstWarn = rows.find((r) => r.status === "WARN")!;
    lines.push(`WARN: ${warnCount} warning${warnCount === 1 ? "" : "s"} (${firstWarn.id}: ${firstWarn.days} days). Plan rotation; see verifier/DEPLOY.md § trust-anchor rotation.`);
  } else {
    const parts: string[] = [];
    if (critCount > 0) {
      const firstCrit = rows.find((r) => r.status === "CRIT")!;
      parts.push(`${critCount} CRITICAL (${firstCrit.id}: ${firstCrit.days} days)`);
    }
    if (errorCount > 0) {
      const firstError = rows.find((r) => r.status === "ERROR")!;
      parts.push(`${errorCount} ERROR (${firstError.id}: ${firstError.error})`);
    }
    if (warnCount > 0) {
      parts.push(`${warnCount} warning${warnCount === 1 ? "" : "s"}`);
    }
    lines.push(`FAIL: ${parts.join(", ")}. Rotate now; see verifier/DEPLOY.md § trust-anchor rotation.`);
  }

  return lines.join("\n");
}

/**
 * Real-world cert reader: shells out to `openssl x509`. Used by the
 * CLI; tests inject their own.
 *
 * Asserts the cert is a self-signed root by comparing the full
 * subject DN to the full issuer DN. An intermediate or leaf dropped
 * in a `trust-sources/<id>/root.pem` slot would chain-validate
 * differently at runtime (or not at all), so we catch the wrong-cert
 * deploy bug at audit time rather than discovering it via
 * SIGNATURE_INVALID floods on the next /verify wave.
 *
 * CN regex caveat: `([^,\n]+)` after `CN=` works for openssl's
 * default subject format and our current anchors. It would break on
 * (a) CNs containing literal commas (RFC 2253 permits escaped commas
 * like `CN=Smith\, John` — real CAs don't do this), or (b) an openssl
 * version that defaults to a different nameopt. If this becomes an
 * issue, swap to `-nameopt RFC2253` and a stricter parse.
 */
export function makeOpensslCertReader(baseDir: string) {
  return async (src: TrustSource): Promise<CertInfo> => {
    const pemPath = resolve(baseDir, src.root_cert);
    const { stdout } = await execFileAsync("openssl", [
      "x509", "-in", pemPath, "-noout", "-enddate", "-subject", "-issuer",
    ]);
    // notAfter=May  5 20:29:34 2051 GMT
    // subject=C=US, O=Google LLC, CN=Google C2PA Root CA G3
    // issuer=C=US, O=Google LLC, CN=Google C2PA Root CA G3
    const notAfterMatch = stdout.match(/notAfter\s*=\s*(.+)/);
    const subjectMatch = stdout.match(/^subject\s*=\s*(.+)$/m);
    const issuerMatch = stdout.match(/^issuer\s*=\s*(.+)$/m);
    if (!notAfterMatch || !subjectMatch || !issuerMatch) {
      throw new Error(`openssl output unparseable for ${src.id}`);
    }

    const subjectDn = subjectMatch[1]!.trim();
    const issuerDn = issuerMatch[1]!.trim();
    if (subjectDn !== issuerDn) {
      throw new Error(
        `${src.id} is not a self-signed root cert (subject="${subjectDn}" issuer="${issuerDn}")`,
      );
    }

    const cnMatch = subjectDn.match(/CN\s*=\s*([^,\n]+)/);
    if (!cnMatch) {
      throw new Error(`no CN in subject DN for ${src.id}: ${subjectDn}`);
    }

    // Normalize the openssl date string ("May  5 20:29:34 2051 GMT")
    // — Date.parse is liberal but double spaces are safer collapsed.
    const dateStr = notAfterMatch[1]!.replace(/\s+/g, " ").trim();
    const notAfter = new Date(dateStr);
    if (Number.isNaN(notAfter.getTime())) {
      throw new Error(`unparseable notAfter for ${src.id}: ${dateStr}`);
    }
    return {
      subjectCn: cnMatch[1]!.trim(),
      notAfter,
    };
  };
}

/**
 * Strict positive-integer parse. parseInt("365abc", 10) silently
 * returns 365 — that's a footgun for env vars. Reject anything that
 * isn't a bare positive-integer string.
 */
function parsePositiveInt(value: string | undefined, defaultValue: number, name: string): number {
  if (value === undefined || value === "") return defaultValue;
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be a positive integer, got: ${JSON.stringify(value)}`);
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer, got: ${JSON.stringify(value)}`);
  }
  return parsed;
}

// ----- CLI -----
async function main(): Promise<void> {
  let warnDays: number;
  let critDays: number;
  try {
    warnDays = parsePositiveInt(process.env.VERIFY_TRUST_WARN_DAYS, DEFAULT_WARN_DAYS, "VERIFY_TRUST_WARN_DAYS");
    critDays = parsePositiveInt(process.env.VERIFY_TRUST_CRIT_DAYS, DEFAULT_CRIT_DAYS, "VERIFY_TRUST_CRIT_DAYS");
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 2;
    return;
  }
  if (warnDays < critDays) {
    console.error(
      `VERIFY_TRUST_WARN_DAYS (${warnDays}) must be >= VERIFY_TRUST_CRIT_DAYS (${critDays})`,
    );
    process.exitCode = 2;
    return;
  }

  const verifierDir = resolve(SCRIPT_DIR, "..");
  const yamlPath = resolve(verifierDir, "trust-sources.yaml");
  let parsed: { sources?: TrustSource[] };
  try {
    parsed = parseYaml(await readFile(yamlPath, "utf-8"));
  } catch (e) {
    console.error(`Failed to read or parse ${yamlPath}: ${e instanceof Error ? e.message : e}`);
    process.exitCode = 2;
    return;
  }

  const sources = (parsed.sources ?? []) as TrustSource[];
  for (const s of sources) {
    // Audit-time strictness: a malformed entry is a deploy bug, not a
    // skip-able anomaly (the runtime loader is more lenient because
    // it tolerates a partially-provisioned fresh-environment deploy).
    if (!s.id || !s.root_cert) {
      console.error(`Malformed source entry: ${JSON.stringify(s)}`);
      process.exitCode = 2;
      return;
    }
  }

  const result = await auditAnchors({
    sources,
    warnDays,
    critDays,
    now: new Date(),
    getCertInfo: makeOpensslCertReader(verifierDir),
  });

  // Use process.exitCode (not process.exit) so the event loop drains
  // stdout naturally. process.exit doesn't flush write buffers — when
  // the workflow pipes us through `tee`, stdout isn't a TTY and an
  // early exit could truncate the issue body.
  console.log(renderAudit(result));
  process.exitCode = result.exitCode;
}

// Run as CLI when invoked directly (node / tsx). pathToFileURL handles
// the macOS / Linux path-vs-URL conversion so tsx and node both match.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Audit failed:", err);
    process.exitCode = 2;
  });
}
