// Upstream drift check for the vendored C2PA TSA Trust List.
//
// trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem mirrors the C2PA Conformance
// Programme's list byte-for-byte, and only a manual refresh moves it. Until
// then a TSA added upstream isn't trusted here (its tokens never reach
// `timeStamp.trusted`) and a TSA removed upstream still is. This fetches the
// upstream list and reports both directions by DER SHA-256.
//
// Run:
//   make verify-tsa-list
//   npx tsx verifier/scripts/audit-tsa-list.ts
//
// Exit codes:
//   0 — byte-identical to upstream
//   2 — the vendored PEM is unreadable or holds an unparseable certificate
//   3 — drift: certificates added or removed upstream, or only the file's
//       annotations / ordering changed (refresh to stay byte-identical)
//   4 — the check could not run: upstream unreachable after retries, or no
//       parseable certificate in its response
//
// Scheduled weekly by .github/workflows/audit-tsa-list.yml; any non-zero exit
// opens a tracking issue. Refresh: verifier/OPERATIONS.md "#tsa-trust-list-refresh".

import { readFile } from "node:fs/promises";
import { createHash, X509Certificate } from "node:crypto";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

export const VENDORED_PATH = "trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem";
export const UPSTREAM_URL =
  "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem";

const FETCH_ATTEMPTS = 3;
const FETCH_BACKOFF_MS = [1_000, 3_000];
const FETCH_TIMEOUT_MS = 15_000;

export interface TsaCert {
  sha256: string;
  subjectCn: string;
  issuerCn: string;
  notAfter: Date;
}

export interface AuditResult {
  exitCode: 0 | 2 | 3 | 4;
  report: string;
}

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

// The upstream file interleaves `Subject\tCN=...` annotation lines with the
// PEM blocks; only the blocks matter here. Throws on an unparseable block.
export function parseBundle(pem: string): TsaCert[] {
  const blocks = pem.match(PEM_BLOCK) ?? [];
  // A BEGIN without its END (a truncated body) would otherwise drop out
  // silently and read as a removal.
  if ((pem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== blocks.length) {
    throw new Error("truncated or malformed PEM block");
  }
  return blocks.map((block) => {
    const cert = new X509Certificate(block);
    return {
      sha256: createHash("sha256").update(cert.raw).digest("hex"),
      subjectCn: commonName(cert.subject),
      issuerCn: commonName(cert.issuer),
      notAfter: cert.validToDate,
    };
  });
}

// node:crypto renders a DN one attribute per line.
function commonName(dn: string): string {
  return dn.match(/^CN=(.+)$/m)?.[1] ?? dn.replace(/\n/g, ", ");
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function row(c: TsaCert): string {
  const until = c.notAfter.toISOString().slice(0, 10);
  return `  ${c.subjectCn} (issuer: ${c.issuerCn}, until ${until}) sha256=${c.sha256}`;
}

/**
 * Pure audit over injected readers, so tests never touch the network or the
 * real vendored file.
 */
export async function auditTsaList(opts: {
  readVendored: () => Promise<Buffer>;
  fetchUpstream: () => Promise<Buffer>;
}): Promise<AuditResult> {
  const lines = ["C2PA TSA Trust List drift check", `Upstream: ${UPSTREAM_URL}`, ""];
  const done = (exitCode: AuditResult["exitCode"]): AuditResult => ({
    exitCode,
    report: lines.join("\n"),
  });

  // Raw bytes, not decoded text: decoding can differ per side (fetch strips a
  // BOM, readFile keeps it), and the mirror is meant to be byte-identical.
  let vendoredBytes: Buffer;
  let vendored: TsaCert[];
  try {
    vendoredBytes = await opts.readVendored();
    vendored = parseBundle(vendoredBytes.toString("utf-8"));
    if (vendored.length === 0) throw new Error("no certificates found");
  } catch (err) {
    lines.push(`ERROR: cannot read ${VENDORED_PATH}: ${message(err)}`);
    return done(2);
  }

  let upstreamBytes: Buffer;
  let upstream: TsaCert[];
  try {
    upstreamBytes = await opts.fetchUpstream();
    upstream = parseBundle(upstreamBytes.toString("utf-8"));
    // An empty or error-page body must not read as "every TSA was removed".
    if (upstream.length === 0) throw new Error("no certificates in the upstream response");
  } catch (err) {
    lines.push(
      `BLIND: the drift check could not run: ${message(err)}`,
      "Until this is fixed, a change to the C2PA TSA list goes unnoticed.",
    );
    return done(4);
  }

  if (vendoredBytes.equals(upstreamBytes)) {
    lines.push(`OK: ${VENDORED_PATH} is byte-identical to upstream (${vendored.length} certificates).`);
    return done(0);
  }

  const ours = new Set(vendored.map((c) => c.sha256));
  const theirs = new Set(upstream.map((c) => c.sha256));
  const removed = vendored.filter((c) => !theirs.has(c.sha256));
  const added = upstream.filter((c) => !ours.has(c.sha256));

  lines.push(`Vendored: ${vendored.length} certificates. Upstream: ${upstream.length}.`, "");
  if (removed.length > 0) {
    lines.push(
      `REMOVED upstream, still trusted here (${removed.length}) — refresh promptly:`,
      ...removed.map(row),
      "",
    );
  }
  if (added.length > 0) {
    lines.push(
      `ADDED upstream, not yet trusted here (${added.length}) — their timestamps don't validate as trusted until the refresh:`,
      ...added.map(row),
      "",
    );
  }
  if (removed.length === 0 && added.length === 0) {
    lines.push("Same certificates; only annotations or ordering changed upstream.", "");
  }
  lines.push(
    `DRIFT: refresh ${VENDORED_PATH} from upstream; see verifier/OPERATIONS.md § TSA trust-list refresh.`,
  );
  return done(3);
}

async function fetchUpstream(): Promise<Buffer> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(UPSTREAM_URL, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return Buffer.from(await res.arrayBuffer());
    } catch (err) {
      lastErr = err;
      if (attempt < FETCH_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, FETCH_BACKOFF_MS[attempt - 1]));
      }
    }
  }
  throw new Error(`upstream unreachable after ${FETCH_ATTEMPTS} attempts: ${message(lastErr)}`);
}

// ----- CLI -----
async function main(): Promise<void> {
  const verifierDir = resolve(SCRIPT_DIR, "..");
  const result = await auditTsaList({
    readVendored: () => readFile(resolve(verifierDir, VENDORED_PATH)),
    fetchUpstream,
  });
  // process.exitCode, not process.exit: stdout is piped through `tee` in CI and
  // an early exit can truncate the issue body.
  console.log(result.report);
  process.exitCode = result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Audit failed:", err);
    process.exitCode = 2;
  });
}
