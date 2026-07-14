// Expiry audit for the pinned hardware-attestation roots in
// _shared/attestation/roots.ts (Google Key Attestation + Apple App Attest).
// A pinned root silently expiring broke Samsung enrollment in 2026; running
// this on a schedule gives runway to rotate before it happens again.
//
//   deno run --allow-read --allow-env --allow-net \
//     ca/scripts/audit-attestation-roots.ts
//
// Exit 0 = healthy; 1 = a root inside the WARN window; 2 = inside CRIT, expired,
// or unparseable; 3 = the pinned Google set drifted from Google's published set;
// 4 = the drift check could not run. CI treats any non-zero as "open a tracking
// issue".
//
// Drift gates rather than informs: Google publishing a root we do not pin is
// the earliest signal of an enrollment break, and an informational note in a
// green weekly build goes unread. Expected divergence is enumerated in the
// ACKNOWLEDGED_* maps so only unexpected drift is loud; transient network
// failure is absorbed by retries, not silence.

import {
  APPLE_APPATTEST_ROOT_PEM,
  GOOGLE_HW_ATTESTATION_ROOT_PEMS,
} from "../_shared/attestation/roots.ts";
import { parseCertFromPem, pemToDer } from "../_shared/attestation/pki.ts";

const MS_PER_DAY = 86_400_000;
const DEFAULT_WARN_DAYS = 180;
const DEFAULT_CRIT_DAYS = 30;
const GOOGLE_ROOT_ENDPOINT = "https://android.googleapis.com/attestation/root";

const EXIT_OK = 0;
const EXIT_WARN = 1;
const EXIT_CRIT = 2;
const EXIT_DRIFT = 3;
const EXIT_DRIFT_UNAVAILABLE = 4;

// UNAVAILABLE should mean a persistently dead watch, not one TLS hiccup, so
// the drift fetch retries with backoff before we call it blind.
const DRIFT_FETCH_ATTEMPTS = 3;
const DRIFT_BACKOFF_MS = [1_000, 3_000];
const DRIFT_TIMEOUT_MS = 15_000;

// Roots we pin that Google no longer publishes. Legitimate: Google delists a
// root once it stops provisioning new devices with it, but field devices keep
// presenting chains rooted there, so the pin stays until that population ages
// out. Anything not listed here is unacknowledged drift and fails the audit.
const ACKNOWLEDGED_UNPUBLISHED_PINS: Record<string, string> = {
  "19de1c3e1da7e06f3c2712301342c17941b1ec90ba5ee396a8ec2ee4f46dfad2":
    "Google root serial e35d38c6897d47e8 (RSA, notAfter 2028-03-18), delisted by Google " +
    "but still rooting chains from devices provisioned before the rotation. The pin stays " +
    "until that population ages out; the expiry gate above is the backstop.",
};

// Roots Google publishes that we deliberately do not pin. Expected to stay
// empty: an unpinned published root means enrollment failures for devices
// chaining to it. Add one only to drop support for that population, and say why.
const ACKNOWLEDGED_UNPINNED_PUBLISHED: Record<string, string> = {};

async function sha256OfPem(pem: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", pemToDer(pem) as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Strict positive-integer parse: Number() turns "999_999"/"abc" into NaN and
// "" into 0, any of which would silently collapse the expiry gate to "all OK".
// Reject non-integers so a misconfigured env var fails loud, not blind.
function parsePositiveInt(
  value: string | undefined,
  fallback: number,
  name: string,
): number {
  if (value === undefined || value.trim() === "") return fallback;
  if (!/^\d+$/.test(value.trim()) || Number(value) < 1) {
    throw new Error(`${name} must be a positive integer, got: ${JSON.stringify(value)}`);
  }
  return Number(value);
}

interface Pin {
  id: string;
  pem: string;
}

interface Row {
  id: string;
  notAfter: Date | null;
  days: number | null;
  status: "OK" | "WARN" | "CRIT" | "ERROR";
}

const PINS: Pin[] = [
  { id: "apple-appattest-root", pem: APPLE_APPATTEST_ROOT_PEM },
  ...GOOGLE_HW_ATTESTATION_ROOT_PEMS.map((pem, i) => ({
    id: `google-hw-attestation-root-${i + 1}`,
    pem,
  })),
];

function auditPins(
  now: Date,
  warnDays: number,
  critDays: number,
): { rows: Row[]; exitCode: 0 | 1 | 2 } {
  const rows: Row[] = PINS.map(({ id, pem }) => {
    try {
      const notAfter = parseCertFromPem(pem).notAfter.value;
      const t = notAfter.getTime();
      if (!Number.isFinite(t)) return { id, notAfter: null, days: null, status: "ERROR" };
      const days = Math.floor((t - now.getTime()) / MS_PER_DAY);
      const status = days < critDays ? "CRIT" : days < warnDays ? "WARN" : "OK";
      return { id, notAfter, days, status };
    } catch {
      return { id, notAfter: null, days: null, status: "ERROR" };
    }
  });
  const hasCrit = rows.some((r) => r.status === "CRIT" || r.status === "ERROR");
  const hasWarn = rows.some((r) => r.status === "WARN");
  return { rows, exitCode: hasCrit ? 2 : hasWarn ? 1 : 0 };
}

function render(rows: Row[], now: Date, warnDays: number, critDays: number): string {
  const idW = Math.max("id".length, ...rows.map((r) => r.id.length));
  const line = (id: string, na: string, days: string, status: string) =>
    `${id.padEnd(idW)}  ${na.padEnd(11)}  ${days.padStart(6)}  ${status}`;
  const out = [
    `Attestation-root expiry audit (warn <${warnDays}d, crit <${critDays}d)`,
    `Now: ${now.toISOString()}`,
    "",
    line("id", "notAfter", "days", "status"),
    line("-".repeat(idW), "-".repeat(11), "-".repeat(6), "------"),
    ...rows.map((r) =>
      line(
        r.id,
        r.notAfter ? r.notAfter.toISOString().slice(0, 10) : "(unparsed)",
        r.days != null ? String(r.days) : "n/a",
        r.status,
      )
    ),
    "",
  ];
  return out.join("\n");
}

type DriftStatus = "IN_SYNC" | "DRIFT" | "UNAVAILABLE";

interface Drift {
  status: DriftStatus;
  notes: string[];
}

// Fetch Google's published root set, retrying transient failures. Shape is
// validated by the caller so a genuinely malformed response is reported once
// rather than retried three times.
async function fetchPublishedRoots(): Promise<unknown> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= DRIFT_FETCH_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(GOOGLE_ROOT_ENDPOINT, {
        signal: AbortSignal.timeout(DRIFT_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      lastError = e;
      if (attempt < DRIFT_FETCH_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, DRIFT_BACKOFF_MS[attempt - 1]));
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

// Compares pinned vs published Google roots by DER SHA-256. Unacknowledged
// drift in either direction fails the audit, as does being unable to answer.
async function checkGooglePublishedSet(): Promise<Drift> {
  let pinnedFps: Set<string>;
  let publishedFps: Set<string>;
  try {
    const json = await fetchPublishedRoots();
    if (!Array.isArray(json) || json.some((p) => typeof p !== "string")) {
      throw new Error("expected a JSON array of PEM strings");
    }
    pinnedFps = new Set(await Promise.all(GOOGLE_HW_ATTESTATION_ROOT_PEMS.map(sha256OfPem)));
    publishedFps = new Set(await Promise.all((json as string[]).map(sha256OfPem)));
  } catch (e) {
    return {
      status: "UNAVAILABLE",
      notes: [
        `DRIFT CHECK UNAVAILABLE after ${DRIFT_FETCH_ATTEMPTS} attempts: ` +
          `${e instanceof Error ? e.message : String(e)}`,
        `Endpoint: ${GOOGLE_ROOT_ENDPOINT}`,
        "Until this is fixed the rotation watch is blind, so a new Google root could ship unnoticed.",
      ],
    };
  }

  const notes: string[] = [];
  let unacknowledged = 0;

  for (const fp of publishedFps) {
    if (pinnedFps.has(fp)) continue;
    const reason = ACKNOWLEDGED_UNPINNED_PUBLISHED[fp];
    if (reason) {
      notes.push(`(acknowledged) Google publishes a root we do not pin: ${reason} [sha256=${fp.slice(0, 16)}…]`);
      continue;
    }
    unacknowledged++;
    notes.push(
      `DRIFT: Google publishes a root we do NOT pin (sha256=${fp}).\n` +
        "  This is what a root rotation looks like, and devices chaining to it will fail enrollment.\n" +
        "  Add it to GOOGLE_HW_ATTESTATION_ROOT_PEMS (PEM + EXPECTED_FINGERPRINTS), or, if we are\n" +
        "  deliberately not supporting that device population, record it in ACKNOWLEDGED_UNPINNED_PUBLISHED.",
    );
  }

  for (const fp of pinnedFps) {
    if (publishedFps.has(fp)) continue;
    const reason = ACKNOWLEDGED_UNPUBLISHED_PINS[fp];
    if (reason) {
      notes.push(`(acknowledged) We pin a root Google no longer publishes: ${reason} [sha256=${fp.slice(0, 16)}…]`);
      continue;
    }
    unacknowledged++;
    notes.push(
      `DRIFT: We pin a root Google no longer publishes (sha256=${fp}).\n` +
        "  Google delists a root when it stops provisioning new devices with it. Keep the pin while\n" +
        "  field devices still chain to it, then retire it. Either way, record the decision in\n" +
        "  ACKNOWLEDGED_UNPUBLISHED_PINS or remove the pin.",
    );
  }

  if (unacknowledged === 0 && notes.length === 0) {
    notes.push("Google published-set: in sync with pinned Google roots.");
  }
  return { status: unacknowledged > 0 ? "DRIFT" : "IN_SYNC", notes };
}

async function main(): Promise<number> {
  let warnDays: number;
  let critDays: number;
  try {
    warnDays = parsePositiveInt(Deno.env.get("ATTEST_ROOT_WARN_DAYS"), DEFAULT_WARN_DAYS, "ATTEST_ROOT_WARN_DAYS");
    critDays = parsePositiveInt(Deno.env.get("ATTEST_ROOT_CRIT_DAYS"), DEFAULT_CRIT_DAYS, "ATTEST_ROOT_CRIT_DAYS");
  } catch (e) {
    console.log(`CONFIG ERROR: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  if (warnDays < critDays) {
    console.log(`CONFIG ERROR: WARN window (${warnDays}d) must be >= CRIT window (${critDays}d).`);
    return 2;
  }

  const now = new Date();
  const { rows, exitCode: expiryExit } = auditPins(now, warnDays, critDays);
  console.log(render(rows, now, warnDays, critDays));
  const drift = await checkGooglePublishedSet();
  console.log(drift.notes.join("\n"));
  console.log("");

  // Report every failing condition, not just the one that sets the exit code, so
  // a CRIT expiry never masks concurrent drift in the issue body.
  const problems: string[] = [];
  if (expiryExit === EXIT_CRIT) {
    problems.push(`CRIT: a pinned attestation root is expired, within ${critDays}d, or unparseable — rotate now.`);
  }
  if (drift.status === "DRIFT") {
    problems.push("DRIFT: the pinned Google root set no longer matches Google's published set — see above.");
  }
  if (drift.status === "UNAVAILABLE") {
    problems.push("BLIND: the drift check could not run, so the rotation watch is not working — see above.");
  }
  if (expiryExit === EXIT_WARN) {
    const w = rows.find((r) => r.status === "WARN")!;
    problems.push(`WARN: ${w.id} expires in ${w.days}d. Rotate the pin in ca/_shared/attestation/roots.ts before then.`);
  }

  if (problems.length === 0) {
    console.log(
      `OK: all ${rows.length} pinned attestation roots are >= ${warnDays}d from expiry, ` +
        "and there is no unacknowledged drift from Google's published set.",
    );
    return EXIT_OK;
  }
  for (const p of problems) console.log(p);

  // Most severe category wins; the numeric codes are labels, not a ranking.
  if (expiryExit === EXIT_CRIT) return EXIT_CRIT;
  if (drift.status === "DRIFT") return EXIT_DRIFT;
  if (drift.status === "UNAVAILABLE") return EXIT_DRIFT_UNAVAILABLE;
  return EXIT_WARN;
}

if (import.meta.main) {
  // Deno flushes console.log synchronously, so the report is written before
  // Deno.exit — no Node-style stdout truncation to guard against.
  Deno.exit(await main());
}
