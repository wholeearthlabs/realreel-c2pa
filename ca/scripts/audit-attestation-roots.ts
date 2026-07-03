// Expiry audit for the pinned hardware-attestation roots in
// _shared/attestation/roots.ts (Google Key Attestation + Apple App Attest).
// A pinned root silently expiring broke Samsung enrollment in 2026; running
// this on a schedule gives runway to rotate before it happens again.
//
//   deno run --allow-read --allow-env --allow-net \
//     ca/scripts/audit-attestation-roots.ts
//
// Exit 0 = healthy; 1 = a root inside the WARN window; 2 = inside CRIT,
// expired, or unparseable. CI treats any non-zero as "open a tracking issue".
// The Google published-set drift check is informational only (never changes
// the exit code; network failure is swallowed) so the expiry gate is stable.

import {
  APPLE_APPATTEST_ROOT_PEM,
  GOOGLE_HW_ATTESTATION_ROOT_PEMS,
} from "../_shared/attestation/roots.ts";
import { parseCertFromPem, pemToDer } from "../_shared/attestation/pki.ts";

const MS_PER_DAY = 86_400_000;
const DEFAULT_WARN_DAYS = 180;
const DEFAULT_CRIT_DAYS = 30;
const GOOGLE_ROOT_ENDPOINT = "https://android.googleapis.com/attestation/root";

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

// Non-fatal drift check: warn if Google publishes a root we don't pin, or vice
// versa. Compares by DER SHA-256. Everything fallible stays inside the try so a
// bad response can only return a note, never throw or change the exit code.
async function checkGooglePublishedSet(): Promise<string[]> {
  try {
    const res = await fetch(GOOGLE_ROOT_ENDPOINT);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const published: unknown = await res.json();
    if (!Array.isArray(published)) throw new Error("expected a JSON array of PEMs");

    const fp = async (pem: string) => {
      const digest = await crypto.subtle.digest("SHA-256", pemToDer(pem) as BufferSource);
      return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    };
    const pinnedFps = new Set(await Promise.all(GOOGLE_HW_ATTESTATION_ROOT_PEMS.map(fp)));
    const publishedFps = new Set(await Promise.all(published.map((p) => fp(String(p)))));

    const notes: string[] = [];
    for (const p of publishedFps) {
      if (!pinnedFps.has(p)) {
        notes.push(`Google publishes a root we do NOT pin (sha256=${p.slice(0, 16)}…) — rotation to review.`);
      }
    }
    for (const p of pinnedFps) {
      if (!publishedFps.has(p)) {
        notes.push(`We pin a root Google no longer publishes (sha256=${p.slice(0, 16)}…) — retiring device population?`);
      }
    }
    if (notes.length === 0) notes.push("Google published-set: in sync with pinned Google roots.");
    return notes;
  } catch (e) {
    return [`(skipped Google published-set check: ${e instanceof Error ? e.message : String(e)})`];
  }
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
  const { rows, exitCode } = auditPins(now, warnDays, critDays);
  console.log(render(rows, now, warnDays, critDays));
  const notes = await checkGooglePublishedSet();
  console.log(notes.join("\n"));
  console.log("");
  if (exitCode === 0) {
    console.log(`OK: all ${rows.length} pinned attestation roots are >= ${warnDays}d from expiry.`);
  } else if (exitCode === 1) {
    const w = rows.find((r) => r.status === "WARN")!;
    console.log(`WARN: ${w.id} expires in ${w.days}d. Rotate the pin in ca/_shared/attestation/roots.ts before then.`);
  } else {
    console.log(`CRIT: a pinned attestation root is expired, within ${critDays}d, or unparseable — rotate now.`);
  }
  return exitCode;
}

if (import.meta.main) {
  // Deno flushes console.log synchronously, so the report is written before
  // Deno.exit — no Node-style stdout truncation to guard against.
  Deno.exit(await main());
}
