// Unit tests for audit-trust-anchors.
//
// Covers the pure auditAnchors() function. The CLI wrapper and the
// openssl shell-out (makeOpensslCertReader) are exercised by manual
// `make verify-trust-anchors` runs, not by these tests — the test
// seam is the getCertInfo callback, so we never spawn a child process
// in unit tests.

import { describe, it, expect } from "vitest";
import {
  auditAnchors,
  renderAudit,
  type TrustSource,
  type CertInfo,
} from "../scripts/audit-trust-anchors.js";

const NOW = new Date("2026-05-14T00:00:00Z");
const MS_PER_DAY = 86_400_000;

function stubReader(
  map: Record<string, CertInfo | Error>,
): (src: TrustSource) => Promise<CertInfo> {
  return async (src) => {
    if (!(src.id in map)) throw new Error(`no fixture for ${src.id}`);
    const entry = map[src.id]!;
    if (entry instanceof Error) throw entry;
    return entry;
  };
}

const sources: TrustSource[] = [
  { id: "realreel", root_cert: "trust-sources/realreel/root.pem" },
  { id: "pixel", root_cert: "trust-sources/pixel/root.pem" },
];

describe("auditAnchors", () => {
  it("returns exitCode=0 when all anchors are well within validity", async () => {
    const result = await auditAnchors({
      sources,
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: {
          subjectCn: "RealReel Root CA",
          notAfter: new Date("2051-05-05T20:29:34Z"),
        },
        pixel: {
          subjectCn: "Google C2PA Root CA G3",
          notAfter: new Date("2050-05-08T22:32:21Z"),
        },
      }),
    });
    expect(result.exitCode).toBe(0);
    expect(result.rows.every((r) => r.status === "OK")).toBe(true);
    // Sorted ascending by days — pixel expires before realreel.
    expect(result.rows.map((r) => r.id)).toEqual(["pixel", "realreel"]);
  });

  it("returns exitCode=1 (WARN) when an anchor is between crit and warn", async () => {
    // 200 days remaining → within 365-day WARN, outside 90-day CRIT.
    const notAfter = new Date(NOW.getTime() + 200 * MS_PER_DAY);
    const result = await auditAnchors({
      sources: [{ id: "realreel", root_cert: "trust-sources/realreel/root.pem" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: { subjectCn: "RealReel Root CA", notAfter },
      }),
    });
    expect(result.exitCode).toBe(1);
    expect(result.rows[0]!.status).toBe("WARN");
    expect(result.rows[0]!.days).toBe(200);
  });

  it("returns exitCode=2 (CRIT) when an anchor is within critDays", async () => {
    const notAfter = new Date(NOW.getTime() + 30 * MS_PER_DAY);
    const result = await auditAnchors({
      sources: [{ id: "pixel", root_cert: "trust-sources/pixel/root.pem" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        pixel: { subjectCn: "Google C2PA Root CA G3", notAfter },
      }),
    });
    expect(result.exitCode).toBe(2);
    expect(result.rows[0]!.status).toBe("CRIT");
    expect(result.rows[0]!.days).toBe(30);
  });

  // Boundary cases — lock in the comparison semantics so a future
  // refactor from `<` to `<=` (or vice versa) doesn't silently shift
  // thresholds. days===warnDays should be OK; days===critDays should
  // be WARN (since `days < warnDays` is true at boundary - 1).
  it("treats days === warnDays as OK (boundary)", async () => {
    const notAfter = new Date(NOW.getTime() + 365 * MS_PER_DAY);
    const result = await auditAnchors({
      sources: [{ id: "realreel", root_cert: "x" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: { subjectCn: "RealReel Root CA", notAfter },
      }),
    });
    expect(result.exitCode).toBe(0);
    expect(result.rows[0]!.status).toBe("OK");
    expect(result.rows[0]!.days).toBe(365);
  });

  it("treats days === critDays as WARN (boundary)", async () => {
    const notAfter = new Date(NOW.getTime() + 90 * MS_PER_DAY);
    const result = await auditAnchors({
      sources: [{ id: "realreel", root_cert: "x" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: { subjectCn: "RealReel Root CA", notAfter },
      }),
    });
    expect(result.exitCode).toBe(1);
    expect(result.rows[0]!.status).toBe("WARN");
    expect(result.rows[0]!.days).toBe(90);
  });

  it("returns exitCode=2 with ERROR row when getCertInfo throws (missing/unreadable PEM)", async () => {
    const result = await auditAnchors({
      sources,
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: {
          subjectCn: "RealReel Root CA",
          notAfter: new Date("2051-05-05T20:29:34Z"),
        },
        pixel: new Error("ENOENT: no such file or directory, open '.../pixel/root.pem'"),
      }),
    });
    expect(result.exitCode).toBe(2);
    // ERROR rows are surfaced first regardless of OK/WARN/CRIT sort.
    expect(result.rows[0]!.id).toBe("pixel");
    expect(result.rows[0]!.status).toBe("ERROR");
    expect(result.rows[0]!.error).toContain("ENOENT");
    // The healthy realreel row still surfaces — partial-state visibility
    // matters when an operator is triaging a partial outage.
    const healthy = result.rows.find((r) => r.id === "realreel")!;
    expect(healthy.status).toBe("OK");
  });
});

describe("renderAudit", () => {
  // The summary line is the load-bearing text on the issue body —
  // operators read it to decide what to do. These assertions lock in
  // the wording (FAIL/WARN/OK prefixes + the first-CRIT call-out).

  it("renders an OK summary when all anchors are healthy", async () => {
    const result = await auditAnchors({
      sources: [{ id: "realreel", root_cert: "x" }, { id: "pixel", root_cert: "y" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        realreel: { subjectCn: "RealReel Root CA", notAfter: new Date("2051-05-05T20:29:34Z") },
        pixel: { subjectCn: "Google C2PA Root CA G3", notAfter: new Date("2050-05-08T22:32:21Z") },
      }),
    });
    const output = renderAudit(result);
    expect(output).toContain("Trust anchor expiry audit");
    expect(output).toContain("realreel");
    expect(output).toContain("RealReel Root CA");
    expect(output).toContain("pixel");
    expect(output).toContain("Google C2PA Root CA G3");
    expect(output).toContain("OK: all 2 trust anchors within validity windows.");
    expect(output).not.toContain("FAIL");
    expect(output).not.toContain("WARN");
  });

  it("renders a FAIL summary with the first-CRIT call-out", async () => {
    const result = await auditAnchors({
      sources: [{ id: "pixel", root_cert: "x" }],
      warnDays: 365,
      critDays: 90,
      now: NOW,
      getCertInfo: stubReader({
        pixel: {
          subjectCn: "Google C2PA Root CA G3",
          notAfter: new Date(NOW.getTime() + 30 * MS_PER_DAY),
        },
      }),
    });
    const output = renderAudit(result);
    expect(output).toContain("FAIL: 1 CRITICAL (pixel: 30 days)");
    expect(output).toContain("Rotate now");
  });
});
