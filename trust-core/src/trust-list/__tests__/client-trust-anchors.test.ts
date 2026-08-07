// Self-contained sanity for the generated client trust-anchors bundle —
// runs in trust-core's own suite so a trust-core-only change can't ship a
// mangled bundle without this package's tests noticing. (Byte-lockstep
// against the verifier's boot-time pool lives in the verifier workspace:
// verifier/__tests__/client-trust-anchors-lockstep.test.ts.)

import { describe, it, expect } from "vitest";
import { X509Certificate } from "node:crypto";

import { CLIENT_TRUST_ANCHORS_PEM } from "../client-trust-anchors.generated.js";

const CERT_BLOCK =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

describe("CLIENT_TRUST_ANCHORS_PEM (generated bundle)", () => {
  it("holds a plausible number of well-paired certificate blocks", () => {
    const begins = CLIENT_TRUST_ANCHORS_PEM.match(/-----BEGIN CERTIFICATE-----/g) ?? [];
    const ends = CLIENT_TRUST_ANCHORS_PEM.match(/-----END CERTIFICATE-----/g) ?? [];
    expect(begins.length).toBe(ends.length);
    // RealReel roots + Google root + the C2PA TSA list — a regeneration
    // that collapses below this floor lost real trust material.
    expect(begins.length).toBeGreaterThanOrEqual(4);
  });

  it("every block parses as an X.509 certificate", () => {
    for (const block of CLIENT_TRUST_ANCHORS_PEM.match(CERT_BLOCK) ?? []) {
      expect(() => new X509Certificate(block)).not.toThrow();
    }
  });

  it("contains no private key material", () => {
    expect(CLIENT_TRUST_ANCHORS_PEM).not.toMatch(/PRIVATE KEY/);
  });

  it("survived the template-literal emitter unmangled", () => {
    expect(CLIENT_TRUST_ANCHORS_PEM).not.toContain("`");
    expect(CLIENT_TRUST_ANCHORS_PEM).not.toContain("${");
  });
});
