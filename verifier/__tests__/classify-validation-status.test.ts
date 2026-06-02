// Unit tests for classifyStrictValidationStatus (src/profiles/_shared.ts) —
// the pure mapping from c2pa-rs `validation_status` codes to our VerifyError
// taxonomy. Synthetic inputs only; no fixtures, no c2pa-node Reader.
//
// Why this is the test that matters for the cert-expiry reject path:
// verifyRealReel() calls this FIRST thing on `store.validation_status`. When
// c2pa-rs reports an expired signing cert — including an expired Stage-1
// ANCESTOR, which it surfaces in the TOP-LEVEL validation_status (verified
// empirically 2026-05-29; see "Why the verifier needs no ancestor-specific
// code" in TRUST_ARCHITECTURE.md) — this
// mapping is the OUR-CODE step that turns it into CERT_EXPIRED. c2pa-rs's own
// detection is pinned by the @contentauth/c2pa-node version, not re-tested
// here; this locks the half we own.

import { describe, it, expect } from "vitest";
import { classifyStrictValidationStatus } from "../src/profiles/_shared.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";

/** Run the classifier; return the thrown VerifyError's code, or null if it
 *  accepted (didn't throw). Asserts the throw is a VerifyError. */
function codeThrownBy(
  status: Array<{ code: string; explanation?: string | null }>,
): VerifyErrorCode | null {
  try {
    classifyStrictValidationStatus(status);
    return null;
  } catch (e) {
    expect(e).toBeInstanceOf(VerifyError);
    return (e as VerifyError).code;
  }
}

describe("classifyStrictValidationStatus", () => {
  it("accepts an empty status array (no throw)", () => {
    expect(codeThrownBy([])).toBeNull();
  });

  it("maps signingCredential.expired → CERT_EXPIRED (the ancestor-expiry reject)", () => {
    expect(codeThrownBy([{ code: "signingCredential.expired" }])).toBe(
      VerifyErrorCode.CERT_EXPIRED,
    );
  });

  it("maps signingCredential.untrusted → UNTRUSTED_ISSUER", () => {
    expect(codeThrownBy([{ code: "signingCredential.untrusted" }])).toBe(
      VerifyErrorCode.UNTRUSTED_ISSUER,
    );
  });

  it("maps claimSignature.* / *.mismatch / *.invalid → SIGNATURE_INVALID", () => {
    expect(codeThrownBy([{ code: "claimSignature.mismatch" }])).toBe(
      VerifyErrorCode.SIGNATURE_INVALID,
    );
    expect(codeThrownBy([{ code: "assertion.hashedURI.mismatch" }])).toBe(
      VerifyErrorCode.SIGNATURE_INVALID,
    );
    expect(codeThrownBy([{ code: "timeStamp.invalid" }])).toBe(
      VerifyErrorCode.SIGNATURE_INVALID,
    );
  });

  it("maps any other non-empty status → MANIFEST_MALFORMED", () => {
    expect(codeThrownBy([{ code: "manifest.unknownFutureCode" }])).toBe(
      VerifyErrorCode.MANIFEST_MALFORMED,
    );
  });

  it("classifies on the FIRST status entry", () => {
    // First wins: an expired-cert entry ahead of a benign one still rejects.
    expect(
      codeThrownBy([
        { code: "signingCredential.expired" },
        { code: "manifest.unknownFutureCode" },
      ]),
    ).toBe(VerifyErrorCode.CERT_EXPIRED);
  });

  it("INVARIANT: throws on ANY non-empty validation status, regardless of which entry or how many", () => {
    // The classifier only inspects status[0] for the specific code, but the
    // load-bearing security property is that it rejects ANY non-empty
    // validation status — a future tolerant branch must never let a real
    // failure at status[1+] through unthrown. This pins that: every
    // non-empty array below throws, including ones whose first entry looks
    // benign / unknown and whose real failure sits later.
    const nonEmptyCases: Array<
      Array<{ code: string; explanation?: string | null }>
    > = [
      [{ code: "manifest.unknownFutureCode" }],
      [{ code: "some.benignLookingCode" }, { code: "claimSignature.mismatch" }],
      [
        { code: "another.unknownCode" },
        { code: "signingCredential.expired" },
        { code: "manifest.somethingElse" },
      ],
      [{ code: "x" }, { code: "y" }, { code: "z" }],
    ];
    for (const status of nonEmptyCases) {
      // codeThrownBy asserts the throw is a VerifyError and returns its code;
      // a non-null code means it threw (did not silently accept).
      expect(codeThrownBy(status)).not.toBeNull();
    }
  });

  it("surfaces the explanation in the error detail when present", () => {
    try {
      classifyStrictValidationStatus([
        { code: "signingCredential.expired", explanation: "certificate expired" },
      ]);
      throw new Error("expected classifyStrictValidationStatus to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).detail).toBe("certificate expired");
      expect((e as VerifyError).message).toContain("certificate expired");
    }
  });
});
