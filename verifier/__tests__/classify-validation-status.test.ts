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
  status: Parameters<typeof classifyStrictValidationStatus>[0],
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

  it("maps untrusted followed by expired for the same signature → CERT_EXPIRED (c2pa-rs 0.91 order)", () => {
    const sig = "self#jumbf=/c2pa/urn:c2pa:a/c2pa.signature";
    expect(
      codeThrownBy([
        { code: "signingCredential.untrusted", url: sig },
        { code: "signingCredential.expired", url: sig },
      ]),
    ).toBe(VerifyErrorCode.CERT_EXPIRED);
    // An expiry on a different signature doesn't explain the untrusted one.
    expect(
      codeThrownBy([
        { code: "signingCredential.untrusted", url: sig },
        { code: "signingCredential.expired", url: "self#jumbf=/c2pa/urn:c2pa:b/c2pa.signature" },
      ]),
    ).toBe(VerifyErrorCode.UNTRUSTED_ISSUER);
  });

  it("maps signingCredential.ocsp.revoked → UNTRUSTED_ISSUER, never KEY_REVOKED", () => {
    // KEY_REVOKED makes the app discard the uploader's own key; a revoked
    // wrap-mode parent is another camera's certificate.
    expect(codeThrownBy([{ code: "signingCredential.ocsp.revoked" }])).toBe(
      VerifyErrorCode.UNTRUSTED_ISSUER,
    );
  });

  it("an OCSP rejection carries the code in its detail and the ocsp category (c2pa-rs's explanation alone never says 'ocsp')", () => {
    try {
      classifyStrictValidationStatus([
        { code: "signingCredential.ocsp.revoked", explanation: "certificate revoked" },
      ]);
      throw new Error("expected classifyStrictValidationStatus to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).detail).toBe("signingCredential.ocsp.revoked: certificate revoked");
      expect((e as VerifyError).category).toBe("ocsp");
    }
  });

  it("maps signingCredential.ocsp.unknown → UNTRUSTED_ISSUER", () => {
    expect(codeThrownBy([{ code: "signingCredential.ocsp.unknown" }])).toBe(
      VerifyErrorCode.UNTRUSTED_ISSUER,
    );
  });

  it("finds ocsp.revoked anywhere in the array, ahead of the first-entry mapping", () => {
    expect(
      codeThrownBy([
        { code: "manifest.unknownFutureCode" },
        { code: "signingCredential.ocsp.revoked" },
      ]),
    ).toBe(VerifyErrorCode.UNTRUSTED_ISSUER);
    expect(
      codeThrownBy([
        { code: "signingCredential.expired" },
        { code: "assertion.hashedURI.mismatch" },
        { code: "signingCredential.ocsp.revoked", explanation: "certificate revoked at: 2026-09-01" },
      ]),
    ).toBe(VerifyErrorCode.UNTRUSTED_ISSUER);
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

  it("classifies on the FIRST status entry (revocation aside)", () => {
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

  describe("CERT_EXPIRED about a signature other than this upload's", () => {
    const UPLOAD = "urn:c2pa:upload";
    const sig = (label: string) => `self#jumbf=/c2pa/${label}/c2pa.signature`;
    const expired = (url: string) => ({ code: "signingCredential.expired", explanation: "certificate expired", url });
    const detailOf = (status: Parameters<typeof classifyStrictValidationStatus>[0], active?: string) => {
      try {
        classifyStrictValidationStatus(status, active);
      } catch (e) {
        expect((e as VerifyError).code).toBe(VerifyErrorCode.CERT_EXPIRED);
        return (e as VerifyError).detail;
      }
      throw new Error("expected a throw");
    };

    it("marks the capture's expired signature", () => {
      expect(detailOf([expired(sig("urn:c2pa:capture"))], UPLOAD)).toBe("capture: certificate expired");
    });

    it("marks it on the untrusted-then-expired pair too", () => {
      const url = sig("urn:c2pa:capture");
      expect(detailOf([{ code: "signingCredential.untrusted", url }, expired(url)], UPLOAD)).toBe(
        "capture: certificate expired",
      );
    });

    it("leaves this upload's own expired signature unmarked", () => {
      expect(detailOf([expired(sig(UPLOAD))], UPLOAD)).toBe("certificate expired");
    });

    it("leaves it unmarked without an active label or a url naming another manifest", () => {
      expect(detailOf([expired(sig("urn:c2pa:capture"))])).toBe("certificate expired");
      expect(detailOf([{ code: "signingCredential.expired", explanation: "certificate expired" }], UPLOAD)).toBe(
        "certificate expired",
      );
      for (const url of ["", UPLOAD, "urn:c2pa:capture", "OCSP_RESPONSE"]) {
        expect(detailOf([expired(url)], UPLOAD)).toBe("certificate expired");
      }
    });
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
