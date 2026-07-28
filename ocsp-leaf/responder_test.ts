// Tests for the leaf-status responder core. Everything runs against an
// ephemeral P-256 "responder key" + a synthetic ICA-shaped issuer, with the
// real trust-source PEMs exercised where chain identity matters.
//
// Run with:  deno task test   (from ocsp-leaf/)

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { p256 } from "@noble/curves/nist.js";
import {
  buildLeafOcspResponseDer,
  issuerMatches,
  leafIssuerTargets,
  OCSP_MALFORMED_REQUEST,
  OCSP_UNAUTHORIZED,
  respond,
  serialToDecimal,
} from "./responder.ts";
import type { LeafStatus, ResponderDeps } from "./responder.ts";
import {
  blockBytes,
  buildOcspRequestDer,
  OID_OCSP_BASIC,
  OID_SHA1,
  parseCert,
  subjectPublicKeyBits,
  toArrayBuffer,
} from "../ocsp/ocsp.ts";
import type { CertIdValues } from "../ocsp/ocsp.ts";

function assertEquals<T>(a: T, b: T, msg?: string) {
  const sa = JSON.stringify(a);
  const sb = JSON.stringify(b);
  if (sa !== sb) throw new Error(msg ?? `expected ${sb}, got ${sa}`);
}
function assert(cond: unknown, msg: string) {
  if (!cond) throw new Error(msg);
}

const ICA_PEM = await Deno.readTextFile(
  new URL(
    "../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem",
    import.meta.url,
  ),
);
const RESPONDER_PEM = await Deno.readTextFile(
  new URL(
    "../verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem",
    import.meta.url,
  ),
);

// Ephemeral P-256 signer standing in for KMS. The real responder cert's key
// is in KMS, so signature-verification tests check against THIS key rather
// than the embedded cert (same technique as ocsp/build_ocsp_responses_test.ts).
const testKp = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const testKeyBits = new Uint8Array(
  await crypto.subtle.exportKey("raw", testKp.publicKey),
);
async function testSignTbs(tbs: Uint8Array): Promise<Uint8Array> {
  const p1363 = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      testKp.privateKey,
      toArrayBuffer(tbs),
    ),
  );
  const canon = (raw: Uint8Array): ArrayBuffer => {
    let start = 0;
    while (start < raw.length - 1 && raw[start] === 0) start++;
    const trimmed = raw.subarray(start);
    if (trimmed[0] & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1);
      padded.set(trimmed, 1);
      return padded.buffer;
    }
    const out = new Uint8Array(trimmed.length);
    out.set(trimmed);
    return out.buffer;
  };
  return new Uint8Array(
    new asn1js.Sequence({
      value: [
        new asn1js.Integer({ valueHex: canon(p1363.slice(0, 32)) }),
        new asn1js.Integer({ valueHex: canon(p1363.slice(32)) }),
      ],
    }).toBER(false),
  );
}

const NOW = new Date("2026-07-27T12:00:00Z");
const TARGETS = await leafIssuerTargets(ICA_PEM);

async function leafCertId(serial: number[]): Promise<CertIdValues> {
  const t = TARGETS.find((x) => x.hashOid === OID_SHA1)!;
  return {
    hashOid: t.hashOid,
    issuerNameHash: t.issuerNameHash,
    issuerKeyHash: t.issuerKeyHash,
    serialNumber: new Uint8Array(serial),
  };
}

function makeDeps(status: LeafStatus, over: Partial<ResponderDeps> = {}): ResponderDeps {
  return {
    issuerTargets: TARGETS,
    responderPem: RESPONDER_PEM,
    lookupStatus: () => Promise.resolve(status),
    signTbs: testSignTbs,
    now: () => NOW,
    validityMs: 24 * 3_600_000,
    ...over,
  };
}

// Parse a successful response and return its pieces for assertions.
function parseSuccessful(der: Uint8Array) {
  const response = pkijs.OCSPResponse.fromBER(toArrayBuffer(der));
  assertEquals(blockBytes(response.responseStatus)[0], 0, "responseStatus successful");
  assert(
    response.responseBytes?.responseType === OID_OCSP_BASIC,
    "responseBytes is id-pkix-ocsp-basic",
  );
  const basic = pkijs.BasicOCSPResponse.fromBER(
    toArrayBuffer(blockBytes(response.responseBytes!.response)),
  );
  assertEquals(basic.tbsResponseData.responses.length, 1, "one SingleResponse");
  return { basic, single: basic.tbsResponseData.responses[0] };
}

function statusTag(single: pkijs.SingleResponse): number {
  return (single.certStatus as { idBlock: { tagNumber: number } }).idBlock.tagNumber;
}

Deno.test("serialToDecimal — matches the ledger's canonical-decimal form incl. DER 0x00 pad", () => {
  assertEquals(serialToDecimal(new Uint8Array([0x01])), "1");
  assertEquals(serialToDecimal(new Uint8Array([0x01, 0x00])), "256");
  // A DER INTEGER pads a high-bit value with 0x00 — same numeric value.
  assertEquals(serialToDecimal(new Uint8Array([0x00, 0x80])), "128");
  assertEquals(serialToDecimal(new Uint8Array([0x80])), "128");
});

Deno.test("leafIssuerTargets / issuerMatches — leaf CertIDs name the ICA, not the root", async () => {
  const id = await leafCertId([0x42]);
  assert(issuerMatches(TARGETS, id), "ICA-issued CertID matches");
  const wrong = { ...id, issuerKeyHash: new Uint8Array(id.issuerKeyHash.length) };
  assert(!issuerMatches(TARGETS, wrong), "foreign issuerKeyHash does not match");
});

Deno.test("respond — good / revoked statuses round-trip, signed by the injected key", async () => {
  const cases: Array<[LeafStatus, number]> = [
    [{ kind: "good" }, 0],
    [{ kind: "revoked", revokedAt: new Date("2026-07-01T00:00:00Z") }, 1],
  ];
  for (const [status, wantTag] of cases) {
    const reqDer = buildOcspRequestDer(await leafCertId([0x0a, 0xbc]));
    const { der, signed } = await respond(reqDer, makeDeps(status));
    assert(signed, "successful response is marked signed/cacheable");
    const { basic, single } = parseSuccessful(der);

    assertEquals(statusTag(single), wantTag, `status tag for ${status.kind}`);

    // The CertID must echo the request (by value).
    const gotSerial = blockBytes(single.certID.serialNumber);
    assertEquals(Array.from(gotSerial), [0x0a, 0xbc], "serial echoed");

    // thisUpdate/nextUpdate window from the injected clock.
    assertEquals(single.thisUpdate.getTime(), NOW.getTime(), "thisUpdate = now");
    assertEquals(
      single.nextUpdate!.getTime() - single.thisUpdate.getTime(),
      24 * 3_600_000,
      "24h validity window",
    );

    // Signature verifies against the injected ephemeral key.
    const digest = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        toArrayBuffer(basic.tbsResponseData.tbsView),
      ),
    );
    const sig = p256.Signature.fromDER(blockBytes(basic.signature))
      .toCompactRawBytes();
    assert(
      p256.verify(sig, digest, testKeyBits, { lowS: false }),
      "signature verifies",
    );

    // The real responder cert rides along in certs[0].
    const embedded = basic.certs?.[0];
    const want = parseCert(RESPONDER_PEM);
    assert(
      embedded !== undefined &&
        blockBytes(embedded.serialNumber).join(",") ===
          blockBytes(want.serialNumber).join(","),
      "embedded certs[0] is the leaf-status responder cert",
    );
  }
});

Deno.test("respond — a never-issued serial is unsigned unauthorized, no signature spent", async () => {
  let signs = 0;
  const reqDer = buildOcspRequestDer(await leafCertId([0x0a, 0xbc]));
  const { der, signed } = await respond(
    reqDer,
    makeDeps({ kind: "unknown" }, {
      signTbs: (tbs) => {
        signs++;
        return testSignTbs(tbs);
      },
    }),
  );
  assertEquals(Array.from(der), Array.from(OCSP_UNAUTHORIZED), "unauthorized bytes");
  assert(!signed, "not marked cacheable");
  assertEquals(signs, 0, "no KMS signature for serial enumeration");
});

Deno.test("respond — revoked response carries the revocation time", async () => {
  const revokedAt = new Date("2026-06-15T08:30:00Z");
  const reqDer = buildOcspRequestDer(await leafCertId([0x77]));
  const { der } = await respond(reqDer, makeDeps({ kind: "revoked", revokedAt }));
  const { single } = parseSuccessful(der);
  const revokedInfo = single.certStatus as { idBlock: { tagNumber: number } };
  assertEquals(revokedInfo.idBlock.tagNumber, 1, "revoked tag");
  const timeNode =
    (single.certStatus as unknown as { valueBlock: { value: unknown[] } })
      .valueBlock.value[0] as asn1js.GeneralizedTime;
  assertEquals(
    timeNode.toDate().getTime(),
    revokedAt.getTime(),
    "revocationTime = ledger revoked_at",
  );
});

Deno.test("respond — sub-second revoked_at is truncated (DER GeneralizedTime is fraction-free)", async () => {
  // revoked_at is a timestamptz with sub-second precision; strict parsers
  // (Go's encoding/asn1) reject a fractional GeneralizedTime.
  const revokedAt = new Date("2026-06-15T08:30:00.789Z");
  const reqDer = buildOcspRequestDer(await leafCertId([0x78]));
  const { der } = await respond(reqDer, makeDeps({ kind: "revoked", revokedAt }));
  const { single } = parseSuccessful(der);
  const timeNode =
    (single.certStatus as unknown as { valueBlock: { value: unknown[] } })
      .valueBlock.value[0] as asn1js.GeneralizedTime;
  assertEquals(
    timeNode.toDate().getTime(),
    new Date("2026-06-15T08:30:00.000Z").getTime(),
    "revocationTime truncated to whole seconds",
  );
});

Deno.test("respond — SHA-384-hashed CertID for our ICA gets a signed status", async () => {
  // RFC 6960 permits any hash for the CertID; SHA-384 is the natural pairing
  // for the SHA-384 hierarchy and must answer, not claim non-authority.
  const t = TARGETS.find((x) => x.hashOid === "2.16.840.1.101.3.4.2.2")!;
  const reqDer = buildOcspRequestDer({
    hashOid: t.hashOid,
    issuerNameHash: t.issuerNameHash,
    issuerKeyHash: t.issuerKeyHash,
    serialNumber: new Uint8Array([0x21]),
  });
  const { der, signed } = await respond(reqDer, makeDeps({ kind: "good" }));
  assert(signed, "SHA-384 CertID is answered, not refused");
  const { single } = parseSuccessful(der);
  assertEquals(statusTag(single), 0, "good status");
});

Deno.test("respond — cache: repeat CertID serves the same bytes with no second lookup/signature", async () => {
  let lookups = 0;
  let signs = 0;
  const store = new Map<string, Uint8Array>();
  const deps = makeDeps({ kind: "good" }, {
    lookupStatus: () => {
      lookups++;
      return Promise.resolve({ kind: "good" });
    },
    signTbs: (tbs) => {
      signs++;
      return testSignTbs(tbs);
    },
    cache: { get: (k) => store.get(k), set: (k, v) => store.set(k, v) },
  });
  const reqDer = buildOcspRequestDer(await leafCertId([0x0c, 0x0d]));
  const first = await respond(reqDer, deps);
  const second = await respond(reqDer, deps);
  assertEquals(lookups, 1, "one ledger lookup");
  assertEquals(signs, 1, "one signature");
  assert(second.signed, "cache hit is still marked signed/cacheable");
  assertEquals(Array.from(second.der), Array.from(first.der), "identical bytes");
  // A different serial is a different cache key.
  await respond(buildOcspRequestDer(await leafCertId([0x0e])), deps);
  assertEquals(signs, 2, "distinct serial signs again");
});

Deno.test("respond — foreign issuer → unauthorized, no lookup, no signature", async () => {
  let lookups = 0;
  let signs = 0;
  const id = await leafCertId([0x01]);
  const foreign = { ...id, issuerNameHash: new Uint8Array(id.issuerNameHash.length) };
  const { der, signed } = await respond(
    buildOcspRequestDer(foreign),
    makeDeps({ kind: "good" }, {
      lookupStatus: () => {
        lookups++;
        return Promise.resolve({ kind: "good" });
      },
      signTbs: (tbs) => {
        signs++;
        return testSignTbs(tbs);
      },
    }),
  );
  assertEquals(Array.from(der), Array.from(OCSP_UNAUTHORIZED), "unauthorized bytes");
  assert(!signed, "error form is not cacheable");
  assertEquals(lookups, 0, "no ledger lookup for foreign issuers");
  assertEquals(signs, 0, "no KMS signature spent on foreign issuers");
});

Deno.test("respond — garbage request → malformedRequest", async () => {
  const { der, signed } = await respond(
    new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    makeDeps({ kind: "good" }),
  );
  assertEquals(Array.from(der), Array.from(OCSP_MALFORMED_REQUEST), "malformed bytes");
  assert(!signed, "error form is not cacheable");
});

Deno.test("respond — multi-CertID request → unauthorized (single-status policy)", async () => {
  const id = await leafCertId([0x05]);
  // Hand-build a two-Request OCSPRequest.
  const single = buildOcspRequestDer(id);
  const parsed = asn1js.fromBER(toArrayBuffer(single));
  const tbs = (parsed.result as asn1js.Sequence).valueBlock.value[0] as asn1js.Sequence;
  const requestList = tbs.valueBlock.value[0] as asn1js.Sequence;
  requestList.valueBlock.value.push(requestList.valueBlock.value[0]);
  const doubled = new Uint8Array(
    new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [requestList] })] })
      .toBER(false),
  );
  const { der } = await respond(doubled, makeDeps({ kind: "good" }));
  assertEquals(Array.from(der), Array.from(OCSP_UNAUTHORIZED), "unauthorized bytes");
});

Deno.test("buildLeafOcspResponseDer — openssl-style sanity via pkijs re-parse of certs and responderID", async () => {
  const der = await buildLeafOcspResponseDer({
    certId: await leafCertId([0x33, 0x44]),
    status: { kind: "good" },
    responderPem: RESPONDER_PEM,
    now: NOW,
    validityMs: 3_600_000,
    signTbs: testSignTbs,
  });
  const { basic } = parseSuccessful(der);
  // responderID is byKey = SHA-1 of the responder cert's key bits.
  const wantKeyHash = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-1",
      toArrayBuffer(subjectPublicKeyBits(parseCert(RESPONDER_PEM))),
    ),
  );
  const gotKeyHash = blockBytes(
    basic.tbsResponseData.responderID as asn1js.OctetString,
  );
  assertEquals(Array.from(gotKeyHash), Array.from(wantKeyHash), "responderID byKey");
});
