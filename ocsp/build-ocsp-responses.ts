// Refresh tool: builds, KMS-signs, and self-verifies the pre-signed OCSP
// responses the realreel-ocsp Worker serves from KV. Run on a schedule (see
// .github/workflows/refresh-ocsp.yml) so `nextUpdate` never lapses, and on
// demand after a responder-cert re-issue or an ICA revocation.
//
//   deno run --allow-read --allow-write --allow-env --allow-run=gcloud \
//     ocsp/build-ocsp-responses.ts --out-dir out
//
// Writes one DER OCSPResponse per supported CertID hash algorithm (a response
// must echo the CertID hash the client sent, so both are pre-produced):
//   out/response-sha1.der   → KV key response:sha1
//   out/response-sha256.der → KV key response:sha256
//
// ICA compromise (CP §3.6, revoke ≤ 72 h): re-run with
//   --status revoked --revocation-time <ISO-8601> [--revocation-reason N]
// and publish the same files to KV.
//
// Keyring/location/key default to the ceremony values (realreel-ca-v2 / us /
// realreel-ocsp-root, version 1); override with env RING / LOC / KEY /
// KEY_VERSION / PROJECT after a responder key rotation. Signing shells out to
// `gcloud kms asymmetric-sign` — the caller needs roles/cloudkms.signer on the
// responder key. Every built response is verified before it is written: the
// signature must check out against the responder certificate's public key and
// the embedded cert must byte-match the trust-source PEM, so a wrong-key or
// wrong-cert configuration fails here instead of at validators.

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { p256 } from "@noble/curves/nist.js";
import {
  blockBytes,
  bytesEqual,
  certIdMatches,
  certIdValues,
  icaCertIdTargets,
  KV_KEY_BY_HASH_OID,
  OID_ECDSA_WITH_SHA256,
  OID_OCSP_BASIC,
  OID_SHA1,
  parseCert,
  pemToDer,
  subjectPublicKeyBits,
  toArrayBuffer,
} from "./ocsp.ts";

// Output filename per hash OID, mirrored by the KV keys in KV_KEY_BY_HASH_OID.
export const OUT_FILE_BY_HASH_OID: Record<string, string> = Object.fromEntries(
  Object.entries(KV_KEY_BY_HASH_OID).map(([oid, kvKey]) => [oid, `${kvKey.replace(":", "-")}.der`]),
);

// Returns a DER ECDSA signature (ecdsa-with-SHA256) over the TBS bytes.
export type SignTbs = (tbs: Uint8Array) => Promise<Uint8Array>;

export interface BuildOpts {
  rootPem: string;
  icaPem: string;
  responderPem: string;
  hashOid: string; // OID_SHA1 | OID_SHA256 — which CertID variant to produce
  status: "good" | "revoked";
  revocationTime?: Date; // required when status is "revoked"
  revocationReason?: number; // optional CRLReason (RFC 5280 §5.3.1)
  now: Date;
  validityDays: number;
  signTbs: SignTbs;
}

function certStatusSchema(opts: BuildOpts): asn1js.Primitive | asn1js.Constructed {
  if (opts.status === "good") {
    // good ::= [0] IMPLICIT NULL — an empty context-0 primitive.
    return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
  }
  if (!opts.revocationTime) throw new Error("revoked status requires revocationTime");
  if (
    opts.revocationReason !== undefined &&
    (!Number.isInteger(opts.revocationReason) ||
      opts.revocationReason < 0 || opts.revocationReason > 10)
  ) {
    // A non-integer (e.g. NaN from a typo) would encode as a zero-length
    // ENUMERATED that openssl rejects as illegal DER — refuse to build it.
    throw new Error(
      `revocationReason must be a CRLReason integer 0..10, got ${opts.revocationReason}`,
    );
  }
  const revokedInfo: (asn1js.GeneralizedTime | asn1js.Constructed)[] = [
    new asn1js.GeneralizedTime({ valueDate: opts.revocationTime }),
  ];
  if (opts.revocationReason !== undefined) {
    revokedInfo.push(
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Enumerated({ value: opts.revocationReason })],
      }),
    );
  }
  return new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 }, value: revokedInfo });
}

export async function buildOcspResponseDer(opts: BuildOpts): Promise<Uint8Array> {
  const responder = parseCert(opts.responderPem);
  const target = (await icaCertIdTargets(opts.rootPem, opts.icaPem)).find(
    (t) => t.hashOid === opts.hashOid,
  );
  if (!target) throw new Error(`unsupported CertID hash OID: ${opts.hashOid}`);

  const now = new Date(opts.now.getTime());
  now.setMilliseconds(0); // whole seconds: keeps GeneralizedTime fraction-free
  const nextUpdate = new Date(now.getTime() + opts.validityDays * 86_400_000);

  const certID = new pkijs.CertID({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: target.hashOid,
      algorithmParams: new asn1js.Null(),
    }),
    issuerNameHash: new asn1js.OctetString({ valueHex: toArrayBuffer(target.issuerNameHash) }),
    issuerKeyHash: new asn1js.OctetString({ valueHex: toArrayBuffer(target.issuerKeyHash) }),
    serialNumber: new asn1js.Integer({ valueHex: toArrayBuffer(target.serialNumber) }),
  });

  const single = new pkijs.SingleResponse({
    certID,
    certStatus: certStatusSchema(opts),
    thisUpdate: now,
    nextUpdate,
  });

  // responderID byKey: SHA-1 of the responder's subjectPublicKey bits
  // (RFC 6960 §4.2.1 KeyHash). byKey avoids any DN re-encoding concerns.
  const responderKeyHash = new Uint8Array(
    await crypto.subtle.digest("SHA-1", toArrayBuffer(subjectPublicKeyBits(responder))),
  );

  const responseData = new pkijs.ResponseData({
    responderID: new asn1js.OctetString({ valueHex: toArrayBuffer(responderKeyHash) }),
    producedAt: now,
    responses: [single],
  });
  const tbs = new Uint8Array(responseData.toSchema(true).toBER(false));
  responseData.tbsView = tbs; // BasicOCSPResponse.toSchema() serializes tbsView

  const signature = await opts.signTbs(tbs);

  const basic = new pkijs.BasicOCSPResponse({
    tbsResponseData: responseData,
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_ECDSA_WITH_SHA256 }),
    signature: new asn1js.BitString({ valueHex: toArrayBuffer(signature) }),
    certs: [responder],
  });

  const response = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 0 }), // successful
    responseBytes: new pkijs.ResponseBytes({
      responseType: OID_OCSP_BASIC,
      response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
    }),
  });
  return new Uint8Array(response.toSchema().toBER(false));
}

// --- Self-verification ----------------------------------------------------

export interface VerifyOpts {
  rootPem: string;
  icaPem: string;
  hashOid: string;
  status: "good" | "revoked";
  now: Date;
  // Public key (uncompressed EC point bits) the signature must verify
  // against. Defaults to the embedded certs[0] key; tests inject their
  // ephemeral key here.
  signerKeyBits?: Uint8Array;
  // When set, the embedded certs[0] must byte-match this PEM (TBS compare).
  expectEmbeddedCertPem?: string;
}

export interface VerifiedResponse {
  producedAt: Date;
  thisUpdate: Date;
  nextUpdate: Date;
  signerCn: string;
}

export async function verifyOcspResponseDer(
  der: Uint8Array,
  opts: VerifyOpts,
): Promise<VerifiedResponse> {
  const fail = (msg: string) => {
    throw new Error(`OCSP response self-verify failed: ${msg}`);
  };

  const response = pkijs.OCSPResponse.fromBER(toArrayBuffer(der));
  if (blockBytes(response.responseStatus)[0] !== 0) fail("responseStatus is not successful");
  if (!response.responseBytes || response.responseBytes.responseType !== OID_OCSP_BASIC) {
    fail("responseBytes is not id-pkix-ocsp-basic");
  }
  const basic = pkijs.BasicOCSPResponse.fromBER(
    toArrayBuffer(blockBytes(response.responseBytes!.response)),
  );

  if (basic.signatureAlgorithm.algorithmId !== OID_ECDSA_WITH_SHA256) {
    fail(`unexpected signatureAlgorithm ${basic.signatureAlgorithm.algorithmId}`);
  }

  const tbsData = basic.tbsResponseData;
  if (tbsData.responses.length !== 1) fail(`expected 1 SingleResponse, got ${tbsData.responses.length}`);
  const single = tbsData.responses[0];

  const expected = (await icaCertIdTargets(opts.rootPem, opts.icaPem)).find(
    (t) => t.hashOid === opts.hashOid,
  );
  if (!expected || !certIdMatches(expected, certIdValues(single.certID))) {
    fail("CertID does not name the ICA under the requested hash algorithm");
  }

  const statusBlock = single.certStatus as { idBlock: { tagClass: number; tagNumber: number } };
  const wantTag = opts.status === "good" ? 0 : 1;
  if (statusBlock.idBlock.tagClass !== 3 || statusBlock.idBlock.tagNumber !== wantTag) {
    fail(`certStatus is not '${opts.status}'`);
  }

  if (!single.nextUpdate) fail("nextUpdate is absent");
  if (single.thisUpdate.getTime() > opts.now.getTime()) fail("thisUpdate is in the future");
  if (single.nextUpdate!.getTime() <= opts.now.getTime()) fail("nextUpdate is not in the future");

  const certs = basic.certs ?? [];
  if (certs.length === 0) fail("responder certificate is not embedded in certs");
  if (opts.expectEmbeddedCertPem) {
    const want = parseCert(opts.expectEmbeddedCertPem);
    if (!bytesEqual(certs[0].tbsView, want.tbsView)) {
      fail("embedded certs[0] does not match the expected responder certificate");
    }
  }

  const signerKeyBits = opts.signerKeyBits ?? subjectPublicKeyBits(certs[0]);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(tbsData.tbsView)),
  );
  const sig = p256.Signature.fromDER(blockBytes(basic.signature)).toCompactRawBytes();
  if (!p256.verify(sig, digest, signerKeyBits, { lowS: false })) {
    fail("signature does not verify against the responder public key");
  }

  const cnAttr = certs[0].subject.typesAndValues.find((tv) => tv.type === "2.5.4.3");
  return {
    producedAt: tbsData.producedAt,
    thisUpdate: single.thisUpdate,
    nextUpdate: single.nextUpdate!,
    signerCn: cnAttr ? String(cnAttr.value.valueBlock.value) : "(no CN)",
  };
}

// --- gcloud KMS plumbing (CLI only; tests inject their own signer) --------

async function kmsSignTbs(tbs: Uint8Array): Promise<Uint8Array> {
  const ring = Deno.env.get("RING") ?? "realreel-ca-v2";
  const loc = Deno.env.get("LOC") ?? "us";
  const key = Deno.env.get("KEY") ?? "realreel-ocsp-root";
  const version = Deno.env.get("KEY_VERSION") ?? "1";
  const project = Deno.env.get("PROJECT");

  const inFile = await Deno.makeTempFile({ suffix: ".der" });
  const sigFile = await Deno.makeTempFile({ suffix: ".sig" });
  try {
    await Deno.writeFile(inFile, tbs);
    const args = [
      "kms", "asymmetric-sign",
      "--version", version,
      "--key", key,
      "--keyring", ring,
      "--location", loc,
      "--digest-algorithm", "sha256",
      "--input-file", inFile,
      "--signature-file", sigFile,
    ];
    if (project) args.push("--project", project);
    const out = await new Deno.Command("gcloud", { args }).output();
    if (!out.success) {
      throw new Error(`gcloud kms asymmetric-sign failed:\n${new TextDecoder().decode(out.stderr)}`);
    }
    return await Deno.readFile(sigFile);
  } finally {
    await Deno.remove(inFile).catch(() => {});
    await Deno.remove(sigFile).catch(() => {});
  }
}

// --- CLI ------------------------------------------------------------------

if (import.meta.main) {
  const getFlag = (flag: string): string | undefined => {
    const i = Deno.args.indexOf(flag);
    const v = i >= 0 ? Deno.args[i + 1] : undefined;
    return v && !v.startsWith("--") ? v : undefined;
  };

  const outDir = getFlag("--out-dir") ?? "out";
  const status = (getFlag("--status") ?? "good") as "good" | "revoked";
  if (status !== "good" && status !== "revoked") {
    console.error(`--status must be good or revoked, got '${status}'`);
    Deno.exit(2);
  }
  const revocationTimeRaw = getFlag("--revocation-time");
  const revocationTime = revocationTimeRaw ? new Date(revocationTimeRaw) : undefined;
  if (status === "revoked" && (!revocationTime || Number.isNaN(revocationTime.getTime()))) {
    console.error("--status revoked requires --revocation-time <ISO-8601>");
    Deno.exit(2);
  }
  const reasonRaw = getFlag("--revocation-reason");
  let revocationReason: number | undefined;
  if (reasonRaw !== undefined) {
    if (!/^\d+$/.test(reasonRaw) || Number(reasonRaw) > 10) {
      console.error(`--revocation-reason must be a CRLReason integer 0..10, got '${reasonRaw}'`);
      Deno.exit(2);
    }
    revocationReason = Number(reasonRaw);
  }
  const validityDays = Number(Deno.env.get("OCSP_VALIDITY_DAYS") ?? "7");
  if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 30) {
    console.error(`OCSP_VALIDITY_DAYS must be an integer in 1..30, got '${validityDays}'`);
    Deno.exit(2);
  }

  const certsDir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
  const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", certsDir));
  const icaPem = await Deno.readTextFile(new URL("realreel-claim-signing-ca.pem", certsDir));
  const responderPem = await Deno.readTextFile(new URL("realreel-ocsp-responder-1.pem", certsDir));

  const now = new Date();
  await Deno.mkdir(outDir, { recursive: true });

  for (const hashOid of Object.keys(KV_KEY_BY_HASH_OID)) {
    const der = await buildOcspResponseDer({
      rootPem, icaPem, responderPem,
      hashOid, status, revocationTime, revocationReason,
      now, validityDays, signTbs: kmsSignTbs,
    });
    const verified = await verifyOcspResponseDer(der, {
      rootPem, icaPem, hashOid, status, now,
      expectEmbeddedCertPem: responderPem,
    });
    const outPath = `${outDir}/${OUT_FILE_BY_HASH_OID[hashOid]}`;
    await Deno.writeFile(outPath, der);
    const alg = hashOid === OID_SHA1 ? "sha1" : "sha256";
    console.log(
      `${outPath} (KV ${KV_KEY_BY_HASH_OID[hashOid]}): ${status} for the ICA, ` +
        `CertID ${alg}, ${der.length} bytes, signed by '${verified.signerCn}', ` +
        `thisUpdate ${verified.thisUpdate.toISOString()}, nextUpdate ${verified.nextUpdate.toISOString()}`,
    );
  }
  console.log("self-verify OK: signatures check out against the responder certificate.");
}
