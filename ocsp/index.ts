// Worker entrypoint: imports the canonical trust-source PEMs (single source of
// truth, no copies in ocsp/) and hands them to the pure router in router.ts
// together with the KV namespace holding the pre-signed responses.
import ROOT_PEM from "../verifier/trust-sources/realreel/realreel-c2pa-root.pem"; // string (Text rule)
import ICA_PEM from "../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem"; // string (Text rule)
import { handleRequest } from "./router.ts";
import { toArrayBuffer } from "./ocsp.ts";

// Structural slice of Cloudflare's KVNamespace — enough for the router's one
// read, without a @cloudflare/workers-types dependency.
interface KvNamespaceLite {
  get(key: string, type: "arrayBuffer"): Promise<ArrayBuffer | null>;
}

interface Env {
  OCSP_RESPONSES: KvNamespaceLite;
  // Origin URL of the live leaf-status responder (../ocsp-leaf/ on Cloud
  // Run). Unset until the cutover deploy: leaf CertIDs then answer
  // `unauthorized`, same as before that responder existed.
  LEAF_RESPONDER_ORIGIN?: string;
}

// Module scope so the router's per-isolate CertID cache (keyed on this object)
// actually hits — a per-request literal would recompute the digests every time.
const ASSETS = { rootPem: ROOT_PEM, icaPem: ICA_PEM };

export default {
  fetch(req: Request, env: Env): Promise<Response> {
    const origin = env.LEAF_RESPONDER_ORIGIN;
    // The client IP rides along so the origin can log — and if ever needed,
    // rate-limit — per client; without it every relayed request looks like
    // Cloudflare.
    const clientIp = req.headers.get("cf-connecting-ip");
    return handleRequest(
      req,
      ASSETS,
      { get: (key) => env.OCSP_RESPONSES.get(key, "arrayBuffer") },
      origin
        ? (der) =>
          fetch(origin, {
            method: "POST",
            headers: {
              "content-type": "application/ocsp-request",
              ...(clientIp ? { "x-forwarded-for": clientIp } : {}),
            },
            body: toArrayBuffer(der),
            signal: AbortSignal.timeout(10_000),
          })
        : undefined,
    );
  },
};
