// Shared-secret gate on the hop from the public OCSP Worker (../ocsp/) to this
// service. Every leaf's AIA points at `http://ocsp.realreel.xyz` — the Worker —
// so that host is the OCSP repository RFC 6960 and CP §4.11 describe and this
// service is only its backend. No OCSP client resolves it, so requiring a
// secret costs no conformance claim and stops the internet spending KMS
// signatures.
import { timingSafeEqual } from "node:crypto";

export const RELAY_SECRET_HEADER = "x-realreel-relay-secret";

export function relayAuthorized(req: Request, expected: string): boolean {
  const provided = req.headers.get(RELAY_SECRET_HEADER);
  if (provided === null) return false;
  const a = new TextEncoder().encode(provided);
  // Fetch trims header values, so the arriving side always is. Match it, or a
  // secret stored with the newline `echo` appends could never match.
  const b = new TextEncoder().encode(expected.trim());
  // Else a blank secret would authorize a blank header. main.ts also refuses
  // to start on one.
  if (b.length === 0) return false;
  // timingSafeEqual throws on a length mismatch, and length isn't the secret.
  return a.length === b.length && timingSafeEqual(a, b);
}
