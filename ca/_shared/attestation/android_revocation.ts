// Google's Android attestation revocation list: leaked or compromised
// attestation keys, keyed by certificate serial.
//   https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status

import type { Certificate } from "./pki.ts";

export const ANDROID_ATTESTATION_STATUS_URL =
  "https://android.googleapis.com/attestation/status";

const REFRESH_AFTER_MS = 24 * 60 * 60 * 1000;
const USABLE_FOR_MS = 7 * 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5_000;

export interface AndroidRevocationEntry {
  status: string;
  reason: string | null;
}

/** Keyed by serial in the list's form: lowercase hex, no leading zeros. */
export type AndroidRevocationList = ReadonlyMap<string, AndroidRevocationEntry>;

/** Big-endian DER INTEGER content octets → lowercase hex, no leading zeros. */
export function serialHex(der: Uint8Array): string {
  let v = 0n;
  for (const b of der) v = (v << 8n) | BigInt(b);
  return v.toString(16);
}

export function certSerialHex(cert: Certificate): string {
  return serialHex(new Uint8Array(cert.serialNumber.valueBlock.valueHexView));
}

export function parseAndroidRevocationList(
  json: unknown,
): Map<string, AndroidRevocationEntry> {
  const entries = (json as { entries?: unknown } | null)?.entries;
  if (!entries || typeof entries !== "object") {
    throw new Error("attestation status list has no entries object");
  }
  const out = new Map<string, AndroidRevocationEntry>();
  for (const [serial, value] of Object.entries(entries)) {
    const v = value as { status?: unknown; reason?: unknown } | null;
    out.set(serial.toLowerCase().replace(/^0+(?=.)/, ""), {
      status: typeof v?.status === "string" ? v.status : "UNKNOWN",
      reason: typeof v?.reason === "string" ? v.reason : null,
    });
  }
  return out;
}

/**
 * Returns a loader that caches the list for REFRESH_AFTER_MS and, when a
 * refresh fails, keeps serving a copy up to USABLE_FOR_MS old. With no usable
 * copy it throws, and the caller must not enroll.
 */
export function buildAndroidRevocationLoader(
  deps: { fetch?: typeof fetch; now?: () => Date } = {},
): () => Promise<AndroidRevocationList> {
  const fetchImpl = deps.fetch ?? fetch;
  const now = deps.now ?? (() => new Date());
  let cached: { list: AndroidRevocationList; fetchedAt: number } | null = null;
  return async () => {
    const t = now().getTime();
    if (cached && t - cached.fetchedAt < REFRESH_AFTER_MS) return cached.list;
    try {
      const res = await fetchImpl(ANDROID_ATTESTATION_STATUS_URL, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      cached = {
        list: parseAndroidRevocationList(await res.json()),
        fetchedAt: t,
      };
      return cached.list;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.warn(`[android-revocation] list fetch failed: ${msg}`);
      if (cached && t - cached.fetchedAt < USABLE_FOR_MS) return cached.list;
      throw new Error(
        `Android attestation revocation list unavailable: ${msg}`,
      );
    }
  };
}
