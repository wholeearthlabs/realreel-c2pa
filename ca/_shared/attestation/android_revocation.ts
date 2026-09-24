// Google's Android attestation revocation list: leaked or compromised
// attestation keys, keyed by certificate serial.
//   https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status

const ANDROID_ATTESTATION_STATUS_URL =
  "https://android.googleapis.com/attestation/status";
export { ANDROID_ATTESTATION_STATUS_URL };

const REFRESH_AFTER_MS = 24 * 60 * 60 * 1000;
const USABLE_FOR_MS = 7 * 24 * 60 * 60 * 1000;
const RETRY_AFTER_FAILURE_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5_000;

export interface AndroidRevocationEntry {
  status: string;
  reason: string | null;
}

/** Keyed by serial as the list writes it: lowercase, no leading zeros, in
 *  either hex (128-bit RKP serials) or decimal (64-bit OEM keybox serials). */
export type AndroidRevocationList = ReadonlyMap<string, AndroidRevocationEntry>;

/** Big-endian DER INTEGER content octets → the serial in both list forms. */
export function serialForms(der: Uint8Array): { hex: string; dec: string } {
  let v = 0n;
  for (const b of der) v = (v << 8n) | BigInt(b);
  return { hex: v.toString(16), dec: v.toString(10) };
}

export function findRevoked(
  serialDer: Uint8Array,
  list: AndroidRevocationList,
): { serial: string; entry: AndroidRevocationEntry } | null {
  const { hex, dec } = serialForms(serialDer);
  for (const serial of [hex, dec]) {
    const entry = list.get(serial);
    if (entry) return { serial, entry };
  }
  return null;
}

/** Fails on anything but a non-empty object of numeric serials, so a
 *  truncated or reshaped response can never read as "nothing revoked". */
export function parseAndroidRevocationList(
  json: unknown,
): Map<string, AndroidRevocationEntry> {
  const entries = (json as { entries?: unknown } | null)?.entries;
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) {
    throw new Error("attestation status list has no entries object");
  }
  const out = new Map<string, AndroidRevocationEntry>();
  for (const [serial, value] of Object.entries(entries)) {
    const key = serial.toLowerCase();
    if (!/^[0-9a-f]+$/.test(key)) {
      throw new Error(
        `attestation status list has a non-numeric serial: ${
          serial.slice(0, 64)
        }`,
      );
    }
    const v = value as { status?: unknown; reason?: unknown } | null;
    out.set(key.replace(/^0+(?=.)/, ""), {
      status: typeof v?.status === "string" ? v.status : "UNKNOWN",
      reason: typeof v?.reason === "string" ? v.reason : null,
    });
  }
  if (out.size === 0) throw new Error("attestation status list is empty");
  return out;
}

/**
 * Returns a loader that caches the list for REFRESH_AFTER_MS and, when a
 * refresh fails, keeps serving a copy up to USABLE_FOR_MS old without
 * retrying the network for RETRY_AFTER_FAILURE_MS. With no usable copy it
 * throws, and the caller must not enroll.
 */
export function buildAndroidRevocationLoader(
  deps: { fetch?: typeof fetch; now?: () => Date } = {},
): () => Promise<AndroidRevocationList> {
  const fetchImpl = deps.fetch ?? fetch;
  const now = deps.now ?? (() => new Date());
  let cached: { list: AndroidRevocationList; fetchedAt: number } | null = null;
  let retryAt = 0;
  return async () => {
    const t = now().getTime();
    const usable = cached && t - cached.fetchedAt < USABLE_FOR_MS
      ? cached.list
      : null;
    if (usable && (t - cached!.fetchedAt < REFRESH_AFTER_MS || t < retryAt)) {
      return usable;
    }
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
      retryAt = t + RETRY_AFTER_FAILURE_MS;
      if (usable) return usable;
      throw new Error(
        `Android attestation revocation list unavailable: ${msg}`,
      );
    }
  };
}
