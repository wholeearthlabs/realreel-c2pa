// Workflow-support commands for .github/workflows/refresh-ocsp.yml — the
// logic that would otherwise live as curl/jq/sed in `run:` blocks, moved here
// so it is typed, unit-tested (refresh_ops_test.ts), and reviewable. The
// workflow steps reduce to one `deno run` line each.
//
// Subcommands (env-driven; see the workflow for the wiring):
//
//   resolve-status   dispatch input > persisted KV `ica-status` > good.
//                    Prints GitHub step outputs (key=value lines) on stdout —
//                    append to "$GITHUB_OUTPUT" — and the human summary on
//                    stderr. A KV read error is fatal (defaulting to `good`
//                    on a flaky read could un-revoke); 404 = never persisted.
//   persist-status   writes the published status to the `ica-status` KV key
//                    (sticky status the daily cron re-signs).
//   verify-live      polls the live endpoint until BOTH the POST and GET
//                    (RFC 6960 A.1) forms serve bytes identical to the
//                    freshly built out/response-sha1.der — byte-equality is
//                    the freshness proof; a same-status stale response
//                    cannot pass. Rides through KV eventual consistency
//                    (~60 s) with 10 × 30 s attempts.

import {
  buildOcspRequestDer,
  bytesEqual,
  bytesToBase64,
  type CertIdValues,
  icaCertIdTargets,
  OID_SHA1,
} from "./ocsp.ts";

export interface StatusRecord {
  status: "good" | "revoked";
  revocationTime: string;
  revocationReason: string;
}

export interface ResolvedStatus extends StatusRecord {
  explicit: boolean;
}

export function namespaceIdFromWranglerToml(toml: string): string {
  const m = toml.match(/binding = "OCSP_RESPONSES", id = "([0-9a-f]{32})"/);
  if (!m) throw new Error("could not find the OCSP_RESPONSES namespace id in wrangler.toml");
  return m[1];
}

// The resolved fields end up as GitHub step outputs and CLI arguments, so
// hold them to strict shapes — a stray newline in a persisted value must not
// become an output-injection or argv surprise.
function checkStatusRecord(r: StatusRecord): StatusRecord {
  if (r.status !== "good" && r.status !== "revoked") {
    throw new Error(`unexpected status '${r.status}' (want good|revoked)`);
  }
  if (!/^[0-9A-Za-z:.+-]*$/.test(r.revocationTime)) {
    throw new Error("revocationTime contains characters outside an ISO-8601 timestamp");
  }
  if (!/^\d*$/.test(r.revocationReason)) {
    throw new Error("revocationReason must be empty or an integer");
  }
  if (r.status === "revoked" && !r.revocationTime) {
    throw new Error(
      "status=revoked requires a revocation time (dispatch input or persisted ica-status)",
    );
  }
  return r;
}

export interface KvReadResult {
  code: number;
  body: string;
}

export async function resolveStatus(opts: {
  inputStatus: string;
  inputTime: string;
  inputReason: string;
  readPersisted: () => Promise<KvReadResult>;
}): Promise<ResolvedStatus> {
  if (opts.inputStatus && opts.inputStatus !== "inherit") {
    return {
      ...checkStatusRecord({
        status: opts.inputStatus as StatusRecord["status"],
        revocationTime: opts.inputTime,
        revocationReason: opts.inputReason,
      }),
      explicit: true,
    };
  }

  const read = await opts.readPersisted();
  if (read.code === 404) {
    return { status: "good", revocationTime: "", revocationReason: "", explicit: false };
  }
  if (read.code !== 200) {
    throw new Error(`reading persisted ica-status from KV failed (HTTP ${read.code})`);
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(read.body);
  } catch {
    throw new Error("persisted ica-status is not valid JSON");
  }
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  return {
    ...checkStatusRecord({
      status: (str(parsed.status) || "good") as StatusRecord["status"],
      revocationTime: str(parsed.revocationTime),
      revocationReason: str(parsed.revocationReason),
    }),
    explicit: false,
  };
}

// --- Live-endpoint check --------------------------------------------------

export interface VerifyLiveOpts {
  url: string; // e.g. http://ocsp.realreel.xyz (no trailing slash)
  requestDer: Uint8Array;
  expected: Uint8Array; // the freshly built + published response bytes
  attempts: number;
  sleep: (ms: number) => Promise<void>;
  fetchFn?: typeof fetch;
  log?: (line: string) => void;
}

async function fetchOcspBytes(
  fetchFn: typeof fetch,
  input: string,
  init?: RequestInit,
): Promise<Uint8Array | null> {
  const res = await fetchFn(input, init);
  const body = new Uint8Array(await res.arrayBuffer());
  if (res.status !== 200) return null;
  if (!(res.headers.get("content-type") ?? "").startsWith("application/ocsp-response")) return null;
  return body;
}

// Resolves with the attempt number that succeeded; throws when every attempt
// fails. Both transports must serve the exact published bytes.
export async function verifyLive(opts: VerifyLiveOpts): Promise<number> {
  const fetchFn = opts.fetchFn ?? fetch;
  const log = opts.log ?? (() => {});
  const getUrl = `${opts.url}/${encodeURIComponent(bytesToBase64(opts.requestDer))}`;
  for (let attempt = 1; attempt <= opts.attempts; attempt++) {
    try {
      const viaPost = await fetchOcspBytes(fetchFn, opts.url, {
        method: "POST",
        headers: { "content-type": "application/ocsp-request" },
        body: opts.requestDer.slice().buffer as ArrayBuffer,
      });
      const viaGet = await fetchOcspBytes(fetchFn, getUrl);
      if (
        viaPost && bytesEqual(viaPost, opts.expected) &&
        viaGet && bytesEqual(viaGet, opts.expected)
      ) {
        log(
          `live endpoint serves the freshly published response ` +
            `(${opts.expected.length} bytes, POST+GET, attempt ${attempt})`,
        );
        return attempt;
      }
      log(`attempt ${attempt}: live bytes do not yet match the published response`);
    } catch (err) {
      log(`attempt ${attempt}: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (attempt < opts.attempts) await opts.sleep(30_000);
  }
  throw new Error("live endpoint never served the freshly published response");
}

// --- CLI ------------------------------------------------------------------

interface KvConfig {
  token: string;
  accountId: string;
  namespaceId: string;
}

function kvStatusUrl(cfg: KvConfig): string {
  return `https://api.cloudflare.com/client/v4/accounts/${cfg.accountId}` +
    `/storage/kv/namespaces/${cfg.namespaceId}/values/ica-status`;
}

async function kvConfigFromEnv(): Promise<KvConfig> {
  const token = Deno.env.get("CLOUDFLARE_API_TOKEN") ?? "";
  const accountId = Deno.env.get("CLOUDFLARE_ACCOUNT_ID") ?? "";
  if (!token || !accountId) {
    throw new Error("CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID must be set");
  }
  const toml = await Deno.readTextFile(new URL("wrangler.toml", import.meta.url));
  return { token, accountId, namespaceId: namespaceIdFromWranglerToml(toml) };
}

async function sha1Target(): Promise<CertIdValues> {
  const dir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
  const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", dir));
  const icaPem = await Deno.readTextFile(new URL("realreel-claim-signing-ca.pem", dir));
  const target = (await icaCertIdTargets(rootPem, icaPem)).find((t) => t.hashOid === OID_SHA1);
  if (!target) throw new Error("no SHA-1 CertID target");
  return target;
}

if (import.meta.main) {
  const env = (k: string) => Deno.env.get(k) ?? "";
  try {
    switch (Deno.args[0]) {
      case "resolve-status": {
        const cfg = await kvConfigFromEnv();
        const resolved = await resolveStatus({
          inputStatus: env("INPUT_STATUS"),
          inputTime: env("INPUT_TIME"),
          inputReason: env("INPUT_REASON"),
          readPersisted: async () => {
            const res = await fetch(kvStatusUrl(cfg), {
              headers: { authorization: `Bearer ${cfg.token}` },
            });
            return { code: res.status, body: await res.text() };
          },
        });
        console.error(
          `publishing status '${resolved.status}' (explicit dispatch: ${resolved.explicit})`,
        );
        console.log(`status=${resolved.status}`);
        console.log(`time=${resolved.revocationTime}`);
        console.log(`reason=${resolved.revocationReason}`);
        console.log(`explicit=${resolved.explicit}`);
        break;
      }
      case "persist-status": {
        const cfg = await kvConfigFromEnv();
        const record = checkStatusRecord({
          status: env("STATUS") as StatusRecord["status"],
          revocationTime: env("REVOCATION_TIME"),
          revocationReason: env("REVOCATION_REASON"),
        });
        const res = await fetch(kvStatusUrl(cfg), {
          method: "PUT",
          headers: {
            authorization: `Bearer ${cfg.token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(record),
        });
        await res.body?.cancel();
        if (res.status !== 200) {
          throw new Error(`persisting ica-status to KV failed (HTTP ${res.status})`);
        }
        console.log(`persisted ica-status: ${JSON.stringify(record)}`);
        break;
      }
      case "verify-live": {
        const url = env("OCSP_URL") || "http://ocsp.realreel.xyz";
        const expected = await Deno.readFile(new URL("out/response-sha1.der", import.meta.url));
        await verifyLive({
          url,
          requestDer: buildOcspRequestDer(await sha1Target()),
          expected,
          attempts: 10,
          sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
          log: console.log,
        });
        break;
      }
      default:
        console.error("usage: refresh-ops.ts <resolve-status|persist-status|verify-live>");
        Deno.exit(2);
    }
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    Deno.exit(1);
  }
}
