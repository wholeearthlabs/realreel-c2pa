// Regression tests for SSRF Layer 2 (host regex + allowlist).
//
// These exercise the two-step host check independently of Fastify so
// we don't need fastify.inject() infrastructure to assert the defense.
// Logic mirrors src/server.ts:
//   1. signedUrl must match ASSET_STORAGE_HOST_REGEX (shape).
//   2. new URL(signedUrl).host (lowercase) must be in the allowlist set.
//
// The pivotal regression is the userinfo trick:
//   https://abc.supabase.co@attacker.com/...
// A permissive regex like /supabase\.co/ matches the URL string; but
// `new URL(...).host` is "attacker.com", which is correctly rejected
// by the allowlist. The two-step defense closes this gap.

import { describe, it, expect } from "vitest";

function checkUrl(
  signedUrl: string,
  regex: RegExp,
  allowlist: Set<string>,
): { ok: boolean; reason?: string } {
  if (!regex.test(signedUrl)) return { ok: false, reason: "regex" };
  let host: string;
  try {
    host = new URL(signedUrl).host.toLowerCase();
  } catch {
    return { ok: false, reason: "url_parse" };
  }
  if (!allowlist.has(host)) return { ok: false, reason: "allowlist" };
  return { ok: true };
}

// Realistic Supabase regex shape: starts with https://, has the project
// host, /storage/v1/object/sign/ path.
const REGEX = /^https:\/\/[a-z0-9]+\.supabase\.co\/storage\/v1\/object\/sign\//;
const ALLOWLIST = new Set(["abc123.supabase.co"]);

describe("SSRF Layer 2 (regex + URL.host allowlist)", () => {
  it("accepts a legitimate signed URL", () => {
    expect(
      checkUrl(
        "https://abc123.supabase.co/storage/v1/object/sign/media/user/file.jpg?token=x",
        REGEX,
        ALLOWLIST,
      ),
    ).toEqual({ ok: true });
  });

  // -------- Userinfo trick: regex may pass, allowlist must reject ----
  it("rejects the userinfo-prefix trick (host = attacker.com)", () => {
    // The realistic regex at the top of the file uses [a-z0-9]+ which
    // doesn't match 'abc123.supabase.co@attacker.com' — but a future
    // "simplify" PR might use a permissive shape that DOES match. Test
    // against an overly-permissive regex (`https.*supabase\.co.*` — the
    // shape someone would write if they forgot about userinfo URLs) to
    // assert the allowlist is the load-bearing gate that closes the
    // gap even when the regex is wrong.
    const permissiveRegex = /^https:\/\/.*supabase\.co.*\/storage\//;
    const url =
      "https://abc123.supabase.co@attacker.com/storage/v1/object/sign/media/x.jpg";

    // Confirm the regex DOES match (= permissive enough to be wrong).
    expect(permissiveRegex.test(url)).toBe(true);

    // Confirm URL parses the way we think: host is attacker.com.
    expect(new URL(url).host).toBe("attacker.com");

    // And the load-bearing assertion: even with the bad regex, the
    // allowlist rejects.
    expect(checkUrl(url, permissiveRegex, ALLOWLIST)).toEqual({
      ok: false,
      reason: "allowlist",
    });
  });

  it("rejects subdomain-prefix attack (127.0.0.1.attacker.com)", () => {
    const url =
      "https://127.0.0.1.attacker.com/storage/v1/object/sign/media/x.jpg";
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({
      ok: false,
      // regex catches this since 127.0.0.1.attacker.com doesn't match
      // [a-z0-9]+\.supabase\.co
      reason: "regex",
    });
  });

  it("rejects link-local metadata endpoint (169.254.169.254)", () => {
    const url = "http://169.254.169.254/latest/meta-data/iam/security-credentials";
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "regex",
    });
  });

  it("rejects loopback (127.0.0.1)", () => {
    const url = "http://127.0.0.1:54321/storage/v1/object/sign/media/x.jpg";
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "regex",
    });
  });

  it("rejects uppercase scheme (HTTPS://) — regex is case-sensitive", () => {
    const url =
      "HTTPS://abc123.supabase.co/storage/v1/object/sign/media/x.jpg";
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "regex",
    });
  });

  it("rejects wrong project ref even with matching shape", () => {
    const url =
      "https://otherproject.supabase.co/storage/v1/object/sign/media/x.jpg";
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "allowlist",
    });
  });

  it("rejects unparseable input cleanly (no exception thrown)", () => {
    // Won't match the regex either, but the function should return a
    // structured rejection instead of throwing.
    expect(() => checkUrl("not-a-url", REGEX, ALLOWLIST)).not.toThrow();
    expect(checkUrl("not-a-url", REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "regex",
    });
  });

  it("rejects empty string", () => {
    expect(checkUrl("", REGEX, ALLOWLIST)).toEqual({
      ok: false,
      reason: "regex",
    });
  });

  it("rejects redirects via Location-trick host (we never see this — verify by URL parse)", () => {
    // server.ts uses `redirect: 'error'` so this case can't reach the
    // verifier in practice. Documented here so a future "follow
    // redirects" PR has to face this test.
    const url =
      "https://abc123.supabase.co/storage/v1/object/sign/media/x.jpg#@attacker.com";
    // Fragment is on the abc123.supabase.co side of @; host is still
    // abc123.supabase.co.
    expect(new URL(url).host).toBe("abc123.supabase.co");
    expect(checkUrl(url, REGEX, ALLOWLIST)).toEqual({ ok: true });
  });
});
