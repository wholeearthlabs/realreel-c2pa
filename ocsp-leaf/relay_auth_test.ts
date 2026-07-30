// Tests for the Worker→responder shared-secret gate.
//
// Run with:  deno task test   (from ocsp-leaf/)

import { RELAY_SECRET_HEADER, relayAuthorized } from "./relay-auth.ts";

function assertEq<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

const SECRET = "s3cret-relay-value";

function reqWith(headers: Record<string, string>): Request {
  return new Request("https://example.invalid/", { method: "POST", headers });
}

Deno.test("relay auth — matching secret is authorized", () => {
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: SECRET }), SECRET),
    true,
    "exact match",
  );
});

Deno.test("relay auth — header name is case-insensitive", () => {
  // Headers normalizes; the Worker's casing must not matter.
  assertEq(
    relayAuthorized(reqWith({ "X-RealReel-Relay-Secret": SECRET }), SECRET),
    true,
    "mixed-case header",
  );
});

Deno.test("relay auth — rejects missing, wrong, prefix, padded, empty", () => {
  assertEq(relayAuthorized(reqWith({}), SECRET), false, "absent");
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: "nope" }), SECRET),
    false,
    "wrong value",
  );
  assertEq(
    relayAuthorized(
      reqWith({ [RELAY_SECRET_HEADER]: SECRET.slice(0, -1) }),
      SECRET,
    ),
    false,
    "correct prefix",
  );
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: "" }), SECRET),
    false,
    "empty value",
  );
});

Deno.test("relay auth — a blank expected secret never authorizes", () => {
  // Both sides trim, so a whitespace-only configured secret would otherwise
  // compare equal to a blank header and let the whole internet through.
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: "" }), "  \n "),
    false,
    "blank header vs whitespace-only secret",
  );
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: SECRET }), ""),
    false,
    "real header vs empty secret",
  );
});

Deno.test("relay auth — whitespace is normalized on both sides", () => {
  // Fetch trims header values, so a padded header still matches. The point of
  // the test is the other side: a stored secret carrying the newline `echo`
  // appends must still authorize, or the deploy is a silent total outage.
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: `${SECRET} ` }), SECRET),
    true,
    "padded header",
  );
  assertEq(
    relayAuthorized(reqWith({ [RELAY_SECRET_HEADER]: SECRET }), `${SECRET}\n`),
    true,
    "stored secret with trailing newline",
  );
});
