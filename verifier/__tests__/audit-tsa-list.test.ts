// Unit tests for audit-tsa-list. Covers the pure auditTsaList() over stubbed
// readers; the real fetch is exercised by `make verify-tsa-list`. Fixtures are
// certs already in the repo — they only need to be distinct, parseable
// certificates, not TSAs.

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { auditTsaList, parseBundle } from "../scripts/audit-tsa-list.js";

const SOURCES = resolve(dirname(fileURLToPath(import.meta.url)), "../trust-sources");
const pem = (path: string) => readFileSync(resolve(SOURCES, path), "utf-8").trim();

const ROOT = pem("realreel/realreel-c2pa-root.pem");
const ICA = pem("realreel/realreel-claim-signing-ca.pem");
const PIXEL = pem("pixel/root.pem");

// Mirrors the upstream format: an annotation line before each block.
const bundle = (...certs: string[]) =>
  certs.map((c) => `Subject\tCN=${parseBundle(c)[0]!.subjectCn}\n${c}\n`).join("");

const audit = (vendored: string, upstream: string | Error) =>
  auditTsaList({
    readVendored: () => Promise.resolve(Buffer.from(vendored)),
    fetchUpstream: () =>
      upstream instanceof Error ? Promise.reject(upstream) : Promise.resolve(Buffer.from(upstream)),
  });

const [rootCn, icaCn, pixelCn] = [ROOT, ICA, PIXEL].map((c) => parseBundle(c)[0]!.subjectCn);

describe("auditTsaList", () => {
  it("passes when the vendored file is byte-identical to upstream", async () => {
    const result = await audit(bundle(ROOT, ICA), bundle(ROOT, ICA));
    expect(result.exitCode).toBe(0);
    expect(result.report).toContain("byte-identical to upstream (2 certificates)");
  });

  it("reports a certificate added upstream", async () => {
    const result = await audit(bundle(ROOT, ICA), bundle(ROOT, ICA, PIXEL));
    expect(result.exitCode).toBe(3);
    expect(result.report).toContain("ADDED upstream, not yet trusted here (1)");
    expect(result.report).toContain(pixelCn);
    expect(result.report).not.toContain("REMOVED");
  });

  it("reports a certificate removed upstream", async () => {
    const result = await audit(bundle(ROOT, ICA), bundle(ROOT));
    expect(result.exitCode).toBe(3);
    expect(result.report).toContain("REMOVED upstream, still trusted here (1)");
    expect(result.report).toContain(icaCn);
    expect(result.report).not.toContain("ADDED");
  });

  it("reports both directions at once", async () => {
    const result = await audit(bundle(ROOT, ICA), bundle(ROOT, PIXEL));
    expect(result.exitCode).toBe(3);
    expect(result.report).toMatch(/REMOVED[^\n]*\(1\)[\s\S]*ADDED[^\n]*\(1\)/);
  });

  it("flags an annotation-only change, so the mirror stays byte-identical", async () => {
    const result = await audit(bundle(ROOT, ICA), `${ROOT}\n${ICA}\n`);
    expect(result.exitCode).toBe(3);
    expect(result.report).toContain("only annotations or ordering changed");
  });

  it("is blind, not drifted, when upstream is unreachable", async () => {
    const result = await audit(bundle(ROOT), new Error("HTTP 503"));
    expect(result.exitCode).toBe(4);
    expect(result.report).toContain("BLIND");
    expect(result.report).toContain("HTTP 503");
  });

  it("is blind, not 'everything removed', when upstream returns no certificates", async () => {
    const result = await audit(bundle(ROOT, ICA), "<html>rate limited</html>");
    expect(result.exitCode).toBe(4);
    expect(result.report).not.toContain("REMOVED");
  });

  it("is blind when upstream holds a corrupt certificate", async () => {
    const corrupt = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    const result = await audit(bundle(ROOT), `${bundle(ROOT)}${corrupt}\n`);
    expect(result.exitCode).toBe(4);
  });

  it("is blind, not 'removed', when upstream is truncated mid-certificate", async () => {
    const full = bundle(ROOT, ICA);
    const result = await audit(full, full.slice(0, full.lastIndexOf("-----END")));
    expect(result.exitCode).toBe(4);
    expect(result.report).not.toContain("REMOVED");
  });

  it("compares bytes: a BOM upstream is drift, not a match", async () => {
    const result = await audit(bundle(ROOT), `﻿${bundle(ROOT)}`);
    expect(result.exitCode).toBe(3);
  });

  it("errors when the vendored file is unreadable", async () => {
    const result = await auditTsaList({
      readVendored: () => Promise.reject(new Error("ENOENT")),
      fetchUpstream: () => Promise.resolve(Buffer.from(bundle(ROOT))),
    });
    expect(result.exitCode).toBe(2);
    expect(result.report).toContain("ENOENT");
  });

  it("lists each certificate's subject, issuer and SHA-256", async () => {
    const result = await audit(bundle(ROOT), bundle(ROOT, ICA));
    const ica = parseBundle(ICA)[0]!;
    expect(ica.issuerCn).toBe(rootCn);
    expect(result.report).toContain(`${icaCn} (issuer: ${rootCn}, until `);
    expect(result.report).toContain(`sha256=${ica.sha256}`);
  });
});
