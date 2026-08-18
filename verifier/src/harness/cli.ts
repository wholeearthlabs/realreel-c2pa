#!/usr/bin/env node
// CLI adapter over runCrjsonHarness (./crjson.ts) — the entry point handed
// to the Conformance Administrator.
//
//   crjson-harness --asset a.jpg --trust-list c2pa.pem --tsa-trust-list tsa.pem \
//                  --validation-time 2026-08-17T00:00:00Z [--out a.crjson] [--record a.run.json]
//
// stdout: the crJSON exactly as the validator emitted it (or --out).
// stderr: the run record — validator + engine versions, input digests, the
//         validation time, and whether the deployed engine agreed (or --record).
//
// Exit: 0 ok · 2 usage · 3 environment (c2patool / faketime missing) ·
//       4 the validator failed on the asset (no crJSON) ·
//       5 crJSON written, but the deployed engine disagreed with it or
//         failed on the asset (record.engineAgreement says which).

import { readFileSync, writeFileSync } from "node:fs";
import { CrjsonHarnessError, parseValidationTime, runCrjsonHarness } from "./crjson.js";

interface Args {
  asset?: string;
  trustList?: string;
  tsaTrustList?: string;
  validationTime?: string;
  wallClock?: boolean;
  out?: string;
  record?: string;
  crossCheck: boolean;
  c2patool?: string;
}

function usage(msg?: string): never {
  if (msg) console.error(`crjson-harness: ${msg}\n`);
  console.error(
    "usage: crjson-harness --asset <file> --trust-list <pem> --tsa-trust-list <pem>\n" +
      "       (--validation-time <RFC 3339> | --wall-clock)\n" +
      "       [--out <crjson file>] [--record <run-record file>] [--no-cross-check] [--c2patool <bin>]",
  );
  process.exit(2);
}

function parseArgs(argv: string[]): Args {
  const out: Args = { crossCheck: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      if (i + 1 >= argv.length) usage(`${a} needs a value`);
      return argv[++i];
    };
    switch (a) {
      case "--asset": out.asset = next(); break;
      case "--trust-list": out.trustList = next(); break;
      case "--tsa-trust-list": out.tsaTrustList = next(); break;
      case "--validation-time": out.validationTime = next(); break;
      case "--wall-clock": out.wallClock = true; break;
      case "--out": out.out = next(); break;
      case "--record": out.record = next(); break;
      case "--no-cross-check": out.crossCheck = false; break;
      case "--c2patool": out.c2patool = next(); break;
      case "-h": case "--help": usage();
      default: usage(`unknown argument ${a}`);
    }
  }
  if (!out.asset || !out.trustList || !out.tsaTrustList) usage("--asset, --trust-list and --tsa-trust-list are required");
  if (!out.validationTime && !out.wallClock) usage("--validation-time is required (or --wall-clock for local smoke tests)");
  return out;
}

const args = parseArgs(process.argv.slice(2));

let validationTime: Date | "wall-clock" = "wall-clock";
if (args.validationTime) {
  try {
    validationTime = parseValidationTime(args.validationTime);
  } catch (e) {
    usage(e instanceof Error ? e.message : String(e));
  }
}

const readPem = (path: string, what: string): string => {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    return usage(`cannot read ${what} ${path}: ${e instanceof Error ? e.message : String(e)}`);
  }
};

try {
  const run = runCrjsonHarness(
    {
      assetPath: args.asset!,
      trustListPem: readPem(args.trustList!, "trust list"),
      tsaTrustListPem: readPem(args.tsaTrustList!, "TSA trust list"),
      validationTime,
    },
    { c2patool: args.c2patool, crossCheck: args.crossCheck },
  );

  if (args.out) writeFileSync(args.out, run.crjsonText);
  else process.stdout.write(run.crjsonText);

  const record = JSON.stringify(run.record, null, 2) + "\n";
  if (args.record) writeFileSync(args.record, record);
  else process.stderr.write(record);

  if (!run.record.engineAgreement.agree) {
    console.error("crjson-harness: the deployed engine did NOT attest this crJSON (see engineAgreement.differences)");
    process.exit(5);
  }
} catch (e) {
  if (e instanceof CrjsonHarnessError) {
    console.error(`crjson-harness: ${e.message}${e.detail ? `\n${e.detail}` : ""}`);
    process.exit(e.kind === "c2patool-missing" || e.kind === "faketime-missing" ? 3 : e.kind === "input" ? 2 : 4);
  }
  throw e;
}
