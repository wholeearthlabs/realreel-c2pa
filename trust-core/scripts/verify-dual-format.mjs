// Release gate: prove the packed tarball is genuinely dual-format. 0.1.0 shipped
// ESM-only and broke every CommonJS (jest) consumer; this makes that regression
// impossible to publish. Packs THIS package (which rebuilds via `prepare`),
// extracts the tarball, and asserts the CommonJS build is present, loads as real
// CJS via require() (not ESM), and is wired into exports.require — plus the ESM
// side still loads.
import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const node = process.execPath;
const fail = (m) => {
  console.error(`✗ dual-format check FAILED: ${m}`);
  process.exit(1);
};
// Run `node -e <code>`; return null on success or the last stderr line on failure.
const tryNode = (args) => {
  try {
    execFileSync(node, args, { stdio: "pipe" });
    return null;
  } catch (e) {
    return String(e.stderr || e.message).trim().split("\n").pop();
  }
};

const tmp = mkdtempSync(join(tmpdir(), "verify-dual-"));
try {
  // `npm pack` runs `prepare` → a fresh dual build, then archives per `files`.
  const tgz = execSync(`npm pack --silent --pack-destination ${tmp}`, { encoding: "utf8" }).trim().split("\n").pop();
  execFileSync("tar", ["-xzf", join(tmp, tgz), "-C", tmp]);
  const pkg = join(tmp, "package");

  // (1) the CommonJS build is actually in the tarball
  const cjs = join(pkg, "dist/commonjs/index.js");
  if (!existsSync(cjs)) fail("dist/commonjs/index.js missing from the tarball (ESM-only build?)");

  // (2) it is marked CommonJS and require() loads it (throws on an ESM entry)
  const marker = JSON.parse(readFileSync(join(pkg, "dist/commonjs/package.json"), "utf8"));
  if (marker.type !== "commonjs") fail(`dist/commonjs/package.json type is ${JSON.stringify(marker.type)}, expected "commonjs"`);
  const cjsErr = tryNode(["-e", `const m=require(${JSON.stringify(cjs)});if(!Object.keys(m).length)throw new Error("no exports")`]);
  if (cjsErr) fail(`require() of dist/commonjs/index.js failed (not loadable as CommonJS): ${cjsErr}`);

  // (3) exports["."] routes `require` at the CommonJS build
  const dot = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8")).exports?.["."];
  const req = dot?.require?.default ?? dot?.require;
  if (typeof req !== "string" || !req.includes("commonjs")) {
    fail(`exports["."] has no require condition pointing at the CommonJS build (got ${JSON.stringify(dot)})`);
  }

  // (4) the ESM build still loads via import
  const esm = join(pkg, "dist/esm/index.js");
  if (!existsSync(esm)) fail("dist/esm/index.js missing from the tarball");
  const esmErr = tryNode(["--input-type=module", "-e", `const m=await import(${JSON.stringify(esm)});if(!Object.keys(m).length)throw new Error("no exports")`]);
  if (esmErr) fail(`import() of dist/esm/index.js failed: ${esmErr}`);

  console.log("✓ dual-format OK: tarball ships CJS (loads via require) + ESM (loads via import); exports.require → dist/commonjs");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
