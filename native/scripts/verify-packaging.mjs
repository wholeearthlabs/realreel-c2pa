// Release gate: app.plugin.js does `require('./plugin/build')`, but the
// expo-module publish lifecycle builds the native module and not the config
// plugin. Pack the tarball, extract, and assert that require resolves.
import { execFileSync, execSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const tmp = mkdtempSync(join(tmpdir(), "verify-packaging-"));
try {
  // `npm pack` runs `prepack` → builds the config plugin, then archives per `files`.
  const tgz = execSync(`npm pack --silent --pack-destination ${tmp}`, { encoding: "utf8" }).trim().split("\n").pop();
  execFileSync("tar", ["-xzf", join(tmp, tgz), "-C", tmp]);

  // Resolve the exact module app.plugin.js requires, the way Node would — but
  // don't execute it (that would need the consumer's @expo/config-plugins).
  try {
    require.resolve(join(tmp, "package", "plugin/build"));
  } catch {
    console.error("✗ packaging check FAILED: plugin/build is missing from the tarball — app.plugin.js's require('./plugin/build') would crash consumers");
    process.exit(1);
  }

  console.log("✓ packaging OK: tarball ships the compiled config plugin (plugin/build)");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
