// After the two tsc passes, drop a package.json into each dist subtree so Node
// (and TS node16/nodenext) treat dist/commonjs/* as CommonJS and dist/esm/* as
// ESM despite the root package's "type": "module".
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

writeFileSync(join(dist, "commonjs", "package.json"), JSON.stringify({ type: "commonjs" }, null, 2) + "\n");
writeFileSync(join(dist, "esm", "package.json"), JSON.stringify({ type: "module" }, null, 2) + "\n");
