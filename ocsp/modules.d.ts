// Ambient type for the .pem modules bundled via wrangler.toml [[rules]]
// (type = "Text"). Imported by index.ts from ../verifier/trust-sources/.
declare module "*.pem" {
  const data: string;
  export default data;
}
