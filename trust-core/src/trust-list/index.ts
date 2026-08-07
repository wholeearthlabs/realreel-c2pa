export {
  TRUSTED_ISSUERS,
  findTrustedIssuer,
  type TrustedIssuer,
} from "./trusted-issuers.js";
// CLIENT_TRUST_ANCHORS_PEM is deliberately NOT re-exported here: the 27 KB
// PEM bundle would ride along with every barrel import (CJS defeats
// tree-shaking under Metro/jest-expo), taxing surfaces that only want
// VerifyErrorCode or TRUSTED_ISSUERS. Import it from the dedicated
// subpath: `@realreel/c2pa-trust-core/trust-anchors`.
