// Worker entrypoint: imports the canonical trust-source PEMs (single source of
// truth, no copies in pki/) and hands them to the pure router in router.ts.
import ROOT_PEM from "../verifier/trust-sources/realreel/realreel-c2pa-root.pem"; // string (Text rule)
import ICA_PEM from "../verifier/trust-sources/realreel/realreel-claim-signing-ca.pem"; // string (Text rule)
import { handleRequest } from "./router";

export default {
  fetch(req: Request): Promise<Response> {
    return handleRequest(req, { rootPem: ROOT_PEM, icaPem: ICA_PEM });
  },
};
