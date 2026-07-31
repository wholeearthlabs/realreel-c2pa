# Leaf-status OCSP responder. Build from the REPO ROOT (the service imports
# shared modules from ../ocsp and ../ca/_shared and bakes in the trust-source
# PEMs):
#   docker build -f ocsp-leaf/Dockerfile -t realreel-ocsp-leaf .
FROM denoland/deno:2.9.4

WORKDIR /app

# Only what the service actually imports/reads — keeps rebuilds tight.
COPY ocsp-leaf/ ocsp-leaf/
COPY ocsp/ocsp.ts ocsp/
COPY ca/_shared/kms.ts ca/_shared/
COPY verifier/trust-sources/realreel/realreel-claim-signing-ca.pem \
     verifier/trust-sources/realreel/realreel-leaf-ocsp-responder-1.pem \
     verifier/trust-sources/realreel/

WORKDIR /app/ocsp-leaf
RUN deno install --entrypoint main.ts

# Cloud Run injects PORT; every other env is documented in main.ts / README.
CMD ["deno", "run", "--allow-net", "--allow-env", "--allow-read", "main.ts"]
