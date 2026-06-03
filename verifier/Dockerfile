# RealReel C2PA verifier image (Cloud Run), built from the MONOREPO ROOT so the
# @realreel/c2pa-trust-core workspace dep is compiled from source — no published
# npm dependency, no publish-before-deploy.  Build: docker build -f verifier/Dockerfile .
# Pinned to linux/amd64 (Cloud Run's arch): c2pa-node ships a single-arch prebuilt
# that --ignore-scripts doesn't arch-correct, so the image must match the deploy arch.
# bookworm (not alpine): that prebuilt is glibc, not musl.

# ---------- Stage 1: build ----------
FROM --platform=linux/amd64 node:24-bookworm-slim AS builder
WORKDIR /app

# build-essential: fallback if c2pa-node has no prebuilt for this arch/libc.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

# Skip the native workspace (-w); trust-core is built explicitly below, after its source.
COPY package.json package-lock.json ./
COPY trust-core/package.json ./trust-core/
COPY verifier/package.json ./verifier/
RUN npm ci --ignore-scripts --include-workspace-root -w trust-core -w verifier

COPY trust-core/tsconfig.json trust-core/tsconfig.cjs.json trust-core/tsconfig.esm.json ./trust-core/
COPY trust-core/src ./trust-core/src
COPY trust-core/scripts ./trust-core/scripts
COPY verifier/tsconfig.json ./verifier/
COPY verifier/src ./verifier/src
RUN npm run build -w trust-core
RUN npm run build -w verifier

# ---------- Stage 2: runtime ----------
FROM --platform=linux/amd64 node:24-bookworm-slim AS runtime
WORKDIR /app

COPY package.json package-lock.json ./
COPY trust-core/package.json ./trust-core/
COPY verifier/package.json ./verifier/
RUN npm ci --omit=dev --ignore-scripts --include-workspace-root -w trust-core -w verifier

COPY --from=builder /app/trust-core/dist ./trust-core/dist
COPY --from=builder /app/verifier/dist ./verifier/dist
# Trust-source bundle is baked into the image; rotating a vendor root cert is a redeploy.
COPY verifier/trust-sources.yaml ./trust-sources.yaml
COPY verifier/trust-sources ./trust-sources

USER node

ENV NODE_ENV=production
ENV PORT=8080
ENV TRUST_SOURCES_PATH=/app/trust-sources.yaml
EXPOSE 8080

# Cloud Run uses its own probes and ignores HEALTHCHECK; this is for docker run / Compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||8080)+'/healthz/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "verifier/dist/server.js"]
