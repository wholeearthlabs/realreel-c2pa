# RealReel C2PA verifier — multi-stage build for Cloud Run.
#
# Stage 1 (builder): install all deps incl. dev, compile TypeScript to dist/.
# Stage 2 (runtime): production-only deps + dist/ + the trust-sources/ tree.
# node:22-bookworm-slim is small enough (~150 MB base) and includes glibc
# (c2pa-node's prebuilt native binary is glibc, not musl — don't use alpine).

# ---------- Stage 1: build ----------
FROM node:22-bookworm-slim AS builder
WORKDIR /app

# Install build-time deps for native modules. c2pa-node fetches a prebuilt
# binary via @neon-rs/load at install time, but having build-essential
# present lets the install fall back gracefully if the prebuilt for this
# arch/libc isn't available.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---------- Stage 2: runtime ----------
FROM node:22-bookworm-slim AS runtime
WORKDIR /app

# Production-only deps. Re-running npm ci with --omit=dev gives a smaller
# node_modules than copying from the builder.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Bring over the compiled JS and the trust-source bundle. The bundle is
# baked into the image; rotating a vendor's root cert is a redeploy.
COPY --from=builder /app/dist ./dist
COPY trust-sources.yaml ./trust-sources.yaml
COPY trust-sources ./trust-sources

# Non-root runtime user. Cloud Run runs containers as the user the image
# specifies; node:bookworm-slim already includes a `node` user with UID 1000.
USER node

ENV NODE_ENV=production
ENV PORT=8080
ENV TRUST_SOURCES_PATH=/app/trust-sources.yaml
EXPOSE 8080

# Hits /healthz/ready so a container with broken DB access (wrong
# DATABASE_URL, expired pooler creds, missing GRANT) reports unhealthy
# instead of serving /verify requests that all 500. Cloud Run ignores
# HEALTHCHECK and uses its own startup/liveness probes (configured in
# the service YAML — see verifier/DEPLOY.md); this directive is for
# `docker run`, Compose, and local smoke tests.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||8080)+'/healthz/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
