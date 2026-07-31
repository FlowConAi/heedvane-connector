# syntax=docker/dockerfile:1
# heedvane/connector image. The connector is a pnpm workspace app, so the build context
# is the REPOSITORY ROOT and the root .dockerignore governs what enters the context:
#
#   docker build -f apps/connector/Dockerfile -t heedvane/connector:0.1.0 .

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY packages/connector-protocol ./packages/connector-protocol
COPY apps/connector ./apps/connector
# --ignore-scripts: neither ws nor the protocol package needs an install script to build.
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @heedvane/connector...
RUN pnpm --filter @heedvane/connector-protocol build \
  && pnpm --filter @heedvane/connector build
# Prune to the connector's production footprint: deploy bundles the workspace protocol
# package and rewrites the workspace: dependency, then drop everything but its dist.
RUN pnpm deploy --legacy --ignore-scripts --filter @heedvane/connector --prod /out \
  && rm -rf /out/node_modules/@heedvane/connector-protocol/src \
            /out/node_modules/@heedvane/connector-protocol/AGENTS.md \
            /out/node_modules/@heedvane/connector-protocol/CLAUDE.md \
            /out/node_modules/@heedvane/connector-protocol/README.md \
            /out/node_modules/@heedvane/connector-protocol/tsconfig.json

FROM node:22-alpine AS runtime
RUN addgroup -S connector && adduser -S connector -G connector \
  && mkdir -p /var/lib/heedvane-connector && chown connector:connector /var/lib/heedvane-connector
WORKDIR /app
COPY --from=build --chown=connector:connector /out ./
USER connector
ENV NODE_ENV=production
# WEBHOOK_LISTEN_PORT (default 8080) is the only inbound port, and only the customer
# GitLab ever talks to it; the tunnel itself is outbound only.
EXPOSE 8080
ENTRYPOINT ["node", "dist/cli.js"]
