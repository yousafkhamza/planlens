# syntax=docker/dockerfile:1
# planlens container — for CI systems without Node (Jenkins, Azure DevOps,
# Bitbucket, Atlantis…). Usage:
#   docker run --rm -v "$PWD:/work" ghcr.io/yousafkhamza/planlens plan.json
# Base images are pinned by digest; Dependabot keeps them current.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
COPY docs ./docs
RUN npm run build

FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
LABEL org.opencontainers.image.title="planlens" \
      org.opencontainers.image.description="Terraform plan reviewer — destroys, forced replacements, security regressions, IAM widening and cost, with a risk gate." \
      org.opencontainers.image.source="https://github.com/yousafkhamza/planlens" \
      org.opencontainers.image.url="https://yousafkhamza.github.io/planlens/" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/dist/cli.mjs /opt/planlens/cli.mjs
ENV NO_UPDATE_NOTIFIER=1
WORKDIR /work
USER node
ENTRYPOINT ["node", "/opt/planlens/cli.mjs"]
CMD ["--help"]
