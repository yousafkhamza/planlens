# syntax=docker/dockerfile:1
# planlens container — for CI systems without Node (Jenkins, Azure DevOps,
# Bitbucket, Atlantis…). Usage:
#   docker run --rm -v "$PWD:/work" ghcr.io/yousafkhamza/planlens plan.json
# Base images are pinned by digest; Dependabot keeps them current.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
COPY docs ./docs
RUN npm run build

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
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
