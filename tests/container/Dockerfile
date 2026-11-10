ARG NODE_VERSION=24
FROM node:${NODE_VERSION} AS node
WORKDIR /opt/markdown
COPY tests/container/package.json tests/container/package-lock.json ./
# WORKAROUND: Scoped overrides patch CLI dependencies for these advisories.
# https://github.com/advisories/GHSA-gg6h-894w-4m9c
# https://github.com/advisories/GHSA-238p-pmpm-9mq7
# Remove the overrides when the upstream CLI resolves patched versions unaided.
RUN npm ci --ignore-scripts --no-audit --no-fund
FROM golang:1.27
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=node /opt/markdown /opt/markdown
ENV PATH="/opt/markdown/node_modules/.bin:${PATH}"
COPY --from=golangci/golangci-lint:v2.15.0 /usr/bin/golangci-lint /usr/local/bin/golangci-lint
COPY --from=koalaman/shellcheck:v0.11.0 /bin/shellcheck /usr/local/bin/shellcheck
COPY --from=goreleaser/goreleaser:v2.20.0 /usr/bin/goreleaser /usr/local/bin/goreleaser
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && groupadd -g 19001 tester \
    && useradd -u 19001 -g tester -m tester \
    && mkdir -p /out /cache /go/pkg/mod \
    && chown tester:tester /out /cache /go/pkg/mod
COPY tests/container/check /opt/check/run
RUN chmod 0755 /opt/check/run
