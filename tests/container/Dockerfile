ARG NODE_VERSION=24
FROM node:${NODE_VERSION} AS node
FROM golang:1.27
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=golangci/golangci-lint:v2.15.0 /usr/bin/golangci-lint /usr/local/bin/golangci-lint
COPY --from=koalaman/shellcheck:v0.11.0 /bin/shellcheck /usr/local/bin/shellcheck
COPY --from=goreleaser/goreleaser:v2.20.0 /usr/bin/goreleaser /usr/local/bin/goreleaser
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && npm install --global --ignore-scripts markdownlint-cli2@0.24.0 \
    && groupadd -g 19001 tester \
    && useradd -u 19001 -g tester -m tester \
    && mkdir -p /out /cache /go/pkg/mod \
    && chown tester:tester /out /cache /go/pkg/mod
COPY tests/container/check /opt/check/run
RUN chmod 0755 /opt/check/run
