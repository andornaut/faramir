# The Go suite's container: the toolchain go.mod names, the programs the tests
# run, an editor for the tests that choose one, and a second group for the
# tests that regroup a file. sops is not here: run.sh mounts the pinned copy `e2e.sh fetch`
# downloads, so the suite and the e2e stacks test the same binary.
#
# The tests run as uid 19001, which owns nothing on the host.
ARG NODE_VERSION=24
FROM node:${NODE_VERSION} AS node
FROM golang:1.27
COPY --from=node /usr/local/bin/node /usr/local/bin/node
RUN sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=2 -o Acquire::https::Timeout=20 \
      -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt \
      -o APT::Update::Error-Mode=any update \
    && apt-get -o Acquire::Retries=2 -o Acquire::https::Timeout=20 \
      -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt install -y --no-install-recommends \
      openssh-client nano \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd second \
    && groupadd -g 19001 tester \
    && useradd -u 19001 -g tester -m -G second tester
COPY tests/go/inside.sh /usr/local/bin/faramir-go-test
COPY tests/cgroup.sh /usr/local/bin/faramir-cgroup
ENTRYPOINT ["/usr/local/bin/faramir-cgroup", "/usr/local/bin/faramir-go-test"]
