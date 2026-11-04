# The Go suite's container: the toolchain go.mod names, the programs the tests
# run, an editor for the tests that choose one, and a second group for the
# tests that regroup a file. sops is not here: run.sh mounts the pinned copy `e2e.sh fetch`
# downloads, so the suite and the e2e stacks test the same binary.
#
# The tests run as uid 19001, which owns nothing on the host.
FROM golang:1.27
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client nodejs nano \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd second \
    && groupadd -g 19001 tester \
    && useradd -u 19001 -g tester -m -G second tester
COPY inside.sh /usr/local/bin/faramir-go-test
ENTRYPOINT ["/usr/local/bin/faramir-go-test"]
