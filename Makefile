BIN := bin
# faramir-guard is the PreToolUse hook.  It installs to /usr/local/libexec
# rather than /usr/local/bin, but it is built like everything else.
CMDS := faramir faramir-broker faramir-keeper faramir-exec faramir-mcp faramir-guard
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0

.PHONY: all build coverage fmt lint test test-unit test-e2e install verify sizes clean

all: build

## build: static binaries, stripped
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		go build -ldflags="$(LDFLAGS)" -trimpath -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## test: the whole suite.  Needs no sops installed: the round trip runs
## through a stand-in built from the sops libraries at test time.
test:
	go test ./...

## test-unit: everything except the end-to-end suite.  Derived rather than
## listed, so a new package is covered the day it is added.
test-unit:
	go test $$(go list ./... | grep -v '/internal/e2e$$')

## test-e2e: end-to-end, against a real keeper, executor and broker in a
## temp directory, all under one uid.
test-e2e:
	go test -v ./internal/e2e/

## coverage: the suite with the race detector, then the per-function report.
## CGO_ENABLED=1 for this recipe only: -race needs cgo, and the export above
## turns it off for every other one because the shipped binaries are static.
coverage:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt

## fmt: apply the import grouping and gofmt rules CI checks
fmt:
	golangci-lint fmt

## lint: the same golangci-lint run CI does
lint:
	golangci-lint run

## install: provision this host.  Deliberately NOT dependent on build: this
## runs as root, the compiler should not, and init is meant to work on a host
## with no Go at all (see --binaries).  It refuses to run without the binaries
## and says so.
##
## Pass anything else through INIT_ARGS, e.g. --config-dir or --seal-age-key.
install:
	sudo $(BIN)/faramir init --operator "$$(id -un)" $(INIT_ARGS)

## verify: the verification matrix, against a live deployment (root)
verify:
	tests/verify.sh

## sizes: per-binary size and the package count each one links.  sops is a
## test-only dependency; no shipped binary links it.
sizes: build
	@printf '%-16s %10s %10s %8s\n' BINARY SIZE PACKAGES SOPS
	@for c in $(CMDS); do \
		printf '%-16s %9.1fM %10s %8s\n' $$c \
			$$(echo "scale=1; $$(stat -c%s $(BIN)/$$c)/1048576" | bc) \
			$$(go list -deps ./cmd/$$c | grep -c '\.') \
			$$(go list -deps ./cmd/$$c | grep -c getsops); \
	done

clean:
	rm -rf $(BIN) dist
	rm -f coverage.txt
