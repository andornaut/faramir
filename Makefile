BIN := bin
# One binary.  The three daemons, the MCP stdio server and the PreToolUse hook
# are subcommands of it; what separates them is User= in the units, not main().
# Only the hook's deny list and wrap script go to /usr/local/libexec.
CMDS := faramir
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0

.PHONY: all build coverage fmt lint test test-unit test-e2e install verify clean

all: build

## build: a static binary, stripped
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		go build -ldflags="$(LDFLAGS)" -trimpath -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## test: the whole suite.  Needs no sops installed: the round trip runs
## through a stand-in built from the sops libraries at test time.
test: test-unit test-e2e

## test-unit: everything except the end-to-end suite.  Derived rather than
## listed, so a new package is covered the day it is added.
test-unit:
	go test $$(go list ./... | grep -v '/internal/e2e$$')

## test-e2e: end-to-end, against a real keeper, executor and broker in a
## temp directory, all under one uid.
##
## -count=1, which is the documented way to say "do not use the cache", and it
## is not optional here.  These tests build the CLI with `go build` at run time
## rather than importing it, so the test binary has no compile-time dependency
## on ./cmd/faramir and Go's cache key does not cover it: edit the CLI, run
## `go test ./...`, and this package replays a stale PASS for code it never ran.
## CI escapes it by passing -coverprofile, which disables caching as a side
## effect; nothing should depend on that.
test-e2e:
	go test -count=1 -v ./internal/e2e/

## coverage: the suite with the race detector, then the per-function report.
## CGO_ENABLED=1 for this recipe only: -race needs cgo, and the export above
## turns it off for every other one because the shipped binary is static.
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
## with no Go at all (see --binaries).  It refuses to run without the binary
## and says so.
##
## Pass anything else through INIT_ARGS, e.g. --config-dir or --seal-age-key.
install:
	sudo $(BIN)/faramir init --operator "$$(id -un)" $(INIT_ARGS)

## verify: examine a live deployment (root).  Asks each account what it can
## reach, which is a question only root can put to another uid.
verify:
	sudo faramir doctor

clean:
	rm -rf $(BIN) dist
	rm -f coverage.txt
