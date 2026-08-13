BIN := bin
# One binary.  The three daemons, the MCP stdio server and the PreToolUse hook
# are subcommands of it; what separates them is User= in the units, not main().
# Only the hook's deny list and wrap script go to /usr/local/libexec.
CMDS := faramir
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0

# The platforms the release ships, so a local cross-compile check covers what
# GoReleaser will actually build. Linux only: the broker is systemd units, PAM
# and cgroups.
PLATFORMS := linux-amd64 linux-arm64

.PHONY: all build coverage fmt lint release test test-unit test-e2e install verify clean $(PLATFORMS)

all: build

## build: a static binary, stripped
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		go build -ldflags="$(LDFLAGS)" -trimpath -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## release: cross-compile every platform the release ships, into dist/, to
## check that they all still build. GoReleaser publishes; this only tests.
release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(word 1,$(subst -, ,$@)) GOARCH=$(word 2,$(subst -, ,$@)) \
		go build -ldflags="$(LDFLAGS)" -trimpath -o "dist/faramir-$@" ./cmd/faramir

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
## runs as root and the compiler should not.  init installs the binary it was
## run from, so a host needs no Go of its own.
##
## Pass anything else through INIT_ARGS, e.g. --config-dir or --allow-sudo.
install:
	sudo $(BIN)/faramir init --operator-user "$$(id -un)" $(INIT_ARGS)

## verify: examine a live deployment (root).  Asks each account what it can
## reach, which is a question only root can put to another uid.
verify:
	sudo faramir doctor

clean:
	rm -rf $(BIN) dist
	rm -f coverage.txt
