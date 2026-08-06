BIN := bin
# faramir-guard is the PreToolUse hook.  It installs to /usr/local/libexec
# rather than /usr/local/bin, but it is built like everything else.
CMDS := faramir faramir-broker faramir-keeper faramir-exec faramir-mcp faramir-guard
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0

.PHONY: all build build-debug test test-unit test-e2e check install verify sizes clean

all: build

## build: static binaries, stripped
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		go build -ldflags="$(LDFLAGS)" -trimpath -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## build-debug: unstripped, for profiling and stack traces
build-debug:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do go build -o $(BIN)/$$c ./cmd/$$c || exit 1; done

## test: the whole suite.  Needs no sops installed: the round trip runs
## through a stand-in built from the sops libraries at test time.
test:
	go test ./...

test-unit:
	go test ./internal/config/ ./internal/redact/ ./internal/resolve/ \
	        ./internal/keeper/ ./internal/execserver/ ./cmd/faramir-guard/

test-e2e:
	go test -v ./internal/e2e/

check:
	go vet ./...
	@gofmt -l . | grep . && { echo "gofmt needed on the files above"; exit 1; } || true

## install: the four phases, in order.  build first; the installer refuses to
## run without the binaries and needs no toolchain on the target host.
install: build
	@for phase in install/[0-9][0-9]-*.sh; do \
		echo "==> $$phase"; "$$phase" || exit 1; \
	done

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
	rm -rf $(BIN)
