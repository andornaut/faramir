# bash for one feature: a test recipe pipes go's output through a filter, and
# only pipefail makes the pipeline exit with the test's status rather than the
# filter's. Without it a failing suite reports success.
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

# https://www.gnu.org/prep/standards/html_node/Directory-Variables.html#Directory-Variables
PREFIX    ?= /usr/local
BINPREFIX ?= $(PREFIX)/bin
BIN := bin
# One binary. The three daemons, the MCP stdio server and the PreToolUse hook
# are subcommands of it; what separates them is User= in the units, not main().
# Only the hook's deny list and wrap script go to /usr/local/libexec.
CMDS := faramir
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0

# DELEGATE runs a test in a cgroup of its own. Every brokered command is
# confined to a cgroup and reaped there, with no process-group fallback, so an
# executor that cannot make one refuses every command: on a bare shell that
# skips a couple of dozen tests and still prints ok, which is a green run that
# checked none of the confinement or the executor. A user
# scope inherits the delegation systemd gives user@.service, so this asks for no
# privilege and no container. CI hands its runner a cgroup the same way.
#
# Recursive rather than immediate, so the probe runs when a test target uses it
# and not on every `make build`. Empty where systemd-run cannot make a scope,
# which leaves those tests skipping and report-skips saying so.
DELEGATE = $(shell systemd-run --user --scope --quiet true >/dev/null 2>&1 \
	&& echo systemd-run --user --scope --quiet)

# QUIET renders a -v run as a quiet one. -v is the only way a skip is reported
# at all, and it also repeats everything a passing test wrote, which here is the
# brokers and keepers the tests start: thousands of lines that say only that the
# suite worked. Dropping it by line shape does not work, since that output is
# arbitrary; so each test's own lines are held until its result is known and
# kept only where that result was not a pass.
#
# Only a top-level `--- PASS` clears the buffer. A subtest's is indented and
# clears nothing, because a parent writes before its first subtest and after its
# last, and that output belongs to the parent's verdict rather than to whichever
# subtest happened to run next. `=== RUN` and `=== NAME` mark those switches
# and are dropped without clearing, for the same reason.
QUIET := awk ' \
	/^=== (RUN|NAME|PAUSE|CONT)/ { next } \
	/^PASS$$/                    { next } \
	/^--- PASS/                  { buf = ""; next } \
	/^[[:space:]]+--- PASS/      { next } \
	/--- (SKIP|FAIL)/            { printf "%s", buf; print; buf = ""; next } \
	/^(ok|FAIL|\?)/              { print; buf = ""; next } \
	                             { buf = buf $$0 "\n" }'

# REPORT names what a green run did not check. A skipped test reports nothing
# of its own, so a suite that skipped a third of itself and one that ran every
# line both end in "ok". Reads the whole -v log, not the filtered view.
#
# A reason is the line the skip was reported on, which is not always there to
# find: a subtest's is printed in the parent's block, and a skip from an
# unmarked helper names that file instead. Counted separately rather than
# dropped, so the total and the breakdown cannot disagree in silence.
REPORT := awk ' \
	/^=== RUN/ { why = "" } \
	/^[[:space:]]*[a-z0-9_]+_test\.go:[0-9]+: / { \
	  why = $$0; sub(/^[[:space:]]*[a-z0-9_]+_test\.go:[0-9]+: /, "", why) } \
	/^[[:space:]]*--- SKIP/ { \
	  n++; if (why != "") { count[why]++; named++; why = "" } } \
	END { \
	  if (n == 0) { print "skipped: none, every test ran"; exit } \
	  printf "skipped: %d test(s) this run did not check\n", n; \
	  for (w in count) printf "  %4d  %s\n", count[w], w; \
	  if (named < n) \
	    printf "  %4d  (no reason recorded against the skip)\n", n - named }'

# The platforms the release ships, so a local cross-compile check covers what
# GoReleaser will actually build. Linux only: the broker is systemd units, PAM
# and cgroups.

.PHONY: all build clean coverage e2e fmt install lint shellcheck test uninstall

all: build

## build: a static binary, stripped
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		go build -ldflags="$(LDFLAGS)" -trimpath -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## test: everything that tests this, the Go suite and the end-to-end suites
## both, so that `make test` means the same here as in a repository whose
## end-to-end tests are Go files. `make e2e` still runs those alone.
##
## Needs no sops installed: the round trip runs
## through a stand-in built from the sops libraries at test time. The tests
## that assert how sops resolves a creation rule skip without the real binary,
## the stand-in modelling none, so CI installs it pinned and they run there.
##
## Under a delegated cgroup where there is one: the executor makes a cgroup per
## child, and without one it refuses every command, which skips the tests that
## exercise confinement rather than failing them.
##
## The status is taken from the pipeline's first command rather than left to
## pipefail, so that the skip report still runs when the suite failed: a run
## that fails is not one that checked everything else.
test: e2e
	@mkdir -p $(BIN)
	@$(DELEGATE) go test -v ./... 2>&1 \
		| tee $(BIN)/test.log | $(QUIET); \
	  status=$${PIPESTATUS[0]}; \
	  $(REPORT) $(BIN)/test.log; \
	  exit $$status

## coverage: the suite with the race detector, then the per-function report.
## CGO_ENABLED=1 for this recipe only: -race needs cgo, and the export above
## turns it off for every other one because the shipped binary is static.
coverage:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt

## fmt: apply the import grouping and gofmt rules CI checks
fmt:
	golangci-lint fmt

## lint: golangci-lint and ShellCheck, so that `make lint` covers the shell as
## well as the Go and means here what it means in a repository holding no shell.
## `make shellcheck` still runs that alone. CI's Lint job also runs markdownlint
## and `goreleaser check`, which need tooling this repository does not otherwise
## ask for, so they are left to CI.
##
## `run` accepts an unknown key inside `linters.settings` and exits 0, which
## leaves that setting disabled while CI stays green, so `config verify` is what
## rejects a misspelled one.
lint: shellcheck
	golangci-lint config verify
	golangci-lint run

## shellcheck: the same shellcheck run CI does
shellcheck:
	shellcheck tests/*.sh tests/e2e/*.sh agent/hooks/wrap.sh

## e2e: the functional suites, against a real install in a container: systemd
## units, three uids, a sops store and an agent working in a project tree. Go
## covers the code, these cover what an operator gets after `faramir init`.
##
## Needs Docker and the three third-party binaries `e2e.sh fetch` downloads.
## `up` every time because it is the clean baseline: the suites share one
## install and mutate it, so a `run` without it measures the last run's
## leftovers and reports failures that are not regressions.
e2e:
	cd tests/e2e && ./e2e.sh fetch && ./e2e.sh up && ./e2e.sh run

## install: build, then copy the binaries to $(BINPREFIX). Only the copy runs
## as root: the build is a prerequisite, so the compiler runs as whoever typed
## it. This installs the programs; `faramir init` provisions the host.
install: build
	sudo mkdir -p "$(DESTDIR)$(BINPREFIX)"
	@for c in $(CMDS); do \
		sudo cp -pf $(BIN)/$$c "$(DESTDIR)$(BINPREFIX)/" || exit 1; \
	done

## uninstall: remove what install copied
uninstall:
	@for c in $(CMDS); do \
		sudo rm -f "$(DESTDIR)$(BINPREFIX)/$$c"; \
	done

clean:
	rm -rf $(BIN) dist
	rm -f coverage.txt
