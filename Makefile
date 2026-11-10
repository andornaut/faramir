# bash for one feature: a test recipe pipes go's output through a filter, and
# only pipefail makes the pipeline exit with the test's status rather than the
# filter's. Without it a failing suite reports success.
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

# https://www.gnu.org/prep/standards/html_node/Directory-Variables.html#Directory-Variables
PREFIX    ?= /usr/local
BINPREFIX ?= $(PREFIX)/bin
BIN := bin
# One binary. The three daemons and the guard are subcommands of it; what
# separates them is User= in the units, not main(). Only the guard's deny list,
# the wrap script and the PAM helper go to /usr/local/libexec.
LDFLAGS := -s -w
# CGO_ENABLED=0 is the point of the port: a static binary with no libc and no
# interpreter runs on a host whose Python is older than 3.11.
export CGO_ENABLED := 0
.DEFAULT_GOAL := check
override COMMAND := $(value COMMAND)
export COMMAND

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

.PHONY: all build check clean coverage e2e exec fmt fuzz install lint release release-check shellcheck test test-go uninstall

all: build

## check: the complete isolated lint, test and build gates
check:
	@tests/container/run check

## exec: run COMMAND against an isolated writable source copy
exec:
	@tests/container/run command

## build: a static binary, stripped
build:
	@FARAMIR_BUILD_LDFLAGS="$(LDFLAGS)" tests/container/run build

## test: everything that tests this, the Go suite and the end-to-end suites
## alike, so that `make test` means the same here as in a repository whose
## end-to-end tests are Go files. `make e2e` still runs those alone, and runs
## them under both sudo implementations, so this pulls in two containers rather
## than one: half the arrangements would not be everything.
##
## The Go suite runs in a container (tests/go/run.sh), never on the host: a test
## that deletes, walks or copies files can escape its temporary directory, and
## there it reaches nothing but a copy of the checkout. The container owns a
## cgroup, which the executor tests need, as CI's runner does.
##
## sops is the pinned copy `make e2e` fetches into tests/e2e, which CI installs
## too. The fixtures are built by running it rather than by linking its
## libraries, which is what keeps every cloud KMS SDK out of the module as well
## as out of the binary, and it is the only way to hold a test against how sops
## itself resolves a creation rule.
##
## The status is taken from the pipeline's first command rather than left to
## pipefail, so that the skip report still runs when the suite failed: a run
## that fails is not one that checked everything else.
test: e2e
	@$(MAKE) --no-print-directory test-go

## test-go: dependency checks, build, race detection and delegated-cgroup tests
test-go:
	@mkdir -p $(BIN)
	@tests/container/run test-go 2>&1 \
		| tee $(BIN)/test.log | $(QUIET); \
	  status=$${PIPESTATUS[0]}; \
	  $(REPORT) $(BIN)/test.log; \
	  exit $$status

## coverage: the suite with the race detector, then the per-function report.
## CGO_ENABLED=1 for this recipe only: -race needs cgo, and the export above
## turns it off for every other one because the shipped binary is static. In
## the container for the reason `make test` is; the profile is written to
## $(BIN)/coverage.txt, the one directory a run's output is copied out to.
coverage:
	CGO_ENABLED=1 FARAMIR_TEST_OUT=$(BIN) tests/go/run.sh sh -c \
	  'go test -race -count=1 -p=1 -parallel=4 -coverprofile=/out/coverage.txt -covermode=atomic ./... && \
	   go tool cover -func=/out/coverage.txt'

## fuzz: run every fuzz target for FUZZTIME each, one package at a time.
##
## `go test` alone runs a fuzz target against its seeds and no further, so the
## properties these state -- that no rendering of a value survives the redactor,
## that a rule refuses every spelling and nothing wider -- are only ever checked
## against the handful of inputs somebody wrote down. This is what exercises
## them.
##
## Not in CI and not in `make test`: fuzzing is time-boxed rather than finished,
## so a pass says how long it ran rather than that it holds, and a failure on a
## seed nobody chose would stop a push over something the run before it also
## would not have found.
##
## In the container, which runs a copy of the checkout. A crasher comes back
## through $(BIN)/fuzz and is copied under its package's testdata/fuzz, which is
## a regression seed worth committing. The copy happens whether the run passed or
## not, since a failing run is the one that wrote a crasher.
FUZZTIME ?= 30s
fuzz:
	@rm -rf $(BIN)/fuzz; \
	  FARAMIR_TEST_OUT=$(BIN)/fuzz tests/go/run.sh tests/go/fuzz.sh $(FUZZTIME); \
	  status=$$?; \
	  cp -r $(BIN)/fuzz/. .; \
	  exit $$status

## fmt: apply the import grouping and gofmt rules CI checks
fmt:
	golangci-lint fmt

## lint: golangci-lint and ShellCheck, so that `make lint` covers the shell as
## well as the Go. Markdown and release configuration use the same container
## tools locally and in CI. `make shellcheck` still runs that check alone.
##
## `run` accepts an unknown key inside `linters.settings` and exits 0, which
## leaves that setting disabled while CI stays green, so `config verify` is what
## rejects a misspelled one.
lint:
	@tests/container/run lint

## shellcheck: the same shellcheck run CI does
shellcheck:
	@tests/container/run shellcheck

## e2e: the functional suites, against a real install in a container: systemd
## units, three uids, a sops store and an agent working in a project tree. Go
## covers the code, these cover what an operator gets after `faramir init`.
##
## Needs Docker and the three third-party binaries `e2e.sh fetch` downloads.
## `up` every time because it is the clean baseline: the suites share one
## install and mutate it, so a `run` without it measures the last run's
## leftovers and reports failures that are not regressions.
##
## `both` rather than `up && run`: the two sudo implementations take different
## settings out of the same /etc/sudoers.d, so `--allow-sudo` installs a
## different arrangement for each and a run that does not say which covers one of
## them. They run at the same time, on stacks that share nothing. `SUDO=sudo-rs
## ./e2e.sh up` is one of them alone.
e2e:
	@tests/container/run e2e

## release: the authorized exact-tag CI publisher, isolated from host credentials
release:
	@tests/container/run release

## release-check: compile snapshot archives without publishing or credentials
release-check:
	@tests/container/run release-check

## install: build, then copy the binaries to $(BINPREFIX). Only the copy runs
## as root: the build is a prerequisite, so the compiler runs as whoever typed
## it. This installs the programs; `faramir init` provisions the host.
##
## install rather than cp -p: the copy must be owned by root. The keeper, broker
## and executor units run this file, so one owned by the builder is one the
## agent's account can replace with a program that is handed the age key.
install: build
	sudo mkdir -p "$(DESTDIR)$(BINPREFIX)"
	@sudo install -m 0755 -o root -g root $(BIN)/faramir "$(DESTDIR)$(BINPREFIX)/"

## uninstall: remove what install copied
uninstall:
	@sudo rm -f "$(DESTDIR)$(BINPREFIX)/faramir"

clean:
	rm -rf $(BIN) dist
