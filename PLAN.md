# Working on faramir

Orientation for a coding agent changing this repository. What faramir *is* and
how to operate it is the [README](README.md) and [docs/](docs/); this is the
part that is about the checkout.

`make build test lint fmt` are the entry points, and the
[Developing](README.md#developing) section says what each covers and what the
suite cannot reach.

## Things that will cost you a CI run

**Commits are authored as the repository owner.** The `AI attributions`
workflow fails on `Claude <noreply@anthropic.com>` in the author or committer
field and prints the identity to use instead. It runs on every branch, not only
on pull requests, so an agent that sets its own identity fails before anything
else is checked. Set `user.name` and `user.email` locally in the checkout.

**`golangci-lint` is pinned to the version in
[test.yml](.github/workflows/test.yml), and the version alone is not enough to
reproduce it.** `go install ...@<version>` builds it with whatever toolchain the
tool's own `go.mod` pins, which is older than this module targets, and the
result refuses to load the config. Name the toolchain:

```bash
GOTOOLCHAIN=go1.26.5 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1
```

A newer golangci-lint reports around ninety findings that the pinned one does
not, almost all `goconst` wanting constants for audit-record keys. They are not
regressions.

**Some tests need more than a checkout.** Every brokered command is confined to
its own cgroup, and the tests exercise that path, so they need cgroup v2 and a
cgroup the test process can subdivide; without one they skip rather than fail.
The approval end-to-end tests need root, for the same reason the approval
channel does. A suite that skipped is not a suite that passed.

## Conventions

**No em dashes or en dashes.** A comma, a colon or another sentence says the
same thing, and a range reads as well written out.
`TestTheShippedProseHasNoDashedAsides` fails on one in the embedded prose. Go
comments spell the same aside `--`.

**Comments say why, not what.** The reason a thing is the way it is, the
alternative that was rejected, and what breaks if somebody changes it back. A
comment restating the line below it is noise; a comment naming the bug that line
prevents is the only record of it.

**Documentation placement is decided by whether it ships.** `docs/` is embedded
into the binary and installed onto a host, so it is the operator's; developer
documentation stays at the root, where this file is.

**Tests are named as the sentence they assert**, and carry the reasoning in a
comment above them. A test whose name is `TestFoo2` says nothing when it fails
at three in the morning.

## The agent integrations

Five agents are supported, and what they have in common is thinner than it
looks. [docs/design.md](docs/design.md#agents) has the shape; three things are
worth knowing before changing any of it.

**The paths an agent's file tools are refused are written once**, in
[internal/install/protectedpaths.go](internal/install/protectedpaths.go), and
rendered into each agent's own spelling. Four agents used to hold a copy and had
already drifted apart. Add a path there and nowhere else;
`TestEveryAgentsRulesCoverEveryProtectedPath` checks every rendering.

**`--agent` defaults to `auto`**, which configures the agents already present:
`init` asks that of the operator's home and `init-project` of the tree, and
those are not the same paths. Naming an agent configures it regardless. The two
compose, because detection only ever adds.

**Nothing faramir did not write is ever overwritten.** Files it owns outright
are replaced whole. Shared JSON is merged by key, which means entries can be
added and refreshed but never retracted: an entry there is a bare string or a
map key with nowhere to record who wrote it, so `faramir doctor` names the
leftovers and a human deletes them. The credentials section in `AGENTS.md` or
`CLAUDE.md` is written once when the file shows no sign of faramir, left alone
when it matches, and reported when it has drifted. It is never edited in place,
because a file that mentions faramir may hold an older section, somebody's own
notes, or the same section reworded by whatever last tidied it, and none of
those is faramir's to rewrite.

## Known

`TestClosingDoesNotWaitOutAStreamIdlingBetweenChunks` in `internal/server` is
timing-sensitive and has failed once under full-suite load, passing in
isolation. Not diagnosed.
