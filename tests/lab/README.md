# The lab

Functional tests that drive a real `faramir` install: systemd units, three uids,
a sops store, and an agent's account working in a project tree. `go test`
covers the code; these cover what an operator gets after `faramir init`.

Nothing here runs in CI. It needs Docker, a privileged container and the host's
cgroup tree, so it is run by hand against a tree you are about to release.

## Prerequisites

Copy four binaries beside `lab.sh` before the first `up`. The image has no
network, so it installs what it finds in the build context.

| File | Where it comes from |
| --- | --- |
| `faramir` | built by `lab.sh up` from the tree two levels up |
| `sops` | https://github.com/getsops/sops/releases |
| `age` | https://github.com/FiloSottile/age/releases |
| `age-keygen` | the same age release |

They are gitignored. `up` refuses to build without them rather than producing an
image whose failures all look like missing tools.

## Running

```sh
./lab.sh up                 # build, start the containers, bootstrap an install
./lab.sh run                # every suite
./lab.sh run logs doctor    # check-logs.sh and check-doctor.sh
./lab.sh sh                 # a root shell in the container
./lab.sh down               # remove the containers, images and network
```

`up` is idempotent and rebuilds the binary from the current tree, so it is how
you pick up a change. `run` copies each script in fresh, so editing a suite
needs no rebuild.

Each suite prints one line per check and exits non-zero if any failed. They
share one bootstrapped install and are ordered so that the destructive ones
(`secrets`, `uninstall`) come last; running a single suite out of order against
a container that has already run them may need an `up` first.

## The containers

`guardlab` runs systemd under `--privileged --cgroupns=host`, which is what a
socket-activated `Type=notify` unit needs to behave the way it does on a host.
`managed-host` is a second container running sshd, on a network of their own, so
the SSH relay suite reaches a real server rather than a stub.

`bootstrap-guard.sh` runs inside `guardlab` and makes the install: an age key, a
secrets store with known values, `faramir init`, and an operator account with an
enrolled project tree.

## The suites

| Script | What it covers |
| --- | --- |
| `check-init.sh` | `faramir init` against the layout in `docs/layout.md` |
| `check-project.sh` | `faramir init-project`, the enrolment that protects a tree |
| `check-config.sh` | changing a configuration: drop-ins plus reload |
| `check-disclose.sh` | what the broker tells the account it keeps values from |
| `check-guard.sh` | the guard's decision surface |
| `check-wrap.sh` | the rewrite the guard hands back, executed |
| `check-plugin.sh` | the opencode and Kilo Code plugins, executed |
| `check-gemini.sh` | the Gemini hook, and its deny policy matched the way Gemini matches it |
| `check-mcp.sh` | the MCP server |
| `check-exec.sh` | the executor boundary |
| `check-leak.sh` | the leak hunt: every place a value could come back out |
| `check-stream.sh` | the redact stream |
| `check-ssh.sh` | the SSH agent relay, against `managed-host` |
| `check-approval.sh` | the `--allow-sudo` approval channel |
| `check-logs.sh` | `faramir logs`, the operator's record |
| `check-doctor.sh` | `faramir doctor` as a fault detector |
| `check-secrets.sh` | the secret lifecycle: edit, rekey, and a store that will not open |
| `check-uninstall.sh` | `faramir uninstall`, and what it is right to leave behind |

## Writing a check

`ok` counts a pass and `bad` counts a failure, and both print. The idiom is:

```sh
grep -q "$want" <<<"$out" && ok "it says why" || bad "it does not: [$out]"
```

`ok` never fails, which is what makes the `||` safe. `.shellcheckrc` disables
SC2015 for that reason. Say what was expected in the `bad` message and include
the output: a failure an operator cannot read is a failure they will rerun by
hand anyway.

Assert on what an operator or an agent can observe, not on how it is
implemented, and prefer a check that would have caught a real bug over one that
restates the code.
