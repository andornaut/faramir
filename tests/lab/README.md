# The lab

Functional tests that drive a real `faramir` install: systemd units, three uids, a sops store, and an agent's account working in a project tree. `go test` covers the code; these cover what an operator gets after `faramir init`.

The suites do not run in CI. They need Docker, a privileged container and the host's cgroup tree, so they are run by hand against a tree you are about to release. CI does lint them with shellcheck.

## Prerequisites

Copy three binaries beside `lab.sh` before the first `up`. The image has no network, so it installs what it finds in the build context.

| File | Where it comes from |
| --- | --- |
| `sops` | https://github.com/getsops/sops/releases |
| `age` | https://github.com/FiloSottile/age/releases |
| `age-keygen` | the same age release |

`lab.sh up` builds two more into the same directory: `faramir` from the tree two levels up, and `faramir-skew` at a version the installed one does not report. The skew binary is what the `doctor` suite swaps in to make the CLI and the running broker disagree about the build; the version is a compiled-in constant, so `lab.sh` builds it with `go build -overlay`, which replaces that one file at compile time and leaves the tree alone.

All five are gitignored. `up` refuses to build without the three you supply, rather than producing an image whose failures all look like missing tools.

## Running

```sh
./lab.sh up                 # build, start the containers, bootstrap an install
./lab.sh run                # every suite
./lab.sh run logs doctor    # check-logs.sh and check-doctor.sh
./lab.sh sh                 # a root shell in the container
./lab.sh down               # remove the containers, images and network
```

`up` is idempotent and rebuilds the binary from the current tree, so it is how you pick up a change. `run` copies each script in fresh, so editing a suite needs no rebuild.

**`run` is single-shot.** The suites share one install and mutate it: a sudo grant is installed, agent configuration is written into the operator's home, and the last suite uninstalls the host. A second `run` without an `up` measures those leftovers and reports failures that are not regressions. `up` stamps a marker that `run` consumes, so a run against an already-used box warns and says what the failures below may be. `up` is the clean baseline.

`check-secrets.sh` is the exception that was worth fixing: it rotates the shared `db/password` that five other suites redact against, so it snapshots the store and `.sops.yaml` on the way in and restores them on the way out.

Each suite prints one line per check and exits non-zero if any failed.

## The containers

`guardlab` runs systemd under `--privileged --cgroupns=host`, which is what a socket-activated `Type=notify` unit needs to behave the way it does on a host. `managed-host` is a second container running sshd, on a network of their own, so the SSH relay suite reaches a real server rather than a stub.

`bootstrap-guard.sh` runs inside `guardlab` and makes the install: an age key, a secrets store with known values, `faramir init`, and an operator account with an enrolled project tree.

## The suites

| Script | What it covers |
| --- | --- |
| `check-init.sh` | `faramir init` against the layout in `docs/layout.md`, and which agents it writes rules for |
| `check-project.sh` | `faramir init-project`: the enrolment that protects a tree, the record of what was enrolled, and the credentials section |
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

Every suite sources [lib.sh](lib.sh), which `lab.sh` copies in beside it. `ok` counts a pass and `bad` counts a failure, and both print. The idiom is:

```sh
grep -q "$want" <<<"$out" && ok "it says why" || bad "it does not: [$out]"
```

`ok` never fails, which is what makes the `||` safe. `.shellcheckrc` disables SC2015 for that reason, SC2016 for the single-quoted heredocs carrying another language's expansions, and SC1091 for the `lib.sh` source path shellcheck cannot resolve.

Helper | Use
--- | ---
`ok` / `bad` | Count a pass or a failure, and print. Say what was expected in the `bad` message and include the output
`note` | Print without counting, for what a suite observes rather than claims. Reaching for `ok` on both sides of a branch writes an assertion that cannot fail and counts it as a pass; that is what this is for
`waitfor SECONDS COMMAND...` | Poll until the command succeeds. Prefer it to a `sleep` long enough for the slowest case, which is slower than the usual case and still too short for the unusual one
`head_` | A section heading
`summary` | End the suite. Takes its name from the filename, so the name in the output is the one `lab.sh` and the table above use

`check-mcp.sh` is a Python suite and holds its own copy of the primitives, matched by hand.

Assert on what an operator or an agent can observe, not on how it is implemented, and prefer a check that would have caught a real bug over one that restates the code.
