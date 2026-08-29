# The end-to-end suites

Functional tests that drive a real `faramir` install: systemd units, three uids, a sops store, and an agent's account working in a project tree. `go test` covers the code; these cover what an operator gets after `faramir init`.

CI runs them on a push to any branch and on a pull request against main: `fetch`, `up`, `run` over every suite, then `down`. It runs that twice, as a matrix over the two sudo implementations, so the jobs are named `E2E (sudo)` and `E2E (sudo-rs)`. A job each rather than `./e2e.sh both` inside one: a GitHub runner is two CPUs, and a stack is a privileged systemd container plus an sshd host, so the two legs take a runner each and run at the same time. Locally `make e2e` runs both at the same time instead. The Lint job beside it reads these scripts with shellcheck.

Run them by hand as well, against a tree you are about to release or while changing a suite, which is what the rest of this page is for.

## Prerequisites

Three binaries must be beside `e2e.sh` before the first `up`. The image has no network, so it installs what it finds in the build context.

```sh
./e2e.sh fetch              # downloads all three, x86_64
```

| File | Where it comes from |
| --- | --- |
| `sops` | <https://github.com/getsops/sops/releases> |
| `age` | <https://github.com/FiloSottile/age/releases> |
| `age-keygen` | the same age release |

`fetch` takes upstream's own builds, which are static, so the image needs no libc to match. Both the version and the sha256 are pinned in `e2e.sh`: these are what the suites decrypt and generate keys with, so a run that says a release is fit to ship says it about a tool named there. A digest that does not match is refused and nothing is written. Bumping a version means changing its digest too, which the refusal prints.

`fetch` skips what is already there, so it is safe before every `up`; delete a file to replace it. It pins x86_64 digests only, and says so on another architecture: copy the three in by hand there.

`e2e.sh up` builds two more into the same directory: `faramir` from the tree two levels up, and `faramir-skew` at a version the installed one does not report. The skew binary is what the `doctor` suite swaps in to make the CLI and the running broker disagree about the build; the version is a linker variable, so `e2e.sh` stamps it with `go build -ldflags -X` and never edits the tree. It checks the stamp took: a `-X` naming a symbol that has moved does nothing and exits 0, which would leave the suite comparing a binary against itself.

All five are gitignored. `up` refuses to build without the three you supply, rather than producing an image whose failures all look like missing tools.

## Running

```sh
./e2e.sh up                 # build, start the containers, bootstrap an install
./e2e.sh run                # every suite
./e2e.sh run logs doctor    # check-logs.sh and check-doctor.sh
./e2e.sh sh                 # a root shell in the container
./e2e.sh down               # remove every stack's containers, images and network
./e2e.sh both               # a stack per sudo implementation, at the same time
```

## The two sudo implementations

Ubuntu ships two behind one `sudo` alternatives group, and `faramir init --allow-sudo` writes a different arrangement for each: see [escalation.md](../../docs/escalation.md#the-two-sudos). The image installs both and pins the original; `SUDO` picks which one a stack's host runs.

```sh
SUDO=sudo-rs ./e2e.sh up && SUDO=sudo-rs ./e2e.sh run   # under sudo-rs
```

Every container, image and network name takes a suffix from `SUDO`, so the two stacks share nothing and can be up together. `./e2e.sh both` is that pair run concurrently, two logs per arrangement (`up` and `run`) and per uid under `$TMPDIR`. Each container's systemd roots under its own `docker-<id>.scope`, so the cgroup trees do not meet even though both run `--cgroupns=host`.

`SUDO` is `sudo` or `sudo-rs`, the implementations' own names rather than labels for them, so what a CI job is called, what you type and what the docs say are one word. Unset is `sudo`, which is what the image pins, and it takes the unsuffixed names.

`make e2e` from the repository root is `fetch` and `both` in one command, and `make test` is that plus the Go suite. The linters are `make lint`, which CI runs as a job of its own.

`up` is idempotent and rebuilds the binary from the current tree, so it is how you pick up a change. `run` copies each script in fresh, so editing a suite needs no rebuild.

**`run` is single-shot.** The suites share one install and mutate it: a sudo grant is installed, agent configuration is written into the operator's home, and the last suite uninstalls the host. A second `run` without an `up` measures those leftovers and reports failures that are not regressions. `up` stamps a marker that `run` consumes, so a run against an already-used box warns and says what the failures below may be. `up` is the clean baseline.

**Naming suites is the same hazard from the other side.** Each leaves what the later ones examine (`check-project` runs `init --agent claude`, which writes the account-wide settings `check-doctor` then reports missing), so a set that is not a prefix of the run order is measured against a box its predecessors never set up. `run` warns about that too, and `./e2e.sh run logs doctor` above is one: useful while changing those two suites, and not a verdict on the build.

`check-secrets.sh`, `check-link.sh` and `check-block.sh` are the exceptions. The first rotates the shared `db/password` that four other suites redact against; the second adds refs to the running install and regroups two files in the operator's home; the third writes entries into the config and renders rules into the operator's settings. Each snapshots what it changes on the way in and restores it on the way out.

Each suite prints one line per check and exits non-zero if any failed.

## The containers

`faramir-e2e` runs systemd under `--privileged --cgroupns=host`, which is what a socket-activated `Type=notify` unit needs to behave the way it does on a host. `managed-host` is a second container running sshd, on a network of their own, so the SSH relay suite reaches a real server rather than a stub.

`bootstrap.sh` runs inside `faramir-e2e` and makes the install: an age key, a secrets store with known values, `faramir init`, and an operator account with an enrolled project tree.

## The suites

In run order, which is what the prefix rule above is about: a set named to `run` that is not a prefix of this table runs against a box its predecessors never set up.

| Script | What it covers |
| --- | --- |
| `check-init.sh` | `faramir init` against the layout in `docs/layout.md`, and which agents it writes rules for |
| `check-project.sh` | `faramir init-project`: the enrolment that protects a tree, the record of what was enrolled, and the credentials section |
| `check-config.sh` | changing a configuration: drop-ins plus reload |
| `check-disclose.sh` | what the broker tells the account it keeps values from |
| `check-plugin.sh` | the opencode and Kilo Code plugins and pi's extension, executed |
| `check-guard.sh` | the guard's decision surface |
| `check-wrap.sh` | the rewrite the guard hands back, executed |
| `check-leak.sh` | the leak hunt: every place a value could come back out |
| `check-stream.sh` | the redact stream |
| `check-exec.sh` | the executor boundary |
| `check-logs.sh` | `faramir logs`, the operator's record |
| `check-ssh.sh` | the SSH agent relay, against `managed-host` |
| `check-doctor.sh` | `faramir doctor` as a fault detector |
| `check-escalation.sh` | the `--allow-sudo` escalation channel |
| `check-secrets.sh` | the secret lifecycle: edit, reseal, the `.sops.yaml` shapes that seal a store to the wrong people, and a store that will not open |
| `check-link.sh` | `[[secret.link]]`: a value read out of a file another tool maintains, and the grant that lets the broker read it and nobody else |
| `check-block.sh` | `[[secret.block]]`: a path, a name or a command blocked from the agent, the listing that shows the built-in rules beside them, and the two costs of never reading it: the mode is left alone and the value is absent from the redactor |
| `check-uninstall.sh` | `faramir uninstall`, and what it is right to leave behind |

## Writing a check

Every suite sources [lib.sh](lib.sh), which `e2e.sh` copies in beside it. `ok` counts a pass and `bad` counts a failure, and both print. The idiom is:

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
`summary` | End the suite. Takes its name from the filename, so the name in the output is the one `e2e.sh` and the table above use

Assert on what an operator or an agent can observe, not on how it is implemented, and prefer a check that would have caught a real bug over one that restates the code.

A value's absence is not evidence on its own. The broker builds its redactor over the whole value set rather than over the refs a request asked for, so brokered output missing a secret may be output that was redacted rather than output that was refused. Pair the absence with what should be there instead: the token, where the redactor is what covered it, and the refusal, where an account boundary is.
