# Adversarial assessment: `--allow-sudo`

An attack review of the approval gate installed by `faramir init --allow-sudo`:
the sudoers entry, the private PAM service, `faramir pam-approve`, the broker's
`ask_approval`/`approve`/`approvals` ops, `internal/approval`, and the per-run
cgroup the serialisation rests on. Read against
[docs/design.md](docs/design.md#allowing-sudo-on-the-controller) and
[docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller), which
state the intended posture and now state these outcomes.

Findings are ordered by what an attacker gets. Each says what was done about it,
including the one that was considered and left alone.

Probes are in [internal/approval/adversarial_test.go](internal/approval/adversarial_test.go)
and [internal/execserver/quiescence_test.go](internal/execserver/quiescence_test.go).
They assert the closed behaviour, so each fails if its gap comes back.

## The invariant, stated plainly

Everything here is an attack on one of two sentences.

1. **The prompt names the command**, so a human's yes means something.
2. **No `faramir-exec` process exists outside the approved run while an approval
   is live**, so nothing else can spend it.

Sentence 2 is load-bearing in a way worth spelling out. The token is not a secret
so much as a uid-scoped one: `/proc/<pid>/environ` is readable within a uid, and
a process that reads it does not need to forge anything — it `execve`s with
`FARAMIR_APPROVAL_TOKEN` set to the value it read, runs `sudo`, and
`findToken()` walks up from the helper and finds it in that process's own
environment. **Any live `faramir-exec` process during an approved window is
root.** So sentence 2 is not defence in depth; it is the whole of the second half
of the design.

## Findings

### F1 — The prompt was composed from unsanitized, caller-chosen argv — fixed

`Prompt()` joined argv and `printQuestion` rendered it with `%s` onto the
operator's terminal. Argv arrives over the broker socket as JSON strings and
`protocol.Parse` accepts any string; the redactor rewrites managed values and
touches nothing else, so `\r`, `\n`, `\x1b[2K` and `\x1b[A` reached the terminal
intact and the terminal acted on them. A run could erase the line it was being
judged on and repaint a benign one. The same string reaches `notify_command`'s
`{prompt}`, the `busy` refusal and `Answer`'s "another brokered command runs".

`Run.Command()` now renders rather than prints: each argument is quoted the
moment it holds a control character, a quote or a space, ordinary arguments are
left bare, and the whole is bounded at `maxCommandChars` with the truncation
stated. The cwd goes through the same rendering. Everything downstream — the
prompt, the question fields, the refusals, the notifier — reads from that one
place.

Quoting rather than stripping: an argument that held an escape is one the
operator should see holding it. The cost is a slightly noisier prompt for a
command with spaces in an argument.

### F2 — The prompt named the request, not the resolution — fixed

`opExec` resolved `argv0Path` before registering the run and then registered the
request's argv. A relative `argv[0]` resolves against the request's cwd, which is
the agent's working tree, so the human approved `bin/ansible-playbook` without
being told what that was.

`approval.Run` now carries `Argv0Path`, the prompt names it when it differs from
`Argv[0]`, and `faramir approve` prints it on a `program` line. Silent in the
ordinary case, where saying it every time would make the difference harder to
notice rather than easier.

### F3 — Serialisation was bookkeeping, not an observed fact — fixed

The in-memory logic was correct: `Register` and `Answer` are symmetric under one
mutex, and a live approval and a second registered run could not coexist in the
broker's map. The weakness was the coupling between that map and the kernel.
Three ways they came apart:

- **The drain is bounded.** `runCgroup.close()` writes `cgroup.kill`, drains for
  at most five seconds, and on failure logs and returns; the response goes to the
  broker regardless and the token is released. A process the kernel will not reap
  promptly outlived its run and nothing above the log line knew.
- **The abort path never waited.** `executor.Run`'s backstop calls
  `client.Abort()` — which closes the connection — and returns without
  `client.Result()`, while on the other side `await` is only starting
  `terminate(graceSec)`.
- **A broker restart is amnesia.** `runs` lives in one process's memory. A crash,
  a `systemctl restart`, or `init`'s own `restartFor("sudo grant")` brings the
  broker back with an empty map while the executor is still tearing down.

The fix is to stop believing the map. `approval.Server` gained a `Quiescent`
hook, checked before an approval takes: the broker asks the executor whether any
process of its uid is alive outside that daemon and outside the runs it is
confining, and a no refuses the approval **without answering the question**, so
the run keeps waiting and the operator retries rather than the command having to
ask again. Every failure is a no — an executor that cannot be reached has not
said the host is quiet.

The executor answers it because the broker cannot: the broker's unit sets
`ProtectProc=invisible`, so another uid's `/proc` is not in its view at all. The
executor shares the uid with every brokered command, which is what makes it the
place the question can be answered. It tracks each run's cgroup for the whole of
the teardown, not just the run, so a cgroup still draining still accounts for its
members — until it is empty there is no telling the approved run's processes from
a straggler's. Kernel threads and zombies are excluded: no address space, so no
environ to read a token out of and nothing to exec `sudo` with.

The check runs before the lock rather than under it, since it is a round trip. A
process appearing in that gap would have to be spawned by something already
running — which the check would have seen — or by the run being approved, which
is what the approval is for; and a new *run* starting in the gap is caught by the
sole-occupancy check under the lock.

### F4 — The executor daemon is a permanent exception to sentence 2 — mitigated

`faramir-exec.service` runs as the uid every brokered command gets, sits in no
run's cgroup, and receives each run's entire environment over its socket — every
token and every injected value. It is the one process of that uid that outlives
every run by construction, and nothing in a cgroup teardown reaches it. On an
`--allow-sudo` host its unit carries no seccomp filter (correctly — a filter
forces `NoNewPrivileges=` on, which makes `sudo` inert), and
`/proc/sys/kernel/yama/ptrace_scope` is `0` by default on RHEL, Fedora and Arch,
which permits same-uid attach to a non-descendant.

Both daemons now set `PR_SET_DUMPABLE=0` at startup
([cmd/faramir/undumpable.go](cmd/faramir/undumpable.go)). That refuses same-uid
`ptrace` whatever `ptrace_scope` says and reparents `/proc/self` to `root:root`,
so it does not depend on how the host is configured. It costs core dumps from two
daemons that handle plaintext and should not be producing one.

`faramir doctor` warns on `ptrace_scope=0` for a host with a grant, which is
about what that setting still governs: two brokered commands with respect to each
other. A warning rather than a failure — it is a host-wide sysctl other software
has opinions about, and faramir raising it under an operator would be
reconfiguring the machine rather than reporting on it.

Not closed: the daemon and the children it forks still share a uid. Splitting
them is a real change and worth costing on its own.

### F5 — A refusal is not remembered — considered, left as it is

`Answer(id, false)` finishes the question and leaves the run untouched, so the
next `sudo` files a fresh one, re-notifying, without cap or backoff. Deny-by-
default therefore holds per request and not per run, and the practical attack on
a boundary made of attention is not to defeat one prompt but to serve a hundred
and take the first mis-keyed yes.

Left as it is, deliberately: an approval is a decision about one request, and
carrying a **no** forward is the same kind of state as carrying a **yes**
forward, which this design exists to avoid. `TestARefusalIsNotCarried` states the
rule and stays.

What that leaves standing is bounded by the rest: F1 means a hundred prompts
cannot be made to look like the one the operator was expecting, and F9 means a
run cannot put its next question while another is waiting. The residual is
operator fatigue, which is what `[sudo] timeout_sec` and the watcher's own
attention are for.

### F6 — `y` approved, though every prompt says "Type yes" — fixed

`approves()` took `yes` and `y`. Under this project's own threat model — a tmux
pane the agent can `send-keys` into, a tty the operator's account owns — two
injected bytes versus four is a thin difference, but a tool that accepts less
than it asks for is one whose prompt is not the rule. Now the whole word only.

### F7 — `notify_command` can hand the agent the question id — documented

`{id}` is substituted into the notifier's argv and `wall` is named as an example
notifier. `wall` writes to every terminal on the host including the agent's, and
the agent runs as the operator, so this publishes the one thing a blind
keystroke-injection attack would otherwise lack. It is not a credential —
answering still needs uid 0 — so it was not removed; `{id}` is the whole point of
a notifier for an operator who is not sitting at the watcher.

`docs/operating.md` and `docs/configuration.md` now say to keep `{id}` off a
broadcast channel, and what `{prompt}` is for instead.

### F8 — The tool steered the operator into the failure the docs name — fixed

`faramir approve` run as non-root printed *"Try 'sudo faramir approve'"*, while
`docs/operating.md` says correctly that a warm sudo timestamp in a shell the
agent can use has already handed it that account. The message now names the three
places `warnIfTypeable` does not warn about — a console, an ssh session from
another machine, a login as another account — and says why `sudo` from that shell
is the last resort. The docs suggest `Defaults:<operator> timestamp_timeout=0` on
a host with a grant.

Not done: a `doctor` check for the operator's own `timestamp_timeout`. sudo does
not report it in a form worth parsing, and a check that reads the wrong answer is
worse than none.

### F9 — The caller decided whether the host was ever quiet enough — fixed

`Answer` refuses to approve while any other run is registered, and `Register`
admitted new runs freely as long as no approval was *live*. So a caller that kept
starting trivial commands kept the host permanently un-quiet, and every yes came
back "not approving … while another brokered command runs".

A pending question now holds a new registration too, so the host drains toward
the answer instead of away from it. The cost is that one unanswered question
stalls unrelated brokered work for up to `[sudo] timeout_sec` — the cost an
approved run already imposes for its whole length, widened rather than newly
introduced.

### F10 — Smaller things

- **`newID()` returned `"000000"` on RNG failure** — two such failures put two
  questions with the same id in `waiting`, and `Answer` took the first match in
  map order. It now returns empty and `pend` refuses the request: a question that
  cannot be named is one nobody can answer on purpose. Fixed.
- **`Register` ran before the concurrency slot was acquired**, so a run about to
  be refused `busy` briefly counted as an occupant against an approval. The slot
  is taken first now. Fixed.
- **`[sudo] helper` diverging from what PAM runs** was raised in the first pass
  and is wrong: `pamStackProblem` already fails a host whose `pam_exec` line does
  not name the configured helper, so the writability check and the executed path
  cannot disagree by the time it runs. No change.

## What held

Worth stating, because most of this was right and the findings are about its
edges.

- **The answer channel.** `ask_approval`, `approve` and `approvals` refused to
  anything but uid 0, checked with `SO_PEERCRED` at the op rather than left to
  the socket mode — correct, since the socket admits a group by design and the
  group holds the account the agent runs as.
- **The PAM stack, and knowing which two words matter.** `requisite` rather than
  `sufficient`, and `seteuid`, are the two ways this class of design is usually
  broken, and `doctor` reads the installed file back and fails on either. The
  service being private means a mistake cannot reach another account, and
  `/etc/pam.d/other` is checked for the case where the file is removed. `PAM_TYPE`
  and `PAM_USER` are both checked in the helper, and `--account` really is passed
  by the installed wrapper.
- **No credential anywhere.** Nothing at rest, nothing to carry, `usermod -L`,
  `timestamp_timeout=0`, stale `elevate.secret` files actively removed.
- **Fail-closed on every helper path**, including forcing a non-zero exit for
  `--help`.
- **`Release` drops the run's unanswered question with it**, so a question cannot
  outlive the command it names.
- **The honest scoping.** `design.md` says plainly that an approved command can
  make root permanent and that no sandbox distinguishes configuring a host from
  backdooring it. That claim is correct and correctly bounded, and nothing here
  makes it worse than stated.
