# Adversarial assessment: `--allow-sudo`

An attack review of the approval gate installed by `faramir init --allow-sudo`:
the sudoers entry, the private PAM service, `faramir pam-approve`, the broker's
`ask_approval`/`approve`/`approvals` ops, `internal/approval`, and the per-run
cgroup the serialisation rests on.

Read against [docs/design.md](docs/design.md#allowing-sudo-on-the-controller) and
[docs/operating.md](docs/operating.md#allowing-sudo-on-the-controller), which
state the intended posture. Findings are ordered by what an attacker gets, not
by how hard they are to fix.

Three probes are in [internal/approval/adversarial_test.go](internal/approval/adversarial_test.go).
They pass: each records today's behaviour so the gap is a fact in the suite
rather than a claim here, and each fails the moment the gap is closed.

## The invariant, stated plainly

Everything below is an attack on one of two sentences.

1. **The prompt names the command**, so a human's yes means something.
2. **No `faramir-exec` process exists outside the approved run while an approval
   is live**, so nothing else can spend it.

Sentence 2 is load-bearing in a way worth spelling out. The token is `0600`-ish
only by uid: `/proc/<pid>/environ` is readable within a uid, and a process that
reads it does not need to forge anything clever — it `execve`s with
`FARAMIR_APPROVAL_TOKEN` set to the value it read, runs `sudo`, and
`findToken()` walks up from the helper and finds it in that process's own
environment. **Any live `faramir-exec` process during an approved window is
root.** So sentence 2 is not defence in depth; it is the whole of the second
half of the design.

## Findings

### F1 — The prompt is composed from unsanitized, caller-chosen argv

**What.** `Prompt()` is `strings.Join(run.Argv, " ")` with the cwd appended.
`printQuestion` renders it with `fmt.Printf("\n%s\n", …)` onto the operator's
terminal. Argv arrives over the broker socket as JSON strings; `protocol.Parse`
accepts any string. The redactor rewrites managed values and touches nothing
else, so `\r`, `\n`, `\x1b[2K`, `\x1b[A` and friends reach the terminal intact
and the terminal acts on them.

**Why it matters.** Sentence 1 is the entire argument for why an approval is
worth anything, and the caller writes the sentence. A run can erase the line it
is on and repaint a benign one, scroll the real text off, or add a second
plausible-looking question. The same string is substituted into
`[sudo] notify_command`'s `{prompt}`, so it also reaches whatever announces the
question, and the same caller-chosen text appears in the `busy` refusal and in
`Answer`'s "another brokered command runs (%s)" — two more paths to the same
terminal.

**Reproducer.** `TestThePromptCarriesWhateverTheArgvHolds`,
`TestThePromptCarriesWhateverTheCwdHolds`.

**Fix.** Render argv and cwd for a terminal, not for a log: quote each element
(`strconv.Quote` or equivalent) so control bytes become escapes, cap the total
length with an explicit `…` and the full text left to the audit record, and put
each argv element on its own line in `printQuestion` rather than joining them.
Consider refusing a run whose argv holds control characters outright — there is
no legitimate `\x1b` in an `ansible-playbook` invocation — but quoting alone is
enough and breaks nothing.

**Tradeoff.** A quoted prompt is uglier and a long playbook invocation gets
noisier. Against a boundary made of attention, that is the correct direction.

### F2 — The prompt names the requested argv[0], not the path that will run

**What.** `opExec` resolves `argv0Path` via `resolve.Program` *before* it calls
`Register`, then registers `Argv: redactEach(s.redactor(), cmd)` — the request's
argv, not the resolution. `resolve.Program` resolves a relative `argv[0]` against
the request's cwd, which is the agent's working tree, and follows symlinks.

**Why it matters.** The human is shown `bin/ansible-playbook` and approves
whatever that resolved to. The audit record already carries `argv0_path`; the
question, which is the thing being decided, does not.

**Fix.** Carry `argv0Path` on `approval.Run` and show it in the prompt when it
differs from `Argv[0]`. Two lines of work, and it makes the prompt name the
program rather than the request.

**Tradeoff.** A longer prompt. None otherwise.

### F3 — Serialisation is broker bookkeeping, not an observed fact

The in-memory logic is correct: `Register` and `Answer` are symmetric under one
`sync.Mutex`, and a live approval and a second registered run genuinely cannot
coexist in the broker's map. The weakness is the coupling between that map and
the kernel. Three ways they come apart:

**(a) The cgroup drain is best-effort.** `runCgroup.close()` writes
`cgroup.kill`, drains for at most five seconds, and on failure *logs and
returns* — the response goes to the broker regardless, and the broker releases
the token. `terminate()` is the same shape. A process the kernel will not reap
promptly (uninterruptible sleep on a hung mount, a stuck driver) outlives its
run, and nothing above the executor's log line knows.

**(b) The abort path never waits.** In `executor.Run`, the backstop deadline sets
`aborted = true`, calls `client.Abort()` (which just closes the connection) and
returns **without** `client.Result()`. The broker returns from `opExec`, the
deferred `Release(token)` fires, and a new run may register — while on the other
side of the socket `await` has only just seen the hangup and is starting
`terminate(graceSec)`, which is `graceSec` of SIGTERM grace plus a five-second
drain, followed by `close()`'s own kill and drain. The window is the whole
teardown.

**(c) Broker restart is amnesia.** `runs` lives in one process's memory. A crash,
a `systemctl restart faramir-broker`, or `faramir init`'s own
`restartFor("sudo grant")` brings the broker back with an empty map while the
executor is still tearing down. The new broker will happily register a run and
approve it.

**Why it matters.** Each of these produces exactly the state sentence 2 forbids,
and per the note above, that state is root for whatever is left running.

**Reproducer.** Not written — (a) needs an unkillable process and (b) needs the
backstop to win a race with the executor's own timer, which is where the
argument lands rather than a unit test. The code paths are cited above.

**Fix, in order of cost.**

1. **Report the reap.** Add `reaped: bool` to the executor's response (it already
   knows — `drain()` returns it) and have the broker refuse *every* approval
   after an unreaped run until it has seen a clean one, with `doctor` and the log
   saying so. Also make the abort path collect a result rather than returning
   blind, or treat abort as unreaped by definition.
2. **Refuse approvals across a restart** until the broker has observed a quiet
   host — a short deny window after start is a bad answer, an observation is a
   good one, which is (3).
3. **Make quiescence observed at `Answer` time.** The broker cannot do this
   itself: its unit sets `ProtectProc=invisible`, so it cannot see another uid's
   `/proc` at all, and `SupplementaryGroups=` does not help because hidepid keys
   on uid. The executor can — same uid, same procfs. So add an executor op that
   answers "is anything of my uid alive outside this run's cgroup and outside
   me?", and require a yes before an approval takes. That turns the invariant
   from bookkeeping into a fact the kernel agreed to, and closes (a), (b) and (c)
   together along with any future accounting bug.

**Tradeoff.** One extra round trip on a path taken once per approval, a new op on
the executor socket, and approvals that refuse on a host that will not quiesce —
which is the failure mode to want. Fix 1 alone is a few lines and buys most of
it.

### F4 — The executor daemon is a permanent exception to sentence 2

**What.** `faramir-exec.service` runs as `ExecUser`, the same uid every brokered
command gets, and it is not in any run's cgroup. It also receives each run's
entire environment over the exec socket — `FARAMIR_APPROVAL_TOKEN` and every
injected secret — so it is the one process that sees every token of every run.
On an `--allow-sudo` host its unit drops seccomp entirely (correctly — the block
explains why `NoNewPrivileges=` and a filter cannot coexist with a usable sudo),
so `ptrace` is available to children, and `yama/ptrace_scope` is `0` by default
on RHEL, Fedora and Arch, where same-uid attach to a non-descendant is allowed.
`ProtectProc=invisible` hides other uids and not this one.

**Why it matters.** "It rests on no `faramir-exec` process outliving its run" has
a standing exception, and the exception is the process holding every token. A
brokered command that gets into the daemon has a foothold no cgroup teardown
reaches and no serialisation counts.

**Fix.** `prctl(PR_SET_DUMPABLE, 0)` at startup in the executor daemon, and in
the broker for the same reason — it reparents `/proc/self` to `root:root` and
refuses same-uid `ptrace`, which is a one-line change that does not depend on the
host's `ptrace_scope`. Have `doctor` fail an `--allow-sudo` host with
`ptrace_scope=0`. Longer term, the daemon and the children it forks should not
share a uid; that is a real change and worth costing separately.

**Tradeoff.** `PR_SET_DUMPABLE=0` loses core dumps from both daemons. Given
neither is meant to be debugged in production and both handle plaintext, that is
a gain rather than a cost.

### F5 — A refusal is not remembered, so a hostile run can ask forever

**What.** `Answer(id, false)` finishes the pending question and deletes it from
`waiting`; the run itself is untouched. The next `sudo` calls `pend`, which finds
neither `approved` nor a live question, and files a fresh one — new id, and
`notify_command` runs again. No cap, no backoff. `TestARefusalIsNotCarried`
asserts this today, so it is a decision rather than an oversight.

**Why it matters.** Deny-by-default holds per *request* and not per *run*. The
practical attack on a boundary made of attention is not to defeat one prompt but
to serve a hundred nearly identical ones and take the first mis-keyed yes — and
with F1 the hundred can be made to look like the one the operator was expecting.
`maxPending = 4` bounds concurrent questions, not sequential ones.

**Reproducer.** `TestARefusedRunKeepsAsking` — ten refusals, ten questions.

**Fix.** Record the refusal on the `Run` the way approval is recorded, and refuse
the rest of that run's sudos without asking again. Failing that, cap questions
per run (three, say) with backoff, and do not re-run `notify_command` for a
re-ask.

**Tradeoff.** An operator who denies by mistake has to re-run the command instead
of waiting for the next prompt. That is the right side to be wrong on, and it
matches what the existing prompt already promises — a yes covers the whole run,
so a no should too. `TestARefusalIsNotCarried` would need rewriting to assert the
new rule; its real content (a no does not stand in for a yes) survives.

### F6 — `y` approves, though every prompt says "Type yes"

`approves()` accepts `yes` and `y`. Under this project's own stated threat model
— `tmux send-keys` into the watcher's pane, a tty the operator's account owns —
the gap between injecting two bytes and four is thin, but the mismatch between
what the prompt demands and what the code accepts is free to remove. Stronger, and
worth considering: require the question's **id** to be typed to confirm, since
the id is not disclosed to the agent by any op it can reach — subject to F7.

**Tradeoff.** More typing per approval, on a path taken rarely and deliberately.

### F7 — `notify_command` can hand the agent the question id

`{id}` is substituted into the notifier's argv, and `wall` is named as an example
notifier in `docs/operating.md`. `wall` writes to every terminal on the host,
including the agent's, and the agent runs as the operator. That publishes the one
piece of information a blind keystroke-injection attack would otherwise lack.

It is not a credential — answering still requires uid 0 — so it matters only
combined with a warm sudo timestamp (F8) or with typing into the root watcher.
But it converts "the agent does not know what to type" into "the agent does".

**Fix.** Document that `{id}` must not go to a broadcast channel, and consider
dropping `{id}` from the substitution set entirely: the notifier's job is to say
that something is waiting, and the watcher is where it is answered.

### F8 — The tool steers the operator into the failure the docs name

`faramir approve` run as non-root prints *"Try 'sudo faramir approve'"*. Running
it that way warms the operator's sudo timestamp — and `docs/operating.md` already
says, correctly, that "an operator with `NOPASSWD` sudo, or a warm sudo timestamp
in a shell the agent can use, has already handed it that account". The deny rules
refuse `sudo faramir approve` from the agent's shell, which raises the cost of
reaching the binary and does nothing about the timestamp the operator just
created.

**Fix.** Change the message to recommend a root console, an ssh session from
another machine, or a login as another account — the three places
`warnIfTypeable` already names — and mention `sudo` only as the last option. Have
`doctor` check for a non-zero `timestamp_timeout` on the operator on an
`--allow-sudo` host and recommend `Defaults:<operator> timestamp_timeout=0`,
alongside the `NOPASSWD` check it already makes.

**Tradeoff.** Less convenient for the operator. That is the trade the whole
feature is.

### F9 — The caller decides whether the host is ever quiet enough to approve

`Answer` refuses to approve while any other run is registered, and `Register`
admits new runs freely as long as no approval is *live*. So a caller that keeps
starting trivial commands keeps the host permanently un-quiet: every yes comes
back "not approving … while another brokered command runs", naming a command the
operator did not start (and, per F1, in text that caller chose). `maxPending = 4`
does the same to the question queue from the other end.

Availability rather than escalation, and the fail direction is correct. But it is
also a fatigue path, and it is self-inflicted on a busy host without any attacker
at all: an operator retrying a yes that keeps being refused learns to hammer it.

**Reproducer.** `TestARegisteredRunCanHoldEveryApprovalOff`.

**Fix.** Extend the hold: while a question is *pending*, refuse new registrations
with `busy` too, not only while an approval is live. The host then drains toward
the answer instead of away from it, and the operator's yes lands on the first
try.

**Tradeoff.** One run's unanswered question stalls unrelated brokered work for up
to `[sudo] timeout_sec` (120s by default). That is already true for the length of
an approved run, so it is a widening of an accepted cost rather than a new one —
but it is a real one on a host doing other agent work, and worth a config knob
only if it bites.

### F10 — Smaller things

- **`newID()` returns `"000000"` when the RNG fails.** Two such failures put two
  questions with the same id in `waiting`, and `Answer` takes the first match in
  map order — which is to say, at random. Fail the question instead; an id that
  cannot be minted is a question that cannot be answered.
- **Three bytes of id** is fine against at most four pending questions, but the
  fallback above is the part worth removing.
- **`[sudo] helper` is config-settable and diverges from what PAM runs.**
  `doctor` checks the writability of `cfg.Sudo.Helper`; PAM execs the path `init`
  rendered into the service file from `Layout.PamHelper()`. A config naming a
  different helper makes `doctor` vouch for a file nothing runs. Either read the
  path out of the PAM file (which `doctor` already parses) or drop the key.
- **`Register` runs before the concurrency slot is acquired**, so a run that is
  about to be refused `busy` briefly counts as an occupant against an approval.
  Harmless — it fails closed — but it means "another brokered command runs" can
  name a command that never started.

## What held

Worth stating, because most of this is right and the findings above are about the
edges of it.

- **The answer channel.** `ask_approval`, `approve` and `approvals` are refused to
  anything but uid 0, checked with `SO_PEERCRED` at the op rather than left to the
  socket mode — correct, since the socket admits a group by design and the group
  holds the account the agent runs as. `faramir approve` refuses non-root itself
  so the message is useful.
- **The PAM stack, and knowing which two words matter.** `requisite` rather than
  `sufficient`, and `seteuid`, are the two ways this class of design is usually
  broken, and `doctor` reads the installed file back and fails on either. The
  service being private (`pam_service=`) means a mistake cannot reach another
  account, and `/etc/pam.d/other` is checked for the case where the file is
  removed. `PAM_TYPE` and `PAM_USER` are both checked in the helper, and
  `--account` really is passed by the installed wrapper.
- **No credential anywhere.** Nothing at rest, nothing to carry, `usermod -L` on
  the account, `timestamp_timeout=0`, stale `elevate.secret` files from an earlier
  layout actively removed. The argument for a decision over a bearer token is
  sound and the implementation matches it.
- **Fail-closed on every helper path**, including forcing a non-zero exit for
  `--help`, which is the kind of detail that is usually missed.
- **`Release` drops the run's unanswered question with it**, so a question cannot
  outlive the command it names.
- **The honest scoping.** `design.md` says plainly that an approved command can
  make root permanent and that no sandbox distinguishes configuring a host from
  backdooring it. That is the correct claim, correctly bounded, and this review
  found nothing that makes it worse than stated.

## Suggested order

1. **F1 and F2** — cheap, and they restore the meaning of the sentence the whole
   feature rests on.
2. **F5** — cheap, and it removes the practical attack on operator attention.
3. **F3**, starting with `reaped` in the executor response and ending with an
   observed-quiescence op. This is the one that decides whether sentence 2 is
   true.
4. **F4** — `PR_SET_DUMPABLE=0` now, a uid split considered separately.
5. **F6 through F10** as they fit.
