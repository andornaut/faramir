# Wire protocol

Three Unix sockets. Each carries newline-delimited JSON: one request and one response per connection, with no framing beyond the newline.

Socket | Who may connect | What it does | Request limit
--- | --- | --- | ---
`/run/faramir/broker.sock` | the agent (`0660 root:<client-group>`) | run commands, list refs | 256 KiB
`/run/faramir/keeper.sock` | the broker (`0660 root:<broker's group>`) | return decrypted values | 65536 bytes
`/run/faramir/exec.sock` | the broker (`0660 root:<broker's group>`) | fork a command on a passed PTY | 1 MiB

The two internal sockets are root-owned, so neither the keeper's nor the executor's own uid can connect. A child that reached the executor socket could run commands the broker never authorised or logged.

All three close a connection that sends no request within 30s. The broker answers `timeout` first, the executor answers `bad_request`, and the keeper answers nothing.

## version

Every request on every socket carries `version`: the version string of the binary that sent it. A request naming any version other than the receiving daemon's own is refused before its op is read.

There is one binary. The three daemons are that binary under three units, and the CLI is the same binary run by the agent. Two versions on one host means a process outlived an install that replaced the binary under it. The refusal says so:

```json
{"version": "<this daemon's>",
 "error": {"code": "bad_request",
           "message": "the caller names faramir <the caller's> and this is faramir <this daemon's>:
                       restart it. A daemon that outlived the install which replaced
                       the binary under it is the usual cause, and `sudo faramir reload`
                       is what restarts all three"}}
```

Every error response from the broker carries `version`, the build that answered. A version refusal is the one case where the caller cannot learn the version from an op, since the refusal comes before the op is read. [`doctor`](operating.md#checking-an-install) uses this to report version skew.

`status` also carries `build`. Every unstamped build reports the version `dev`, so `build` is what distinguishes two such binaries: the commit, plus `-modified` for a tree with uncommitted edits. It is empty for a release, whose version already names the build. `doctor` compares `build` when the versions match. `build` is not part of `version`, so a rebuild does not trigger the refusal above; only a release does.

A caller that sends no `version` is refused the same way and told it named none. Without this check, a mismatch would fail later and less clearly: an op the daemon no longer has would be refused as unknown, and a field it no longer reads would be silently ignored.

## The broker socket

The socket mode is one check. The broker also tests `SO_PEERCRED` against `[server] allowed_group`, and records the peer's uid, gid and pid in every audit record.

Op | Does | Notes
--- | --- | ---
`run` | run a command | The default when `op` is absent. An unknown `op` is refused, not defaulted.
`redact` | scrub text the caller already holds | An oracle by design. Audited: the input's size and what was found, never the text.
`refs` | ref names only | Adds `refs`.
`status` | version, `build`, `config`, the managed store's `patterns` and resolved `files`, secret count, load errors, `unresolved_patterns`, a `links` count, `degraded_links`, `degraded`, `ssh.configured`/`ssh.usable`, `sudo.enabled` | Reports whether a value exists, never the value. The store's paths are not secret: `config` names the config file, which is `0644`, and its `[secret]` patterns name the directory. `files` lists which globs resolved, never what a file holds. A linked file is a count, never a path. `degraded` is why the exit status is `1`. A ref the redactor refused is counted, not named; `doctor` names it. A linked file that did not load is named by its ref in `degraded_links` with a reason; `faramir link ls` already lists that ref.
`refresh` | re-read the managed store now | Root only. Adds `refs`. `faramir vault` sends it so a rotated value is redacted before the command that rotated it returns, instead of up to a second later at the next staleness check.
`escalations` | what is waiting, and how an approved run ended | Root only. Adds `questions`, and `finished` when the caller named a run that has ended.
`answer` | answer a question by `id`, carrying `approved` | Root only.
`escalate` | the PAM helper's half | Root only. Adds `approved`, `outcome_code`, `reason`.

The four root-only ops are checked with `SO_PEERCRED`. The account the coding agent runs as must not be able to approve what the agent asked for, or ask the broker for a decrypt per request. `status` and `refs` answer whatever state the value set is in.

### run

```json
{
  "op": "run",
  "version": "…",
  "cmd": ["printenv", "ROUTER_PW"],
  "cwd": "/home/you/src/project",
  "env_refs": { "ROUTER_PW": "faramir://home/router/admin" },
  "timeout_sec": 600
}
```

Field | Required | Notes
--- | --- | ---
`version` | yes | The sending binary's own version. Every op on every socket takes it, and a mismatch is refused before the op is read. See [version](#version).
`cmd` | yes | Non-empty array of strings. A string is rejected with guidance; the broker never runs `sh -c`.
`cwd` | yes | Absolute, and must be an existing directory. A relative `cmd[0]` resolves against it. The CLI fills in its own working directory and resolves a relative `-C` against that, so this refusal only happens on the socket.
`env_refs` | no | `NAME` to `faramir://ref`. `NAME` must match `^[A-Za-z_][A-Za-z0-9_]*$` and must not be reserved. Values cannot be passed.
`timeout_sec` | no | Positive integer, clamped down to `[command] max_timeout_sec`. Omitted means `[command] timeout_sec`.
`stdin` | no | Base64, what the child reads on its standard input, at most 131072 bytes decoded. It travels inside the request because the broker watches the connection to detect a caller that has gone, so bytes after the request cannot carry data. Larger input is refused rather than truncated: a command that read half its input did something the caller did not ask for. The CLI sends what was piped into it when `-i` is given. Without `-i`, a pipeline on the CLI's standard input is refused rather than dropped: the CLI does not own that file, and a caller looping over it is still reading it. An anonymous pipe with nothing in it and no writer left is not refused, since nothing can arrive on it; a program driving the CLI as a subprocess inherits one. A FIFO is refused in every state, because another writer can open it after the last one closes. A run with no `stdin` leaves the child on `/dev/null`, which is an immediate end of input rather than a wait.

A caller keeps its write side open until it has the answer. The broker reads the connection for the whole run, and a failed read means the caller has gone: the run is killed and the record carries `abandoned`. A half-close reads the same way, so a client that shuts down its write half after sending has every command killed the moment it starts. Any bytes that arrive mean the caller is still there, so a second request on a connection already carrying a run is discarded rather than answered. No other op is watched: a run is the only op that holds a `[command] concurrency` slot and can outlive its caller by an hour.

Reserved `env_refs` names. These are refused so an injected value cannot redirect the loader, the interpreter, sops or the agent relay. Every other name is accepted:

```text
PATH  HOME  IFS  BASH_ENV  ENV  LD_PRELOAD  LD_LIBRARY_PATH
SOPS_AGE_KEY  SOPS_AGE_KEY_FILE  CREDENTIALS_DIRECTORY
SSH_AUTH_SOCK  SSH_AGENT_PID  SUDO_ASKPASS  FARAMIR_OPERATOR
```

**`FARAMIR_OPERATOR` is set, not only refused.** Every brokered command gets it, from `[server] agent_user`. It names the account whose host and home the run is about; the executor's own uid does not, since every brokered command runs as that uid. It is reserved so a caller cannot name a different account. On a host that grants sudo, [the grant keeps it across sudo](escalation.md#what-a-brokered-command-keeps-across-sudo), where `env_reset` would otherwise drop it.

### redact, and streaming it

`{"op": "redact", "version": "…", "text": "…"}` returns the ordinary response shape, with `output` carrying the scrubbed text and `exit_code` 0. No command runs. `text` is required; `more` is the only other field the op reads.

A caller with more text than one request can carry sends it in chunks **over one connection**, with every chunk but the last marked `{"more": true}`. The broker keeps one redactor per connection and holds back a tail longer than the longest rendering of any value, so a secret split between two chunks is caught by the chunk that completes it. One connection per chunk would give each chunk its own redactor, and a value split across the join would come back unredacted. Ordinary output needs this: a single-line JSON document, a minified bundle and `base64 -w0` all have to be broken somewhere.

- `more` must be a boolean. Sent where no stream state exists, it is a `bad_request`, not a request completed as if it stood alone.
- One audit record per stream, written when it ends, carrying the totals for the whole stream. A stream the peer abandoned still writes one.
- The first request on a connection is on the 30s clock. Between chunks a stream may idle up to `[command] max_timeout_sec`, because `faramir redact -- command` sends a chunk whenever the command prints one.

### escalations

`escalations` takes an optional `wait_sec` and blocks up to that long for a question to appear, so a watcher uses one connection instead of polling every second. The wait is clamped to 60s. It returns at most one question, carrying `caller` (the account that asked, never the one the command runs as), `received` (RFC 3339, when `sudo` asked), `waiting_sec` and `expires_in_sec`. A second command asking to sudo while one question is waiting is refused, not queued.

It also takes an optional `await_log_id`, naming the run the caller approved and has not yet seen end. When that run ends, the response carries `finished`: `log_id`, `exit_code`, `duration_sec`, `waited_sec`, `timed_out`, `error` and, where the code is a stand-in, `status_unknown`. The poll returns as soon as the run ends rather than waiting out `wait_sec`. `exit_code` is `null` where the command never started, with `error` saying why; a zero there would look like a clean exit. A run whose status the executor never reported carries the stand-in code and `status_unknown`. Only an approved run has an ending to report, and only the caller naming it is told. The broker keeps the last ending rather than clearing it when read, so two watchers both see it, and a caller that approved nothing sees none.

`escalate` carries `procs`: the ancestry above the asking `sudo`, most recent first. It is a non-empty array of pids, each an integer above 1 (`0` and negatives name a process group to `kill`, and pid 1 is `init`, which no brokered command is). The op blocks until a human answers, the question expires, or the broker stops. The broker asks the [executor](#the-executor-socket) which of its live runs forked one of those pids; an ancestry no run owns is refused without asking a human. A pid is a claim, not proof, so the executor checks each against a handle it took at the fork: a number the kernel has since reassigned to another process matches nothing. `sudo` is blocked on this op throughout, which makes the wait an authentication step.

`outcome_code` names which of these happened in one word; `reason` is the accompanying sentence. A refusal a human typed and a question nobody answered are different events, handled differently, so the code carries the difference and nothing has to parse the prose. The same code is written to the audit record, where `faramir logs` reads it.

Code | Means
--- | ---
`approved` | a human said yes, or this sudo was covered by the yes given for the same command
`rejected` | a human said no
`expired` | nobody answered within `[sudo] timeout_sec`
`not_quiescent` | an approval was overridden to a refusal: a process of the executor's uid was alive outside the run
`run_ended` | the command exited before the question was answered
`broker_stopped` | the broker stopped, or was stopping when the request arrived
`other_command` | another brokered command was registered, so no question could be put
`unnamed_question` | the question could not be given an id, so nothing could answer it
`unowned_run` | no live run forked the process that asked
`no_grant` | this host was installed without `--allow-sudo`

### Responses

```json
{
  "exit_code": 0,
  "output": "…redacted, ANSI-stripped, stdout+stderr merged…",
  "truncated": false,
  "redactions": [{ "token": "«SECRET:home/router/admin»", "count": 3 }],
  "log_id": "w5vq7dbf00002c",
  "timed_out": false,
  "duration_sec": 12.4,
  "invalid_bytes": 0
}
```

Field | Meaning
--- | ---
`redactions` | Counts, not values. A count of 0 where one was expected means something is misconfigured.
`log_id` | Points into `/var/log/faramir/audit.log`. The agent cannot read the log, but it can cite a record to the operator.
`invalid_bytes` | How many bytes were not valid UTF-8 and came back as `U+FFFD`. Non-zero means the output was binary.
`waited_sec` | How much of `duration_sec` the command spent blocked on its own escalation. Present only where a `sudo` waited. Written to the `run` record and carried on `finished` as well. `duration_sec` is wall time from fork to exit, and the child is blocked inside `sudo` for the whole question, so without this field a slowly answered escalation looks like a slow command. It is reported beside the duration rather than subtracted from it, because `[command] max_timeout_sec` is enforced against the same clock.
`escalation_code`, `escalation` | Why a `sudo` inside the command was turned down. Present only where one was. `sudo` itself reports a refusal and an expiry alike, as an authentication failure, so this is where `rejected` is distinguished from `expired`: running the command again may help in one case and not the other. The codes are the [escalate codes](#escalations); the same pair is written to the `run` record.
`truncated` | Output hit the output cap.
`status_unknown` | Present only where the executor never reported an exit status. The output is kept and `exit_code` is a non-zero stand-in, not the child's own, so a `137` here is not a signal kill. Written to the `run` record as well. A command that failed to start is not this; that is an `error` response: `exec_failed`, `not_found` or `not_executable`.
`abandoned` | Audit record only: the caller's connection went away and the run was killed rather than left to its timeout. Distinct from `timed_out`, which means the command took too long; an abandoned run was within its time. There is no caller left to send a response to, so the record is the only report.

A `redact` response carries no `timed_out` or `duration_sec`. An error nulls `exit_code` and adds `error`:

```json
{"error": {"code": "not_found",
           "message": "ansible-playbook: not found on the broker's PATH (…)"}}
```

Code | Meaning
--- | ---
`bad_request` | Malformed request, a `version` that is not this daemon's own, a bad or reserved env var name, a malformed `faramir://` reference, or a `cwd` that does not exist or is not a directory
`unknown_secret` | The ref is in no managed file, or was refused at load as not redactable
`unknown_question` | `answer` named a question that is no longer waiting: already answered, or its command gave up
`busy` | At `[command] concurrency`; retry
`escalation_in_progress` | An escalation is being decided or held, so no other brokered command runs. Names the command holding it. **Terminal, not retryable**: this command was neither run nor queued. Only where `--allow-sudo` was installed
`not_quiescent` | The answer was yes, but a process of the executor's uid was alive outside the run being approved and could have used the escalation. The `sudo` fails; run the command again once the host is quiet
`no_audit` | The audit log cannot be written, so the command was refused rather than run unrecorded. `run` only
`blocked` | The command would print a file this host holds in the blocks or the links, run a command the blocks name, name one of faramir's own directories, or act on the install rather than through it. **Terminal, not retryable**: nothing about the host will change to make the same command allowed. The message names what matched, which list it is in (the blocks or the links), and the command that removes it; a directory of faramir's own is in neither list and the message says so. A command entry is answered as a command, not as a file. The two kinds follow different rules. A path in the blocks or the links is refused only to the reading commands, so a brokered command that is not one of them may do whatever it does to the file. Faramir's own directories may not be named for any reason, and its own commands may not be run by any route. This is the broker's rule, not the guard's: see [the brokered route](configuration.md#the-brokered-route). `run` only
`no_secrets` | A managed value the redactor should hold is missing: a managed file that matched did not load, or the keeper never answered and no value set was ever loaded. An entry that matched no file is not this: the broker is missing nothing it should hold, and serves. `run` and `redact` both refuse; `status` and `refs` always answer. A `[[secret.link]]` entry that did not load is not this either: it is one ref the broker can name, so that ref alone is refused with `unknown_secret` and the host keeps serving
`not_found` | Nothing at the path `cmd[0]` names, or nothing by that name on `[command.env] PATH`. The shell's 127, which is what `faramir run` exits with
`not_executable` | `cmd[0]` exists but the kernel will not run it: a directory, a device, a file without the execute bit, a file with no interpreter and no magic. The shell's 126
`exec_failed` | The program could not be started for any other reason: a working directory the executor cannot enter, an argument list too long, a byte no argument can carry
`internal` | The broker could not render its own answer. Not a fault of the request
`forbidden` | Peer uid or gid not permitted, or a non-root peer on one of the four root-only ops
`too_large` | Request exceeded the 256 KiB cap, which is a [constant rather than a key](configuration.md#what-is-not-a-key-at-all)
`timeout` | No request arrived within 30s, or a redact stream idled past `[command] max_timeout_sec`

There is no command allowlist, so there is no `denied`. Messages name what failed and where to fix it, so the agent can correct itself in one turn: a program off `[command.env] PATH` says so and names the setting.

## The keeper socket

The peer uid is checked against `[keeper] allowed_user` on top of the socket mode. There is no group form: the only group available contains the agent's own uid. Two ops, and **none that returns the age key**. Adding one would defeat the reason the keeper is a separate service.

```json
{"op": "get_values", "version": "…"}
{"values": {"home/router/admin": "…"},
 "state": [{"path": "/etc/faramir/secrets/x.sops.yml",
            "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": [], "shadowed_refs": []}
```

`get_values` returns every managed value, never a subset. The redactor is built from the whole value set, because a managed host can print a credential no command injected. `state` is the fingerprint of each file this decrypt read. It is returned with the values so both describe the same moment; fetched separately, it could fingerprint a file edited after the decrypt, and that edit would never be noticed.

```json
{"op": "get_state", "version": "…"}
{"state": [{"path": "…", "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": []}
```

`get_state` is the staleness poll. It is also where the managed store globs are expanded, so a file added to the secrets directory appears without a restart. The broker cannot stat those files itself: it is outside `2750 root:faramir-keeper`. This op needs neither the key nor a sops exec, so it is cheap enough to serve on every request.

- A file that could not be stat-ed or decrypted comes back in `errors`, not as an error response, so one broken file does not empty the whole value set. Key material is stripped from those strings before they cross the socket.
- `unresolved_patterns` is kept separate because it means something different. An entry that named no file is a secrets directory not written yet, which is the state of every first install. A file that exists and will not open is a value the redactor is missing without knowing it. Neither stops the daemon. A file that will not open fails `faramir broker --check` and `faramir doctor`; an entry that named no file is logged by `--check` and is a warning in `doctor`, which fails it only where the directory could not be searched.
- `shadowed_refs`, on `get_values` only, names a ref that more than one managed file defines with different values. One of those values ends up in no redactor, so `doctor` fails it under `shadowed refs`.
- An oversized or malformed request gets no response: the connection closes. A JSON `null` payload is the one case that answers `bad_request`.

```json
{"error": {"code": "unsupported",
           "message": "unsupported op 'get_age_key'; the keeper serves
                       'get_values' and 'get_state' only and has no operation
                       that returns key material"}}
```

## The executor socket

One request, carrying a single file descriptor as ancillary data:

```json
{"version": "…",
 "argv": ["/usr/bin/printenv", "ROUTER_PW"],
 "cwd": "/home/you/src/project",
 "env": {"ROUTER_PW": "…"},
 "run_id": "3f8c…",
 "timeout_sec": 600,
 "kill_grace_sec": 5}

{"exit_code": 0, "timed_out": false}
```

The descriptor is the **slave** end of a PTY the broker created. The broker keeps the master, so redaction and the audit log read the child's bytes directly. Both sides close their copy of the slave once the child holds it; otherwise the master never reaches EOF.

`argv[0]` arrives already resolved to an absolute path. The executor checks nothing about it before running it. Only after a failed start does it inspect why, and answer `not_executable` or `exec_failed` instead of a run with no status. A brokered command is bounded by the uid it runs as (no age key, no audit log, no SSH key) and by the mode on this socket, which the executor's own uid cannot open. An exit code is `128+signal` where the child was signalled.

`run_id` is the broker's name for this run. It is passed through so a `sudo` raised inside the run can be attributed to the command a human was shown. It is empty where the host grants no escalation, which leaves the run unattributable and therefore unable to sudo.

Two more ops share the socket. `"op": "exec"` and an absent `op` both mean the request above:

```json
{"op": "quiescent", "version": "…"}

{"quiescent": false, "detail": "1 process(es) are running as the executor outside any brokered command (4821 (sleep))"}
```

The broker asks this before an escalation takes effect: is any process of the executor's uid alive outside the daemon and outside the runs it is confining? The executor answers because the broker cannot observe those processes itself: its own unit sets `ProtectProc=invisible`. Every failure counts as a no.

```json
{"op": "owner", "version": "…", "procs": [4821, 4820, 4815]}

{"run_id": "3f8c…", "detail": "pid 4815 is the command this run was forked as, and is still running"}
```

The broker asks this when an [escalation](#escalations) is raised. `procs` is the ancestry the PAM helper walked. Only the executor can answer: it did the fork, and the broker never sees the pid. An empty `run_id` means no run owns any of them, with `detail` saying why. Every failure is an empty `run_id`.

A pid alone would not settle ownership, because the kernel reuses the number once the process is reaped. The start time that would settle it cannot be read here either: a brokered command that execs `sudo` gets a root-owned `/proc` entry, which `ProtectProc=invisible` hides from this uid. So the executor uses the fork instead. `clone3` returns a pidfd, taken before the exec and referring to the process rather than the number, and signal `0` through it asks whether that process is still alive. Alive means the number is still its own, since a pid is not reused until its holder is reaped. A kernel without `CLONE_PIDFD` leaves the run unowned, so nothing inside it can sudo.

An op this daemon does not know is refused `bad_request` with the name in the message. A broker of another release is refused before that, by [version](#version).

The executor owns the timeout, because it owns the run's cgroup. **Closing the connection is how the broker cancels a run.** The whole cgroup is killed and drained, including a `setsid` child that left the process group. This also covers the broker dying mid-command, which would otherwise leave an orphan holding a credential in its environment.
