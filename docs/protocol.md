# Wire protocol

Three sockets, newline-delimited JSON, one request and one response per connection. No framing beyond the newline.

Socket | Who may connect | What it does | Request limit
--- | --- | --- | ---
`/run/faramir/broker.sock` | the agent (`0660 root:<client-group>`) | run commands, list refs | 256 KiB
`/run/faramir/keeper.sock` | the broker (`0660 root:<broker's group>`) | return decrypted values | 65536 bytes
`/run/faramir/exec.sock` | the broker (`0660 root:<broker's group>`) | fork a command on a passed PTY | 1 MiB

The internal sockets are root-owned so neither the keeper's nor the executor's own uid can connect: a child reaching the executor socket would run commands the broker never authorised and never logged.

All three drop a connection that sends no request within 30s. Only the broker answers with an error code first.

## version

Every request on all three sockets carries `version`, the version string the sending binary reports, and one naming anything but the receiving daemon's own is refused before its op is read.

There is one binary: the three daemons are it under three units, and the CLI and the MCP server are it as the agent's own processes. Two versions on one host is therefore a process that outlived the install which replaced the binary under it, and the refusal names that.

```json
{"version": "0.6.0",
 "error": {"code": "bad_request",
           "message": "the caller names faramir 0.1.4 and this is faramir 0.6.0:
                       restart it. An MCP server is a child of the coding agent, so
                       it is reconnected there rather than restarted on its own"}}
```

Every error response from the broker carries `version`, the build that answered. A request refused for naming another version is the one case where the caller cannot read that out of an op, the refusal coming before the op is read, and it is what [`doctor`](operating.md#checking-an-install) reports skew from.

A caller that sends no `version` is refused the same way and told it named none. The alternative is failing later on whichever op or field changed in between: an op the daemon no longer has is refused as unknown, which reads as a caller asking for something that never existed, and a field it no longer reads is ignored, so a setting the caller sent goes silently unapplied.

The MCP server is the process this is for: a long-lived child of the coding agent, and so the one client that survives an install.

## The broker socket

The mode is one check; the broker also tests `SO_PEERCRED` against `[server] allowed_group`, and records the peer's uid, gid and pid in every audit record.

Op | Does | Notes
--- | --- | ---
`run` | run a command | The default: an absent `op` is read as this. An `op` this broker does not know is refused rather than defaulted, so a caller naming one is told.
`redact` | scrub text the caller already holds | An oracle by design. Audited: the input's size and what was found, never the text.
`refs` | ref names only | Adds `refs`.
`status` | version, `configs`, loaded files, secret count, load errors, `ssh.configured`/`ssh.usable`, `sudo.enabled` | Whether, never where or how.
`escalations` | what is waiting, and how an approved run ended | Root only. Adds `questions`, and `finished` when the caller named a run that has ended.
`approve` | answer by `id` | Root only.
`escalate` | the PAM helper's half | Root only. Adds `approved`, `outcome_code`, `reason`.

The three root-only ops are checked with `SO_PEERCRED`: the account the coding agent runs as must not approve what the agent asked for. `status` and `refs` answer whatever the value set is doing.

### run

```json
{
  "op": "run",
  "version": "0.6.0",
  "cmd": ["printenv", "ROUTER_PW"],
  "cwd": "/home/you/src/project",
  "env_refs": { "ROUTER_PW": "faramir://home/router/admin" },
  "timeout_sec": 600
}
```

Field | Required | Notes
--- | --- | ---
`version` | yes | The sending binary's own version. Every op on every socket takes it, and a mismatch is refused before the op is read. See [version](#version).
`cmd` | yes | Non-empty array of strings. A string is rejected with guidance; the broker never runs `sh -c` for you.
`cwd` | yes | Absolute, and must be an existing directory. A relative `cmd[0]` resolves against it. The CLI and the MCP server fill in their own working directory, so this is a refusal only on the socket.
`env_refs` | no | `NAME` to `faramir://ref`. `NAME` must match `^[A-Za-z_][A-Za-z0-9_]*$` and must not be reserved. Values cannot be passed.
`timeout_sec` | no | Positive integer, clamped down to `[command] max_timeout_sec`. Omitted means `[command] timeout_sec`.

Reserved `env_refs` names, refused so injection cannot redirect the loader, the interpreter, sops or the agent relay. Anything outside this set is accepted:

```text
PATH  HOME  IFS  BASH_ENV  ENV  LD_PRELOAD  LD_LIBRARY_PATH
SOPS_AGE_KEY  SOPS_AGE_KEY_FILE  CREDENTIALS_DIRECTORY
SSH_AUTH_SOCK  SSH_AGENT_PID  SUDO_ASKPASS  FARAMIR_ESCALATION_TOKEN
```

### redact, and streaming it

`{"op": "redact", "version": "…", "text": "…"}` returns the ordinary response shape with `output` carrying the scrubbed text and `exit_code` 0, no command having run. `text` is required; `more` is the only other field the op reads.

A caller with more text than one request may carry sends it a chunk at a time **down one connection**, every chunk but the last marked `{"more": true}`. The broker keeps one redactor per connection, holding back a tail longer than the longest rendering of any value, so a secret split between two chunks is caught by the chunk that completes it. A connection per chunk gives each its own redactor, and a value across the join comes back in the clear. Ordinary output reaches this: a single-line JSON document, a minified bundle and `base64 -w0` all have to be broken somewhere.

- `more` must be a boolean. Sent where no stream state exists, it is a `bad_request` rather than a request completed as though it stood alone.
- One audit record per stream, written when it ends, carrying the totals for the whole of it. A stream the peer abandoned still writes one.
- The first request on a connection is on the 30s clock; between chunks a stream may idle up to `[command] max_timeout_sec`, because `faramir redact -- command` sends a chunk when the command has printed one.

### escalations

`escalations` takes an optional `wait_sec` and blocks up to that long for a question to appear, so a watcher costs one connection rather than a poll a second. The wait is clamped to 60s. It returns at most one question, ever, carrying `caller` (the account that asked, never the one the command would run as), `waiting_sec` and `expires_in_sec`; a second command asking to sudo while one is waiting is refused rather than queued.

It also takes an optional `await_log_id`, naming the run the caller approved and has not yet heard the end of. When that run ends the response carries `finished`: `log_id`, `exit_code`, `duration_sec`, `waited_sec`, `timed_out` and `error`, and the poll returns as soon as the run ends rather than waiting out `wait_sec`. `exit_code` is `null` where the broker got no status for the run, `error` saying why; a zero there would read as a clean exit. Only an approved run has an ending to report, and only the caller naming it is told: the broker holds the last one rather than emptying it when it is read, so two watchers both see it and a caller that approved nothing sees none.

`escalate` names the run by the token in the brokered command's environment and blocks until a human answers, the question expires, or the broker stops. `sudo` is blocked on it throughout, which is what makes the wait an authentication step. A token naming no running command is refused without asking anybody.

`outcome_code` is which of those it was, in one word, `reason` being the sentence beside it. A refusal a human typed and a question nobody answered are different events and are acted on differently, so the code carries the difference and nothing has to parse the prose to find it. The same code is written to the audit record, where `faramir logs` reads it.

Code | Means
--- | ---
`approved` | a human said yes, or this sudo was covered by the yes given for the same command
`denied` | a human said no
`expired` | nobody answered within `[escalation] timeout_sec`
`not_quiescent` | a yes was turned into a no: a process of the executor's uid was alive outside the run
`run_ended` | the command exited before the question was answered
`broker_stopped` | the broker stopped, or was stopping when the request arrived
`other_command` | another brokered command was registered, so no question could be put
`unnamed_question` | the question could not be given an id, so nothing could answer it
`unknown_token` | the token named no running command
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
`redactions` | Counts, not values. A count of 0 where one was expected is a real signal that something is misconfigured.
`log_id` | Points into `/var/log/faramir/audit.log`, which the agent cannot read, so it can cite a record to the operator.
`invalid_bytes` | How many bytes were not valid UTF-8 and came back as `U+FFFD`. What says the output was binary.
`waited_sec` | How much of `duration_sec` the command spent blocked on its own escalation, present only where a `sudo` waited at all. Written to the `run` record and carried on `finished` as well. `duration_sec` is wall time from fork to exit and the child sits inside `sudo` for the whole question, so an escalation answered slowly reads as a slow command without this. Reported beside the duration rather than subtracted from it: `[command] max_timeout_sec` is enforced against the same clock, and a duration that no longer matched it would be a second, quieter number.
`escalation_code`, `escalation` | Why a `sudo` inside the command was turned down, present only where one was. `sudo` reports a refusal and an expiry alike, as its own authentication failure, so this is where `denied` is told from `expired`, and running the command again is worth something in one case and nothing in the other. The codes are the [escalate codes](#escalations); the same pair is written to the `run` record.
`truncated` | Output hit the output cap.

A `redact` response carries no `timed_out` or `duration_sec`. An error nulls `exit_code` and adds `error`:

```json
{"error": {"code": "exec_failed",
           "message": "ansible-playbook: not found on the broker's PATH (…)"}}
```

Code | Meaning
--- | ---
`bad_request` | Malformed request, a `version` that is not this daemon's own, bad or reserved env var name, a malformed `faramir://` reference, or a `cwd` that does not exist or is not a directory
`unknown_secret` | The ref is in no managed file, or was refused at load as not redactable
`unknown_question` | `approve` named a question that is no longer waiting: already answered, or its command gave up
`busy` | At `[command] concurrency`; retry
`escalation_in_progress` | An escalation is being decided or held, so no other brokered command runs. Names the command holding it. **Terminal, not retryable**: this command was neither run nor queued. Only where `--allow-sudo` was installed
`not_quiescent` | `approve` said yes, but a process of the executor's uid was alive outside the run being approved and could have ridden the escalation. The `sudo` fails and the command is run again once the host is quiet
`no_audit` | The audit log cannot be written, so the command was refused rather than run unrecorded. `run` alone
`no_secrets` | A managed file went unread: no entry matched a file, or one that matched did not load. `run` and `redact` both refuse; `status` and `refs` always answer
`exec_failed` | `cmd[0]` did not resolve to an executable, or the program could not be started
`internal` | The broker could not render its own answer. Not a fault of the request
`forbidden` | Peer uid or gid not permitted, or a non-root peer on one of the three root-only ops
`too_large` | Request exceeded the 256 KiB cap, which is a [constant rather than a key](configuration.md#what-is-not-a-key-at-all)
`timeout` | No request arrived within 30s, or a redact stream idled past `[command] max_timeout_sec`

There is no command allowlist, so there is no `denied`. Messages name what failed and where to fix it, so the agent can correct itself in one turn: a program off `[command.env] PATH` says so and names the setting.

## The keeper socket

Peer uid is checked against `[keeper] allowed_user` on top of the mode. There is no group form, the only group in play holding the agent's own uid. Two ops, and **none that returns the age key**; adding one would defeat the reason the keeper is a separate service.

```json
{"op": "get_values", "version": "0.6.0"}
{"values": {"home/router/admin": "…"},
 "state": [{"path": "/etc/faramir/secrets/x.sops.yml",
            "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": []}
```

Every managed value, never a subset: the redactor is built from the whole value set, because a managed host can print a credential no command injected. The `state` is the fingerprint of each file this decrypt read, returned with the values so the two describe the same moment. Fetched separately it could fingerprint a file edited after the decrypt, and that edit would never be noticed.

```json
{"op": "get_state", "version": "0.6.0"}
{"state": [{"path": "…", "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": []}
```

The staleness poll, and where the managed store globs are expanded, so a file added to the secrets directory appears without a restart. The broker cannot stat those files itself, being outside `2750 root:faramir-keeper`. This answers without the key and without execing sops, so it stays cheap enough to serve on every request when `min_refresh_sec` is 0.

- A file that could not be stat-ed or decrypted comes back in `errors` rather than as an error response, so one broken file does not blank the whole value set. Key material is stripped from those strings before they cross the socket.
- `unresolved_patterns` is separate, and the separation is the point: an entry that named no file is a secrets directory not written yet, which is what every first install looks like, while a file that is there and will not open is a value the redactor is missing without knowing it. Neither stops the daemon; both fail `faramir broker --check` and `faramir doctor`.
- An oversized or malformed request gets no response: the connection closes. A JSON `null` payload is the one that answers `bad_request`.

```json
{"error": {"code": "unsupported",
           "message": "unsupported op 'get_age_key'; the keeper serves
                       'get_values' and 'get_state' only and has no operation
                       that returns key material"}}
```

## The executor socket

One request, carrying a single file descriptor as ancillary data:

```json
{"version": "0.6.0",
 "argv": ["/usr/bin/printenv", "ROUTER_PW"],
 "cwd": "/home/you/src/project",
 "env": {"ROUTER_PW": "…"},
 "timeout_sec": 600,
 "kill_grace_sec": 5}

{"exit_code": 0, "timed_out": false, "duration_sec": 12.4}
```

The descriptor is the **slave** end of a PTY the broker created. The broker keeps the master, so redaction and the audit log read the child's bytes directly. Both sides close their copy of the slave once the child holds it, or the master never reaches EOF.

`argv[0]` arrives already resolved to an absolute path and the executor checks nothing about it. What bounds a brokered command is the uid it runs as (no age key, no audit log, no SSH key) and the mode on this socket, which the executor's own uid cannot open. An exit code is `128+signal` where the child was signalled.

A second op shares the socket. `"op": "exec"` and an absent `op` both mean the request above:

```json
{"op": "quiescent", "version": "0.6.0"}

{"quiescent": false, "detail": "1 process(es) are running as the executor outside any brokered command (4821 (sleep))"}
```

The broker asks this before an escalation takes: is any process of the executor's uid alive outside that daemon and outside the runs it is confining? It is asked here because the broker cannot see the answer, its own unit setting `ProtectProc=invisible`. Every failure is a no. An op this daemon does not know is refused `bad_request` with the name in the message, and a broker of another release is refused before that, by [version](#version).

The executor owns the timeout, because it owns the run's cgroup. **Closing the connection is how the broker cancels a run**, and the whole cgroup is killed and drained, including a `setsid` child that broke out of the process group. That covers the broker dying mid-command, which would otherwise leave an orphan holding a credential in its environment.
