# Wire protocol

Three sockets, the same shape on each: newline-delimited JSON, one request, one response, one connection, no framing beyond the newline. An oversized request is refused: the broker's limit is `[server] max_request_bytes`, the keeper's and the executor's are fixed.

One exception, and it is a repetition rather than a second wire format: a `redact` chunk marked `more` keeps the connection open for the next one. Same framing, same limit, same one response per request; only the count changes. [Streaming a redact](#streaming-a-redact) is why.

Socket | Who may connect | What it does
--- | --- | ---
`/run/faramir/broker.sock` | the agent (`0660 root:<client-group>`) | run commands, list refs
`/run/faramir/keeper.sock` | the broker (`0660 root:faramir-broker`) | return decrypted values
`/run/faramir/exec.sock` | the broker (`0660 root:faramir-broker`) | fork a command on a passed PTY

The internal sockets are root-owned so that neither the keeper's nor the executor's own uid can connect: a child reaching the executor socket would run commands the broker never authorised and never logged.

## The broker socket

The mode is one check; the broker also tests `SO_PEERCRED` against `[server] allowed_group`, and records the peer's uid, gid and pid in every audit record.

```json
{
  "op": "exec",
  "cmd": ["printenv", "ROUTER_PW"],
  "cwd": "/home/you/src/project",
  "env_refs": { "ROUTER_PW": "secret://home/router/admin" },
  "timeout_sec": 600
}
```

Field | Required | Notes
--- | --- | ---
`cmd` | yes | **Array.** A string is rejected with guidance; the broker never runs `sh -c` for you.
`cwd` | yes | Absolute, and must exist. No fallback: a request naming none is refused. A relative `cmd[0]` resolves against it. The CLI and the MCP server each fill in their own working directory when the caller names none, so this is a refusal only on the socket.
`env_refs` | no | `NAME` → `secret://ref`. Values cannot be passed; names are validated, and `PATH`, `HOME`, `LD_PRELOAD`, `SOPS_AGE_KEY`, `SSH_AUTH_SOCK` and similar are reserved.
`timeout_sec` | no | Positive integer, clamped to `[exec] max_timeout_sec`. Omitted means `[exec] default_timeout_sec`.

`{"op": "redact", "text": "…"}` scrubs text the caller already holds, so a session outside the broker's uid gets the same redaction a brokered command does. `text` is required and must be a string; `more` is the only other field this op reads. The response is the ordinary shape, `output` carrying the scrubbed text and `exit_code` always 0, no command having run. This is what `faramir redact` and the wrapper send. It is an oracle by design, and is audited like every other op: the input's size and what was found, never the text.

#### Streaming a redact

A caller with more text than one request may carry sends it a chunk at a time **down one connection**, every chunk but the last marked `{"more": true}`.

The broker keeps one redactor for that connection. That is the whole point: the redactor holds back a tail longer than the longest rendering of any value, so a secret split between two chunks is caught by the chunk that completes it. A connection per chunk gives each its own redactor, and a value across the join belongs to neither, and comes back in the clear. A client must break a line longer than one chunk somewhere, so this is reachable by ordinary output: a single-line JSON document, a minified bundle, `base64 -w0`.

- `more` must be a boolean. A chunk carrying it gets `Feed`'s output, which withholds the tail; the chunk without it gets that plus the flush, and ends the stream.
- Sent to an endpoint that cannot keep a redactor between chunks, `more` is a `bad_request` rather than a request completed as though it stood alone.
- A stream writes **one** audit record when it ends, carrying the totals for the whole of it, and one is written for a stream the peer abandoned as well.
- Between chunks a stream in progress may idle up to `[exec] max_timeout_sec`, because `faramir redact -- command` sends a chunk when the command has printed one. The first request on a connection is on the ordinary short clock.

`{"op": "list_secrets"}` returns ref names only. `{"op": "status"}` returns the broker version, `configs` (the base config and every drop-in that contributed, in merge order), loaded files, the count of secrets loaded, load errors, whether an SSH key is configured and usable (`ssh.configured`, `ssh.usable`; whether, never where), and whether a brokered command may ask to sudo (`sudo.enabled`; whether, never how).

`{"op": "approvals"}` and `{"op": "approve", "id": …, "approve": true}` are the operator's half of the approval channel, and with `ask_approval` the only ops the broker refuses to a caller it otherwise admits: all three require the peer to be root, checked with `SO_PEERCRED`, because the account the coding agent runs as must not be able to approve what the agent asked for. `approvals` takes an optional `wait_sec` and blocks up to that long for a question to appear, so a watcher costs one connection rather than a poll a second. It returns at most one question, ever, a second command asking to sudo while one is waiting being refused rather than queued: carrying `waiting_sec` and `expires_in_sec`, the second being what is left of `[sudo] timeout_sec`. `approve` answers a question by `id`, and `unknown_question` means it was already answered or its command gave up.

`{"op": "ask_approval", "token": …}` is the PAM helper's half: it names the run by the token in the brokered command's environment and blocks until a human answers, the question expires, or the broker stops. `sudo` is blocked on it throughout, which is what makes the wait an authentication step. A token naming no running command is refused without asking anybody.

### Responses

```json
{
  "exit_code": 0,
  "output": "…redacted, ANSI-stripped, stdout+stderr merged…",
  "truncated": false,
  "redactions": [{ "token": "«SECRET:home/router/admin»", "count": 3 }],
  "log_id": "2026-08-05T14:22:01Z-a91f00002c",
  "timed_out": false,
  "duration_sec": 12.4
}
```

`redactions` reports **counts, not values**, so the caller can confirm a secret reached the right place without seeing it; a count of 0 where one was expected is a real signal that something is misconfigured. `log_id` points into `/var/log/faramir/audit.log`, which the agent cannot read, so it can say "see log 2026-08-05T14:22:01Z-a91f00002c" to the operator.

An error nulls `exit_code` and adds `error`:

```json
{"error": {"code": "exec_failed",
           "message": "ansible-playbook: not found on the broker's PATH (…)"}}
```

Code | Meaning
--- | ---
`bad_request` | Malformed request, bad or reserved env var name, a malformed `secret://` reference, `cwd` that does not exist
`unknown_secret` | The ref is in no managed file, or was refused at load as not redactable
`unknown_question` | `approve` named a question that is no longer waiting: already answered, or its command gave up
`busy` | At `[server] max_concurrency`; retry
`approval_in_progress` | An approval is being decided or held on the executor's uid, so no other brokered command runs. Names the command holding it. **Terminal, not retryable**: this command was neither run nor queued, and the code names the host's state rather than your request's. Only on a host installed with `--allow-sudo`
`not_quiescent` | `approve` said yes, but a process of the executor's uid was alive outside the run being approved and could have ridden the approval. The question is refused rather than held open, so the `sudo` fails and the command is run again once the host is quiet
`no_audit` | The audit log cannot be written, so the command was refused rather than run unrecorded. `exec` alone: a command that cannot be recorded is not one this host runs, and the filesystem the log sits on is one a brokered command's own output can fill
`no_secrets` | A managed file went unread: no entry matched a file, or one that matched did not load. `exec` and `redact` both refuse; `status` and `list_secrets` always answer
`exec_failed` | `cmd[0]` did not resolve to an executable, or the program could not be started
`forbidden` | Peer uid/gid not permitted (`SO_PEERCRED`)
`too_large` | Request exceeded `[server] max_request_bytes`
`timeout` | The connection was opened but no request arrived within 30s

There is no command allowlist, so there is no `denied`. Messages name what failed and where to fix it, so the agent can correct itself in one turn: a program off `[exec.base_env] PATH` says so and names the setting.

## The keeper socket

Peer uid is checked against `[keeper] allowed_user` on top of the mode. There is no group form, the only group in play holding the agent's own uid.

```json
{"op": "get_values"}
{"values": {"home/router/admin": "…"},
 "state": [{"path": "/etc/faramir/secrets/x.sops.yml",
            "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": []}
```

Every managed value, never a subset: the redactor is built from the whole value set, because a managed host can print a credential no command injected. The `state` is the fingerprint of each file this decrypt read, returned with the values so the two describe the same moment. Fetched separately it could fingerprint a file edited after the decrypt, and that edit would then never be noticed.

```json
{"op": "get_state"}
{"state": [{"path": "…", "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved_patterns": []}
```

The staleness poll, and where `[secrets] patterns` globs are expanded, so a file added to the secrets directory appears without a restart. The broker cannot stat those files itself: it is `2750 root:faramir-keeper` and the broker is not in that group. This answers without the key and without execing sops, so it stays cheap enough to serve on every request when `refresh_interval_sec` is 0.

A file that could not be stat-ed or decrypted comes back in `errors` rather than as an error response, so one broken file does not blank the whole value set. Key material is stripped from those strings before they cross the socket.

`unresolved_patterns` is separate, and the separation is the point: an entry that named no file is a secrets directory not written yet, which is what every first install looks like, while a file that is there and will not open is a value the redactor is missing without knowing it. Neither stops the daemon: it starts either way and refuses `exec` and `redact` per request, so the state can be diagnosed against a running process. Both fail `faramir broker --check` and `faramir doctor`.

Anything else is refused, and **there is no operation that returns the age key**; adding one would defeat the reason the keeper is a separate service.

```json
{"error": {"code": "unsupported",
           "message": "unsupported op 'get_age_key'; the keeper serves
                       'get_values' and 'get_state' only and has no operation
                       that returns key material"}}
```

## The executor socket

One request, carrying a single file descriptor as ancillary data:

```json
{"argv": ["/usr/bin/printenv", "ROUTER_PW"],
 "cwd": "/home/you/src/project",
 "env": {"ROUTER_PW": "…"},
 "timeout_sec": 600,
 "kill_grace_sec": 5}

{"exit_code": 0, "timed_out": false, "duration_sec": 12.4}
```

The descriptor is the **slave** end of a PTY the broker created. The broker keeps the master, so redaction and the audit log read the child's bytes directly. Both sides close their copy of the slave once the child holds it, or the master never reaches EOF.

`argv[0]` arrives already resolved to an absolute path and the executor checks nothing about it. What bounds a brokered command is the uid it runs as (no age key, no audit log, no SSH key) and the mode on this socket, which the executor's own uid cannot open.

A second op shares the socket, and an absent `op` is the request above:

```json
{"op": "quiescent"}

{"quiescent": false, "detail": "1 process(es) are running as the executor outside any brokered command (4821 (sleep))"}
```

The broker asks this before an approval takes: is any process of the executor's uid alive outside that daemon and outside the runs it is confining? It is asked here because the broker cannot see the answer, its own unit setting `ProtectProc=invisible`. Every failure is a no, and an op this daemon does not know is refused by name rather than read as a malformed command, so a version skew says what it is.

The executor owns the timeout, because it owns the run's cgroup. **Closing the connection is how the broker cancels a run**, and the whole cgroup is killed and drained, including a `setsid` child that broke out of the process group. That covers the broker dying mid-command, which would otherwise leave an orphan holding a credential in its environment.
