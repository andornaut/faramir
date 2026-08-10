# Wire protocol

Three sockets, the same shape on each: newline-delimited JSON, one request, one response, one connection, no framing beyond the newline. A request over `[server] max_request_bytes` is refused.

Socket | Who may connect | What it does
--- | --- | ---
`/run/faramir/broker.sock` | the agent (`0660 root:dev`) | run commands, list refs
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
`cwd` | yes | Absolute, and must exist. No fallback: a request naming none is refused. A relative `cmd[0]` resolves against it.
`env_refs` | no | `NAME` → `secret://ref`. Values cannot be passed; names are validated, and `PATH`, `HOME`, `LD_PRELOAD`, `SOPS_AGE_KEY`, `SSH_AUTH_SOCK` and similar are reserved.
`timeout_sec` | no | Positive integer, clamped to `[exec] max_timeout_sec`. Omitted means `[exec] default_timeout_sec`.

`{"op": "redact", "text": "…"}` scrubs text the caller already holds, so a session outside the broker's uid gets the same redaction a brokered command does. `text` is required, must be a string, and is the only field this op reads. The response is the ordinary shape, `output` carrying the scrubbed text and `exit_code` always 0, no command having run. This is what `faramir redact` and the wrapper send, once per Bash command. It is an oracle by design, and is audited like every other op: the input's size and what was found, never the text.

`{"op": "list_secrets"}` returns ref names only. `{"op": "status"}` returns the broker version, `configs` (the base config and every drop-in that contributed, in merge order), loaded files, the count of secrets loaded, and load errors. Neither reports the refs refused at load: that list names exactly the secrets that are never tokenized, so it stays behind `faramir broker --check`. See [redaction.md](redaction.md).

### Responses

```json
{
  "exit_code": 0,
  "output": "…redacted, ANSI-stripped, stdout+stderr merged…",
  "truncated": false,
  "redactions": [{ "token": "«SECRET:home/router/admin»", "count": 3 }],
  "log_id": "2026-08-05T14:22:01Z-a91f",
  "timed_out": false,
  "duration_sec": 12.4
}
```

`redactions` reports **counts, not values**, so the caller can confirm a secret reached the right place without seeing it; a count of 0 where one was expected is a real signal that something is misconfigured. `log_id` points into `/var/log/faramir/audit.log`, which the agent cannot read, so it can say "see log 2026-08-05T14:22:01Z-a91f" to the operator.

An error nulls `exit_code` and adds `error`:

```json
{"error": {"code": "exec_failed",
           "message": "ansible-playbook: not found on the broker's PATH (…)"}}
```

Code | Meaning
--- | ---
`bad_request` | Malformed request, bad or reserved env var name, a malformed `secret://` reference, `cwd` that does not exist
`unknown_secret` | The ref is in no managed file, or was refused at load as not redactable
`busy` | At `[server] max_concurrency`; retry
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
 "errors": [], "unresolved": []}
```

Every managed value, never a subset: the redactor is built from the whole value set, because a managed host can print a credential no command injected. The `state` is the fingerprint of each file this decrypt read, returned with the values so the two describe the same moment. Fetched separately it could fingerprint a file edited after the decrypt, and that edit would then never be noticed.

```json
{"op": "get_state"}
{"state": [{"path": "…", "mtime_unix_nano": 1743160000000000000, "size": 812}],
 "errors": [], "unresolved": []}
```

The staleness poll, and where `[secrets] files` globs are expanded, so a file added to the secrets directory appears without a restart. The broker cannot stat those files itself: it is `2750 root:faramir-keeper` and the broker is not in that group. This answers without the key and without execing sops, so it stays cheap enough to serve on every request when `refresh_interval_sec` is 0.

A file that could not be stat-ed or decrypted comes back in `errors` rather than as an error response, so one broken file does not blank the whole value set. Key material is stripped from those strings before they cross the socket.

`unresolved` is separate, and the separation is the point: an entry that named no file is a secrets directory not written yet, which is what every first install looks like, while a file that is there and will not open is a value the redactor is missing without knowing it. Neither stops the daemon: it starts either way and refuses `exec` and `redact` per request, so the state can be diagnosed against a running process. Both fail `faramir broker --check` and `faramir doctor`, which are the operator's audit rather than the daemon's gate. The broker cannot work this out for itself: expanding a glob means listing the secrets directory, and that is the keeper's alone.

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

The executor owns the timeout, because it owns the process group. **Closing the connection is how the broker says "give up"**, and the child's process group is killed. That covers the broker dying mid-command, which would otherwise leave an orphan holding a credential in its environment.
