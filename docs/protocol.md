# Wire protocol

Two sockets, the same shape on both: newline-delimited JSON, one request, one
response, one connection, no framing beyond the newline.

Socket | Who may connect | What it does
--- | --- | ---
`/run/faramir/broker.sock` | the agent (`0660 root:dev`) | run commands, list refs
`/run/faramir/keeper.sock` | the broker (`0660 root:faramir-broker`) | return decrypted values
`/run/faramir/exec.sock` | the broker (`0660 root:faramir-broker`) | fork a command on a passed PTY

The internal sockets are root-owned so that neither the keeper's nor the
executor's own uid can connect to them: a child that could reach the executor
socket would run commands the broker never authorised and never logged.

The broker's protocol is below; the internal ones are at the end. A request larger
than `[server] max_request_bytes` is refused.

## Requests

### `exec` (default)

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
`cwd` | yes | Absolute, and must exist. There is no fallback: a request that names none is refused. A relative `cmd[0]` resolves against it.
`env_refs` | no | `NAME` → `secret://ref`. Values are impossible to pass; names are validated, and `PATH`, `HOME`, `LD_PRELOAD`, `SOPS_AGE_KEY`, `SSH_AUTH_SOCK` and similar are reserved.
`timeout_sec` | no | Positive integer, clamped to `[exec] max_timeout_sec`. Omitted means `[exec] default_timeout_sec`.

### `list_secrets`

```json
{"op": "list_secrets"}
```

Returns ref names only, never values. A ref whose value is too short or too
low-entropy to redact is refused at load, so it does not appear here and is not
injectable; see [redaction.md](redaction.md).

### `status`

```json
{"op": "status"}
```

Broker version, config path, `config_sources` (the base config and every drop-in that contributed, in the order applied), loaded files, ref count and load errors. Not
the refs refused at load: that list names exactly
the secrets that are never tokenized, so it stays operator-side, behind
`faramir-broker --check`.

## Responses

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

`redactions` reports **counts, not values**, so the caller can confirm a secret
reached the right place without seeing it. A count of 0 for a secret it
expected is a genuine signal that something is misconfigured.

`log_id` points into `/var/log/faramir/audit.log`, which the agent cannot read.
It is there so the agent can say "see log 2026-08-05T14:22:01Z-a91f" to the
operator.

### Errors

```json
{
  "exit_code": null,
  "output": "",
  "truncated": false,
  "redactions": [],
  "log_id": "2026-08-05T14:22:01Z-a91f",
  "error": { "code": "exec_failed", "message": "ansible-playbook: not found on the broker's PATH (…)" }
}
```

Code | Meaning
--- | ---
`bad_request` | Malformed request, bad env var name, reserved env var name, a `secret://` reference that is not well formed, `cwd` that does not exist
`unknown_secret` | The ref does not exist in any managed file, or was refused at load as not redactable
`busy` | At `[server] max_concurrency`; retry
`exec_failed` | `cmd[0]` did not resolve to an executable, or the program could not be started
`forbidden` | Peer uid/gid not permitted (`SO_PEERCRED`)
`too_large` | Request exceeded `[server] max_request_bytes`
`timeout` | The connection was opened but no request arrived within 30s

There is no command allowlist, so there is no `denied`. Errors are deliberately
specific about what failed and where to fix it, so the agent can correct itself
in one turn instead of guessing. A program that is not on `[exec.base_env] PATH`
says so and names the setting.

## Authentication

The socket is `0660 root:dev`, and the broker additionally checks
`SO_PEERCRED` against `[server] allowed_uids` / `allowed_groups`. The peer's
uid, gid and pid are recorded in every audit record.

## The keeper socket

Internal, between the broker and the process that holds the age key. One
operation:

```json
{"op": "get_values"}
```

```json
{"values": {"home/router/admin": "…"}, "errors": []}
```

Every managed value, never a subset: the redactor is built from the whole value
set, because a managed host can print a credential no command injected.

A per-file decryption failure comes back in `errors` rather than as an error
response, so one broken file does not blank the whole value set. Key material
is stripped from those strings before they cross the socket.

Anything other than `get_values` is refused:

```json
{"error": {"code": "unsupported",
           "message": "unsupported op 'get_age_key'; the keeper serves
                       'get_values' only and has no operation that returns
                       key material"}}
```

**There is no operation that returns the age key, and adding one would defeat
the reason the keeper is a separate service.** Peer uid is checked against
`[keeper] allowed_users` on top of the socket mode. There is no group form: the only group in play holds the agent's own uid.

## The executor socket

Internal, between the broker and the uid that forks commands. One request,
carrying a single file descriptor as ancillary data:

```json
{"argv": ["/usr/bin/printenv", "ROUTER_PW"],
 "cwd": "/home/you/src/project",
 "env": {"ROUTER_PW": "…"},
 "timeout_sec": 600,
 "kill_grace_sec": 5}
```

```json
{"exit_code": 0, "timed_out": false, "duration_sec": 12.4}
```

The descriptor is the **slave** end of a PTY the broker created. The broker
keeps the master, so redaction and the audit log read the child's bytes
directly rather than through a second hop. Both sides close their copy of the
slave once the child holds it, or the master never reaches EOF.

`argv[0]` arrives already resolved to an absolute path; the executor checks
nothing about it. What bounds a brokered command is the uid it runs as (no age
key, no audit log, no SSH key) and the mode on this socket, which the executor's
own uid cannot open.

The executor owns the timeout, because it owns the process group. **Closing
the connection is how the broker says "give up"**, and the child's process
group is killed. That covers the broker dying mid-command, which would
otherwise leave an orphan holding a credential in its environment.
