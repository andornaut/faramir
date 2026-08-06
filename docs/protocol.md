# Wire protocol

Two sockets, the same shape on both: newline-delimited JSON, one request, one
response, one connection, no framing beyond the newline.

| Socket | Who may connect | What it does |
|---|---|---|
| `/run/faramir/broker.sock` | the agent (`0660 root:devwork`) | run commands, list refs, sync |
| `/run/faramir/keeper.sock` | the broker (`0660 root:faramir-broker`) | return decrypted values |
| `/run/faramir/exec.sock` | the broker (`0660 root:faramir-broker`) | fork a command on a passed PTY |

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
  "cwd": "/srv/faramir",
  "env_refs": { "ROUTER_PW": "secret://home/router/admin" },
  "timeout_sec": 600
}
```

| Field | Required | Notes |
|---|---|---|
| `cmd` | yes | **Array.** A string is rejected with guidance; the broker never runs `sh -c` for you. |
| `cwd` | no | Absolute. Defaults to `[exec] default_cwd`. Checked against the matching rule's `cwd_allow`. |
| `env_refs` | no | `NAME` → `secret://ref`. Values are impossible to pass; names are validated, and `PATH`, `LD_PRELOAD`, `SOPS_AGE_KEY` and similar are reserved. |
| `timeout_sec` | no | Clamped to the rule's and the global maximum. |

`{{SECRET:ref}}` may appear inside an argument for readability. It is rewritten
to `${VAR}` (a shell variable *reference*) and `VAR` is added to the injected
environment. It never expands to a value broker-side, so the value still never
appears in any `argv`.

### `sync`

```json
{"op": "sync", "ref": "HEAD"}
```

Fetches `ref` from the agent's working tree into the broker's checkout and
hard-checks it out. `ref` is validated against `[sync] allowed_refs` and may
not start with `-`. Deliberately not reachable through `exec`: the shipped
`git-readonly` rule denies `fetch`, `checkout`, `reset` and `clean`.

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

Loaded files, ref count, load errors, allowlist rule names, whether sync is
enabled. Not the refs refused at load; see `list_secrets` above.

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

`log_id` points into `/var/log/faramir/raw.log`, which the agent cannot read.
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
  "error": { "code": "denied", "message": "'cat' is not in the allowlist. Permitted programs: bash, printenv, …" }
}
```

| Code | Meaning |
|---|---|
| `bad_request` | Malformed request, bad env var name, literal value where a ref was required |
| `denied` | No allowlist rule matched, or an argument/cwd constraint failed |
| `unknown_secret` | The ref does not exist in any managed file |
| `busy` | At `max_concurrency`; retry |
| `sync_failed` | Sync refused or git failed |
| `exec_failed` | The program could not be started |
| `forbidden` | Peer uid/gid not permitted (`SO_PEERCRED`) |
| `too_large` | Request exceeded `max_request_bytes` |
| `internal` | Bug; check the journal |

Denials are deliberately specific about *which* check failed, so the agent can
correct itself in one turn instead of guessing.

## Authentication

The socket is `0660 root:devwork`, and the broker additionally checks
`SO_PEERCRED` against `[server] allowed_uids` / `allowed_groups`. The peer's
uid, gid and pid are recorded in every audit record.

## The keeper socket

Internal, between the broker and the process that holds the age key. One
operation:

```json
{"op": "get_values"}
{"op": "get_values", "refs": ["home/router/admin"]}
```

```json
{"values": {"home/router/admin": "…"}, "errors": []}
```

`refs` is optional and filters the result. Without it the keeper returns
everything, which is what the broker wants: the redactor is built from the
whole value set, not just the refs a given command injected.

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
`[keeper] allowed_users` on top of the socket mode.

## The executor socket

Internal, between the broker and the uid that forks commands. One request,
carrying a single file descriptor as ancillary data:

```json
{"argv": ["/usr/bin/printenv", "ROUTER_PW"],
 "cwd": "/srv/faramir",
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

`argv[0]` is re-checked against `[exec] allowed_bin_dirs` here as well as in
the broker. The duplication is deliberate: a broker bug should not become "run
anything from anywhere as `faramir-exec`".

The executor owns the timeout, because it owns the process group. **Closing
the connection is how the broker says "give up"**, and the child's process
group is killed. That covers the broker dying mid-command, which would
otherwise leave an orphan holding a credential in its environment.
