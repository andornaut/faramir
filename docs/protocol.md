# Wire protocol

Newline-delimited JSON over `/run/secretd/sock`. One request, one response, one
connection. No framing beyond the newline; a request larger than
`[server] max_request_bytes` is refused.

## Requests

### `exec` (default)

```json
{
  "op": "exec",
  "cmd": ["ansible-playbook", "site.yml", "--limit", "routers"],
  "cwd": "/srv/ansible-ctrl",
  "env_refs": { "ROUTER_PW": "secret://home/router/admin" },
  "timeout_sec": 600
}
```

| Field | Required | Notes |
|---|---|---|
| `cmd` | yes | **Array.** A string is rejected with guidance — the broker never runs `sh -c` for you. |
| `cwd` | no | Absolute. Defaults to `[exec] default_cwd`. Checked against the matching rule's `cwd_allow`. |
| `env_refs` | no | `NAME` → `secret://ref`. Values are impossible to pass; names are validated, and `PATH`, `LD_PRELOAD`, `SOPS_AGE_KEY` and similar are reserved. |
| `timeout_sec` | no | Clamped to the rule's and the global maximum. |

`{{SECRET:ref}}` may appear inside an argument for readability. It is rewritten
to `${VAR}` — a shell variable *reference* — and `VAR` is added to the injected
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

Returns ref names only, with any non-redactable ones flagged. Never values.

### `status`

```json
{"op": "status"}
```

Loaded files, ref count, load errors, allowlist rule names, whether sync is
enabled.

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
reached the right place without seeing it — a count of 0 for a secret it
expected is a genuine signal that something is misconfigured.

`log_id` points into `/var/log/secretd/raw.log`, which the agent cannot read.
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
  "error": { "code": "denied", "message": "'cat' is not in the allowlist. Permitted programs: ansible, ansible-playbook, …" }
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
