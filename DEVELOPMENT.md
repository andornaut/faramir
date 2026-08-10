# Developing

```bash
make build           # a static binary into bin/
make coverage        # race-enabled suite plus per-function report
make fmt             # apply the import and format rules CI checks
make lint            # golangci-lint
make test            # whole suite; needs no sops installed
make test-e2e        # end-to-end against a real broker in a temp dir
make test-unit       # everything except end-to-end
```

- Everything under `systemd/`, `etc/`, `agent/` and `docs/` is embedded into the binary by `assets.go`, so `init` installs a host without a checkout. The `.tmpl` files are the shipped files themselves, so what you read is what the install writes. That decides where a new document goes: operator documentation in `docs/`, which ships and installs, and developer documentation at the root, which does not.
- Tests live where the logic does. Most of what the broker does is decide, and none of that needs a socket or a child process, so `internal/server` substitutes the executor. `internal/executor` uses a real child, because the PTY and the streaming redactor only mean anything against real bytes.
- The suite runs in a temp directory under one uid, so it covers the protocol, the PTY hand-off and the redactor, but never the uid boundary. That boundary is only real on a host, which is what `sudo faramir doctor` is for. Adversarial exfiltration is asserted nowhere; a value piped through `rev` reaches the caller transformed, as [Not prevented](README.md#not-prevented) says.
- The suite needs no `sops` on `PATH`: `internal/sopstest` builds a stand-in from the sops libraries. It is imported only from `_test.go`, which keeps sops out of the shipped binary; CI fails the build on a `getsops` import reaching `./cmd/faramir`.
- The opencode and Kilo Code plugins are the only shipped logic that is not Go, so they are run rather than read: node drives the shipped file against a stand-in guard, covering the rewrite, the refusal, a tool that is not a shell, and each way of failing closed. Skipped where node is absent. No test covers a running opencode or Kilo Code, or Bun, which is the runtime both load a plugin under.
