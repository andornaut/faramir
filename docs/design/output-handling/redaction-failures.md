# Redaction failures

<a id="rule-withhold-unredacted-output"></a>

## Withhold output when redaction fails

A redaction failure returns a non-zero status and withholds text that the broker could not redact.

- The buffered shell wrapper reports the failure on stderr and withholds the entire captured result. The command has already run.
- A `faramir redact` stream stops on failure, whether it reads standard input or runs a child command. Chunks already redacted and emitted stay visible, so live output can reach the caller without buffering the entire stream.

- Evidence: [Shell wrapper](../../../agent/hooks/wrap.sh) and [wrapper check](../../../tests/e2e/check-wrap.sh)
  cover withholding the captured result if redaction fails.
- Evidence: [CLI entry point](../../../cmd/faramir/redact.go), [broker client](../../../internal/brokerclient/brokerclient.go),
  and [stream tests](../../../internal/brokerclient/redactstream_test.go) cover withholding unredacted output
  and preserving chunks already emitted.

See [how the shell rewrite works](../../design.md#how-the-rewrite-works) for capture and streaming details.
