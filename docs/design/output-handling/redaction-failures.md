# Redaction failures

<a id="rule-withhold-unredacted-output"></a>

## Withhold output when redaction fails

A redaction failure returns a non-zero status and withholds text that the broker could not redact.

- The buffered shell wrapper reports the failure on stderr and withholds the entire captured result. The command has already run.
- A `faramir redact` stream stops on failure, whether it reads standard input or runs a child command. Chunks already redacted and emitted stay visible, so live output can reach the caller without buffering the entire stream.

## Evidence

| Path | Implementation | Test assertions |
| --- | --- | --- |
| Buffered shell wrapper | The wrapper prints the captured result only after the redactor exits successfully. [Shell wrapper](../../../agent/hooks/wrap.sh) | The end-to-end wrapper checks cover an unavailable redactor and a successful child whose result must be withheld. [Wrapper check](../../../tests/e2e/check-wrap.sh) |
| Redaction stream | The CLI reports stream errors. The broker client writes the redacted response for each successful chunk. [CLI entry point](../../../cmd/faramir/redact.go), [broker client](../../../internal/brokerclient/brokerclient.go) | The client tests cover withholding all output when the broker is unreachable and preserving already redacted chunks when the connection fails mid-stream. [Stream tests](../../../internal/brokerclient/redactstream_test.go) |

See [how the shell rewrite works](../../design.md#how-the-rewrite-works) for capture and streaming details.
