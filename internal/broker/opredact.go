package broker

import (
	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
)

// opRedactName is the one op a connection may carry more than one of, so it is
// named in the dispatch and again where the loop decides whether to continue.
const opRedactName = "redact"

// opRedact scrubs text the caller already holds, so a session outside the
// broker's uid gets the same redaction a brokered command does. The value set
// never leaves this process. A deliberate oracle, and deliberately not
// rate-limited; docs/design.md has the weighting.
func (s *Server) opRedact(request *protocol.Request, peer *sockutil.Peer,
	stream *redactStream) protocol.Response {
	if stream == nil {
		// A caller with nowhere to keep the redactor cannot be part way through a
		// stream. Blocked rather than quietly completed: feeding text and never
		// flushing would drop the tail this chunk held back.
		if request.More {
			return protocol.ErrorResponse("bad_request",
				"'more' needs a connection that carries the stream", "")
		}
		stream = &redactStream{}
	}
	if stream.redactor == nil {
		if refused := s.refuseUnreadable("redact", "a redact", audit.NewLogID(), peer); refused != nil {
			return *refused
		}
		// Built once for the whole stream, so every chunk of one command's output
		// is scanned against one value set.
		stream.redactor = s.redactor()
		stream.logID = audit.NewLogID()
	}
	stream.inputBytes += len(request.Text)
	output := stream.redactor.Feed(request.Text)
	if !request.More {
		output += stream.redactor.Flush()
		stream.finish(s, peer)
	}
	response := okResponse(0, output)
	response["redactions"], response["log_id"] = stream.redactor.Summary(), stream.logID
	return response
}

// redactStream is what one connection's redact carries between chunks: the
// redactor, because the tail it holds back is only useful to the chunk that
// follows, and the totals for the one audit record the stream writes.
type redactStream struct {
	redactor   *redact.Redactor
	logID      string
	inputBytes int
	written    bool
}

// finish writes the stream's single audit record, at the end rather than per
// chunk: the counts only add up once the last chunk has been through. Called
// again from serveConnection for a stream the peer abandoned.
func (st *redactStream) finish(s *Server, peer *sockutil.Peer) {
	if st.redactor == nil || st.written {
		return
	}
	st.written = true
	s.Audit.Write(map[string]any{
		"log_id": st.logID, "op": "redact", "peer": peer,
		"input_bytes": st.inputBytes, "redactions": st.redactor.Summary(),
	}, audit.Output{})
}
