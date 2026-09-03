package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"time"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// requireRoot gates the three escalation ops, the only ones this socket refuses
// to a caller it otherwise admits. Root, checked with SO_PEERCRED: not the
// client group, which holds the account the coding agent runs as, and not the
// executor, which is the side asking. Made in the op rather than left to a
// file mode, the socket admitting a group by design.
func (s *Server) requireRoot(op string, peer *sockutil.Peer) *protocol.Response {
	if peer != nil && peer.UID == 0 {
		return nil
	}
	out := protocol.ErrorResponse("forbidden", fmt.Sprintf(
		"%s needs root: an escalation must be answered by an account the coding "+
			"agent cannot become. Run `sudo faramir sudo ls`", op), "")
	return &out
}

// opEscalate is what sudo's PAM helper asks, and the only thing that decides
// whether a brokered command becomes root. It blocks until a human answers.
//
// Root, like the other two: the helper reaches it because pam_exec runs it with
// seteuid inside sudo. What it sends is an ancestry rather than anything it was
// given, so a caller has nothing to present and nothing to copy: the answer comes
// from comparing the kernel's account of who forked whom against what the
// executor forked.
func (s *Server) opEscalate(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("escalate", peer); refused != nil {
		return *refused
	}
	if len(request.Procs) == 0 {
		return protocol.ErrorResponse("bad_request",
			"'procs' must name the processes above the sudo asking to escalate", "")
	}
	approved, code, reason := s.Escalation.Ask(request.Procs)
	// A refusal is a response rather than an error: the helper reports it to PAM
	// as a failed authentication, which is what sudo has to see. The code rides
	// beside the reason, a refusal and an expiry reading alike in prose.
	response := okResponse(0, reason+"\n")
	response["approved"], response["reason"], response["outcome_code"] = approved, reason, code
	return response
}

func (s *Server) opEscalations(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("escalations", peer); refused != nil {
		return *refused
	}
	// Clamped in seconds, before the multiplication rather than after it: int64
	// nanoseconds run out somewhere past 292 years, so a large enough WaitSec
	// wraps negative and the min below keeps the negative. Poll would then return
	// at once on a request that asked to wait, which reads as a watcher that will
	// not hold. The parser bounds this below and not above, any non-negative
	// integer reaching here.
	wait := time.Duration(min(request.WaitSec, maxEscalationWaitSec)) * time.Second
	questions, finished := s.Escalation.Poll(wait, request.AwaitLogID)
	// Present only when the caller named a run and that run has ended, rather
	// than carrying a null nothing asked for.
	rendered := map[string]any{"questions": questions}
	if finished != nil {
		rendered["finished"] = finished
	}
	body, err := json.MarshalIndent(rendered, "", "  ")
	if err != nil {
		return protocol.ErrorResponse("internal", "the questions could not be "+
			"rendered: "+err.Error(), "")
	}
	response := okResponse(0, string(body)+"\n")
	response["questions"] = questions
	if finished != nil {
		response["finished"] = finished
	}
	return response
}

func (s *Server) opApprove(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("answer", peer); refused != nil {
		return *refused
	}
	// Named by the answering account rather than by uid alone: the audit record
	// is read by a person asking who let something through.
	who := fmt.Sprintf("uid %d", peer.UID)
	if entry, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		who = entry.Username
	}
	if peer.PID > 0 {
		who = fmt.Sprintf("%s (pid %d)", who, peer.PID)
	}
	if err := s.Escalation.Answer(request.ID, request.Approve, who); err != nil {
		// A yes turned into a no for want of a quiet host means run the command
		// again; an id nobody is waiting on means the question had already gone.
		if errors.Is(err, escalation.ErrNotQuiescent) {
			return protocol.ErrorResponse("not_quiescent", err.Error(), "")
		}
		return protocol.ErrorResponse("unknown_question", err.Error(), "")
	}
	verdict := "refused"
	if request.Approve {
		verdict = "approved"
	}
	return okResponse(0, request.ID+" "+verdict+"\n")
}

// maxEscalationWait bounds a watcher's long poll. It returns an empty list and
// the watcher asks again, so a broker restarted under it is noticed.
//
// In seconds as well, for the clamp in opEscalations: a caller's WaitSec is a
// count of seconds, and holding it to this before it becomes a Duration is what
// keeps the multiplication from wrapping.
const (
	maxEscalationWaitSec = 60
	maxEscalationWait    = maxEscalationWaitSec * time.Second
)
