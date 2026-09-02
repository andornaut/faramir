package brokerclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
)

// Escalations asks what is waiting, blocking up to waitSec for something to
// be. awaitLogID names the run this caller approved and has not yet heard the
// end of, and is the only run it is told about; empty asks about none.
func Escalations(socketPath string, waitSec int, awaitLogID string) ([]escalation.Question, *escalation.Outcome, error) {
	request := map[string]any{"op": "escalations"}
	if waitSec > 0 {
		request["wait_sec"] = waitSec
	}
	if awaitLogID != "" {
		request["await_log_id"] = awaitLogID
	}
	// The read deadline has to outlast the broker's own wait, or every long poll
	// looks like a broker that stopped answering.
	line, err := roundTrip(socketPath, request, DialWait, time.Duration(waitSec+30)*time.Second)
	if err != nil {
		return nil, nil, err
	}
	var response struct {
		Questions []escalation.Question `json:"questions"`
		Finished  *escalation.Outcome   `json:"finished"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, nil, fmt.Errorf("malformed response: %w", err)
	}
	if response.Error != nil {
		return nil, nil, fmt.Errorf("%s", response.Error.Message)
	}
	return response.Questions, response.Finished, nil
}

// Escalate puts the question and waits for a human's answer. No
// deadline of its own: the broker holds the question for [sudo]
// timeout_sec and refuses it after that.
func Escalate(socketPath string, ancestors []int) (bool, string, error) {
	line, err := roundTrip(socketPath, map[string]any{"op": "escalate", "procs": ancestors}, DialWait, escalationWait)
	if err != nil {
		return false, "", err
	}
	var response struct {
		Approved bool   `json:"approved"`
		Reason   string `json:"reason"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return false, "", errors.New("malformed response")
	}
	if response.Error != nil {
		return false, "", fmt.Errorf("%s", response.Error.Message)
	}
	return response.Approved, response.Reason, nil
}

// escalationWait is the ceiling on one question: the broker decides when to
// give up, and this only stops a lost connection from holding sudo open for
// ever.
//
// Derived rather than picked. It must outlast any question the broker will
// hold, or the helper gives up on a question still open and the operator's yes
// lands on a sudo that has gone. So it is [sudo] timeout_sec's own ceiling plus
// a margin for the round trip: the helper cannot read the config, and the
// broker refuses to load a longer timeout, so the broker always decides first
// and this only ever fires on a broker that stopped answering.
const escalationMarginSec = 30

var escalationWait = time.Duration(config.MaxSudoTimeoutSec+escalationMarginSec) * time.Second
