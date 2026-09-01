package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/escalation"
)

// pending asks what is waiting, blocking up to waitSec for something to be.
// awaitLogID names the run this caller approved and has not yet heard the end
// of, and is the only run it is told about; empty asks about none.
func pending(socketPath string, waitSec int, awaitLogID string) ([]escalation.Question, *escalation.Outcome, error) {
	request := map[string]any{"op": "escalations"}
	if waitSec > 0 {
		request["wait_sec"] = waitSec
	}
	if awaitLogID != "" {
		request["await_log_id"] = awaitLogID
	}
	// The read deadline has to outlast the broker's own wait, or every long poll
	// looks like a broker that stopped answering.
	line, err := brokerclient.RoundTrip(socketPath, request, time.Duration(waitSec+30)*time.Second)
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

func answer(prog, socketPath, id string, approve, asJSON bool) int {
	return send(prog, socketPath, map[string]any{
		"op": "answer", "id": id, "approved": approve,
	}, asJSON, true)
}
