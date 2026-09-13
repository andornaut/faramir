package main

import "github.com/andornaut/faramir/internal/brokerclient"

// reReadNote is what a command that wrote the store says about the broker. It
// stands next to "wrote the file", so it has to say whether the value is
// covered yet rather than leaving that to be assumed.
func reReadNote(answer string) string {
	switch answer {
	case brokerclient.RefreshOK:
		return "broker reloaded"
	case "":
		return "broker did not answer; it reloads within one refresh interval"
	}
	return "broker refused to reload (" + answer + "); it reloads within one refresh interval"
}
