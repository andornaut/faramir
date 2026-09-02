package main

import "github.com/andornaut/faramir/internal/brokerclient"

// reReadNote is what a command that wrote the store says about the broker. It
// stands next to "wrote the file", so it has to say whether the value is
// covered yet rather than leaving that to be assumed.
func reReadNote(answer, waiting string) string {
	switch answer {
	case brokerclient.RefreshOK:
		return "the broker has re-read it"
	case "":
		return "the broker did not answer, so " + waiting
	}
	return "the broker refused to re-read it (" + answer + "), so " + waiting
}
